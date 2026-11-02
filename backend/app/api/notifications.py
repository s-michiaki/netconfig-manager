"""コンフィグ変更の通知 API

- 自分の通知設定: /me（閲覧者以上。自分の分だけ）
- ユーザーグループ（メンバー・グループの通知設定）: /groups（管理者のみ）
- 通知先の確認: /preview（管理者のみ。指定した機器グループの変更で、どこへ送られるか）
"""
import json
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import DeviceGroup
from app.models.notification import NotificationSetting, UserGroup, UserGroupMember
from app.models.user import User
from app.services.audit import Audit, get_audit
from app.services.notify import KINDS, mask_webhook, resolve_destinations, send_test, valid_webhook

router = APIRouter()

USER_MODE_LABELS = {"inherit": "所属グループの設定を使う", "custom": "個別に設定", "off": "通知しない"}
GROUP_MODE_LABELS = {"custom": "有効", "off": "無効", "inherit": "—"}

WebhookUrl = Annotated[str, StringConstraints(strip_whitespace=True, max_length=600)]


class NotificationIn(BaseModel):
    """Webhook は None なら変更しない、空文字なら削除する"""

    mode: Literal["inherit", "custom", "off"]
    discord_webhook: WebhookUrl | None = None
    slack_webhook: WebhookUrl | None = None
    all_devices: bool = True
    device_group_ids: list[str] = Field(default_factory=list, max_length=500)
    include_ungrouped: bool = False


class NotificationOut(BaseModel):
    mode: str
    discord_webhook: str | None = None  # 伏せ字
    slack_webhook: str | None = None
    has_discord: bool = False
    has_slack: bool = False
    all_devices: bool = True
    device_group_ids: list[str] = []
    include_ungrouped: bool = False
    last_sent_at: datetime | None = None
    last_error: str | None = None


class GroupSummary(BaseModel):
    id: str
    name: str
    notification: NotificationOut


class MyNotification(NotificationOut):
    groups: list[GroupSummary]  # 所属するユーザーグループと、その通知設定


class GroupIn(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    member_ids: list[str] = Field(default_factory=list, max_length=1000)
    notification: NotificationIn | None = None


class Member(BaseModel):
    id: str
    username: str
    is_active: bool


class GroupOut(BaseModel):
    id: str
    name: str
    description: str | None
    members: list[Member]
    notification: NotificationOut


class PreviewItem(BaseModel):
    kind: str
    webhook: str  # 伏せ字
    via: list[str]


# ---------------------------------------------------------------- helpers


def _out(s: NotificationSetting | None, default_mode: str) -> NotificationOut:
    if s is None:
        return NotificationOut(mode=default_mode)
    return NotificationOut(
        mode=s.mode,
        discord_webhook=mask_webhook(s.discord_webhook),
        slack_webhook=mask_webhook(s.slack_webhook),
        has_discord=bool(s.discord_webhook),
        has_slack=bool(s.slack_webhook),
        all_devices=s.all_devices,
        device_group_ids=s.group_ids,
        include_ungrouped=s.include_ungrouped,
        last_sent_at=s.last_sent_at,
        last_error=s.last_error,
    )


async def _get_setting(db: AsyncSession, owner_type: str, owner_id: str) -> NotificationSetting | None:
    return (await db.execute(select(NotificationSetting).where(
        NotificationSetting.owner_type == owner_type, NotificationSetting.owner_id == owner_id,
    ))).scalar_one_or_none()


async def _apply(db: AsyncSession, owner_type: str, owner_id: str, p: NotificationIn) -> tuple[NotificationSetting, dict]:
    """入力を検証して通知設定へ反映する。戻り値は（設定, 監査ログ用の変更内容）"""
    if owner_type == "group" and p.mode == "inherit":
        raise HTTPException(status_code=422, detail="グループの通知は「有効」か「無効」を指定してください")
    for kind in KINDS:
        v = getattr(p, f"{kind}_webhook")
        if v and not valid_webhook(kind, v):
            example = "https://discord.com/api/webhooks/…" if kind == "discord" else "https://hooks.slack.com/services/…"
            raise HTTPException(status_code=422, detail=f"{kind.capitalize()} の Webhook URL の形式が正しくありません（{example}）")
    ids = list(dict.fromkeys(p.device_group_ids))
    if ids:
        found = set((await db.execute(select(DeviceGroup.id).where(DeviceGroup.id.in_(ids)))).scalars())
        if len(found) != len(ids):
            raise HTTPException(status_code=422, detail="存在しない機器グループが含まれています")

    s = await _get_setting(db, owner_type, owner_id)
    if s is None:
        s = NotificationSetting(id=str(uuid.uuid4()), owner_type=owner_type, owner_id=owner_id)
        db.add(s)
    labels = GROUP_MODE_LABELS if owner_type == "group" else USER_MODE_LABELS
    changes: dict = {"mode": labels[p.mode]}
    for kind in KINDS:
        v = getattr(p, f"{kind}_webhook")
        if v is not None:
            setattr(s, f"{kind}_webhook", v or None)
            changes[f"{kind}_webhook"] = "（変更）" if v else "（削除）"
    s.mode = p.mode
    s.all_devices = p.all_devices
    s.device_group_ids = json.dumps(ids)
    s.include_ungrouped = p.include_ungrouped
    changes.update(all_devices=p.all_devices, device_groups=len(ids), include_ungrouped=p.include_ungrouped)
    if p.mode == "custom" and not (s.discord_webhook or s.slack_webhook):
        raise HTTPException(status_code=422, detail="通知先（Discord または Slack の Webhook URL）を1つ以上登録してください")
    if p.mode == "custom" and not p.all_devices and not ids and not p.include_ungrouped:
        raise HTTPException(status_code=422, detail="通知の対象にする機器グループを1つ以上選んでください")
    return s, changes


async def _test(s: NotificationSetting | None, label: str) -> dict:
    if s is None or not (s.discord_webhook or s.slack_webhook):
        raise HTTPException(status_code=400, detail="通知先が登録されていません")
    results = await send_test(s, label)
    return {"results": {k: (err or "ok") for k, err in results.items()}}


# ---------------------------------------------------------------- 自分の設定


@router.get("/me", response_model=MyNotification)
async def get_my_notification(
    db: AsyncSession = Depends(get_db), user: User = Depends(require(Perm.NOTIFY_SELF))
):
    own = await _get_setting(db, "user", user.id)
    group_ids = list((await db.execute(
        select(UserGroupMember.group_id).where(UserGroupMember.user_id == user.id)
    )).scalars())
    groups = (await db.execute(
        select(UserGroup).where(UserGroup.id.in_(group_ids)).order_by(UserGroup.name)
    )).scalars().all() if group_ids else []
    summaries = [
        GroupSummary(id=g.id, name=g.name, notification=_out(await _get_setting(db, "group", g.id), "off"))
        for g in groups
    ]
    return MyNotification(**_out(own, "inherit").model_dump(), groups=summaries)


@router.put("/me", response_model=NotificationOut)
async def update_my_notification(
    payload: NotificationIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.NOTIFY_SELF)),
    audit: Audit = Depends(get_audit),
):
    s, changes = await _apply(db, "user", user.id, payload)
    audit("notify.update", target_type="user", target_id=user.id, target_name=user.username, detail=changes)
    await db.commit()
    await db.refresh(s)
    return _out(s, "inherit")


@router.post("/me/test")
async def test_my_notification(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.NOTIFY_SELF)),
    audit: Audit = Depends(get_audit),
):
    result = await _test(await _get_setting(db, "user", user.id), f"ユーザー {user.username}")
    audit("notify.test", target_type="user", target_id=user.id, target_name=user.username, detail=result["results"])
    await db.commit()
    return result


# ---------------------------------------------------------------- ユーザーグループ（管理者）


async def _group_out(db: AsyncSession, g: UserGroup) -> GroupOut:
    members = (await db.execute(
        select(User).join(UserGroupMember, UserGroupMember.user_id == User.id)
        .where(UserGroupMember.group_id == g.id).order_by(User.username)
    )).scalars().all()
    return GroupOut(
        id=g.id, name=g.name, description=g.description,
        members=[Member(id=u.id, username=u.username, is_active=u.is_active) for u in members],
        notification=_out(await _get_setting(db, "group", g.id), "off"),
    )


async def _get_group(db: AsyncSession, group_id: str) -> UserGroup:
    g = await db.get(UserGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="ユーザーグループが見つかりません")
    return g


async def _set_members(db: AsyncSession, group_id: str, member_ids: list[str]) -> int:
    ids = list(dict.fromkeys(member_ids))
    if ids:
        found = set((await db.execute(select(User.id).where(User.id.in_(ids)))).scalars())
        if len(found) != len(ids):
            raise HTTPException(status_code=422, detail="存在しないユーザーが含まれています")
    await db.execute(delete(UserGroupMember).where(UserGroupMember.group_id == group_id))
    for uid in ids:
        db.add(UserGroupMember(group_id=group_id, user_id=uid))
    return len(ids)


@router.get("/groups", response_model=list[GroupOut], dependencies=[Depends(require(Perm.USER_ADMIN))])
async def list_groups(db: AsyncSession = Depends(get_db)):
    groups = (await db.execute(select(UserGroup).order_by(UserGroup.name))).scalars().all()
    return [await _group_out(db, g) for g in groups]


@router.post("/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require(Perm.USER_ADMIN))])
async def create_group(payload: GroupIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    g = UserGroup(id=str(uuid.uuid4()), name=payload.name, description=payload.description or None)
    db.add(g)
    try:
        await db.flush()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のユーザーグループがあります") from e
    n = await _set_members(db, g.id, payload.member_ids)
    detail: dict = {"members": n}
    if payload.notification:
        _, changes = await _apply(db, "group", g.id, payload.notification)
        detail.update(changes)
    audit("user_group.create", target_type="user_group", target_id=g.id, target_name=g.name, detail=detail)
    await db.commit()
    return await _group_out(db, g)


@router.put("/groups/{group_id}", response_model=GroupOut, dependencies=[Depends(require(Perm.USER_ADMIN))])
async def update_group(
    group_id: str, payload: GroupIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)
):
    g = await _get_group(db, group_id)
    g.name = payload.name
    g.description = payload.description or None
    try:
        await db.flush()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のユーザーグループがあります") from e
    n = await _set_members(db, g.id, payload.member_ids)
    detail: dict = {"members": n}
    if payload.notification:
        _, changes = await _apply(db, "group", g.id, payload.notification)
        detail.update(changes)
    audit("user_group.update", target_type="user_group", target_id=g.id, target_name=g.name, detail=detail)
    await db.commit()
    return await _group_out(db, g)


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require(Perm.USER_ADMIN))])
async def delete_group(group_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    g = await _get_group(db, group_id)
    await db.execute(delete(UserGroupMember).where(UserGroupMember.group_id == g.id))
    await db.execute(delete(NotificationSetting).where(
        NotificationSetting.owner_type == "group", NotificationSetting.owner_id == g.id
    ))
    await db.delete(g)
    audit("user_group.delete", target_type="user_group", target_id=g.id, target_name=g.name)
    await db.commit()


@router.post("/groups/{group_id}/test", dependencies=[Depends(require(Perm.USER_ADMIN))])
async def test_group_notification(group_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    g = await _get_group(db, group_id)
    result = await _test(await _get_setting(db, "group", g.id), f"グループ {g.name}")
    audit("notify.test", target_type="user_group", target_id=g.id, target_name=g.name, detail=result["results"])
    await db.commit()
    return result


@router.get("/preview", response_model=list[PreviewItem], dependencies=[Depends(require(Perm.USER_ADMIN))])
async def preview(device_group_id: str | None = None, db: AsyncSession = Depends(get_db)):
    """指定した機器グループ（未指定なら未分類）の機器に変更があったとき、どこへ通知されるか"""
    dests = await resolve_destinations(db, device_group_id or None)
    return [PreviewItem(kind=d.kind, webhook=mask_webhook(d.url) or "", via=sorted(d.via)) for d in dests]
