"""認証情報プロファイルの管理（同じアカウントを使う複数の機器で共有するユーザー名・パスワード・enable・SSH 鍵）

- 一覧は機器を閲覧できるユーザーなら見られる（パスワードや鍵は返さない。有無と鍵の種類・指紋だけ）
- 登録は機器の編集権限（DEVICE_WRITE）が必要。登録した人が所有者になる
- 編集・削除・共有範囲の変更は、所有者と「管理を任せたユーザーグループ」のメンバーだけ（services/profile_access.py）
- 機器への割り当ては、上に加えて「使用を許可したユーザーグループ」のメンバーだけ（api/devices.py で確かめる）
- 所有者が不在のときは、管理者が「引き継ぐ」で所有者になれる（監査ログに残し、前の所有者へ通知する）
- ほかの人が編集・削除・引き継ぎ・割り当てをしたら、所有者へ通知する
- プロファイルを変えると、それを使う全機器の次の接続（収集・ターミナル・FW ヒット数）から反映される
- 使用中のプロファイルは削除できない（409）
- 監査ログに秘密の値は残さない（「（変更）」とだけ記録する）
"""
import logging
import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require
from app.core.database import get_db
from app.core.permissions import Perm, has_permission
from app.core.ssh_keys import (
    MAX_PRIVATE_KEY_LENGTH,
    PrivateKeyError,
    key_summary,
    load_private_key,
    normalize_private_key,
)
from app.models.device import CredentialProfile, CredentialProfileAccess, Device
from app.models.notification import UserGroup, UserGroupMember
from app.models.user import User
from app.services import profile_access
from app.services.audit import Audit, changed_fields, get_audit
from app.services.notify import notify_profile_owner

logger = logging.getLogger(__name__)
router = APIRouter()

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Username = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Secret = Annotated[str, StringConstraints(max_length=100)]  # 暗号化後に VARCHAR(256) に収まる長さ
PrivateKey = Annotated[str, StringConstraints(max_length=MAX_PRIVATE_KEY_LENGTH)]
SECRET_FIELDS = {"password", "private_key", "key_passphrase", "enable_secret"}


class ProfileCreate(BaseModel):
    name: Name
    username: Username
    # 認証はパスワード・SSH 秘密鍵のどちらか、または両方
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    description: str | None = Field(default=None, max_length=1000)
    # 共有範囲（ユーザーグループの ID）。未指定なら所有者だけが編集・使用できる
    manage_group_ids: list[str] = Field(default_factory=list, max_length=50)
    use_group_ids: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _need_auth(self):
        if not self.password and not self.private_key:
            raise ValueError("パスワードとSSH秘密鍵の少なくとも一方を指定してください")
        return self


class ProfileUpdate(BaseModel):
    """部分更新。password / private_key / key_passphrase / enable_secret は空文字または未指定なら変更しない。
    削除したい場合は clear_password / clear_private_key / clear_enable_secret を指定する"""

    name: Name | None = None
    username: Username | None = None
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    clear_password: bool = False
    clear_private_key: bool = False
    clear_enable_secret: bool = False
    description: str | None = Field(default=None, max_length=1000)
    manage_group_ids: list[str] | None = Field(default=None, max_length=50)  # 未指定なら変更しない
    use_group_ids: list[str] | None = Field(default=None, max_length=50)
    owner_id: str | None = None  # 所有者を別の管理者に変える（未指定なら変更しない）


class GroupRef(BaseModel):
    id: str
    name: str


class ProfileResponse(BaseModel):
    id: str
    name: str
    username: str
    description: str | None
    has_password: bool
    has_private_key: bool
    has_enable_secret: bool
    key_info: str | None  # 例: "ssh-ed25519 SHA256:..."（秘密鍵そのものは返さない）
    device_count: int  # このプロファイルを使っている機器の台数
    owner_id: str | None = None
    owner_name: str | None = None  # 所有者がいない（削除された）ときは None
    manage_groups: list[GroupRef] = []  # 管理を任せたユーザーグループ
    use_groups: list[GroupRef] = []  # 使用を許可したユーザーグループ
    can_manage: bool = False  # 自分が編集・削除・共有範囲の変更をできるか
    can_use: bool = False  # 自分が機器へ割り当てられるか


def _validated_key(private_key: str, passphrase: str | None) -> str:
    try:
        load_private_key(private_key, passphrase)
    except PrivateKeyError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return normalize_private_key(private_key)


def key_info(p) -> str | None:
    """鍵の種類と指紋（読めない鍵は「読み込めない鍵」）。機器の一覧でも使う"""
    if not p.private_key:
        return None
    try:
        return key_summary(load_private_key(p.private_key, p.key_passphrase))
    except PrivateKeyError:
        return "読み込めない鍵"


async def device_counts(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(
        select(Device.credential_profile_id, func.count())
        .where(Device.credential_profile_id.is_not(None))
        .group_by(Device.credential_profile_id)
    )
    return dict(rows.all())


@dataclass
class _Ctx:
    """応答を作るための材料（自分の権限、ユーザー名・グループ名の対応）"""
    access: profile_access.Access
    writer: bool  # 機器の編集権限（DEVICE_WRITE）があるか。無ければ can_manage / can_use は常に False
    users: dict[str, str]
    groups: dict[str, str]


async def _ctx(db: AsyncSession, me: User) -> _Ctx:
    return _Ctx(
        access=await profile_access.load(db, me),
        writer=has_permission(me.role, Perm.DEVICE_WRITE),
        users=dict((await db.execute(select(User.id, User.username))).all()),
        groups=dict((await db.execute(select(UserGroup.id, UserGroup.name))).all()),
    )


def _to_response(p: CredentialProfile, device_count: int, c: _Ctx) -> ProfileResponse:
    def refs(access: str) -> list[GroupRef]:
        ids = c.access.groups(p.id, access)
        return sorted((GroupRef(id=i, name=c.groups[i]) for i in ids if i in c.groups), key=lambda g: g.name)

    return ProfileResponse(
        owner_id=p.owner_id,
        owner_name=c.users.get(p.owner_id) if p.owner_id else None,
        manage_groups=refs(profile_access.MANAGE),
        use_groups=refs(profile_access.USE),
        can_manage=c.writer and c.access.can_manage(p),
        can_use=c.writer and c.access.can_use(p),
        id=p.id,
        name=p.name,
        username=p.username,
        description=p.description,
        has_password=bool(p.password),
        has_private_key=bool(p.private_key),
        has_enable_secret=bool(p.enable_secret),
        key_info=key_info(p),
        device_count=device_count,
    )


async def _get_or_404(db: AsyncSession, profile_id: str) -> CredentialProfile:
    p = await db.get(CredentialProfile, profile_id)
    if not p:
        raise HTTPException(status_code=404, detail="認証情報プロファイルが見つかりません")
    return p


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前の認証情報プロファイルが既に登録されています") from e


async def _set_shares(db: AsyncSession, profile_id: str, manage: list[str] | None, use: list[str] | None,
                      current: profile_access.Access) -> None:
    """共有範囲を置き換える（None の側は変更しない）。同じグループを両方に指定した場合は管理を優先する"""
    new_manage = set(manage) if manage is not None else set(current.groups(profile_id, profile_access.MANAGE))
    new_use = (set(use) if use is not None else set(current.groups(profile_id, profile_access.USE))) - new_manage
    wanted = new_manage | new_use
    if wanted:
        found = set((await db.execute(select(UserGroup.id).where(UserGroup.id.in_(wanted)))).scalars())
        if found != wanted:
            raise HTTPException(status_code=422, detail="存在しないユーザーグループが含まれています")
    await db.execute(delete(CredentialProfileAccess).where(CredentialProfileAccess.profile_id == profile_id))
    for gid in new_manage:
        db.add(CredentialProfileAccess(profile_id=profile_id, group_id=gid, access=profile_access.MANAGE))
    for gid in new_use:
        db.add(CredentialProfileAccess(profile_id=profile_id, group_id=gid, access=profile_access.USE))


def _notify_owner(background: BackgroundTasks, p: CredentialProfile, me: User, what: str,
                  facts: list[tuple[str, str]] | None = None, owner_id: str | None = None) -> None:
    """自分以外が操作したときに、所有者へ知らせる（応答を返したあとに送る）"""
    target = owner_id if owner_id is not None else p.owner_id
    if target and target != me.id:
        background.add_task(
            notify_profile_owner, target, f"認証情報プロファイル「{p.name}」{what}",
            f"{me.username} さんが、あなたが所有する認証情報プロファイル「{p.name}」{what}。",
            [("操作した人", me.username), *(facts or [])])


@router.get("/", response_model=list[ProfileResponse], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_profiles(db: AsyncSession = Depends(get_db), me: User = Depends(get_current_user)):
    counts = await device_counts(db)
    c = await _ctx(db, me)
    result = await db.execute(select(CredentialProfile).order_by(CredentialProfile.name))
    return [_to_response(p, counts.get(p.id, 0), c) for p in result.scalars().all()]


class ShareOptions(BaseModel):
    groups: list[dict]  # {id, name, members}
    admins: list[dict]  # 所有者にできるユーザー（有効な管理者）{id, username}


@router.get("/share-options", response_model=ShareOptions, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def share_options(db: AsyncSession = Depends(get_db)):
    """共有範囲の選択肢（ユーザーグループと人数）と、所有者にできるユーザー"""
    members = dict((await db.execute(
        select(UserGroupMember.group_id, func.count()).group_by(UserGroupMember.group_id))).all())
    groups = (await db.execute(select(UserGroup).order_by(UserGroup.name))).scalars().all()
    admins = (await db.execute(select(User).where(User.is_active.is_(True)).order_by(User.username))).scalars().all()
    return ShareOptions(
        groups=[{"id": g.id, "name": g.name, "members": members.get(g.id, 0)} for g in groups],
        admins=[{"id": u.id, "username": u.username} for u in admins if has_permission(u.role, Perm.DEVICE_WRITE)],
    )


@router.post(
    "/",
    response_model=ProfileResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_profile(
    payload: ProfileCreate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    data = payload.model_dump()
    manage_ids, use_ids = data.pop("manage_group_ids"), data.pop("use_group_ids")
    for f in ("password", "enable_secret", "key_passphrase"):
        data[f] = data.get(f) or None
    if data["private_key"]:
        data["private_key"] = _validated_key(data["private_key"], data["key_passphrase"])
    else:
        data["private_key"] = data["key_passphrase"] = None
    p = CredentialProfile(id=str(uuid.uuid4()), owner_id=me.id, **data)  # 登録した人が所有者
    db.add(p)
    try:
        await db.flush()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前の認証情報プロファイルが既に登録されています") from e
    await _set_shares(db, p.id, manage_ids, use_ids, profile_access.Access(user_id=me.id))
    audit("credential_profile.create", target_type="credential_profile", target_id=p.id, target_name=p.name,
          detail={"username": p.username,
                  "auth": [k for k in ("password", "private_key", "enable_secret") if data.get(k)],
                  # 共有した場合だけ、グループの数を残す
                  **({"manage_groups": len(set(manage_ids))} if manage_ids else {}),
                  **({"use_groups": len(set(use_ids) - set(manage_ids))} if use_ids else {})})
    await _commit_or_409(db)
    await db.refresh(p)
    logger.info("認証情報プロファイル登録 by=%s name=%s", me.username, p.name)
    return _to_response(p, 0, await _ctx(db, me))


@router.put("/{profile_id}", response_model=ProfileResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_profile(
    profile_id: str,
    payload: ProfileUpdate,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    p = await _get_or_404(db, profile_id)
    access = await profile_access.load(db, me)
    if not access.can_manage(p):
        raise HTTPException(status_code=403, detail=profile_access.DENY_MANAGE)
    data = payload.model_dump(exclude_unset=True)
    in_use = (await device_counts(db)).get(p.id, 0)
    manage_ids, use_ids = data.pop("manage_group_ids", None), data.pop("use_group_ids", None)
    new_owner = data.pop("owner_id", None)
    previous_owner = p.owner_id
    # 秘密の値は「（変更）」だけ。この変更が何台の機器の次の接続に効くかも残す
    detail = {**changed_fields(data, SECRET_FIELDS), "devices": in_use}
    if manage_ids is not None or use_ids is not None:
        await _set_shares(db, p.id, manage_ids, use_ids, access)
        detail["sharing"] = "（変更）"
    if new_owner and new_owner != p.owner_id:
        target = await db.get(User, new_owner)
        if target is None or not target.is_active or not has_permission(target.role, Perm.DEVICE_WRITE):
            raise HTTPException(status_code=422, detail="所有者にできるのは、有効な管理者だけです")
        detail["owner"] = target.username
        p.owner_id = target.id
    audit("credential_profile.update", target_type="credential_profile", target_id=p.id, target_name=p.name,
          detail=detail)
    clear_password = data.pop("clear_password", False)
    clear_key = data.pop("clear_private_key", False)
    clear_enable = data.pop("clear_enable_secret", False)

    for field in ("name", "username"):
        if data.get(field) is not None:
            setattr(p, field, data[field])
    if "description" in data:
        p.description = data["description"] or None

    if clear_password:
        p.password = None
    elif data.get("password"):
        p.password = data["password"]
    if clear_enable:
        p.enable_secret = None
    elif data.get("enable_secret"):
        p.enable_secret = data["enable_secret"]

    if clear_key:
        p.private_key = None
        p.key_passphrase = None
    elif data.get("private_key"):
        passphrase = data.get("key_passphrase") or None
        p.private_key = _validated_key(data["private_key"], passphrase)
        p.key_passphrase = passphrase
    elif data.get("key_passphrase") and p.private_key:
        _validated_key(p.private_key, data["key_passphrase"])  # 鍵はそのままでパスフレーズだけ変更
        p.key_passphrase = data["key_passphrase"]

    if not p.password and not p.private_key:
        raise HTTPException(status_code=422, detail="パスワードとSSH秘密鍵の両方を削除することはできません")

    await _commit_or_409(db)
    await db.refresh(p)
    logger.info("認証情報プロファイル更新 by=%s name=%s devices=%d", me.username, p.name, in_use)
    changed = "・".join(k for k in detail if k != "devices") or "変更なし"
    _notify_owner(background, p, me, "が変更されました", [("変更した項目", changed), ("使用している機器", f"{in_use} 台")],
                  owner_id=previous_owner)
    return _to_response(p, in_use, await _ctx(db, me))


@router.post("/{profile_id}/takeover", response_model=ProfileResponse,
             dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def take_over_profile(
    profile_id: str,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """所有者を自分にする（所有者が不在・退職などで誰も編集できないときのための、管理者の操作）。

    監査ログに残し、前の所有者へ通知する。共有範囲はそのまま残す
    """
    p = await _get_or_404(db, profile_id)
    if p.owner_id == me.id:
        raise HTTPException(status_code=400, detail="すでにあなたが所有者です")
    previous = await db.get(User, p.owner_id) if p.owner_id else None
    audit("credential_profile.takeover", target_type="credential_profile", target_id=p.id, target_name=p.name,
          detail={"previous_owner": previous.username if previous else None})
    _notify_owner(background, p, me, "の所有者が変更されました（引き継ぎ）", [("新しい所有者", me.username)])
    p.owner_id = me.id
    await db.commit()
    await db.refresh(p)
    logger.warning("認証情報プロファイルの引き継ぎ by=%s name=%s previous=%s", me.username, p.name,
                   previous.username if previous else None)
    return _to_response(p, (await device_counts(db)).get(p.id, 0), await _ctx(db, me))


@router.delete(
    "/{profile_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_profile(
    profile_id: str,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    p = await _get_or_404(db, profile_id)
    if not (await profile_access.load(db, me)).can_manage(p):
        raise HTTPException(status_code=403, detail=profile_access.DENY_MANAGE)
    in_use = (await device_counts(db)).get(p.id, 0)
    if in_use:
        raise HTTPException(
            status_code=409,
            detail=f"{in_use}台のデバイスがこの認証情報プロファイルを使用しているため削除できません"
                   "（先に機器の編集で別のプロファイルか機器ごとの認証情報に切り替えてください）",
        )
    # 共有範囲も消す（SQLite では外部キーの CASCADE が効かないため明示的に）
    await db.execute(delete(CredentialProfileAccess).where(CredentialProfileAccess.profile_id == p.id))
    await db.delete(p)
    audit("credential_profile.delete", target_type="credential_profile", target_id=p.id, target_name=p.name)
    try:
        await db.commit()
    except IntegrityError as e:
        # 件数を確かめた後に、ほかの操作で機器がこのプロファイルを選んだ場合（外部キーで断られる）
        await db.rollback()
        raise HTTPException(
            status_code=409, detail="この認証情報プロファイルを使用しているデバイスがあるため削除できません"
        ) from e
    logger.info("認証情報プロファイル削除 by=%s name=%s", me.username, p.name)
    _notify_owner(background, p, me, "が削除されました")
