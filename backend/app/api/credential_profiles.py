"""認証情報プロファイルの管理（同じアカウントを使う複数の機器で共有するユーザー名・パスワード・enable・SSH 鍵）

- 一覧は機器を閲覧できるユーザーなら見られる（パスワードや鍵は返さない。有無と鍵の種類・指紋だけ）
- 登録・編集・削除は機器の編集権限（DEVICE_WRITE）が必要
- プロファイルを変えると、それを使う全機器の次の接続（収集・ターミナル・FW ヒット数）から反映される
- 使用中のプロファイルは削除できない（409）
- 監査ログに秘密の値は残さない（「（変更）」とだけ記録する）
"""
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.ssh_keys import (
    MAX_PRIVATE_KEY_LENGTH,
    PrivateKeyError,
    key_summary,
    load_private_key,
    normalize_private_key,
)
from app.models.device import CredentialProfile, Device
from app.models.user import User
from app.services.audit import Audit, changed_fields, get_audit

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


def _to_response(p: CredentialProfile, device_count: int) -> ProfileResponse:
    return ProfileResponse(
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


@router.get("/", response_model=list[ProfileResponse], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_profiles(db: AsyncSession = Depends(get_db)):
    counts = await device_counts(db)
    result = await db.execute(select(CredentialProfile).order_by(CredentialProfile.name))
    return [_to_response(p, counts.get(p.id, 0)) for p in result.scalars().all()]


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
    for f in ("password", "enable_secret", "key_passphrase"):
        data[f] = data.get(f) or None
    if data["private_key"]:
        data["private_key"] = _validated_key(data["private_key"], data["key_passphrase"])
    else:
        data["private_key"] = data["key_passphrase"] = None
    p = CredentialProfile(id=str(uuid.uuid4()), **data)
    db.add(p)
    audit("credential_profile.create", target_type="credential_profile", target_id=p.id, target_name=p.name,
          detail={"username": p.username,
                  "auth": [k for k in ("password", "private_key", "enable_secret") if data.get(k)]})
    await _commit_or_409(db)
    await db.refresh(p)
    logger.info("認証情報プロファイル登録 by=%s name=%s", me.username, p.name)
    return _to_response(p, 0)


@router.put("/{profile_id}", response_model=ProfileResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_profile(
    profile_id: str,
    payload: ProfileUpdate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    p = await _get_or_404(db, profile_id)
    data = payload.model_dump(exclude_unset=True)
    in_use = (await device_counts(db)).get(p.id, 0)
    # 秘密の値は「（変更）」だけ。この変更が何台の機器の次の接続に効くかも残す
    audit("credential_profile.update", target_type="credential_profile", target_id=p.id, target_name=p.name,
          detail={**changed_fields(data, SECRET_FIELDS), "devices": in_use})
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
    return _to_response(p, in_use)


@router.delete(
    "/{profile_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    p = await _get_or_404(db, profile_id)
    in_use = (await device_counts(db)).get(p.id, 0)
    if in_use:
        raise HTTPException(
            status_code=409,
            detail=f"{in_use}台のデバイスがこの認証情報プロファイルを使用しているため削除できません"
                   "（先に機器の編集で別のプロファイルか機器ごとの認証情報に切り替えてください）",
        )
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
