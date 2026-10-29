"""踏み台サーバの管理

- 一覧は機器を閲覧できるユーザーなら見られる（認証情報は返さない）
- 登録・編集・削除・接続テストは機器の編集権限（DEVICE_WRITE）が必要
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.ssh_jump import (
    MAX_PRIVATE_KEY_LENGTH,
    JumpHostError,
    PrivateKeyError,
    key_summary,
    load_private_key,
    normalize_private_key,
)
from app.core.ssh_jump import test_jump_host as run_jump_test
from app.models.device import Device, JumpHost
from app.models.user import User
from app.services.connection import jump_info

logger = logging.getLogger(__name__)
router = APIRouter()

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Host = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[A-Za-z0-9.:_\-\[\]%]+$")
]
Username = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Secret = Annotated[str, StringConstraints(max_length=100)]  # 暗号化後に VARCHAR(256) に収まる長さ
PrivateKey = Annotated[str, StringConstraints(max_length=MAX_PRIVATE_KEY_LENGTH)]
Port = Annotated[int, Field(ge=1, le=65535)]


class JumpHostCreate(BaseModel):
    name: Name
    hostname: Host
    port: Port = 22
    username: Username
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    description: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def _need_auth(self):
        if not self.password and not self.private_key:
            raise ValueError("パスワードと秘密鍵の少なくとも一方を指定してください")
        return self


class JumpHostUpdate(BaseModel):
    """部分更新。password / private_key / key_passphrase は空文字または未指定なら変更しない。
    削除したい場合は clear_password / clear_private_key を指定する"""

    name: Name | None = None
    hostname: Host | None = None
    port: Port | None = None
    username: Username | None = None
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    clear_password: bool = False
    clear_private_key: bool = False
    description: str | None = Field(default=None, max_length=1000)


class JumpHostResponse(BaseModel):
    id: str
    name: str
    hostname: str
    port: int
    username: str
    description: str | None
    has_password: bool
    has_private_key: bool
    key_info: str | None  # 例: "ssh-ed25519 SHA256:..."（秘密鍵そのものは返さない）
    device_count: int


class TestRequest(BaseModel):
    """踏み台までの接続に加え、指定すればその先の機器への到達性も確認する"""

    dest_host: Host | None = None
    dest_port: Port = 22


class TestResult(BaseModel):
    ok: bool
    message: str


def _validated_key(private_key: str, passphrase: str | None) -> str:
    try:
        load_private_key(private_key, passphrase)
    except PrivateKeyError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return normalize_private_key(private_key)


def _key_info(j: JumpHost) -> str | None:
    if not j.private_key:
        return None
    try:
        return key_summary(load_private_key(j.private_key, j.key_passphrase))
    except PrivateKeyError:
        return "読み込めない鍵"


async def _device_counts(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(
        select(Device.jump_host_id, func.count()).where(Device.jump_host_id.is_not(None)).group_by(Device.jump_host_id)
    )
    return dict(rows.all())


def _to_response(j: JumpHost, device_count: int) -> JumpHostResponse:
    return JumpHostResponse(
        id=j.id,
        name=j.name,
        hostname=j.hostname,
        port=j.port,
        username=j.username,
        description=j.description,
        has_password=bool(j.password),
        has_private_key=bool(j.private_key),
        key_info=_key_info(j),
        device_count=device_count,
    )


async def _get_or_404(db: AsyncSession, jump_id: str) -> JumpHost:
    j = await db.get(JumpHost, jump_id)
    if not j:
        raise HTTPException(status_code=404, detail="Jump host not found")
    return j


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前の踏み台サーバが既に登録されています") from e


@router.get("/", response_model=list[JumpHostResponse], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_jump_hosts(db: AsyncSession = Depends(get_db)):
    counts = await _device_counts(db)
    result = await db.execute(select(JumpHost).order_by(JumpHost.name))
    return [_to_response(j, counts.get(j.id, 0)) for j in result.scalars().all()]


@router.post(
    "/",
    response_model=JumpHostResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_jump_host(
    payload: JumpHostCreate, db: AsyncSession = Depends(get_db), me: User = Depends(get_current_user)
):
    data = payload.model_dump()
    if data["private_key"]:
        data["private_key"] = _validated_key(data["private_key"], data["key_passphrase"])
    else:
        data["private_key"] = None
        data["key_passphrase"] = None
    data["password"] = data["password"] or None
    data["key_passphrase"] = data["key_passphrase"] or None
    j = JumpHost(**data)
    db.add(j)
    await _commit_or_409(db)
    await db.refresh(j)
    logger.info("踏み台登録 by=%s name=%s", me.username, j.name)
    return _to_response(j, 0)


@router.put("/{jump_id}", response_model=JumpHostResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_jump_host(
    jump_id: str,
    payload: JumpHostUpdate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
):
    j = await _get_or_404(db, jump_id)
    data = payload.model_dump(exclude_unset=True)
    clear_password = data.pop("clear_password", False)
    clear_key = data.pop("clear_private_key", False)

    for field in ("name", "hostname", "port", "username"):
        if data.get(field) is not None:
            setattr(j, field, data[field])
    if "description" in data:
        j.description = data["description"] or None

    if clear_password:
        j.password = None
    elif data.get("password"):
        j.password = data["password"]

    if clear_key:
        j.private_key = None
        j.key_passphrase = None
    elif data.get("private_key"):
        passphrase = data.get("key_passphrase") or None
        j.private_key = _validated_key(data["private_key"], passphrase)
        j.key_passphrase = passphrase
    elif data.get("key_passphrase") and j.private_key:
        # 鍵はそのままでパスフレーズだけ変更
        _validated_key(j.private_key, data["key_passphrase"])
        j.key_passphrase = data["key_passphrase"]

    if not j.password and not j.private_key:
        raise HTTPException(status_code=422, detail="パスワードと秘密鍵の両方を削除することはできません")

    await _commit_or_409(db)
    await db.refresh(j)
    logger.info("踏み台更新 by=%s name=%s", me.username, j.name)
    counts = await _device_counts(db)
    return _to_response(j, counts.get(j.id, 0))


@router.delete(
    "/{jump_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_jump_host(jump_id: str, db: AsyncSession = Depends(get_db), me: User = Depends(get_current_user)):
    j = await _get_or_404(db, jump_id)
    in_use = (await _device_counts(db)).get(j.id, 0)
    if in_use:
        raise HTTPException(
            status_code=409, detail=f"{in_use}台のデバイスがこの踏み台を使用しているため削除できません"
        )
    await db.delete(j)
    await db.commit()
    logger.info("踏み台削除 by=%s name=%s", me.username, j.name)


@router.post("/{jump_id}/test", response_model=TestResult, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def test_jump_host(jump_id: str, payload: TestRequest, db: AsyncSession = Depends(get_db)):
    """踏み台への接続・認証（と、指定があれば機器への到達性）を確認する"""
    info = jump_info(await _get_or_404(db, jump_id))
    try:
        message = await run_in_threadpool(run_jump_test, info, payload.dest_host, payload.dest_port)
    except JumpHostError as e:
        return TestResult(ok=False, message=str(e))
    return TestResult(ok=True, message=message)
