import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.ssh_keys import (
    MAX_PRIVATE_KEY_LENGTH,
    PrivateKeyError,
    key_summary,
    load_private_key,
    normalize_private_key,
)
from app.models.compliance import ComplianceResult
from app.models.device import Device, DeviceGroup, JumpHost
from app.services.audit import Audit, changed_fields, get_audit
from app.worker import collect_all_devices, collect_device_config

router = APIRouter()

Platform = Literal[
    "cisco_ios", "cisco_xe", "cisco_nxos", "juniper_junos", "arista_eos", "hp_comware", "huawei", "paloalto_panos"
]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Host = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[A-Za-z0-9.:_\-\[\]%]+$")
]
Username = Annotated[str, StringConstraints(min_length=1, max_length=128)]
# 暗号化後に VARCHAR(256) に収まる長さに制限
Secret = Annotated[str, StringConstraints(max_length=100)]
Port = Annotated[int, Field(ge=1, le=65535)]
PrivateKey = Annotated[str, StringConstraints(max_length=MAX_PRIVATE_KEY_LENGTH)]
# 応答待ち時間（秒）。収集ロックの保持時間（15分）に収まる範囲
ReadTimeoutSec = Annotated[int, Field(ge=10, le=600)]


class DeviceCreate(BaseModel):
    name: Name
    hostname: Host
    platform: Platform
    port: Port = 22
    username: Username
    # 認証はパスワード・SSH秘密鍵のどちらか、または両方
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool = True
    jump_host_id: str | None = None  # 経由する踏み台（未指定なら直接接続）
    group_id: str | None = None  # 所属グループ（未指定なら未分類）
    read_timeout: ReadTimeoutSec | None = None  # 応答待ち時間（未指定なら既定値）

    @model_validator(mode="after")
    def _need_auth(self):
        if not self.password and not self.private_key:
            raise ValueError("パスワードとSSH秘密鍵の少なくとも一方を指定してください")
        return self


class DeviceUpdate(BaseModel):
    """部分更新。password / private_key / key_passphrase / enable_secret は空文字または未指定なら変更しない。
    削除したい場合は clear_password / clear_private_key / clear_enable_secret を指定する"""

    name: Name | None = None
    hostname: Host | None = None
    platform: Platform | None = None
    port: Port | None = None
    username: Username | None = None
    password: Secret | None = None
    private_key: PrivateKey | None = None
    key_passphrase: Secret | None = None
    enable_secret: Secret | None = None
    clear_password: bool = False
    clear_private_key: bool = False
    clear_enable_secret: bool = False
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None
    jump_host_id: str | None = None  # null を明示すると直接接続に戻す
    group_id: str | None = None  # null を明示すると未分類に戻す
    read_timeout: ReadTimeoutSec | None = None  # null を明示すると既定値に戻す


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    hostname: str
    platform: str
    port: int
    username: str
    description: str | None
    is_active: bool
    has_enable_secret: bool = False
    has_password: bool = False
    has_private_key: bool = False
    key_info: str | None = None  # 例: "ssh-ed25519 SHA256:..."（秘密鍵そのものは返さない）
    jump_host_id: str | None = None
    jump_host_name: str | None = None
    read_timeout: int | None = None
    group_id: str | None = None
    group_name: str | None = None


def _to_response(device: Device, names: dict[str, str] | None = None) -> DeviceResponse:
    """names は踏み台・グループの id → 名前（_ref_names）"""
    resp = DeviceResponse.model_validate(device)
    resp.has_enable_secret = bool(device.enable_secret)
    resp.has_password = bool(device.password)
    resp.has_private_key = bool(device.private_key)
    if device.private_key:
        try:
            resp.key_info = key_summary(load_private_key(device.private_key, device.key_passphrase))
        except PrivateKeyError:
            resp.key_info = "読み込めない鍵"
    if device.jump_host_id and names:
        resp.jump_host_name = names.get(device.jump_host_id)
    if device.group_id and names:
        resp.group_name = names.get(device.group_id)
    return resp


async def _ref_names(db: AsyncSession) -> dict[str, str]:
    """踏み台とグループの id → 名前（どちらも UUID なので1つの辞書にまとめる）"""
    names = dict((await db.execute(select(JumpHost.id, JumpHost.name))).all())
    names.update(dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all()))
    return names


def _validated_key(private_key: str, passphrase: str | None) -> str:
    try:
        load_private_key(private_key, passphrase)
    except PrivateKeyError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return normalize_private_key(private_key)


async def _check_jump_host(db: AsyncSession, jump_host_id: str | None) -> None:
    if jump_host_id and not await db.get(JumpHost, jump_host_id):
        raise HTTPException(status_code=422, detail="指定された踏み台サーバが存在しません")


async def _check_group(db: AsyncSession, group_id: str | None) -> None:
    if group_id and not await db.get(DeviceGroup, group_id):
        raise HTTPException(status_code=422, detail="指定されたグループが存在しません")


async def _get_or_404(db: AsyncSession, device_id: str) -> Device:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のデバイスが既に登録されています") from e


@router.get("/", response_model=list[DeviceResponse], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_devices(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).order_by(Device.name))
    names = await _ref_names(db)
    return [_to_response(d, names) for d in result.scalars().all()]


@router.post(
    "/",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_device(payload: DeviceCreate, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    data = payload.model_dump()
    for f in ("password", "enable_secret", "key_passphrase"):
        data[f] = data.get(f) or None
    if data.get("private_key"):
        data["private_key"] = _validated_key(data["private_key"], data["key_passphrase"])
    else:
        data["private_key"] = data["key_passphrase"] = None
    data["jump_host_id"] = data.get("jump_host_id") or None
    await _check_jump_host(db, data["jump_host_id"])
    data["group_id"] = data.get("group_id") or None
    await _check_group(db, data["group_id"])
    device = Device(id=str(uuid.uuid4()), **data)
    db.add(device)
    audit("device.create", target_type="device", target_id=device.id, target_name=device.name,
          detail={"hostname": device.hostname, "platform": device.platform, "port": device.port,
                  "username": device.username, "jump_host_id": device.jump_host_id, "group_id": device.group_id,
                  "auth": [k for k in ("password", "private_key") if data.get(k)]})
    await _commit_or_409(db)
    await db.refresh(device)
    return _to_response(device, await _ref_names(db))


class DeviceDefaults(BaseModel):
    read_timeout: int


# 注意: "/defaults" "/collect/all" は "/{device_id}" 系より先に定義する
@router.get("/defaults", response_model=DeviceDefaults, dependencies=[Depends(require(Perm.DEVICE_READ))])
async def device_defaults():
    """画面表示用の既定値（応答待ち時間など）"""
    return DeviceDefaults(read_timeout=settings.SSH_READ_TIMEOUT)


@router.post("/collect/all", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect_all(db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """全デバイスのコンフィグ収集をトリガー"""
    task = collect_all_devices.delay("manual")
    audit("collect.run", target_type="device", target_name="全機器")
    await db.commit()
    return {"task_id": task.id, "status": "queued"}


@router.get("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_READ))])
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    return _to_response(await _get_or_404(db, device_id), await _ref_names(db))


@router.put("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_device(
    device_id: str, payload: DeviceUpdate, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)
):
    device = await _get_or_404(db, device_id)
    data = payload.model_dump(exclude_unset=True)
    audit("device.update", target_type="device", target_id=device.id, target_name=device.name,
          detail=changed_fields(data, {"password", "private_key", "key_passphrase", "enable_secret"}))
    clear_enable = data.pop("clear_enable_secret", False)
    clear_password = data.pop("clear_password", False)
    clear_key = data.pop("clear_private_key", False)
    new_key = data.pop("private_key", None)
    new_passphrase = data.pop("key_passphrase", None)
    for secret_field in ("password", "enable_secret"):
        if not data.get(secret_field):
            data.pop(secret_field, None)
    if "jump_host_id" in data:
        data["jump_host_id"] = data["jump_host_id"] or None
        await _check_jump_host(db, data["jump_host_id"])
    if "group_id" in data:
        data["group_id"] = data["group_id"] or None
        await _check_group(db, data["group_id"])
    for k, v in data.items():
        if v is None and k in ("name", "hostname", "platform", "port", "username", "is_active"):
            continue  # 必須項目に null は入れない
        setattr(device, k, v)
    if clear_enable:
        device.enable_secret = None
    if clear_password:
        device.password = None
    if clear_key:
        device.private_key = None
        device.key_passphrase = None
    elif new_key:
        device.private_key = _validated_key(new_key, new_passphrase or None)
        device.key_passphrase = new_passphrase or None
    elif new_passphrase and device.private_key:
        _validated_key(device.private_key, new_passphrase)  # 鍵はそのままでパスフレーズだけ変更
        device.key_passphrase = new_passphrase
    if not device.password and not device.private_key:
        raise HTTPException(status_code=422, detail="パスワードとSSH秘密鍵の両方を削除することはできません")
    await _commit_or_409(db)
    await db.refresh(device)
    return _to_response(device, await _ref_names(db))


@router.delete(
    "/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """デバイスを削除する（Gitの履歴ディレクトリは監査用に残す）"""
    device = await _get_or_404(db, device_id)
    await db.execute(delete(ComplianceResult).where(ComplianceResult.device_id == device.id))
    await db.delete(device)
    audit("device.delete", target_type="device", target_id=device.id, target_name=device.name,
          detail={"hostname": device.hostname})
    await db.commit()


@router.post("/{device_id}/collect", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect(device_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """単一デバイスのコンフィグ収集をトリガー"""
    device = await _get_or_404(db, device_id)
    task = collect_device_config.delay(device_id, "manual")
    audit("collect.run", target_type="device", target_id=device.id, target_name=device.name)
    await db.commit()
    return {"task_id": task.id, "status": "queued"}
