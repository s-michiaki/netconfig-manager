from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device
from app.worker import collect_all_devices, collect_device_config

router = APIRouter()

Platform = Literal["cisco_ios", "cisco_xe", "cisco_nxos", "juniper_junos", "arista_eos", "hp_comware", "huawei"]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Host = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[A-Za-z0-9.:_\-\[\]%]+$")
]
Username = Annotated[str, StringConstraints(min_length=1, max_length=128)]
# 暗号化後に VARCHAR(256) に収まる長さに制限
Secret = Annotated[str, StringConstraints(max_length=100)]
Port = Annotated[int, Field(ge=1, le=65535)]


class DeviceCreate(BaseModel):
    name: Name
    hostname: Host
    platform: Platform
    port: Port = 22
    username: Username
    password: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    enable_secret: Secret | None = None
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool = True


class DeviceUpdate(BaseModel):
    """部分更新。password / enable_secret は空文字または未指定なら変更しない。
    enable_secret を消したい場合は clear_enable_secret=true を指定する"""

    name: Name | None = None
    hostname: Host | None = None
    platform: Platform | None = None
    port: Port | None = None
    username: Username | None = None
    password: Secret | None = None
    enable_secret: Secret | None = None
    clear_enable_secret: bool = False
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None


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


def _to_response(device: Device) -> DeviceResponse:
    resp = DeviceResponse.model_validate(device)
    resp.has_enable_secret = bool(device.enable_secret)
    return resp


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
    return [_to_response(d) for d in result.scalars().all()]


@router.post(
    "/",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_device(payload: DeviceCreate, db: AsyncSession = Depends(get_db)):
    data = payload.model_dump()
    if not data.get("enable_secret"):
        data["enable_secret"] = None
    device = Device(**data)
    db.add(device)
    await _commit_or_409(db)
    await db.refresh(device)
    return _to_response(device)


# 注意: "/collect/all" は "/{device_id}" 系より先に定義する
@router.post("/collect/all", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect_all():
    """全デバイスのコンフィグ収集をトリガー"""
    task = collect_all_devices.delay("manual")
    return {"task_id": task.id, "status": "queued"}


@router.get("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_READ))])
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    return _to_response(await _get_or_404(db, device_id))


@router.put("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_device(device_id: str, payload: DeviceUpdate, db: AsyncSession = Depends(get_db)):
    device = await _get_or_404(db, device_id)
    data = payload.model_dump(exclude_unset=True)
    clear_enable = data.pop("clear_enable_secret", False)
    for secret_field in ("password", "enable_secret"):
        if not data.get(secret_field):
            data.pop(secret_field, None)
    for k, v in data.items():
        if v is None and k in ("name", "hostname", "platform", "port", "username", "is_active"):
            continue  # 必須項目に null は入れない
        setattr(device, k, v)
    if clear_enable:
        device.enable_secret = None
    await _commit_or_409(db)
    await db.refresh(device)
    return _to_response(device)


@router.delete(
    "/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db)):
    """デバイスを削除する（Gitの履歴ディレクトリは監査用に残す）"""
    device = await _get_or_404(db, device_id)
    await db.delete(device)
    await db.commit()


@router.post("/{device_id}/collect", dependencies=[Depends(require(Perm.COLLECT))])
async def trigger_collect(device_id: str, db: AsyncSession = Depends(get_db)):
    """単一デバイスのコンフィグ収集をトリガー"""
    await _get_or_404(db, device_id)
    task = collect_device_config.delay(device_id, "manual")
    return {"task_id": task.id, "status": "queued"}
