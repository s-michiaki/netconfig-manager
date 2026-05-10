from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.device import Device
from app.worker import collect_device_config

router = APIRouter()


class DeviceCreate(BaseModel):
    name: str
    hostname: str
    platform: str
    port: int = 22
    username: str
    password: str
    enable_secret: str | None = None
    description: str | None = None


class DeviceResponse(BaseModel):
    id: str
    name: str
    hostname: str
    platform: str
    port: int
    username: str
    description: str | None
    is_active: bool

    class Config:
        from_attributes = True


@router.get("/", response_model=list[DeviceResponse])
async def list_devices(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).order_by(Device.name))
    return result.scalars().all()


@router.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(payload: DeviceCreate, db: AsyncSession = Depends(get_db)):
    device = Device(**payload.model_dump())
    db.add(device)
    await db.commit()
    await db.refresh(device)
    return device


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str, payload: DeviceCreate, db: AsyncSession = Depends(get_db)
):
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        setattr(device, k, v)
    await db.commit()
    await db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db)):
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    await db.delete(device)
    await db.commit()


@router.post("/{device_id}/collect")
async def trigger_collect(device_id: str, db: AsyncSession = Depends(get_db)):
    """単一デバイスのコンフィグ収集をトリガー"""
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    task = collect_device_config.delay(device_id)
    return {"task_id": task.id, "status": "queued"}


@router.post("/collect/all")
async def trigger_collect_all(db: AsyncSession = Depends(get_db)):
    """全デバイスのコンフィグ収集をトリガー"""
    from app.worker import collect_all_devices
    task = collect_all_devices.delay()
    return {"task_id": task.id, "status": "queued"}
