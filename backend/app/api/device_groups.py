"""機器のグループ API

グループは複数作成でき、機器は1つのグループにだけ所属する（未所属＝未分類も可）。
閲覧はデバイス閲覧権限、作成・変更・所属の変更はデバイス編集権限（管理者）が必要。
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device, DeviceGroup
from app.services.audit import Audit, get_audit

router = APIRouter()

GroupName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Color = Annotated[str, StringConstraints(pattern=r"^#[0-9a-fA-F]{6}$")]


class GroupIn(BaseModel):
    name: GroupName
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    color: Color | None = None


class GroupOut(BaseModel):
    id: str
    name: str
    description: str | None
    color: str | None
    device_count: int = 0


class Assign(BaseModel):
    device_ids: list[str] = Field(min_length=1, max_length=1000)
    group_id: str | None = None  # null で未分類に戻す


def _out(g: DeviceGroup, count: int = 0) -> GroupOut:
    return GroupOut(id=g.id, name=g.name, description=g.description, color=g.color, device_count=count)


async def _counts(db: AsyncSession) -> dict[str, int]:
    rows = (await db.execute(select(Device.group_id, func.count()).group_by(Device.group_id))).all()
    return {gid: n for gid, n in rows if gid}


async def _get_or_404(db: AsyncSession, group_id: str) -> DeviceGroup:
    g = await db.get(DeviceGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="グループが見つかりません")
    return g


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のグループが既にあります") from e


@router.get("/", response_model=list[GroupOut], dependencies=[Depends(require(Perm.DEVICE_READ))])
async def list_groups(db: AsyncSession = Depends(get_db)):
    groups = (await db.execute(select(DeviceGroup).order_by(DeviceGroup.name))).scalars().all()
    counts = await _counts(db)
    return [_out(g, counts.get(g.id, 0)) for g in groups]


@router.post(
    "/", response_model=GroupOut, status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.DEVICE_WRITE))],
)
async def create_group(payload: GroupIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    g = DeviceGroup(id=str(uuid.uuid4()), name=payload.name, description=payload.description or None,
                    color=payload.color)
    db.add(g)
    audit("device_group.create", target_type="device_group", target_id=g.id, target_name=g.name)
    await _commit_or_409(db)
    return _out(g)


@router.put("/{group_id}", response_model=GroupOut, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_group(
    group_id: str, payload: GroupIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)
):
    g = await _get_or_404(db, group_id)
    new = {"name": payload.name, "description": payload.description or None, "color": payload.color}
    changed = {k: v for k, v in new.items() if getattr(g, k) != v}
    if "name" in changed:
        changed["old_name"] = g.name
    for k, v in new.items():
        setattr(g, k, v)
    audit("device_group.update", target_type="device_group", target_id=g.id, target_name=g.name, detail=changed)
    await _commit_or_409(db)
    return _out(g, (await _counts(db)).get(g.id, 0))


@router.delete(
    "/{group_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.DEVICE_WRITE))]
)
async def delete_group(group_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """グループを削除する。所属していた機器は削除せず未分類に戻す"""
    g = await _get_or_404(db, group_id)
    r = await db.execute(update(Device).where(Device.group_id == g.id).values(group_id=None))
    await db.delete(g)
    audit("device_group.delete", target_type="device_group", target_id=g.id, target_name=g.name,
          detail={"moved_to_ungrouped": r.rowcount or 0})
    await db.commit()


@router.post("/assign", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def assign_devices(payload: Assign, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """複数の機器の所属グループをまとめて変更する（group_id が null なら未分類へ）"""
    group = await _get_or_404(db, payload.group_id) if payload.group_id else None
    ids = list(dict.fromkeys(payload.device_ids))
    devices = (await db.execute(select(Device).where(Device.id.in_(ids)))).scalars().all()
    if len(devices) != len(ids):
        raise HTTPException(status_code=404, detail="存在しない機器が含まれています")
    for d in devices:
        if d.group_id != (group.id if group else None):
            audit("device.update", target_type="device", target_id=d.id, target_name=d.name,
                  detail={"group": group.name if group else "（未分類）"})
            d.group_id = group.id if group else None
    await db.commit()
    return {"updated": len(devices), "group_id": group.id if group else None}
