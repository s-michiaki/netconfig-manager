import uuid
from datetime import datetime
from typing import Annotated
from zoneinfo import ZoneInfo

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.services.audit import Audit, get_audit
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device, Schedule

router = APIRouter()


def validate_cron(expr: str) -> str:
    expr = " ".join(expr.split())
    if len(expr.split(" ")) != 5 or not croniter.is_valid(expr):
        raise ValueError("Cron式が不正です（5フィールド形式: 分 時 日 月 曜日）")
    return expr


class ScheduleCreate(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    cron_expression: str
    target: str = "all"
    is_active: bool = True

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str) -> str:
        return validate_cron(v)


class ScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    cron_expression: str
    target: str
    is_active: bool
    next_run: str | None = None


def _to_response(s: Schedule) -> ScheduleResponse:
    resp = ScheduleResponse.model_validate(s)
    if s.is_active:
        try:
            now = datetime.now(ZoneInfo(settings.TIMEZONE))
            resp.next_run = croniter(s.cron_expression, now).get_next(datetime).isoformat()
        except (ValueError, KeyError):
            resp.next_run = None
    return resp


@router.get("/", response_model=list[ScheduleResponse], dependencies=[Depends(require(Perm.SCHEDULE_READ))])
async def list_schedules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Schedule).order_by(Schedule.name))
    return [_to_response(s) for s in result.scalars().all()]


@router.post(
    "/",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Perm.SCHEDULE_WRITE))],
)
async def create_schedule(
    payload: ScheduleCreate, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)
):
    if payload.target != "all" and not await db.get(Device, payload.target):
        raise HTTPException(status_code=422, detail="対象には all または登録済みデバイスのIDを指定してください")
    schedule = Schedule(id=str(uuid.uuid4()), **payload.model_dump())
    db.add(schedule)
    audit("schedule.create", target_type="schedule", target_id=schedule.id, target_name=schedule.name,
          detail={"cron": schedule.cron_expression, "target": schedule.target})
    await db.commit()
    await db.refresh(schedule)
    return _to_response(schedule)


@router.delete(
    "/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.SCHEDULE_WRITE))]
)
async def delete_schedule(schedule_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    audit("schedule.delete", target_type="schedule", target_id=schedule.id, target_name=schedule.name)
    await db.commit()


@router.patch(
    "/{schedule_id}/toggle", response_model=ScheduleResponse, dependencies=[Depends(require(Perm.SCHEDULE_WRITE))]
)
async def toggle_schedule(schedule_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    schedule = await db.get(Schedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.is_active = not schedule.is_active
    audit("schedule.update", target_type="schedule", target_id=schedule.id, target_name=schedule.name,
          detail={"is_active": schedule.is_active})
    await db.commit()
    await db.refresh(schedule)
    return _to_response(schedule)
