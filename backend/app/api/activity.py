"""アクティビティログの閲覧 API（閲覧者以上）"""
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.activity import ActivityLog
from app.services.activity import CATEGORIES, EVENTS, LEVELS

router = APIRouter()


class ActivityItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    at: datetime
    category: str
    event: str
    level: str
    device_id: str | None
    device_name: str | None
    message: str
    detail: str | None
    actor: str | None
    ref: str | None


class ActivityPage(BaseModel):
    items: list[ActivityItem]
    total: int


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/events", dependencies=[Depends(require(Perm.ACTIVITY_READ))])
async def list_events() -> dict:
    """種類・イベントの表示名"""
    return {"categories": CATEGORIES, "events": {k: v[0] for k, v in EVENTS.items()}, "levels": list(LEVELS)}


@router.get("/logs", response_model=ActivityPage, dependencies=[Depends(require(Perm.ACTIVITY_READ))])
async def list_logs(
    category: str | None = Query(None, max_length=32),
    event: str | None = Query(None, max_length=64),
    level: str | None = Query(None, max_length=16, description="info / warning / error。「warning+」で警告以上"),
    device_id: str | None = Query(None, max_length=36),
    ref: str | None = Query(None, max_length=64, description="同じ実行（収集のタスク ID など）の記録"),
    q: str | None = Query(None, max_length=200, description="機器名・内容・きっかけの部分一致"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    cond = []
    if category:
        cond.append(ActivityLog.category == category)
    if event:
        cond.append(ActivityLog.event == event)
    if level == "warning+":
        cond.append(ActivityLog.level.in_(["warning", "error"]))
    elif level:
        cond.append(ActivityLog.level == level)
    if device_id:
        cond.append(ActivityLog.device_id == device_id)
    if ref:
        cond.append(ActivityLog.ref == ref)
    if q:
        pat = _like(q)
        cond.append(or_(ActivityLog.device_name.like(pat, escape="\\"), ActivityLog.message.like(pat, escape="\\"),
                        ActivityLog.actor.like(pat, escape="\\")))
    if since:
        cond.append(ActivityLog.at >= since.replace(tzinfo=None))
    if until:
        cond.append(ActivityLog.at < until.replace(tzinfo=None))
    total = (await db.execute(select(func.count()).select_from(ActivityLog).where(*cond))).scalar_one()
    rows = (await db.execute(
        select(ActivityLog).where(*cond).order_by(ActivityLog.at.desc(), ActivityLog.id).limit(limit).offset(offset)
    )).scalars().all()
    return ActivityPage(items=[ActivityItem.model_validate(r) for r in rows], total=total)
