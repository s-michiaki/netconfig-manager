"""アクティビティログの閲覧 API（閲覧者以上）"""
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import MAX_EXPORT_ROWS, csv_response, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.activity import ActivityLog
from app.services.activity import CATEGORIES, EVENTS, LEVELS
from app.services.audit import Audit, get_audit

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
    cond = _conditions(category, event, level, device_id, ref, q, since, until)
    total = (await db.execute(select(func.count()).select_from(ActivityLog).where(*cond))).scalar_one()
    rows = (await db.execute(
        select(ActivityLog).where(*cond).order_by(ActivityLog.at.desc(), ActivityLog.id).limit(limit).offset(offset)
    )).scalars().all()
    return ActivityPage(items=[ActivityItem.model_validate(r) for r in rows], total=total)


LEVEL_LABELS = {"info": "情報", "warning": "警告", "error": "エラー"}


@router.get("/logs/export", dependencies=[Depends(require(Perm.ACTIVITY_READ))])
async def export_logs(
    category: str | None = Query(None, max_length=32),
    event: str | None = Query(None, max_length=64),
    level: str | None = Query(None, max_length=16),
    device_id: str | None = Query(None, max_length=36),
    ref: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=200),
    since: datetime | None = None,
    until: datetime | None = None,
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """アクティビティログを CSV で出力する（絞り込みは一覧と同じ。新しい順に最大 MAX_EXPORT_ROWS 件）"""
    cond = _conditions(category, event, level, device_id, ref, q, since, until)
    rows = (await db.execute(
        select(ActivityLog).where(*cond).order_by(ActivityLog.at.desc(), ActivityLog.id).limit(MAX_EXPORT_ROWS)
    )).scalars().all()
    audit("activity.export", detail={"rows": len(rows), "category": category, "level": level, "device_id": device_id,
                                     "ref": ref, "q": q, "since": since.isoformat() if since else None,
                                     "until": until.isoformat() if until else None})
    await db.commit()
    header = [f"日時（{settings.TIMEZONE}）", "重要度", "種類", "イベント", "イベントコード", "機器", "内容", "詳細",
              "きっかけ", "実行ID"]
    data = [[r.at, LEVEL_LABELS.get(r.level, r.level), CATEGORIES.get(r.category, r.category),
             EVENTS.get(r.event, (r.event,))[0], r.event, r.device_name, r.message, r.detail, r.actor, r.ref]
            for r in rows]
    return csv_response(header, data, export_name("activity_logs"))


def _conditions(category, event, level, device_id, ref, q, since, until) -> list:
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
    return cond
