"""システムの状態（worker・スケジューラー・Redis・DB の稼働、収集の状況、ディスク、証明書）"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.services import system

router = APIRouter()


@router.get("/status", dependencies=[Depends(require(Perm.SYSTEM_READ))])
async def status(db: AsyncSession = Depends(get_db)):
    data = system.to_dict(await system.collect_status(db))
    data["settings"] = {"watchdog": settings.SYSTEM_WATCHDOG_ENABLED, "alert_after_min": settings.SYSTEM_ALERT_AFTER_MIN,
                        "stale_days": settings.SYSTEM_STALE_DAYS}
    return data
