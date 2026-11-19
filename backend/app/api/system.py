"""システムの状態（worker・スケジューラー・Redis・DB の稼働、収集の状況、ディスク、証明書、バックアップ、外部 Git）"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.services import system
from app.services.audit import Audit, get_audit

router = APIRouter()


@router.get("/status", dependencies=[Depends(require(Perm.SYSTEM_READ))])
async def status(db: AsyncSession = Depends(get_db)):
    data = system.to_dict(await system.collect_status(db))
    data["settings"] = {"watchdog": settings.SYSTEM_WATCHDOG_ENABLED, "alert_after_min": settings.SYSTEM_ALERT_AFTER_MIN,
                        "stale_days": settings.SYSTEM_STALE_DAYS, "backup_stale_hours": settings.BACKUP_STALE_HOURS}
    return data


@router.post("/git-export", status_code=202, dependencies=[Depends(require(Perm.SYSTEM_READ))])
async def git_export_now(audit: Audit = Depends(get_audit), db: AsyncSession = Depends(get_db)):
    """外部 Git への push を今すぐ行う（worker で実行。結果はシステム状態に出る）"""
    from app.services import git_export
    from app.worker import git_export_sync

    if not git_export.enabled():
        raise HTTPException(status_code=409, detail="外部 Git への push は設定していません（.env の GIT_EXPORT_URL）")
    git_export_sync.delay()
    audit("system.git_export")
    await db.commit()
    return {"queued": True}
