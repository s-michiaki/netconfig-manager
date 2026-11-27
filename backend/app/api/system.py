"""システムの状態（worker・スケジューラー・Redis・DB の稼働、収集の状況、ディスク、証明書、バックアップ、外部 Git、
外部への接続）"""
import asyncio

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


OUTBOUND_CHECK_INTERVAL_SEC = 30  # 「接続を確かめる」の間隔（全体で。外部へ続けて送らない）


@router.post("/outbound-check", dependencies=[Depends(require(Perm.SYSTEM_READ))])
async def outbound_check(audit: Audit = Depends(get_audit), db: AsyncSession = Depends(get_db)):
    """外部への接続を確かめる（固定の宛先 outbound.CHECK_URL へ HEAD。利用者は宛先を選べない）。管理者だけ・ログインのみ

    結果: 成功／プロキシに接続できない／プロキシの認証に失敗／証明書を検証できない／時間切れ など。
    応答・監査ログ・システム状態には、プロキシのホスト:ポート以外の設定値（認証情報）を出さない
    """
    from app.core import outbound
    from app.core.timeutil import utcnow
    from app.services import report  # 間隔の制限（Redis）を使い回す

    wait = await report.take_slot("all", "outbound-check", OUTBOUND_CHECK_INTERVAL_SEC)
    if wait:
        raise HTTPException(status_code=429, detail=f"続けて確かめられません。{wait} 秒ほど待ってからやり直してください",
                            headers={"Retry-After": str(wait)})
    result = await asyncio.to_thread(outbound.check_connectivity)
    result["at"] = utcnow().isoformat()
    await system.record_outbound_check(result)
    audit("system.outbound_check", detail={"result": result["result"], "via": result["via"], "target": result.get("target")},
          success=result["result"] == "ok")
    await db.commit()
    return result
