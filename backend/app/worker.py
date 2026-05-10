"""
Celeryワーカー定義
- collect_device_config: 単一デバイスのコンフィグ収集タスク
- collect_all_devices: 全デバイスの一括収集タスク
"""
import asyncio
from datetime import datetime

from celery import Celery

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.device import CollectLog, ConfigSnapshot, Device
from app.services.config_service import collect_config_sync

celery_app = Celery(
    "netconfig",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_expires=3600,
    timezone="Asia/Tokyo",
    enable_utc=True,
)


def _run_async(coro):
    """Celeryの同期コンテキストで非同期DBアクセスを実行するヘルパー"""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _get_device(device_id: str):
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Device).where(Device.id == device_id))
        return result.scalar_one_or_none()


async def _save_result(device_id: str, result: dict, started_at: datetime):
    async with AsyncSessionLocal() as db:
        log = CollectLog(
            device_id=device_id,
            status="success" if result["success"] else "failed",
            message=result.get("error"),
            started_at=started_at,
            finished_at=datetime.utcnow(),
        )
        db.add(log)

        if result["success"] and result.get("commit_hash"):
            snapshot = ConfigSnapshot(
                device_id=device_id,
                commit_hash=result["commit_hash"],
                lines_added=result["added"],
                lines_removed=result["removed"],
                triggered_by="manual",
            )
            db.add(snapshot)

        await db.commit()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def collect_device_config(self, device_id: str):
    """単一デバイスのコンフィグを収集する"""
    started_at = datetime.utcnow()

    device = _run_async(_get_device(device_id))
    if not device:
        return {"error": f"Device {device_id} not found"}

    result = collect_config_sync(device)
    _run_async(_save_result(device_id, result, started_at))

    if not result["success"] and self.request.retries < self.max_retries:
        raise self.retry(exc=Exception(result["error"]))

    return result


@celery_app.task
def collect_all_devices():
    """全デバイスのコンフィグを一括収集する"""

    async def _get_all_devices():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Device).where(Device.is_active == True)  # noqa: E712
            )
            return result.scalars().all()

    devices = _run_async(_get_all_devices())
    task_ids = []
    for device in devices:
        task = collect_device_config.delay(device.id)
        task_ids.append(task.id)

    return {"dispatched": len(task_ids), "task_ids": task_ids}
