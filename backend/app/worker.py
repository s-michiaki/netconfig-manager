"""
Celeryワーカー定義
- collect_device_config: 単一デバイスのコンフィグ収集タスク
- collect_all_devices: 全デバイスの一括収集タスク
- dispatch_due_schedules: beat から毎分起動され、DBのスケジュールに従って収集を投入する
"""
import asyncio
import logging
from datetime import datetime, timedelta
from functools import lru_cache
from zoneinfo import ZoneInfo

import redis
from celery import Celery
from croniter import croniter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models import CollectLog, ConfigSnapshot, Device, Schedule
from app.services.config_service import (
    CollectResult,
    DeviceConnectionInfo,
    collect_config_sync,
)
from app.services.connection import load_connection_info

logger = logging.getLogger(__name__)

celery_app = Celery(
    "netconfig",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_expires=3600,
    task_track_started=True,  # 画面に「収集中」を表示するため STARTED 状態を記録する
    timezone=settings.TIMEZONE,
    enable_utc=True,
    beat_schedule={
        "dispatch-due-schedules": {
            "task": "app.worker.dispatch_due_schedules",
            "schedule": 60.0,
        },
    },
)

# このウィンドウ内に直近のcron発火時刻があれば実行する（beat の60秒間隔の揺らぎを吸収）
SCHEDULE_WINDOW = timedelta(seconds=90)
COLLECT_LOCK_TIMEOUT = 900


@lru_cache
def _sessionmaker() -> async_sessionmaker[AsyncSession]:
    # タスクごとに asyncio.run で新しいイベントループを作るため、
    # ループをまたいでコネクションを使い回さないよう NullPool にする
    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@lru_cache
def _redis() -> redis.Redis:
    return redis.Redis.from_url(settings.REDIS_URL)


def _run_async(coro):
    """Celeryの同期コンテキストで非同期DBアクセスを実行するヘルパー"""
    return asyncio.run(coro)


async def _get_device(device_id: str) -> DeviceConnectionInfo | None:
    async with _sessionmaker()() as db:
        return await load_connection_info(db, device_id)


async def _save_result(device_id: str, result: CollectResult, started_at: datetime, triggered_by: str):
    async with _sessionmaker()() as db:
        db.add(
            CollectLog(
                device_id=device_id,
                status="success" if result.success else "failed",
                message=result.error,
                started_at=started_at,
                finished_at=utcnow(),
            )
        )
        if result.success and result.commit_hash:
            db.add(
                ConfigSnapshot(
                    device_id=device_id,
                    commit_hash=result.commit_hash,
                    lines_added=result.added,
                    lines_removed=result.removed,
                    triggered_by=triggered_by,
                )
            )
        await db.commit()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def collect_device_config(self, device_id: str, triggered_by: str = "manual"):
    """単一デバイスのコンフィグを収集する"""
    started_at = utcnow()

    # 同じ機器の収集が重なると git の index.lock が競合するため、機器単位でロックする
    lock = _redis().lock(f"netconfig:collect:{device_id}", timeout=COLLECT_LOCK_TIMEOUT)
    if not lock.acquire(blocking=False):
        return {"success": False, "skipped": True, "error": "同じデバイスの収集が実行中です"}

    try:
        device = _run_async(_get_device(device_id))
        if not device:
            return {"success": False, "error": f"Device {device_id} not found"}

        result = collect_config_sync(device, triggered_by)
        _run_async(_save_result(device_id, result, started_at, triggered_by))
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass

    # 認証失敗などはリトライしても結果が変わらないので、一時的な失敗のみリトライする
    if not result.success and result.retryable and self.request.retries < self.max_retries:
        raise self.retry(exc=RuntimeError(result.error))

    return result.as_dict()


async def _active_device_ids() -> list[str]:
    async with _sessionmaker()() as db:
        result = await db.execute(select(Device.id).where(Device.is_active.is_(True)))
        return list(result.scalars().all())


@celery_app.task
def collect_all_devices(triggered_by: str = "manual"):
    """全デバイスのコンフィグを一括収集する"""
    task_ids = [
        collect_device_config.delay(device_id, triggered_by).id
        for device_id in _run_async(_active_device_ids())
    ]
    return {"success": True, "dispatched": len(task_ids), "task_ids": task_ids}


async def _active_schedules() -> list[tuple[str, str, str]]:
    async with _sessionmaker()() as db:
        result = await db.execute(select(Schedule).where(Schedule.is_active.is_(True)))
        return [(s.id, s.cron_expression, s.target) for s in result.scalars().all()]


def is_due(cron_expression: str, now: datetime) -> datetime | None:
    """now の直前の発火時刻が SCHEDULE_WINDOW 内なら、その発火時刻を返す"""
    # croniter は「開始時刻より前」の発火時刻を返すため、1秒進めて丁度の時刻も拾う
    prev = croniter(cron_expression, now + timedelta(seconds=1)).get_prev(datetime)
    return prev if now - prev < SCHEDULE_WINDOW else None


@celery_app.task
def dispatch_due_schedules():
    """DBのスケジュールを確認し、発火時刻を迎えたものの収集を投入する"""
    return dispatch_schedules_at(datetime.now(ZoneInfo(settings.TIMEZONE)))


def dispatch_schedules_at(now: datetime) -> dict:
    dispatched = []
    for schedule_id, cron_expression, target in _run_async(_active_schedules()):
        try:
            fire_at = is_due(cron_expression, now)
        except (ValueError, KeyError):
            logger.error("不正なCron式のためスキップ: schedule=%s expr=%r", schedule_id, cron_expression)
            continue
        if fire_at is None:
            continue
        # 同じ発火時刻で二重に投入しないよう Redis で冪等にする
        key = f"netconfig:schedule-fired:{schedule_id}:{int(fire_at.timestamp())}"
        if not _redis().set(key, "1", nx=True, ex=int(SCHEDULE_WINDOW.total_seconds()) * 2):
            continue
        if target == "all":
            collect_all_devices.delay("schedule")
        else:
            collect_device_config.delay(target, "schedule")
        dispatched.append(schedule_id)
        logger.info("スケジュール実行: %s (target=%s)", schedule_id, target)
    return {"dispatched": dispatched}
