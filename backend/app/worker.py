"""
Celeryワーカー定義
- collect_device_config: 単一デバイスのコンフィグ収集タスク
- collect_all_devices: 全デバイスの一括収集タスク
- dispatch_due_schedules: beat から毎分起動され、DBのスケジュールに従って収集を投入する
- purge_audit_logs: beat から毎日起動され、保持期間を過ぎた監査ログ・ターミナル記録を削除する
- send_change_notification: コンフィグに変更があったときの通知（Discord / Slack）
- send_violation_notification / send_failure_notification: 違反の発生・収集の失敗の通知
収集に成功したら、その機器のコンプライアンスチェックも行う。
収集の結果・スケジュールの実行などはアクティビティログに記録する（ref で同じ実行の記録をまとめる）
"""
import asyncio
import logging
import uuid
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
from app.models import CollectLog, ConfigSnapshot, Device, DeviceGroup, Schedule
from app.services.activity import SYSTEM_ACTOR, record
from app.services.audit import purge_old
from app.services.compliance import recheck_expired_exceptions as _recheck_expired
from app.services.compliance import run_checks
from app.services.config_service import (
    CollectResult,
    DeviceConnectionInfo,
    collect_config_sync,
)
from app.services.connection import load_connection_info
from app.services.notify import notify_change, notify_failure, notify_violations, wants_any

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
        "recheck-expired-exceptions": {
            "task": "app.worker.recheck_expired_exceptions",
            "schedule": 300.0,
        },
        "purge-audit-logs": {
            "task": "app.worker.purge_audit_logs",
            "schedule": 24 * 3600.0,
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


def _actor(triggered_by: str, actor: str | None) -> str:
    """アクティビティログの「きっかけ」（手動ならユーザー名、スケジュールならスケジュール名）"""
    if actor:
        return actor
    return "スケジュール" if triggered_by == "schedule" else SYSTEM_ACTOR


async def _save_result(
    device: DeviceConnectionInfo, result: CollectResult, started_at: datetime, triggered_by: str,
    actor: str, ref: str | None, will_retry: bool = False, attempt: int = 0,
):
    device_id = device.id
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
        kw = dict(device_id=device_id, device_name=device.name, actor=actor, ref=ref)
        seconds = round((utcnow() - started_at).total_seconds(), 1)
        if not result.success:
            if will_retry:
                record(db, "collect.failed", f"収集に失敗しました（{attempt + 1}回目。1分後に再試行します）: {result.error}",
                       level="warning", detail={"error": result.error, "seconds": seconds}, **kw)
            else:
                record(db, "collect.failed", f"収集に失敗しました: {result.error}",
                       detail={"error": result.error, "attempt": attempt + 1, "seconds": seconds}, **kw)
        elif result.commit_hash and result.first:
            record(db, "collect.first", f"初めてコンフィグを取得しました（{result.added} 行）",
                   detail={"commit": result.commit_hash, "lines": result.added, "seconds": seconds}, **kw)
        elif result.commit_hash:
            record(db, "collect.changed", f"コンフィグの変更を検出しました（+{result.added} / -{result.removed} 行）",
                   detail={"commit": result.commit_hash, "added": result.added, "removed": result.removed,
                           "seconds": seconds}, **kw)
        elif settings.ACTIVITY_LOG_UNCHANGED:
            record(db, "collect.unchanged", "変更はありませんでした", detail={"seconds": seconds}, **kw)
        await db.commit()


async def _record(event: str, message: str, **kw) -> None:
    async with _sessionmaker()() as db:
        record(db, event, message, **kw)
        await db.commit()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def collect_device_config(
    self, device_id: str, triggered_by: str = "manual", actor: str | None = None, ref: str | None = None
):
    """単一デバイスのコンフィグを収集する

    actor: アクティビティログに残すきっかけ（手動ならユーザー名、スケジュールなら名前）
    ref: 同じ実行の記録をまとめる ID（一括収集・スケジュールでは親の ID、省略時はこのタスクの ID）
    """
    started_at = utcnow()
    actor = _actor(triggered_by, actor)
    ref = ref or self.request.id

    # 同じ機器の収集が重なると git の index.lock が競合するため、機器単位でロックする
    lock = _redis().lock(f"netconfig:collect:{device_id}", timeout=COLLECT_LOCK_TIMEOUT)
    if not lock.acquire(blocking=False):
        try:
            _run_async(_record("collect.skipped", "同じ機器の収集が実行中のため、スキップしました",
                               device_id=device_id, device_name=_run_async(_device_name(device_id)),
                               actor=actor, ref=ref))
        except Exception:  # noqa: BLE001 - 記録の失敗で処理を止めない
            logger.exception("アクティビティログの記録に失敗しました")
        return {"success": False, "skipped": True, "error": "同じデバイスの収集が実行中です"}

    try:
        device = _run_async(_get_device(device_id))
        if not device:
            return {"success": False, "error": f"Device {device_id} not found"}

        result = collect_config_sync(device, triggered_by)
        # 認証失敗などはリトライしても結果が変わらないので、一時的な失敗のみリトライする
        will_retry = not result.success and result.retryable and self.request.retries < self.max_retries
        _run_async(_save_result(device, result, started_at, triggered_by, actor, ref,
                                will_retry=will_retry, attempt=self.request.retries or 0))
        if result.success:
            try:
                _run_async(_check_compliance(device_id, actor, ref))
            except Exception:  # noqa: BLE001 - 検査の失敗で収集を失敗扱いにしない
                logger.exception("コンプライアンスチェックに失敗しました device=%s", device_id)
        if not result.success and not will_retry:
            try:
                if _run_async(_wants("failure")):
                    send_failure_notification.delay(device_id, result.error or "", triggered_by, ref)
            except Exception:  # noqa: BLE001 - 通知の投入の失敗で収集の結果を変えない
                logger.exception("収集失敗の通知を投入できませんでした device=%s", device_id)
        if result.success and result.commit_hash and not result.first:
            # 送信（外部への HTTP）は別タスクにして、収集の完了を待たせない
            send_change_notification.delay(device_id, result.commit_hash, result.added, result.removed, triggered_by,
                                           ref)
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass

    if will_retry:
        raise self.retry(exc=RuntimeError(result.error))

    return result.as_dict()


async def _device_name(device_id: str) -> str | None:
    async with _sessionmaker()() as db:
        d = await db.get(Device, device_id)
        return d.name if d else None


@celery_app.task
def send_change_notification(device_id: str, commit_hash: str, added: int, removed: int, triggered_by: str,
                             ref: str | None = None):
    async def run():
        async with _sessionmaker()() as db:
            return await notify_change(db, device_id, commit_hash, added, removed, triggered_by, ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001 - 通知の失敗は収集に影響させない
        logger.exception("変更通知に失敗しました device=%s", device_id)
        return {"error": True}


async def _wants(event: str) -> bool:
    async with _sessionmaker()() as db:
        return await wants_any(db, event)


@celery_app.task
def send_violation_notification(items: list, ref: str | None = None):
    """コンプライアンス違反の発生の通知。items: [[機器ID, [[ルール名, 重要度], ...]], ...]"""
    async def run():
        async with _sessionmaker()() as db:
            return await notify_violations(db, [(i, [tuple(r) for r in rules]) for i, rules in items], ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001
        logger.exception("違反の通知に失敗しました")
        return {"error": True}


@celery_app.task
def send_failure_notification(device_id: str, error: str, triggered_by: str, ref: str | None = None):
    """収集の失敗（リトライしても失敗したとき）の通知"""
    async def run():
        async with _sessionmaker()() as db:
            return await notify_failure(db, device_id, error, triggered_by, ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001
        logger.exception("収集失敗の通知に失敗しました device=%s", device_id)
        return {"error": True}


async def _check_compliance(device_id: str, actor: str | None = None, ref: str | None = None) -> None:
    async with _sessionmaker()() as db:
        await run_checks(db, device_ids=[device_id], actor=actor, ref=ref)
        await db.commit()


async def _recheck_expired_exceptions() -> int:
    async with _sessionmaker()() as db:
        return await _recheck_expired(db)


@celery_app.task
def recheck_expired_exceptions() -> int:
    """期限が切れたコンプライアンスの例外を反映する（5分ごと）"""
    n = _run_async(_recheck_expired_exceptions())
    if n:
        logger.info("期限切れの例外 %d 件を反映して再検査しました", n)
    return n


async def _purge() -> dict:
    async with _sessionmaker()() as db:
        return await purge_old(db)


@celery_app.task
def purge_audit_logs():
    """保持期間（AUDIT_LOG_RETENTION_DAYS / TERMINAL_LOG_RETENTION_DAYS）を過ぎた記録を削除する"""
    result = _run_async(_purge())
    if result["audit_logs"] or result["terminal_sessions"]:
        logger.info("古い監査ログを削除しました: %s", result)
    return result


async def _active_device_ids(group_id: str | None = None) -> list[str]:
    """有効な機器（group_id を指定するとそのグループの機器だけ）"""
    async with _sessionmaker()() as db:
        q = select(Device.id).where(Device.is_active.is_(True))
        if group_id:
            q = q.where(Device.group_id == group_id)
        result = await db.execute(q)
        return list(result.scalars().all())


async def _group_name(group_id: str) -> str | None:
    async with _sessionmaker()() as db:
        g = await db.get(DeviceGroup, group_id)
        return g.name if g else None


@celery_app.task(bind=True)
def collect_all_devices(
    self, triggered_by: str = "manual", actor: str | None = None, ref: str | None = None, group_id: str | None = None
):
    """有効な機器のコンフィグを一括収集する（group_id を指定するとそのグループだけ）。

    各機器の記録はこのタスクの ID（または ref）でまとめる
    """
    actor = _actor(triggered_by, actor)
    ref = ref or self.request.id
    device_ids = _run_async(_active_device_ids(group_id))
    task_ids = [collect_device_config.delay(device_id, triggered_by, actor, ref).id for device_id in device_ids]
    if triggered_by != "schedule":  # スケジュールは schedule.run で記録済み
        where = f"グループ「{_run_async(_group_name(group_id))}」の" if group_id else ""
        _run_async(_record("collect.batch", f"{where}有効な機器 {len(task_ids)} 台の収集を開始しました",
                           detail={"devices": len(task_ids), "group_id": group_id}, actor=actor, ref=ref))
    return {"success": True, "dispatched": len(task_ids), "task_ids": task_ids}


async def _scheduled_compliance(device_ids: list[str], actor: str, ref: str, where: str) -> dict:
    async with _sessionmaker()() as db:
        result = await run_checks(db, device_ids=device_ids, actor=actor, ref=ref)
        n_v, n_r = result.get("new_violations", 0), result.get("resolved", 0)
        record(db, "compliance.run",
               f"{where}{result['devices']} 台 × {result['rules']} ルールを検査しました（新しい違反 {n_v} 件・解消 {n_r} 件）",
               level="warning" if n_v else "info", detail=result, actor=actor, ref=ref)
        await db.commit()
        return result


@celery_app.task
def run_compliance_checks(actor: str, ref: str, target: str = "all") -> dict:
    """収集済みのコンフィグをコンプライアンスチェックする（スケジュール用。収集はしない）

    target: all（有効な機器すべて）/ group:<id> / 機器 ID。期限切れになった例外もここで反映される
    """
    if target == "all":
        device_ids, where = _run_async(_active_device_ids()), ""
    elif target.startswith("group:"):
        gid = target.split(":", 1)[1]
        device_ids, where = _run_async(_active_device_ids(gid)), f"グループ「{_run_async(_group_name(gid))}」の "
    else:
        device_ids, where = [target], ""
    return _run_async(_scheduled_compliance(device_ids, actor, ref, where))


async def _active_schedules() -> list[tuple[str, str, str, str, str]]:
    async with _sessionmaker()() as db:
        result = await db.execute(select(Schedule).where(Schedule.is_active.is_(True)))
        return [(s.id, s.cron_expression, s.target, s.name, s.kind or "collect") for s in result.scalars().all()]


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
    for schedule_id, cron_expression, target, name, kind in _run_async(_active_schedules()):
        try:
            fire_at = is_due(cron_expression, now)
        except (ValueError, KeyError):
            logger.error("不正なCron式のためスキップ: schedule=%s expr=%r", schedule_id, cron_expression)
            # 毎分呼ばれるため、記録は1時間に1回まで
            if _redis().set(f"netconfig:schedule-invalid:{schedule_id}", "1", nx=True, ex=3600):
                _run_async(_record("schedule.invalid", f"スケジュール「{name}」の Cron 式が不正なため実行できません",
                                   detail={"cron": cron_expression}, actor=f"スケジュール「{name}」"))
            continue
        if fire_at is None:
            continue
        # 同じ発火時刻で二重に投入しないよう Redis で冪等にする
        key = f"netconfig:schedule-fired:{schedule_id}:{int(fire_at.timestamp())}"
        if not _redis().set(key, "1", nx=True, ex=int(SCHEDULE_WINDOW.total_seconds()) * 2):
            continue
        actor = f"スケジュール「{name}」"
        ref = str(uuid.uuid4())
        compliance = kind == "compliance"
        what = "コンプライアンスチェック" if compliance else "収集"
        if target == "all":
            device_name, msg = None, f"全機器の{what}を開始しました"
        elif target.startswith("group:"):
            gname = _run_async(_group_name(target.split(":", 1)[1]))
            if gname is None:
                _run_async(_record("schedule.invalid", f"スケジュール「{name}」の対象グループが削除されています",
                                   detail={"target": target}, actor=actor))
                continue
            device_name, msg = None, f"グループ「{gname}」の{what}を開始しました"
        else:
            device_name = _run_async(_device_name(target))
            if device_name is None:
                _run_async(_record("schedule.invalid", f"スケジュール「{name}」の対象機器が削除されています",
                                   detail={"target": target}, actor=actor))
                continue
            msg = f"{what}を開始しました"
        # 開始の記録を先に残す（タスクの記録と同じ ref でまとまる）
        _run_async(_record("schedule.run", f"スケジュール「{name}」: {msg}",
                           device_id=None if target == "all" or target.startswith("group:") else target,
                           device_name=device_name,
                           detail={"cron": cron_expression, "target": target, "schedule_kind": kind}, actor=actor, ref=ref))
        if compliance:
            run_compliance_checks.delay(actor, ref, target)
        elif target == "all":
            collect_all_devices.delay("schedule", actor, ref)
        elif target.startswith("group:"):
            collect_all_devices.delay("schedule", actor, ref, target.split(":", 1)[1])
        else:
            collect_device_config.delay(target, "schedule", actor, ref)
        dispatched.append(schedule_id)
        logger.info("スケジュール実行: %s (kind=%s target=%s)", schedule_id, kind, target)
    return {"dispatched": dispatched}
