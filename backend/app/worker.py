"""
Celeryワーカー定義
- collect_device_config: 単一デバイスのコンフィグ収集タスク
- collect_all_devices: 全デバイスの一括収集タスク
- dispatch_due_schedules: beat から毎分起動され、DBのスケジュールに従って収集を投入する
- purge_audit_logs: beat から毎日起動され、保持期間を過ぎた監査ログ・ターミナル記録を削除する
- send_change_notification: コンフィグに変更があったときの通知（Discord / Slack）
- send_violation_notification / send_failure_notification: 違反の発生・収集の失敗の通知
- send_inventory_notification: 機器情報（OS バージョン・シリアル番号など）が変わったときの通知
- ping_monitor: Ping監視の常時監視（PING_MONITOR_INTERVAL_SEC ごと。応答なし・復旧を通知）
- git_export_sync: コンフィグ履歴を外部 Git へ push（GIT_EXPORT_URL を設定したとき。収集で変わったときと 1 時間ごと）
  （収集の失敗は flush_failure_notifications で NOTIFY_FAILURE_BATCH_SEC 秒ごとにまとめて送る）
- poll_snmp / collect_fw_hits_all / collect_fw_hits_device: モニタリング（試験導入。MONITORING_ENABLED のときだけ動く）
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
from app.services import collect_state, failure_batch, fw_hits, git_export, inventory, monitoring, system
from app.services import ping_monitor as ping_monitor_svc
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
from app.services.notify import (
    notify_change,
    notify_failure,
    notify_failures,
    notify_inventory,
    notify_ping,
    notify_violations,
    wants_any,
)
from app.services.ping import PingUnavailable

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
        # スケジューラーと worker が動いていることの印（services/system.py が時刻を見て停止を検出する）
        "system-heartbeat": {
            "task": "app.worker.heartbeat",
            "schedule": 60.0,
        },
        "dispatch-due-schedules": {
            "task": "app.worker.dispatch_due_schedules",
            "schedule": 60.0,
        },
        # 収集失敗の通知のまとめ: 予約した送信が失われた（worker の再起動など）ときに、残った分を送る
        "flush-failure-notifications": {
            "task": "app.worker.flush_failure_notifications",
            "schedule": 300.0,
            "kwargs": {"stale_only": True},
        },
        "recheck-expired-exceptions": {
            "task": "app.worker.recheck_expired_exceptions",
            "schedule": 300.0,
        },
        # モニタリング（無効のときはタスク側で何もしない）
        "monitor-poll-snmp": {
            "task": "app.worker.poll_snmp",
            "schedule": float(settings.MONITOR_INTERVAL_SEC),
        },
        "monitor-fw-hits": {
            "task": "app.worker.collect_fw_hits_all",
            "schedule": float(settings.MONITOR_FW_INTERVAL_MIN * 60),
        },
        "ping-monitor": {
            "task": "app.worker.ping_monitor",
            "schedule": float(settings.PING_MONITOR_INTERVAL_SEC),
        },
        # 外部 Git への push（設定していなければ何もしない）。送り損ねの再送も兼ねる
        "git-export-sync": {
            "task": "app.worker.git_export_sync",
            "schedule": 3600.0,
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
# 同じ機器へ SSH で入る処理（コンフィグ収集・FW ヒット数の取得）は1つずつにする。
# FortiGate は接続のたびに console の output を変えて終了時に戻すため、重なると片方の出力がページングで止まる
SSH_LOCK_WAIT = 300  # 収集は、ほかの SSH 処理が終わるのを最大この秒数待つ


def _ssh_lock(device_id: str):
    return _redis().lock(f"netconfig:ssh:{device_id}", timeout=COLLECT_LOCK_TIMEOUT)


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


def mark_collect_queued(device_id: str, triggered_by: str = "manual") -> None:
    """画面に「収集待ち」と出せるよう、収集を依頼した時点で状態を記録する（すでに動いている機器は上書きしない）"""
    collect_state.mark(_redis(), device_id, "queued", triggered_by, only_if_idle=True)


def enqueue_collect(device_id: str, triggered_by: str = "manual", actor: str | None = None, ref: str | None = None):
    """1 台の収集を依頼する"""
    mark_collect_queued(device_id, triggered_by)
    return collect_device_config.delay(device_id, triggered_by, actor, ref)


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
) -> list[list[str]]:
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
        inventory_changes: list[list[str]] = []
        if result.success and result.inventory:
            inventory_changes = await _save_inventory(db, device_id, result.inventory, kw)
        await db.commit()
        return inventory_changes


async def _save_inventory(db: AsyncSession, device_id: str, facts: dict, kw: dict) -> list[list[str]]:
    """機器台帳を保存する。OS バージョンやシリアル番号が変わったら（バージョンアップ・機器の交換）記録に残す。

    変わった項目を [項目, 以前, 今回] の並びで返す（通知に使う）
    """
    d = await db.get(Device, device_id)
    if d is None:
        return []
    old = {f: getattr(d, f) for f in inventory.FIELDS}
    for f in inventory.FIELDS:
        if facts.get(f):  # 今回読み取れなかった項目は、前回の値を残す
            setattr(d, f, facts[f])
    d.inventory_at = utcnow()
    diff = inventory.changes(old, facts)
    if diff:
        text = "、".join(f"{inventory.LABELS[f]}: {a} → {b}" for f, a, b in diff)
        # シリアル番号・モデルが変わるのは機器の交換（または登録先の取り違え）なので、警告にする
        level = "warning" if any(f in ("serial_number", "model") for f, _, _ in diff) else "info"
        record(db, "inventory.changed", f"機器情報が変わりました（{text}）", level=level,
               detail={f: {"before": a, "after": b} for f, a, b in diff}, **kw)
    return [[f, a, b] for f, a, b in diff]


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

    will_retry = False
    collect_state.mark(_redis(), device_id, "running", triggered_by)
    try:
        device = _run_async(_get_device(device_id))
        if not device:
            return {"success": False, "error": f"Device {device_id} not found"}

        ssh = _ssh_lock(device_id)
        if ssh.acquire(blocking=True, blocking_timeout=SSH_LOCK_WAIT):
            try:
                result = collect_config_sync(device, triggered_by)
            finally:
                try:
                    ssh.release()
                except redis.exceptions.LockError:
                    pass
        else:
            result = CollectResult(False, error="同じ機器への別の SSH 処理（FW ヒット数の取得など）が終わらないため、"
                                                "収集できませんでした", retryable=True)
        # 認証失敗などはリトライしても結果が変わらないので、一時的な失敗のみリトライする
        will_retry = not result.success and result.retryable and self.request.retries < self.max_retries
        inventory_changes = _run_async(_save_result(device, result, started_at, triggered_by, actor, ref,
                                                    will_retry=will_retry, attempt=self.request.retries or 0))
        if result.success:
            try:
                _run_async(_check_compliance(device_id, actor, ref))
            except Exception:  # noqa: BLE001 - 検査の失敗で収集を失敗扱いにしない
                logger.exception("コンプライアンスチェックに失敗しました device=%s", device_id)
        if not result.success and not will_retry:
            try:
                if _run_async(_wants("failure")):
                    queue_failure_notification(device_id, result.error or "", triggered_by, ref)
            except Exception:  # noqa: BLE001 - 通知の投入の失敗で収集の結果を変えない
                logger.exception("収集失敗の通知を投入できませんでした device=%s", device_id)
        if inventory_changes:
            try:
                if _run_async(_wants("inventory")):
                    send_inventory_notification.delay(device_id, inventory_changes, ref)
            except Exception:  # noqa: BLE001 - 通知の投入の失敗で収集の結果を変えない
                logger.exception("機器情報の変化の通知を投入できませんでした device=%s", device_id)
        if result.success and result.commit_hash:
            try:
                schedule_git_export()
            except Exception:  # noqa: BLE001 - push の予約の失敗で収集の結果を変えない（1 時間ごとの同期で送る）
                logger.exception("外部 Git への push を予約できませんでした")
        if result.success and result.commit_hash and not result.first:
            # 送信（外部への HTTP）は別タスクにして、収集の完了を待たせない
            send_change_notification.delay(device_id, result.commit_hash, result.added, result.removed, triggered_by,
                                           ref)
    finally:
        # やり直す場合は「再試行待ち」、それ以外（成功・失敗・例外）は状態を消す
        if will_retry:
            collect_state.mark(_redis(), device_id, "retry", triggered_by)
        else:
            collect_state.clear(_redis(), device_id)
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


@celery_app.task
def send_inventory_notification(device_id: str, changes: list[list[str]], ref: str | None = None):
    async def run():
        async with _sessionmaker()() as db:
            return await notify_inventory(db, device_id, changes, ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001 - 通知の失敗は収集に影響させない
        logger.exception("機器情報の変化の通知に失敗しました device=%s", device_id)
        return {"error": True}


PING_MONITOR_LOCK = "netconfig:ping:monitor-lock"


async def _ping_monitor(r) -> dict:
    async with _sessionmaker()() as db:
        res = await ping_monitor_svc.run_once(db, r)
        if res["down"] or res["up"]:
            try:
                res["notify"] = await notify_ping(db, res["down"], res["up"])
            except Exception:  # noqa: BLE001 - 通知の失敗で監視を止めない
                logger.exception("Ping監視の通知に失敗しました")
        return res


@celery_app.task
def ping_monitor():
    """Ping監視の常時監視（1 回分）。前の実行が終わっていなければ飛ばす"""
    r = _redis()
    lock = r.lock(PING_MONITOR_LOCK, timeout=max(30, settings.PING_MONITOR_INTERVAL_SEC * 2), blocking=False)
    if not lock.acquire(blocking=False):
        return {"skipped": True}
    try:
        res = _run_async(_ping_monitor(r))
        if res["down"] or res["up"]:
            logger.info("Ping監視: 応答なし %d 件・復旧 %d 件", len(res["down"]), len(res["up"]))
        return {"checked": res["checked"], "down": len(res["down"]), "up": len(res["up"])}
    except PingUnavailable as e:
        logger.warning("Ping監視の常時監視: %s", e)
        return {"error": str(e)}
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


def schedule_git_export() -> None:
    """収集でコンフィグが変わったときに呼ぶ。GIT_EXPORT_DELAY_SEC 秒後に 1 回だけ同期する（その間の変更はまとめる）"""
    if not git_export.enabled():
        return
    r = _redis()
    if r.set(git_export.PENDING_KEY, "1", nx=True, ex=settings.GIT_EXPORT_DELAY_SEC + 600):
        git_export_sync.apply_async(countdown=settings.GIT_EXPORT_DELAY_SEC)


async def _export_devices() -> list[git_export.DeviceFile]:
    async with _sessionmaker()() as db:
        groups = {g.id: g.name for g in (await db.execute(select(DeviceGroup))).scalars()}
        return [git_export.DeviceFile(d.id, d.name, d.hostname, d.platform, groups.get(d.group_id))
                for d in (await db.execute(select(Device))).scalars()]


@celery_app.task
def git_export_sync():
    """コンフィグ履歴を外部 Git へ push する（services/git_export.py）。同時に 1 つだけ動かす"""
    if not git_export.enabled():
        return {"enabled": False}
    r = _redis()
    lock = r.lock(git_export.LOCK_KEY, timeout=settings.GIT_EXPORT_TIMEOUT + 300, blocking_timeout=settings.GIT_EXPORT_TIMEOUT)
    if not lock.acquire():
        return {"skipped": True}
    try:
        r.delete(git_export.PENDING_KEY)  # これより後の変更は、次の同期で送る
        prev = git_export.load_state(r)
        result = git_export.sync(r, _run_async(_export_devices()))
        if not result.get("ok") and (prev.get("ok", True) or prev.get("error") != result.get("error")):
            _run_async(_record("export.failed", f"外部 Git への push に失敗しました: {result.get('error')}",
                               detail={"url": result.get("url"), "branch": result.get("branch")}))
        elif result.get("ok") and not result.get("skipped") and result.get("pushed"):
            names = result.get("devices") or []
            _run_async(_record("export.pushed", f"外部 Git へ push しました（{len(names)} 台の変更）" if names
                               else "外部 Git へ push しました", detail={"commit": result["pushed"], "devices": names[:50]}))
        return {k: result.get(k) for k in ("ok", "committed", "pushed", "error")}
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


# ---------------------------------------------------------------- モニタリング（試験導入）


@celery_app.task
def poll_snmp():
    """SNMP を有効にした機器の帯域を取得する（MONITOR_INTERVAL_SEC ごと）"""
    if not settings.MONITORING_ENABLED:
        return {"disabled": True}
    # 定期実行と「今すぐ取得」が重なると、インタフェースの同時作成（一意制約違反）で全体が失敗したり、
    # 間隔の短すぎるサンプルが入ったりするため、1つずつ実行する
    lock = _redis().lock("netconfig:snmp-poll", timeout=max(settings.MONITOR_INTERVAL_SEC * 2, 600))
    if not lock.acquire(blocking=False):
        return {"skipped": True}

    async def run():
        async with _sessionmaker()() as db:
            return await monitoring.poll_all(db)

    try:
        result = _run_async(run())
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass
    if result.get("failed"):
        logger.warning("SNMP の取得に失敗した機器があります: %s", result)
    return result


async def _fw_device_ids() -> list[str]:
    async with _sessionmaker()() as db:
        return list((await db.execute(select(Device.id).where(
            Device.is_active.is_(True), Device.platform.in_(list(fw_hits.SUPPORTED))))).scalars())


@celery_app.task
def collect_fw_hits_all():
    """FW（PAN-OS・FortiGate）のルールのヒット数を取得する（MONITOR_FW_INTERVAL_MIN ごと）"""
    if not settings.MONITORING_ENABLED:
        return {"disabled": True}
    ids = _run_async(_fw_device_ids())
    for device_id in ids:
        collect_fw_hits_device.delay(device_id, SYSTEM_ACTOR)
    return {"devices": len(ids)}


@celery_app.task
def collect_fw_hits_device(device_id: str, actor: str | None = None, ref: str | None = None):
    """1台の FW のルールのヒット数を取得して保存する"""
    # コンフィグ収集と同じ機器の SSH ロックを使う。収集中なら今回は取得しない（次の定期取得で取る）
    lock = _ssh_lock(device_id)
    if not lock.acquire(blocking=False):
        return {"skipped": True}
    try:
        device = _run_async(_get_device(device_id))
        if device is None:
            return {"error": "not found"}
        res = fw_hits.collect_fw_hits(device)

        async def save():
            async with _sessionmaker()() as db:
                await monitoring.store_fw_result(db, device_id, res)
                if res.error:
                    record(db, "monitor.fw_failed", f"FW ルールのヒット数を取得できませんでした: {res.error}",
                           device_id=device_id, device_name=device.name, detail={"error": res.error},
                           actor=actor or SYSTEM_ACTOR, ref=ref)
                    await db.commit()

        _run_async(save())
        return {"rules": len(res.rules), "error": res.error}
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


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


def queue_failure_notification(device_id: str, error: str, triggered_by: str, ref: str | None) -> None:
    """収集の失敗を通知する。NOTIFY_FAILURE_BATCH_SEC 秒の間の失敗をまとめて送る（0 ならすぐ機器ごとに送る）"""
    wait = settings.NOTIFY_FAILURE_BATCH_SEC
    if wait > 0:
        try:
            if failure_batch.add(_redis(), device_id, error, triggered_by, ref, wait):
                flush_failure_notifications.apply_async(countdown=wait)
            return
        except redis.exceptions.RedisError:
            logger.warning("収集失敗の通知をまとめられないため、すぐに送ります device=%s", device_id)
    send_failure_notification.delay(device_id, error, triggered_by, ref)


@celery_app.task
def flush_failure_notifications(stale_only: bool = False):
    """ためた収集の失敗を、通知先ごとに 1 通にまとめて送る。

    stale_only: beat の定期実行。送信のタスクが失われて残っている分だけを送る（予約どおりなら何もしない）
    """
    r = _redis()
    if stale_only and not failure_batch.stale(r):
        return {"sent": 0, "failed": 0}
    items = failure_batch.take(r)
    if not items:
        return {"sent": 0, "failed": 0}

    async def run():
        async with _sessionmaker()() as db:
            return await notify_failures(db, items)

    try:
        result = _run_async(run())
        logger.info("収集失敗の通知（まとめ） 機器=%d 件 %s", len({i["device_id"] for i in items}), result)
        return result
    except Exception:  # noqa: BLE001
        logger.exception("収集失敗の通知（まとめ）に失敗しました 件数=%d", len(items))
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
        result = await purge_old(db)
        result["ping_results"] = await ping_monitor_svc.purge(db)
        await db.commit()
        return result


@celery_app.task
def purge_audit_logs():
    """保持期間（AUDIT_LOG_RETENTION_DAYS / TERMINAL_LOG_RETENTION_DAYS）を過ぎた記録を削除する"""
    result = _run_async(_purge())
    if any(result.values()):
        logger.info("古いログを削除しました: %s", result)
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
    task_ids = [enqueue_collect(device_id, triggered_by, actor, ref).id for device_id in device_ids]
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
def heartbeat(record: bool = True) -> str:
    """beat が毎分投入する。実行できた時刻を残す（record=False は自己診断用で、時刻を残さない）"""
    if record:
        _redis().set(system.HEARTBEAT_KEY, utcnow().isoformat(), ex=86400)
    return "ok"


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
            enqueue_collect(target, "schedule", actor, ref)
        dispatched.append(schedule_id)
        logger.info("スケジュール実行: %s (kind=%s target=%s)", schedule_id, kind, target)
    return {"dispatched": dispatched}
