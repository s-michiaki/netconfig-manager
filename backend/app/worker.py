"""
Celeryワーカー定義
- collect_device_config: 単一デバイスのコンフィグ収集タスク
- collect_all_devices: 全デバイスの一括収集タスク
- dispatch_due_schedules: beat から毎分起動され、DBのスケジュールに従って収集を投入する
- purge_audit_logs: beat から毎日起動され、保持期間を過ぎた監査ログ・ターミナル記録・コマンド実行の結果を削除する
  （失効・期限切れから 30 日を過ぎた API トークンも）
- run_command_device: コマンド実行（表示コマンドの一括実行）の機器 1 台ぶん。実行前にもう一度コマンドを検証する
- send_change_notification: コンフィグに変更があったときの通知（Discord / Slack / Teams）
- send_violation_notification / send_failure_notification: 違反の発生・収集の失敗の通知
- send_inventory_notification: 機器情報（OS バージョン・シリアル番号など）が変わったときの通知
- send_drift_notification: 基準の世代からずれたとき（ずれなし → ずれあり）の通知
- send_unsaved_notification: running-config が startup-config に保存されていない状態に変わったときの通知
- send_periodic_reports: 定期レポート（週次・月次）の毎時の判定（月曜・1 日の REPORT_HOUR 時以降に送る。二重には送らない）
- ping_monitor: Ping監視の常時監視（PING_MONITOR_INTERVAL_SEC ごと。応答なし・復旧を通知）
- git_export_sync: コンフィグ履歴を外部 Git へ push（GIT_EXPORT_URL を設定したとき。収集で変わったときと 1 時間ごと）
  （収集の失敗は flush_failure_notifications で NOTIFY_FAILURE_BATCH_SEC 秒ごとにまとめて送る）
- fetch_vulns: 脆弱性・サポート終了日の外部からの取得（beat が毎時に判定。VULN_ENABLED のときだけ、1 日 1 回）。
  あわせて、サポート終了日が近いことの通知（1 日 1 回まで）
- import_fortinet_advisories: 管理者が指定した Fortinet の過去の勧告の取り込み
- send_vuln_notification: 新しく脆弱性に該当した機器と勧告の通知（照合の commit のあとに投入される）
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
from celery.signals import worker_ready
from croniter import croniter
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import outbound
from app.core.config import settings
from app.core.timeutil import utcnow
from app.models import CollectLog, CommandResult, CommandRun, ConfigBaseline, ConfigSnapshot, Device, DeviceGroup, Schedule
from app.models.command_run import STATUS_FAILED, STATUS_OK, STATUS_QUEUED, STATUS_RUNNING, STATUS_SKIPPED
from app.services import api_tokens as api_tokens_svc
from app.services import baseline as baseline_svc
from app.services import collect_state, config_service, failure_batch, fw_hits, git_export, inventory, monitoring, system
from app.services import command_run as command_run_svc
from app.services import ping_monitor as ping_monitor_svc
from app.services import report as report_svc
from app.services import vuln_service as vuln_svc
from app.services.activity import SYSTEM_ACTOR, record
from app.services.audit import purge_old
from app.services.compliance import recheck_expired_exceptions as _recheck_expired
from app.services.compliance import run_checks
from app.services.config_service import (
    CollectResult,
    DeviceConnectionInfo,
    collect_config_sync,
    describe_failure,
    head_commit_hash,
)
from app.services.connection import load_connection_info
from app.services.ignore_rules import SKIP_TIMEOUT, SKIP_TOO_HEAVY, SKIP_UNAVAILABLE, WARN_RATIO
from app.services.ignore_rules import load_patterns as load_ignore_patterns
from app.services.notify import (
    notify_change,
    notify_drift,
    notify_eol,
    notify_failure,
    notify_failures,
    notify_inventory,
    notify_ping,
    notify_unsaved,
    notify_violations,
    notify_vulns,
    wants_any,
)
from app.services.ping import PingUnavailable

logger = logging.getLogger(__name__)

celery_app = Celery(
    "netconfig",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)


@worker_ready.connect
def _log_outbound(**_kw) -> None:
    """worker の起動時に、外部への接続の設定を 1 行（プロキシはホスト:ポートと認証の有無だけ）"""
    outbound.startup_log(logger)


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
        # コマンド実行: worker の停止などで終わらなくなった機器を失敗にする
        "fail-stale-command-runs": {
            "task": "app.worker.fail_stale_command_runs",
            "schedule": 300.0,
        },
        # 定期レポート: 毎時に「今が送る日・時刻か」「送信済みか」を判定する（送信済みの期間は DB に記録。二重には送らない）
        "send-periodic-reports": {
            "task": "app.worker.send_periodic_reports",
            "schedule": 3600.0,
        },
        # 脆弱性・サポート終了日の取得: 毎時に「今が取る時刻か・今日は取得済みか」を判定する（無効のときは何もしない）
        "fetch-vulns": {
            "task": "app.worker.fetch_vulns",
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
VULN_FETCH_LOCK_TIMEOUT = 1800  # 脆弱性の取得の最大（vuln_service.MAX_FETCH_SECONDS = 約 16 分）より長くする（テストで確認）
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


async def _get_ignore_patterns(device: DeviceConnectionInfo) -> list[str]:
    """機器に効く「無視する行」の正規表現。読めなければ例外のまま返す

    無視せずに保存すると、その回だけ行が戻る偽の変更になるため、呼び出し側は保存しない（再試行できる失敗にする）
    """
    async with _sessionmaker()() as db:
        return await load_ignore_patterns(db, device.id, device.platform)


IGNORE_LOAD_FAILED = "無視する行の設定を読み込めなかったため、コンフィグを保存しませんでした"


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
        for sk in result.ignore_skipped:
            # 時間切れと、そもそも使えない正規表現（不正・読み込みが重すぎる）は分けて記録する
            detail = {"pattern": sk.pattern[:500], "reason": sk.reason}
            if sk.reason == SKIP_TIMEOUT:
                record(db, "ignore.timeout", "「無視する行」の正規表現の照合が時間切れになったため、"
                       "コンフィグを保存しませんでした", level="warning", detail=detail, **kw)
            elif sk.reason == SKIP_UNAVAILABLE:
                # 重さを測る子プロセスの起動の失敗など一時的なもの。正規表現そのものの問題とは分けて残す
                record(db, "ignore.unavailable", "「無視する行」の正規表現の重さを確かめられなかったため、"
                       "コンフィグを保存しませんでした（再試行します）", level="warning", detail=detail, **kw)
            else:
                why = "読み込みが重すぎます" if sk.reason == SKIP_TOO_HEAVY else "正規表現が正しくありません"
                record(db, "ignore.skipped", "「無視する行」の正規表現を使えなかったため、"
                       f"コンフィグを保存しませんでした（{why}）", level="warning", detail=detail, **kw)
        if result.success and result.ignore_dropped:
            dropped, before = result.ignore_dropped
            if before and dropped / before >= WARN_RATIO:
                record(db, "ignore.broad", f"「無視する行」で全行の {int(dropped * 100 / before)}% が消えました"
                       f"（{dropped} / {before} 行）。正規表現が広すぎないか確認してください",
                       level="warning", detail={"dropped": dropped, "lines": before}, **kw)
        inventory_changes: list[list[str]] = []
        if result.success and result.inventory:
            inventory_changes = await _save_inventory(db, device_id, result.inventory, kw)
        if result.success and result.startup is not None:
            result.unsaved_notify = await _save_startup(db, device_id, result.startup, kw)
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


async def _save_startup(db: AsyncSession, device_id: str, check, kw: dict) -> tuple[int, int] | None:
    """保存し忘れ（startup と running の不一致）の状態を機器に保存する。収集が成功した回だけ呼ぶ。

    - 対象外・無効（state が None）なら、前回の値を消して NULL に戻す
    - unknown（読み取れなかった・比べられなかった）の回は、前回の状態・行数・差分・日時を上書きしない
      （startup_checked_at は「最後に比べられた日時」のまま）。理由は（中身を含まない短い文で）ログにだけ残す。
      一度も比べられていない機器（state が NULL）のときだけ unknown を保存する
    - 通知するのは synced → unsaved のときだけ（追加, 削除の行数を返す）。初めて比べられた回（NULL・unknown → unsaved）は、
      導入直後に未保存の機器の通知がまとめて届かないよう通知しない。unsaved のままの間も通知しない
    - unsaved → synced はアクティビティに残すだけ
    差分の本文は機器にだけ保存し、アクティビティ・通知には行数しか入れない（コンフィグの中身を含むため）
    """
    d = await db.get(Device, device_id)
    if d is None:
        return None
    before = d.startup_state
    if check.state is None:
        d.startup_state = d.startup_added = d.startup_removed = d.startup_diff = d.startup_checked_at = None
        return None
    if check.state == "unknown":
        logger.info("startup と running を比べられませんでした device=%s: %s", device_id, check.reason)
        if before is None:
            d.startup_state = "unknown"
            d.startup_added = d.startup_removed = d.startup_diff = d.startup_checked_at = None
        return None
    d.startup_state = check.state
    d.startup_added, d.startup_removed = check.added, check.removed
    d.startup_diff = check.diff if check.state == "unsaved" else None
    d.startup_checked_at = utcnow()
    if check.state == "unsaved" and before != "unsaved":
        record(db, "startup.unsaved", f"running-config が startup-config に保存されていません"
               f"（+{check.added} / -{check.removed} 行）", level="warning",
               detail={"added": check.added, "removed": check.removed}, **kw)
        return (check.added or 0, check.removed or 0) if before == "synced" else None
    if check.state == "synced" and before == "unsaved":
        record(db, "startup.synced", "running-config が startup-config に保存されました", **kw)
    return None


async def _recheck_baseline(device_id: str, device_name: str, actor: str | None, ref: str | None,
                            only_if_stale: bool = False):
    """基準の世代があれば、最新とのずれを計算し直して保存する。

    only_if_stale: 世代が増えなかった収集で呼ぶとき。保存した値が最新（HEAD）のものでなく、または未計算のときだけ計算する
    （HEAD は本文を読まずに確かめる）。

    保存は「読んだときの基準のまま」のときだけ行う（計算している間に API で基準が付け替えられたら、結果は捨てる）。
    ずれなし → ずれあり に変わったときだけ（added, removed, 基準の世代, 最新の世代）を返す（通知する）。
    未計算 → ずれあり（計算できなかった後など）は通知しない。ずれあり → ずれなしはアクティビティに残すだけ。
    計算できないとき（基準の世代・リポジトリが無いなど）は、ずれを未計算に戻し、アクティビティに警告（baseline.error）を
    1 回だけ残す（同じ状態が続く間は増やさない）
    """
    async with _sessionmaker()() as db:
        row = await db.get(ConfigBaseline, device_id)
        if row is None:
            return None
        base_hash = row.commit_hash
        was_unknown = baseline_svc.is_unknown(row)
        was_drift = baseline_svc.drift_total(row) > 0
        had_error = was_unknown and row.checked_at is not None  # 前回までに計算を試みて失敗している
        if only_if_stale and not was_unknown:
            head = await asyncio.to_thread(head_commit_hash, device_id)
            if head is not None and row.latest_hash == head:
                return None
        drift = await asyncio.to_thread(baseline_svc.compute_drift, device_id, base_hash)
        kw = dict(device_id=device_id, device_name=device_name, actor=actor, ref=ref)
        same = (ConfigBaseline.device_id == device_id) & (ConfigBaseline.commit_hash == base_hash)
        if drift is None:
            logger.warning("基準からのずれを計算できませんでした（基準の世代か最新の世代を読めません）device=%s", device_id)
            res = await db.execute(update(ConfigBaseline).where(same).values(
                drift_added=None, drift_removed=None, latest_hash=None, checked_at=utcnow()))
            if res.rowcount and not had_error:
                record(db, "baseline.error", "基準からのずれを計算できませんでした（基準の世代がコンフィグの履歴に無いか、"
                       "履歴を読めません）。基準を指定し直してください", level="warning",
                       detail={"baseline": base_hash}, **kw)
            await db.commit()
            return None
        res = await db.execute(update(ConfigBaseline).where(same).values(
            drift_added=drift.added, drift_removed=drift.removed, latest_hash=drift.latest_hash, checked_at=utcnow()))
        if not res.rowcount:  # 計算の間に基準が付け替えられた・解除された。古い基準の結果は捨てる
            await db.rollback()
            return None
        detail = {"baseline": base_hash, "latest": drift.latest_hash, "added": drift.added, "removed": drift.removed}
        if drift.total > 0 and not was_drift:
            record(db, "baseline.drift", f"基準の世代からずれました（+{drift.added} / -{drift.removed} 行）",
                   detail=detail, **kw)
        elif drift.total == 0 and was_drift:
            record(db, "baseline.resolved", "基準の世代と同じ状態に戻りました", detail=detail, **kw)
        await db.commit()
        if drift.total > 0 and not was_drift and not was_unknown:
            return drift.added, drift.removed, base_hash, drift.latest_hash
        return None


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

        try:
            extra: list[str] | None = _run_async(_get_ignore_patterns(device))
        except Exception:  # noqa: BLE001 - 読めないまま無視せずに保存すると偽の変更になるので、接続もしない
            logger.exception("無視する行の設定を読めませんでした device=%s", device_id)
            extra = None
        ssh = _ssh_lock(device_id)
        if extra is None:
            result = CollectResult(False, error=IGNORE_LOAD_FAILED, retryable=True)
        elif ssh.acquire(blocking=True, blocking_timeout=SSH_LOCK_WAIT):
            try:
                # 設定が無いときは引数を足さない（従来の呼び出しのまま）
                result = (collect_config_sync(device, triggered_by, extra_ignore=extra) if extra
                          else collect_config_sync(device, triggered_by))
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
        if result.success and result.inventory and (result.inventory.get("os_version") or result.inventory.get("model")) \
                and settings.VULN_ENABLED:
            try:  # OS バージョンが変わったかもしれないので、その機器だけ照合し直す（外部へはつながない）
                _run_async(_reconcile_vulns(device_id))
            except Exception:  # noqa: BLE001 - 照合の失敗で収集を失敗扱いにしない
                logger.exception("脆弱性の照合に失敗しました device=%s", device_id)
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
        if result.unsaved_notify:
            try:
                if _run_async(_wants("unsaved")):
                    send_unsaved_notification.delay(device_id, *result.unsaved_notify, ref)
            except Exception:  # noqa: BLE001 - 通知の投入の失敗で収集の結果を変えない
                logger.exception("保存し忘れの通知を投入できませんでした device=%s", device_id)
        if result.success:
            # 基準の世代があれば、最新とのずれを計算し直す（失敗しても収集は成功のまま）。変更なしの回は古い・未計算のときだけ
            try:
                drifted = _run_async(_recheck_baseline(device_id, device.name, actor, ref,
                                                       only_if_stale=not result.commit_hash))
                if drifted and _run_async(_wants("drift")):
                    send_drift_notification.delay(device_id, *drifted, ref)
            except Exception:  # noqa: BLE001 - ずれの再計算・通知の投入の失敗で収集の結果を変えない
                logger.warning("基準からのずれの再計算に失敗しました device=%s", device_id, exc_info=True)
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


@celery_app.task
def send_drift_notification(device_id: str, added: int, removed: int, baseline_hash: str, latest_hash: str,
                            ref: str | None = None):
    async def run():
        async with _sessionmaker()() as db:
            return await notify_drift(db, device_id, added, removed, baseline_hash, latest_hash, ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001 - 通知の失敗は収集に影響させない
        logger.exception("基準からのずれの通知に失敗しました device=%s", device_id)
        return {"error": True}


@celery_app.task
def send_unsaved_notification(device_id: str, added: int, removed: int, ref: str | None = None):
    async def run():
        async with _sessionmaker()() as db:
            return await notify_unsaved(db, device_id, added, removed, ref=ref)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001 - 通知の失敗は収集に影響させない
        logger.exception("保存し忘れの通知に失敗しました device=%s", device_id)
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


async def _reconcile_vulns(device_id: str) -> None:
    async with _sessionmaker()() as db:
        await vuln_svc.reconcile(db, device_ids=[device_id])
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
        result["command_runs"] = await command_run_svc.purge_old_runs(db)
        result["api_tokens"] = await api_tokens_svc.purge_old(db)  # 失効・期限切れから 30 日を過ぎた API トークン
        result["report_sends"] = await report_svc.purge_old(db)  # 定期レポートの古い送信の記録
        await db.commit()
        return result


async def _send_reports() -> dict:
    async with _sessionmaker()() as db:
        return await report_svc.send_due_reports(db)


@celery_app.task
def send_periodic_reports():
    """定期レポートの送信（beat が毎時に呼ぶ。月曜（週次）・1 日（月次）の REPORT_HOUR 時以降なら、未送信の設定へ送る）"""
    try:
        result = _run_async(_send_reports())
    except Exception:  # noqa: BLE001 - 次の毎時にやり直せる。ほかのタスクに影響させない
        logger.exception("定期レポートの送信に失敗しました")
        return {"error": True}
    if result["sent"] or result["failed"]:
        logger.info("定期レポート: %s", result)
    return result


async def _fetch_vulns(force: bool) -> dict:
    async with _sessionmaker()() as db:
        sources = vuln_svc.active_sources() if force else await vuln_svc.due_sources(db)
        if not sources:
            return {"due": []}
        return await vuln_svc.run_fetch(db, sources)


async def _eol_notices() -> dict:
    """サポート終了日が近いことの通知（毎日 VULN_FETCH_HOUR 時以降の最初の判定。1 日 1 回まで）

    印（どの段階まで知らせたか）は、送信が済んでから確定する。すべての宛先で失敗したら印を残さず、次の毎時の判定で
    送り直す（1 つでも届いた・通知する設定が無いときは確定して、二重には送らない）。脆弱性の取得と同じロックの中で呼ぶ
    """
    if vuln_svc.local_now().hour < settings.VULN_FETCH_HOUR:
        return {"sent": 0, "failed": 0}
    async with _sessionmaker()() as db:
        groups, cursor = await vuln_svc.plan_eol_notices(db)
        if not groups or not await wants_any(db, "vuln"):
            await vuln_svc.save_eol_notice_state(db, cursor)
            await db.commit()
            return {"sent": 0, "failed": 0, "groups": len(groups)}
        result = await notify_eol(db, groups)
        if result.get("sent") or not result.get("failed"):
            await vuln_svc.save_eol_notice_state(db, cursor)
            await db.commit()
        return {**result, "groups": len(groups)}


@celery_app.task
def send_vuln_notification(items: list):
    """新しく脆弱性に該当した機器と勧告の通知。items: [[機器ID, [[勧告 ID, 題, 重大度, CVSS, KEV], ...]], ...]"""
    async def run():
        async with _sessionmaker()() as db:
            return await notify_vulns(db, items)

    try:
        return _run_async(run())
    except Exception:  # noqa: BLE001
        logger.exception("脆弱性の通知に失敗しました")
        return {"error": True}


@celery_app.task
def import_fortinet_advisories(ids: list[str], actor: str | None = None):
    """Fortinet の過去の勧告の取り込み（管理者が API から投入）。結果は vuln_sources の fortinet_import に残す（画面に出す）

    毎日の取得と同じロックを取る（同時に Fortinet へ要求しない）。取れなければ「取得中」として終わる
    """
    if not settings.VULN_ENABLED:
        return {"disabled": True}

    async def save(state: dict) -> None:
        async with _sessionmaker()() as db:
            await vuln_svc.set_import_state(db, state)
            await db.commit()

    base = {"by": actor, "ids": ids, "at": utcnow().isoformat()}
    lock = _redis().lock("netconfig:vuln-fetch", timeout=VULN_FETCH_LOCK_TIMEOUT)
    if not lock.acquire(blocking=False):
        _run_async(save({**base, "status": "busy",
                         "message": "取得の途中のため、取り込めませんでした。しばらくしてからやり直してください"}))
        return {"busy": True}

    async def run():
        async with _sessionmaker()() as db:
            return await vuln_svc.import_fortinet(db, ids)

    try:
        results = _run_async(run())
        _run_async(save({**base, "status": "done", "results": results, "finished_at": utcnow().isoformat()}))
        return {"results": len(results)}
    except Exception:  # noqa: BLE001
        logger.exception("Fortinet の勧告の取り込みに失敗しました")
        _run_async(save({**base, "status": "error", "message": "想定外のエラーで取り込めませんでした（ログを確認してください）"}))
        return {"error": True}
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


@celery_app.task
def fetch_vulns(force: bool = False):
    """脆弱性・サポート終了日を外部から取得する（beat が毎時に呼ぶ。force は管理者の「いま取得」）。

    VULN_ENABLED=false（既定）なら何もしない（外部へはつながない）。取得するのは製品単位の公開情報だけで、機器の情報は送らない
    """
    if not settings.VULN_ENABLED:
        return {"disabled": True}
    lock = _redis().lock("netconfig:vuln-fetch", timeout=VULN_FETCH_LOCK_TIMEOUT)
    if not lock.acquire(blocking=False):
        return {"skipped": True}
    try:
        try:
            result = _run_async(_fetch_vulns(force))
        except Exception:  # noqa: BLE001 - 次の毎時にやり直せる。ほかのタスクに影響させない
            logger.exception("脆弱性情報の取得に失敗しました")
            return {"error": True}
        if result.get("sources"):
            logger.info("脆弱性情報の取得: %s", {k: ("ok" if v["ok"] else "failed") for k, v in result["sources"].items()})
        try:  # サポート終了日の通知も同じロックの中で（2 つの worker が同時に送らない）
            eol = _run_async(_eol_notices())
            if eol.get("sent") or eol.get("failed") or eol.get("groups"):
                result["eol_notices"] = eol
        except Exception:  # noqa: BLE001 - 次の毎時にやり直せる
            logger.exception("サポート終了日の通知に失敗しました")
        return result
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass


@celery_app.task
def purge_audit_logs():
    """保持期間（AUDIT_LOG_RETENTION_DAYS / TERMINAL_LOG_RETENTION_DAYS）を過ぎた記録を削除する"""
    result = _run_async(_purge())
    if any(result.values()):
        logger.info("古いログを削除しました: %s", result)
    return result


# ---------------------------------------------------------------- コマンド実行（表示コマンドの一括実行）


def _pending_key(run_id: str) -> str:
    return f"netconfig:cmdrun:{run_id}:pending"


def enqueue_command_run(run_id: str, result_ids: list[str]) -> None:
    """実行の各機器のタスクを投入する。同時に走らせるのは COMMAND_RUN_CONCURRENCY 台までで、
    残りは Redis の待ち行列に置き、機器のタスクが終わるたびに次の 1 台を投入する"""
    n = settings.COMMAND_RUN_CONCURRENCY
    first, rest = result_ids[:n], result_ids[n:]
    if rest:
        r = _redis()
        r.rpush(_pending_key(run_id), *rest)
        r.expire(_pending_key(run_id), 24 * 3600)
    for rid in first:
        run_command_device.delay(rid)


def _dispatch_next_command(run_id: str) -> None:
    raw = _redis().lpop(_pending_key(run_id))
    if raw:
        run_command_device.delay(raw.decode() if isinstance(raw, bytes) else raw)


async def _claim_command_result(result_id: str) -> dict | None:
    """結果を「実行中」にして、実行の ID とコマンドを返す。結果が無ければ None。
    すでに着手済み（queued 以外）なら claimed=False"""
    async with _sessionmaker()() as db:
        res = await db.get(CommandResult, result_id)
        if res is None:
            return None
        run = await db.get(CommandRun, res.run_id)
        info: dict = {"run_id": res.run_id, "claimed": False, "commands": list(run.commands) if run else []}
        if res.status != STATUS_QUEUED or run is None:
            return info
        res.status = STATUS_RUNNING
        res.started_at = utcnow()
        await db.commit()
        info["claimed"] = True
        return info


async def _load_command_device(result_id: str) -> tuple[DeviceConnectionInfo | None, bool]:
    """結果の機器の接続情報と、有効かどうか"""
    async with _sessionmaker()() as db:
        res = await db.get(CommandResult, result_id)
        dev = await db.get(Device, res.device_id) if res is not None and res.device_id else None
        if dev is None:
            return None, False
        return await load_connection_info(db, dev.id), bool(dev.is_active)


async def _save_command_result(result_id: str, run_id: str, commands: list[str], status: str,
                               raw: list[str] | None = None, error: str | None = None) -> None:
    """結果を保存する（出力は 1 コマンドと実行全体の上限で切り、暗号化して保存）。"""
    async with _sessionmaker()() as db:
        res = await db.get(CommandResult, result_id)
        if res is None:
            return
        res.status = status
        res.error = error
        res.finished_at = utcnow()
        if raw is not None:
            used_by_others = (await db.execute(
                select(func.coalesce(func.sum(CommandResult.output_chars), 0))
                .where(CommandResult.run_id == run_id, CommandResult.id != result_id)
            )).scalar_one()
            budget = max(settings.COMMAND_RUN_MAX_RUN_OUTPUT - int(used_by_others), 0)
            items, used = command_run_svc.build_outputs(commands, raw, budget)
            res.outputs = command_run_svc.dumps_outputs(items)
            res.output_chars = used
        await db.commit()


async def _finish_command_run(run_id: str) -> None:
    """全台が終わっていれば実行を終わらせる。自分の結果を確定してから数える（同時に終わった別の機器と、
    どちらかが必ず「全部終わった」と判定する）。保存（成功など）とは別の処理で、失敗しても結果は変えない"""
    async with _sessionmaker()() as db:
        await command_run_svc.mark_finished_if_done(db, run_id)
        await db.commit()


@celery_app.task
def run_command_device(result_id: str):
    """コマンド実行の 1 台ぶん。機器へ接続する直前に、コマンドをもう一度検証する（キューの値を信用しない）。
    失敗しても再試行はしない（同じコマンドを何度も機器へ送らない）。
    「実行中」にしたあとは、何があっても（例外でも）その機器を失敗にし、必ず次の機器を投入する"""
    info = _run_async(_claim_command_result(result_id))
    if info is None:
        return {"error": "not found"}
    run_id, commands = info["run_id"], info["commands"]
    try:
        if not info["claimed"]:
            return {"skipped": True}

        def save(status, raw=None, error=None):
            _run_async(_save_command_result(result_id, run_id, commands, status, raw, error))
            try:  # 保存が済んだあとの後処理の失敗で、保存した結果を失敗に上書きしない（残りは fail_stale が終わらせる）
                _run_async(_finish_command_run(run_id))
            except Exception:  # noqa: BLE001
                logger.exception("コマンド実行の終了判定に失敗しました run=%s", run_id)

        try:
            device, active = _run_async(_load_command_device(result_id))
            if not settings.COMMAND_RUN_ENABLED:
                save(STATUS_SKIPPED, error="コマンド実行が無効になっているため、実行しませんでした")
                return {"status": STATUS_SKIPPED}
            if device is None:
                save(STATUS_SKIPPED, error="機器が削除されているため、実行しませんでした")
                return {"status": STATUS_SKIPPED}
            if not active:
                save(STATUS_SKIPPED, error="無効な機器のため、実行しませんでした")
                return {"status": STATUS_SKIPPED}
            try:
                # 機器の今の機種で検証し直す（作成後に機種を変えられていても、送れるものだけ送る）
                commands = command_run_svc.validate_for_platform(device.platform, commands)
            except command_run_svc.CommandError as e:
                save(STATUS_SKIPPED, error=f"送れないコマンドのため、実行しませんでした（{e}）")
                return {"status": STATUS_SKIPPED}
            ssh = _ssh_lock(device.id)
            if not ssh.acquire(blocking=True, blocking_timeout=SSH_LOCK_WAIT):
                save(STATUS_FAILED, error="同じ機器への別の SSH 処理（収集など）が終わらないため、実行できませんでした")
                return {"status": STATUS_FAILED}
            try:
                raw = config_service.run_commands(device, commands)
            except Exception as e:  # noqa: BLE001 - 失敗の理由を日本語にして結果に残す（再試行しない）
                msg, _ = describe_failure(e, device)
                save(STATUS_FAILED, error=msg)
                return {"status": STATUS_FAILED}
            finally:
                try:
                    ssh.release()
                except redis.exceptions.LockError:
                    pass
            save(STATUS_OK, raw=raw)
            return {"status": STATUS_OK}
        except Exception as e:  # noqa: BLE001 - 想定外の失敗でも、この機器を「実行中」のままにしない（出力は入れない）
            logger.exception("コマンド実行に失敗しました result=%s", result_id)
            try:
                save(STATUS_FAILED, error=f"内部エラーのため実行できませんでした（{type(e).__name__}）")
            except Exception:  # noqa: BLE001 - 保存もできないときは、古い結果の整理（fail_stale）が失敗にする
                logger.exception("コマンド実行の結果を保存できませんでした result=%s", result_id)
            return {"status": STATUS_FAILED}
    finally:
        try:
            _dispatch_next_command(run_id)
        except Exception:  # noqa: BLE001 - 次の投入の失敗で、この機器の結果を変えない（残りは fail_stale が失敗にする）
            logger.exception("コマンド実行の次の機器を投入できませんでした run=%s", run_id)


async def _fail_stale_runs() -> int:
    async with _sessionmaker()() as db:
        n = await command_run_svc.fail_stale(db)
        await db.commit()
        return n


@celery_app.task
def fail_stale_command_runs() -> int:
    """worker の停止などで終わらなくなったコマンド実行の機器を失敗にする（5 分ごと）"""
    n = _run_async(_fail_stale_runs())
    if n:
        logger.warning("止まっていたコマンド実行の機器 %d 台を失敗にしました", n)
    return n


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
