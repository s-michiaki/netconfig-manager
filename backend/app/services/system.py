"""システムの状態の確認と、異常の検出・通知（ウォッチドッグ）

目的: 「止まっていることに気づけない」をなくす。
収集の失敗は「収集して失敗した」ときにしか通知されず、worker やスケジューラー（beat）が
止まっているときは何も起きない（2026/11 に本番で 3 日間、収集が止まっていたのに気づけなかった）。

確認する項目（components）
  db       : データベースに接続できるか
  redis    : Redis に接続できるか
  worker   : worker が応答するか（収集・通知・コンプライアンスチェックを実行する）
  beat     : スケジューラーが動いているか（beat が毎分投入し worker が実行する heartbeat の時刻で判断）
  schedule : 有効なスケジュールと、最後に実行した時刻（表示のみ）
  collect  : SYSTEM_STALE_DAYS 日以上収集できていない有効な機器
  disk     : コンフィグ履歴・ターミナルの記録の保存先の空き
  cert     : HTTPS の証明書の期限

ウォッチドッグは **API のプロセス**で動かす（worker / beat が止まっていても検出・通知できるように）。
- worker / beat / redis の異常は SYSTEM_ALERT_AFTER_MIN 分続いたら通知する（再起動中の一時的な停止では通知しない）
- 通知は状態が変わったときだけ（異常になった・悪化した・未収集の機器が増えた・復旧した）
- 通知済みの状態は Redis に保存する（API を再起動しても同じ通知を繰り返さない）。Redis が使えなければメモリに持つ
"""
import asyncio
import json
import logging
import shutil
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from redis.exceptions import RedisError
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.activity import ActivityLog
from app.models.device import CollectLog, Device, Schedule
from app.services import login_limit, notify
from app.services.activity import record as record_activity

logger = logging.getLogger(__name__)

HEARTBEAT_KEY = "netconfig:system:heartbeat"  # beat → worker の heartbeat タスクが書く時刻（UTC の ISO 形式）
STATE_KEY = "netconfig:system:alerts"  # 通知済みの状態（項目ごと）
BEAT_STALE_SEC = 180  # heartbeat（毎分）がこの秒数より古ければ、スケジューラーが止まっているとみなす
DISK_WARN_PCT, DISK_ERROR_PCT = 15, 5
CERT_WARN_DAYS, CERT_ERROR_DAYS = 30, 7
RANK = {"unknown": 0, "ok": 0, "warn": 1, "error": 2}
# 通知する項目（db は、止まっていると通知先も読めないため対象外）
ALERT_KEYS = ("redis", "worker", "beat", "collect", "disk", "cert")
GRACE_KEYS = ("redis", "worker", "beat")  # 一時的な停止では通知しない項目


@dataclass
class Component:
    key: str
    label: str
    status: str  # ok / warn / error / unknown（確認できない・対象外）
    summary: str
    detail: dict = field(default_factory=dict)
    items: list[str] = field(default_factory=list)  # 通知の「増えた」を判定するための識別子（未収集の機器 ID など）


# ---------------------------------------------------------------- 個別の確認


async def check_db(db: AsyncSession) -> Component:
    try:
        await db.execute(text("SELECT 1"))
        return Component("db", "データベース", "ok", "接続できます")
    except Exception as e:  # noqa: BLE001 - 状態として返す
        return Component("db", "データベース", "error", f"接続できません: {str(e)[:200]}")


async def check_redis() -> tuple[Component, str | None]:
    """（Redis の状態, heartbeat の値）"""
    try:
        r = login_limit.client()
        await r.ping()
        hb = await r.get(HEARTBEAT_KEY)
        return Component("redis", "Redis", "ok", "接続できます"), hb.decode() if isinstance(hb, bytes) else hb
    except (RedisError, OSError) as e:
        return Component("redis", "Redis", "error",
                         f"接続できません（収集・スケジュール・ログインの試行制限が動きません）: {str(e)[:200]}"), None


def ping_workers(timeout: float = 1.5) -> list[str]:
    """応答した worker の名前。Celery が broker に接続できないときは例外"""
    from app.worker import celery_app  # 循環 import を避けるため、ここで読み込む

    return [name for reply in (celery_app.control.ping(timeout=timeout) or []) for name in reply]


async def check_worker(redis_ok: bool) -> Component:
    label = "worker（収集・通知の実行）"
    if not redis_ok:
        return Component("worker", label, "unknown", "Redis に接続できないため確認できません")
    try:
        names = await asyncio.to_thread(ping_workers)
    except Exception as e:  # noqa: BLE001 - 依存パッケージの不具合などで import・接続に失敗することがある
        return Component("worker", label, "error",
                         f"worker に指示を送れません（収集の受け付けが失敗します）: {type(e).__name__}: {str(e)[:200]}")
    if not names:
        return Component("worker", label, "error", "worker が応答しません（収集・通知・スケジュールの処理が実行されません）")
    return Component("worker", label, "ok", f"{len(names)} 個が応答しています", {"workers": names})


def check_beat(heartbeat: str | None, worker: Component, now: datetime) -> Component:
    label = "スケジューラー（beat）"
    if worker.status != "ok":
        return Component("beat", label, "unknown", "worker が応答しないため確認できません")
    try:
        at = datetime.fromisoformat(heartbeat) if heartbeat else None
    except ValueError:
        at = None
    if at is None:
        return Component("beat", label, "error",
                         "スケジューラーからの定期実行が届いていません（スケジュール収集が実行されません）")
    age = (now - at).total_seconds()
    detail = {"last_heartbeat": at.isoformat()}
    if age > BEAT_STALE_SEC:
        return Component("beat", label, "error",
                         f"{int(age // 60)} 分前から定期実行が届いていません（スケジュール収集が実行されません）", detail)
    return Component("beat", label, "ok", "動いています", detail)


async def check_schedules(db: AsyncSession) -> Component:
    active = (await db.execute(select(func.count()).select_from(Schedule).where(Schedule.is_active.is_(True)))).scalar_one()
    last = (await db.execute(select(func.max(ActivityLog.at)).where(ActivityLog.event == "schedule.run"))).scalar_one()
    detail = {"active": active, "last_run": last.isoformat() if last else None}
    if not active:
        return Component("schedule", "スケジュール", "ok", "有効なスケジュールはありません", detail)
    return Component("schedule", "スケジュール", "ok", f"有効 {active} 件", detail)


async def check_collect(db: AsyncSession, now: datetime) -> Component:
    label = "収集の状況"
    days = settings.SYSTEM_STALE_DAYS
    last_ok = (await db.execute(select(func.max(CollectLog.finished_at)).where(CollectLog.status == "success"))).scalar_one()
    detail: dict = {"last_success": last_ok.isoformat() if last_ok else None, "stale_days": days}
    if days <= 0:
        return Component("collect", label, "ok", "長期間収集できていない機器の確認は無効です", detail)
    rows = (await db.execute(
        select(Device.id, Device.name, Device.created_at, func.max(CollectLog.finished_at))
        .outerjoin(CollectLog, (CollectLog.device_id == Device.id) & (CollectLog.status == "success"))
        .where(Device.is_active.is_(True)).group_by(Device.id, Device.name, Device.created_at).order_by(Device.name)
    )).all()
    border = now - timedelta(days=days)
    stale = [(i, n, last) for i, n, created, last in rows if (last or created or now) < border]
    detail["devices"] = [{"id": i, "name": n, "last_success": last.isoformat() if last else None} for i, n, last in stale]
    if stale:
        return Component("collect", label, "warn", f"{len(stale)} 台が {days} 日以上収集できていません",
                         detail, items=[i for i, _, _ in stale])
    if not rows:
        return Component("collect", label, "ok", "有効な機器はありません", detail)
    return Component("collect", label, "ok", f"有効な {len(rows)} 台すべて、{days} 日以内に収集できています", detail)


def check_disk() -> Component:
    worst, parts, seen = "ok", [], set()
    for name, path in (("コンフィグ履歴", settings.GIT_REPO_PATH), ("ターミナルの記録", settings.TERMINAL_LOG_PATH)):
        target = Path(path)
        while not target.exists() and target != target.parent:  # まだ作られていなければ、置かれる先のディスクを見る
            target = target.parent
        try:
            u = shutil.disk_usage(target)
        except OSError:
            continue
        if (u.total, u.free) in seen:  # 同じディスクは1回だけ
            continue
        seen.add((u.total, u.free))
        pct = u.free * 100 / u.total if u.total else 100
        st = "error" if pct < DISK_ERROR_PCT else "warn" if pct < DISK_WARN_PCT else "ok"
        worst = max(worst, st, key=RANK.get)
        parts.append({"name": name, "path": path, "free_gb": round(u.free / 1e9, 1), "total_gb": round(u.total / 1e9, 1),
                      "free_pct": round(pct, 1), "status": st})
    if not parts:
        return Component("disk", "ディスクの空き", "unknown", "保存先を確認できません")
    low = min(parts, key=lambda p: p["free_pct"])
    return Component("disk", "ディスクの空き", worst,
                     f"空き {low['free_gb']} GB（{low['free_pct']}%）" + ("。空きが少なくなっています" if worst != "ok" else ""),
                     {"volumes": parts})


def fetch_cert_expiry(host: str, port: int) -> datetime:
    from cryptography import x509

    pem = ssl.get_server_certificate((host, port), timeout=3)
    return x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc.replace(tzinfo=None)


async def check_cert(now: datetime) -> Component:
    label = "HTTPS の証明書"
    endpoint = settings.SYSTEM_CERT_ENDPOINT.strip()
    if not endpoint:
        return Component("cert", label, "unknown", "確認しない設定です")
    host, _, port = endpoint.rpartition(":")
    try:
        expires = await asyncio.to_thread(fetch_cert_expiry, host or endpoint, int(port) if host else 443)
    except Exception:  # noqa: BLE001 - HTTPS を使っていない環境では接続できない
        return Component("cert", label, "unknown", "HTTPS が無効か、証明書を確認できません")
    days = (expires - now).days
    detail = {"expires_at": expires.isoformat(), "days_left": days}
    if days < 0:
        return Component("cert", label, "error",
                         "期限が切れています（scripts/import_cert.sh で新しい証明書を取り込んでください）", detail)
    st = "error" if days <= CERT_ERROR_DAYS else "warn" if days <= CERT_WARN_DAYS else "ok"
    hint = "。更新してください（scripts/import_cert.sh）" if st != "ok" else ""
    return Component("cert", label, st, f"期限まであと {days} 日{hint}", detail)


async def collect_status(db: AsyncSession, now: datetime | None = None) -> list[Component]:
    now = now or utcnow()
    database = await check_db(db)
    redis_c, heartbeat = await check_redis()
    worker = await check_worker(redis_c.status == "ok")
    out = [database, redis_c, worker, check_beat(heartbeat, worker, now)]
    if database.status == "ok":
        out += [await check_schedules(db), await check_collect(db, now)]
    return [*out, check_disk(), await check_cert(now)]


def overall(components: list[Component]) -> str:
    return max((c.status for c in components), key=RANK.get, default="ok").replace("unknown", "ok")


def to_dict(components: list[Component]) -> dict:
    return {"overall": overall(components), "checked_at": utcnow().isoformat(),
            "components": [{k: v for k, v in asdict(c).items() if k != "items"} for c in components]}


# ---------------------------------------------------------------- 異常の検出と通知


class Watchdog:
    def __init__(self) -> None:
        self.first_bad: dict[str, datetime] = {}  # 異常を最初に見た時刻（一時的な停止を通知しないため）
        self.memory: dict[str, dict] = {}  # 通知済みの状態（Redis が使えないときの代わり）

    async def _load(self) -> dict[str, dict]:
        try:
            raw = await login_limit.client().hgetall(STATE_KEY)
            state = {(k.decode() if isinstance(k, bytes) else k): json.loads(v) for k, v in raw.items()}
            self.memory.update(state)
            return dict(state)
        except (RedisError, OSError, ValueError):
            return dict(self.memory)

    async def _save(self, key: str, value: dict) -> None:
        self.memory[key] = value
        try:
            await login_limit.client().hset(STATE_KEY, key, json.dumps(value))
        except (RedisError, OSError):
            pass

    async def tick(self, db: AsyncSession, now: datetime | None = None) -> list[tuple[str, str]]:
        """状態を確認し、変化があれば通知する。通知した（項目, "alert" / "recovered"）を返す"""
        now = now or utcnow()
        components = await collect_status(db, now)
        state = await self._load()
        sent: list[tuple[str, str]] = []
        for c in components:
            if c.key not in ALERT_KEYS or c.status == "unknown":
                continue
            prev = state.get(c.key) or {"status": "ok", "items": []}
            if c.status == "ok":
                self.first_bad.pop(c.key, None)
                if prev["status"] != "ok":
                    await self._notify(db, c, recovered=True)
                    await self._save(c.key, {"status": "ok", "items": []})
                    sent.append((c.key, "recovered"))
                continue
            first = self.first_bad.setdefault(c.key, now)
            if c.key in GRACE_KEYS and now - first < timedelta(minutes=settings.SYSTEM_ALERT_AFTER_MIN):
                continue
            worse = RANK[c.status] > RANK[prev["status"]]
            added = [i for i in c.items if i not in prev.get("items", [])]
            if worse or added:
                await self._notify(db, c, recovered=False)
                sent.append((c.key, "alert"))
            if worse or added or c.items != prev.get("items", []) or c.status != prev["status"]:
                await self._save(c.key, {"status": c.status, "items": c.items})
        return sent

    async def _notify(self, db: AsyncSession, c: Component, recovered: bool) -> None:
        if recovered:
            title, body, event = f"復旧: {c.label}", c.summary, "system.recovered"
        else:
            title, body, event = f"システムの異常: {c.label}", c.summary, "system.alert"
        names = [d["name"] for d in c.detail.get("devices", [])]
        facts = [("機器", "・".join(names[:notify.MAX_LIST]) + (f" ほか {len(names) - notify.MAX_LIST} 台"
                                                             if len(names) > notify.MAX_LIST else ""))] if names else []
        logger.warning("%s: %s", title, body)
        try:
            record_activity(db, event, f"{c.label}: {body}", level="info" if recovered else None,
                            detail={"component": c.key, "status": c.status, **({"devices": names} if names else {})})
            await db.commit()
            await notify.notify_system(db, title, body, facts, ok=recovered)
        except Exception:  # noqa: BLE001 - 通知の失敗でウォッチドッグを止めない
            logger.exception("システムの状態の通知に失敗しました")
            await db.rollback()


watchdog = Watchdog()


async def watchdog_loop() -> None:
    from app.core.database import AsyncSessionLocal

    while True:
        await asyncio.sleep(settings.SYSTEM_CHECK_INTERVAL_SEC)
        try:
            async with AsyncSessionLocal() as db:
                await watchdog.tick(db)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("システムの状態の確認に失敗しました")
