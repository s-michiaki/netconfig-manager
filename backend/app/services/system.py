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
  backup   : 定期バックアップ（scripts/backup.sh）の結果。backup.sh が backend コンテナの
             app.tools.backup_report を呼んで Redis に書いた記録を読む。記録が無い環境（バックアップを
             使っていない・開発環境）では unknown にして、警告も通知もしない
  git_export : コンフィグ履歴の外部 Git への push（services/git_export.py）の最後の結果。設定していなければ unknown
  mail     : メール送信の設定と最後の送信の結果（有効にしていなければ unknown）
  vuln     : 脆弱性・サポート終了日の外部からの取得（VULN_ENABLED のときだけ）。最後の成功・失敗している情報源・
             STALE_DAYS 日以上取得できていなければ warn（画面に注意を出すだけで、通知はしない）
  outbound : 外部への接続（core/outbound.py）。プロキシ（ホスト:ポートと認証の有無だけ）・追加の CA の件数と期限・
             最後の「接続を確かめる」の結果。CA の期限切れ・30 日以内・確認の失敗は warn（画面に出すだけで、通知はしない）
  images   : コンテナのイメージ（DB・Redis・ビルドの土台）の作成日時。setup.sh が app.tools.image_report で伝える。
             古い（IMAGE_STALE_DAYS 日より前）・取り直せなかったら warn

ウォッチドッグは **API のプロセス**で動かす（worker / beat が止まっていても検出・通知できるように）。
- worker / beat / redis の異常は SYSTEM_ALERT_AFTER_MIN 分続いたら通知する（再起動中の一時的な停止では通知しない）
- 通知は状態が変わったときだけ（異常になった・悪化した・未収集の機器が増えた・復旧した）
- 通知済みの状態は Redis に保存する（API を再起動しても同じ通知を繰り返さない）。Redis が使えなければメモリに持つ
"""
import asyncio
import json
import logging
import re
import shutil
import ssl
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from redis.exceptions import RedisError
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.activity import ActivityLog
from app.models.device import CollectLog, Device, Schedule
from app.services import git_export, login_limit, notify
from app.services.activity import record as record_activity

logger = logging.getLogger(__name__)

HEARTBEAT_KEY = "netconfig:system:heartbeat"  # beat → worker の heartbeat タスクが書く時刻（UTC の ISO 形式）
STATE_KEY = "netconfig:system:alerts"  # 通知済みの状態（項目ごと）
IMAGES_KEY = "netconfig:system:images"  # setup.sh が伝えたコンテナのイメージ（名前・作成日時・取り直せなかったもの。JSON）
BACKUP_KEY = "netconfig:system:backup"  # バックアップの記録（最後の結果・最後の成功・タイマーの登録状況。JSON）
OUTBOUND_CHECK_KEY = "netconfig:system:outbound_check"  # 最後の「接続を確かめる」の結果（JSON。秘密は含めない）
BEAT_STALE_SEC = 180  # heartbeat（毎分）がこの秒数より古ければ、スケジューラーが止まっているとみなす
DISK_WARN_PCT, DISK_ERROR_PCT = 15, 5
CERT_WARN_DAYS, CERT_ERROR_DAYS = 30, 7
RANK = {"unknown": 0, "ok": 0, "warn": 1, "error": 2}
# 通知する項目（db は、止まっていると通知先も読めないため対象外）
ALERT_KEYS = ("redis", "worker", "beat", "collect", "disk", "cert", "backup", "git_export", "images", "mail")
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


# ---------------------------------------------------------------- バックアップ


async def load_backup_state() -> dict:
    raw = await login_limit.client().get(BACKUP_KEY)
    try:
        state = json.loads(raw) if raw else {}
    except ValueError:
        state = {}
    return state if isinstance(state, dict) else {}


async def save_backup_state(state: dict) -> None:
    await login_limit.client().set(BACKUP_KEY, json.dumps(state, ensure_ascii=False))


async def record_backup_result(result: dict) -> dict:
    """backup.sh の結果を記録する（app.tools.backup_report から呼ぶ）。最後の成功は失敗しても引き継ぐ"""
    state = await load_backup_state()
    state["last"] = result
    if result.get("status") == "ok":
        state["last_success"] = result
    await save_backup_state(state)
    return state


async def record_backup_schedule(enabled: bool, calendar: str | None, now: datetime) -> None:
    """setup.sh がタイマーを登録・解除したことを記録する（登録したのに一度も届かないことに気づけるように）"""
    state = await load_backup_state()
    prev = state.get("schedule") or {}
    since = prev.get("since") if prev.get("enabled") == enabled else None
    state["schedule"] = {"enabled": enabled, "calendar": calendar, "since": since or now.isoformat()}
    await save_backup_state(state)


def _parse_at(value) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


def _size_text(size) -> str:
    try:
        n = float(size)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "—"


async def check_backup(now: datetime, redis_ok: bool = True) -> Component:
    label = "バックアップ"
    hours = settings.BACKUP_STALE_HOURS
    if not redis_ok:
        return Component("backup", label, "unknown", "Redis に接続できないため確認できません")
    try:
        state = await load_backup_state()
    except (RedisError, OSError):
        return Component("backup", label, "unknown", "Redis に接続できないため確認できません")
    last, ok, schedule = state.get("last") or {}, state.get("last_success") or {}, state.get("schedule") or {}
    enabled = schedule.get("enabled")  # True / False / None（setup.sh からの連絡が無い）
    detail = {"last": last or None, "last_success": ok or None, "schedule": schedule or None, "stale_hours": hours}
    if not last:
        since = _parse_at(schedule.get("since"))
        if enabled and hours > 0 and since and now - since > timedelta(hours=hours):
            return Component("backup", label, "warn",
                             f"定期バックアップを登録してから {int((now - since).total_seconds() // 3600)} 時間、"
                             "実行の記録が届いていません（systemctl status netconfig-backup.timer で確認してください）",
                             detail, items=["never"])
        if enabled is False:
            return Component("backup", label, "unknown", "定期バックアップは無効です（BACKUP_ON_CALENDAR=off）", detail)
        return Component("backup", label, "unknown", "バックアップの記録はまだありません", detail)
    at = last.get("at") or ""
    if last.get("status") != "ok":
        msg = last.get("message") or "原因はサーバーの journalctl -u netconfig-backup.service で確認してください"
        return Component("backup", label, "error", f"前回のバックアップに失敗しました: {msg}", detail,
                         items=[f"failed:{at}"])
    ok_at = _parse_at(ok.get("at"))
    if enabled is not False and hours > 0 and ok_at and now - ok_at > timedelta(hours=hours):
        return Component("backup", label, "warn",
                         f"{int((now - ok_at).total_seconds() // 3600)} 時間バックアップが成功していません"
                         "（タイマーが止まっている可能性があります）", detail, items=["stale"])
    failed = [name for key, name in (("copy", "外部へのコピー"), ("post", "後処理のコマンド"))
              if last.get(key) == "failed"]
    if failed:
        msg = last.get("message") or ""
        return Component("backup", label, "warn",
                         f"サーバー内には保存しましたが、{'と'.join(failed)}に失敗しました" + (f": {msg}" if msg else ""),
                         detail, items=[f"offsite:{at}"])
    if last.get("encrypted") is False and (last.get("copy"), last.get("post")) != ("none", "none"):
        # 外部へ出すのに暗号化していない: 1 つ漏れれば .env の鍵で全機器のパスワードを復号できる（#15）
        return Component("backup", label, "warn",
                         "バックアップをサーバーの外へ保管していますが、暗号化していません"
                         "（BACKUP_ENCRYPT_PASSPHRASE_FILE を設定してください）", detail, items=["unencrypted"])
    copied = "。外部へのコピーも成功" if last.get("copy") == "ok" else ""
    return Component("backup", label, "ok", f"前回のバックアップは成功しました（{_size_text(last.get('size'))}{copied}）",
                     detail)


def parse_image_created(value: str) -> datetime | None:
    """podman image inspect の Created（例 "2026-11-19 03:12:45.123456789 +0000 UTC"）や ISO 形式を読む"""
    value = (value or "").strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?", value)
    if not m:
        return None
    tz = (m.group(3) or "+0000").replace("Z", "+0000").replace(":", "")
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)} {tz}", "%Y-%m-%d %H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None


def _short_image(name: str) -> str:
    """表示用に Docker Hub の公式イメージの接頭辞を省く（docker.io/library/nginx:1.30-alpine → nginx:1.30-alpine）"""
    return name.removeprefix("docker.io/library/")


async def record_images(report: dict) -> None:
    await login_limit.client().set(IMAGES_KEY, json.dumps(report, ensure_ascii=False))


async def check_images(now: datetime, redis_ok: bool = True) -> Component:
    """コンテナのイメージ（DB・Redis と、ビルドの土台）が古いまま動いていないか（#18）

    公式のイメージはセキュリティ修正のたびに作り直されるので、作成日時が IMAGE_STALE_DAYS 日より古ければ、
    取り直していない（setup.sh を長く実行していない）とみなして注意を出す
    """
    key, label, days = "images", "コンテナのイメージ", settings.IMAGE_STALE_DAYS
    if not redis_ok:
        return Component(key, label, "unknown", "Redis に接続できないため確認できません")
    try:
        raw = await login_limit.client().get(IMAGES_KEY)
        report = json.loads(raw) if raw else {}
    except (RedisError, OSError, ValueError):
        return Component(key, label, "unknown", "Redis に接続できないため確認できません")
    if not report:
        return Component(key, label, "unknown", "記録がありません（setup.sh で更新すると表示します）")
    images = []
    for img in report.get("images") or []:
        at = _parse_at(img.get("created"))
        if at and at.tzinfo:  # 記録は UTC（タイムゾーン付き）。比べる now は UTC（タイムゾーンなし）
            at = at.astimezone(UTC).replace(tzinfo=None)
        images.append({**img, "age_days": (now - at).days if at else None})
    detail = {"reported_at": report.get("reported_at"), "images": images, "pull_failed": report.get("pull_failed") or [],
              "stale_days": days}
    if detail["pull_failed"]:
        return Component(key, label, "warn",
                         "イメージを取り直せませんでした（手元の古いイメージで動いています）: "
                         + "、".join(_short_image(n) for n in detail["pull_failed"]),
                         detail, items=[f"pull:{n}" for n in detail["pull_failed"]])
    old = [i for i in images if days > 0 and i["age_days"] is not None and i["age_days"] > days]
    if old:
        names = "、".join(f"{_short_image(i['name'])}（{i['age_days']} 日前）" for i in old)
        return Component(key, label, "warn",
                         f"{days} 日より前に作られたイメージのまま動いています: {names}。"
                         "setup.sh で更新すると取り直します", detail, items=[f"old:{i['name']}" for i in old])
    return Component(key, label, "ok", f"{len(images)} 個のイメージ。どれも {days} 日以内に作られたものです", detail)


async def check_vuln(db: AsyncSession, now: datetime) -> Component:
    """脆弱性情報の取得（services/vuln_service.py）。無効なら unknown（画面にも出さない）"""
    from app.models.vuln import VulnSource
    from app.services import vuln_service

    key, label = "vuln", "脆弱性情報の取得"
    if not settings.VULN_ENABLED:
        return Component(key, label, "unknown", "無効です（.env の VULN_ENABLED=true で有効）")
    names = vuln_service.active_sources()
    saved = {s.source: s for s in (await db.execute(select(VulnSource))).scalars()}
    srcs = [{"source": n, "label": vuln_service.SOURCE_LABELS[n], "last_ok_at": saved[n].last_ok_at.isoformat()
             if n in saved and saved[n].last_ok_at else None, "last_error": saved[n].last_error if n in saved else None}
            for n in names]
    oks = [s.last_ok_at for s in saved.values() if s.source in names and s.last_ok_at]
    detail = {"last_success": max(oks).isoformat() if oks else None, "sources": srcs,
              "failed": [s["label"] for s in srcs if s["last_error"]], "stale_days": vuln_service.STALE_DAYS}
    if not names:
        return Component(key, label, "unknown", "使う情報源がありません（VULN_SOURCES）", detail)
    if detail["failed"]:
        return Component(key, label, "warn", "取得に失敗している情報源があります: " + "、".join(detail["failed"]), detail)
    never = [s["label"] for s in srcs if not s["last_ok_at"]]
    if never and not oks:
        return Component(key, label, "ok", f"まだ取得していません（毎日 {settings.VULN_FETCH_HOUR} 時以降に取得します）", detail)
    old = [s["label"] for s in srcs if s["last_ok_at"] and now - datetime.fromisoformat(s["last_ok_at"])
           > timedelta(days=vuln_service.STALE_DAYS)]
    if old or never:
        return Component(key, label, "warn", f"{vuln_service.STALE_DAYS} 日以上取得できていない情報源があります: "
                         + "、".join(old + never), detail)
    return Component(key, label, "ok", "取得できています", detail)


async def check_git_export(redis_ok: bool = True) -> Component:
    key, label = "git_export", "外部 Git への push"
    if not git_export.enabled():
        return Component(key, label, "unknown", "設定していません（GIT_EXPORT_URL）")
    detail = {"url": git_export.mask_url(settings.GIT_EXPORT_URL.strip()), "branch": settings.GIT_EXPORT_BRANCH}
    if not redis_ok:
        return Component(key, label, "unknown", "Redis に接続できないため確認できません", detail)
    try:
        raw = await login_limit.client().get(git_export.STATE_KEY)
        state = json.loads(raw) if raw else {}
    except (RedisError, OSError, ValueError):
        return Component(key, label, "unknown", "Redis に接続できないため確認できません", detail)
    detail.update(last=state or None)
    if not state:
        return Component(key, label, "unknown",
                         "まだ push していません（収集でコンフィグが変わったとき、または 1 時間ごとに push します）", detail)
    if not state.get("ok"):
        return Component(key, label, "error", f"push に失敗しています: {state.get('error') or '原因不明'}", detail,
                         items=[(state.get("error") or "")[:80]])
    if git_export.url_has_credentials(settings.GIT_EXPORT_URL):
        # 動くが、.env を見られると漏れる。調査用ログ・.git/config には残らないが、設定の場所を移してもらう（#14）
        return Component(key, label, "warn",
                         "GIT_EXPORT_URL に認証情報が書かれています。GIT_EXPORT_USERNAME / GIT_EXPORT_TOKEN に移してください",
                         detail, items=["URL の認証情報"])
    return Component(key, label, "ok", state.get("message") or "push できています", detail)


async def check_mail(db: AsyncSession, redis_ok: bool = True) -> Component:
    """メール送信（通知設定 → メールサーバー）の最後の結果。有効にしていなければ unknown"""
    from app.services import mail  # notify → mail の循環を避ける

    key, label = "mail", "メール送信"
    cfg = await mail.load_config(db)
    if not cfg.enabled:
        return Component(key, label, "unknown", "使っていません（通知設定 → メールサーバー）")
    detail: dict = {"host": f"{cfg.host}:{cfg.port}", "auth": mail.AUTH_LABELS.get(cfg.auth, cfg.auth)}
    if problem := mail.check_config(cfg):
        return Component(key, label, "error", problem, detail, items=["config"])
    last = None
    if redis_ok:
        try:
            last = await mail.last_result()
        except (RedisError, OSError, ValueError):
            last = None
    detail["mail_last"] = last
    if not last:
        return Component(key, label, "ok", "設定済み（まだ送っていません）", detail)
    if not last.get("ok"):
        # 失敗が続いている間は同じ注意（items）なので、通知は最初の 1 回だけ。成功すると「復旧」を知らせる
        return Component(key, label, "error", f"最後の送信に失敗しました: {last.get('error')}", detail, items=["send"])
    return Component(key, label, "ok", "送信できています", detail)


async def record_outbound_check(result: dict) -> None:
    try:
        await login_limit.client().set(OUTBOUND_CHECK_KEY, json.dumps(result, ensure_ascii=False))
    except (RedisError, OSError):
        pass


async def check_outbound(now: datetime, redis_ok: bool = True) -> Component:
    """外部への接続の設定と、最後の「接続を確かめる」の結果。認証情報・プロキシの URL は出さない"""
    from app.core import outbound

    key, label = "outbound", "外部への接続"
    detail: dict = outbound.summary()
    warns: list[str] = []
    if detail["proxy_error"]:
        warns.append(detail["proxy_error"])
    try:
        ca = outbound.ca_info(now)
    except ValueError as e:  # ファイル名が不正（起動時に確かめているので、実行中に変えたときだけ）
        ca = {"file": settings.OUTBOUND_CA_FILE, "count": 0, "error": str(e)}
    detail["ca"] = ca
    if ca and ca.get("error"):
        warns.append(ca["error"])
    elif ca and ca["expired"]:
        warns.append("追加の CA 証明書の期限が切れています（OUTBOUND_CA_FILE を新しい証明書にしてください）")
    elif ca and ca["days_left"] <= outbound.CA_WARN_DAYS:
        warns.append(f"追加の CA 証明書の期限まであと {ca['days_left']} 日です")
    last = None
    if redis_ok:
        try:
            raw = await login_limit.client().get(OUTBOUND_CHECK_KEY)
            last = json.loads(raw) if raw else None
        except (RedisError, OSError, ValueError):
            last = None
    detail["last_check"] = last
    if last and last.get("result") != "ok":
        warns.append(f"最後の接続の確認に失敗しました: {last.get('message') or last.get('label')}")
    how = (f"プロキシ {detail['proxy']}（認証{'あり' if detail['proxy_auth'] else 'なし'}）を通して接続します"
           if detail["proxy"] else "プロキシを使わず直接接続します")
    if ca and not ca.get("error"):
        how += f"。追加の CA {ca['count']} 件"
    if warns:
        return Component(key, label, "warn", "。".join([how, *warns]), detail, items=warns)
    if not detail["proxy"] and not ca and not last:
        return Component(key, label, "unknown", how + "（プロキシ・追加の CA は設定していません）", detail)
    return Component(key, label, "ok", how, detail)


async def collect_status(db: AsyncSession, now: datetime | None = None) -> list[Component]:
    now = now or utcnow()
    database = await check_db(db)
    redis_c, heartbeat = await check_redis()
    worker = await check_worker(redis_c.status == "ok")
    out = [database, redis_c, worker, check_beat(heartbeat, worker, now)]
    if database.status == "ok":
        out += [await check_schedules(db), await check_collect(db, now), await check_mail(db, redis_c.status == "ok")]
    extra = [await check_vuln(db, now)] if database.status == "ok" and settings.VULN_ENABLED else []
    return [*out, check_disk(), await check_cert(now), await check_backup(now, redis_c.status == "ok"),
            await check_git_export(redis_c.status == "ok"), await check_images(now, redis_c.status == "ok"),
            await check_outbound(now, redis_c.status == "ok"), *extra]


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
