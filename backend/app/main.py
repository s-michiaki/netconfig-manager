import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text

from app.api import (
    activity,
    api_tokens,
    audit,
    auth,
    commands,
    compliance,
    config_baselines,
    config_comments,
    config_reviews,
    configs,
    credential_profiles,
    dashboard,
    device_groups,
    devices,
    ignore_rules,
    jump_hosts,
    mail,
    monitoring,
    notifications,
    ping,
    schedules,
    system,
    tasks,
    terminal,
    topology,
    users,
    vulns,
)
from app.api.deps import get_current_user, require, require_session
from app.core import outbound
from app.core.api_docs import install_api_docs
from app.core.config import settings
from app.core.crypto import encrypt, is_encrypted
from app.core.database import AsyncSessionLocal, engine
from app.core.migrate import run_migrations
from app.core.permissions import Perm
from app.models import Device
from app.services import idle
from app.services import system as system_service
from app.services.config_service import migrate_legacy_repo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def _encrypt_legacy_passwords() -> None:
    """旧バージョンで平文保存された機器パスワードを暗号化する（一度きりの移行）"""
    async with engine.begin() as conn:
        rows = (await conn.execute(text("SELECT id, password, enable_secret FROM devices"))).all()
        migrated = 0
        for device_id, password, enable_secret in rows:
            updates = {}
            if password and not is_encrypted(password):
                updates["password"] = encrypt(password)
            if enable_secret and not is_encrypted(enable_secret):
                updates["enable_secret"] = encrypt(enable_secret)
            if updates:
                sets = ", ".join(f"{k} = :{k}" for k in updates)
                await conn.execute(text(f"UPDATE devices SET {sets} WHERE id = :id"), {**updates, "id": device_id})
                migrated += 1
        if migrated:
            logger.warning("平文で保存されていた %d 台分の機器パスワードを暗号化しました", migrated)


LEGACY_DIFF_BATCH = 200  # 平文の差分を暗号化するときに 1 回に読む・書く行数


async def _encrypt_legacy_startup_diffs() -> None:
    """0041 より前に平文で保存された startup の差分（devices.startup_diff）を暗号化する。

    暗号化済み（enc: で始まる）の行は読まないので二重に暗号化しない（何度呼んでも同じ）。行数が多くても、平文の行だけを
    LEGACY_DIFF_BATCH 行ずつまとめて書き直す。失敗しても起動は止めない（ログに残し、次の起動・次の収集で暗号化される）
    """
    migrated = 0
    try:
        while True:
            async with engine.begin() as conn:
                rows = (await conn.execute(text(
                    "SELECT id, startup_diff FROM devices WHERE startup_diff IS NOT NULL AND startup_diff NOT LIKE 'enc:%' "
                    "ORDER BY id LIMIT :n"), {"n": LEGACY_DIFF_BATCH})).all()
                if not rows:
                    break
                await conn.execute(text("UPDATE devices SET startup_diff = :diff WHERE id = :id AND startup_diff = :old"),
                                   [{"id": i, "diff": encrypt(d), "old": d} for i, d in rows if not is_encrypted(d)])
                migrated += len(rows)
            if len(rows) < LEGACY_DIFF_BATCH:
                break
    except Exception:  # noqa: BLE001 - 起動は止めない（差分は付加情報。次の収集でも暗号化される）
        logger.exception("平文の startup の差分を暗号化できませんでした（%d 台は済み）", migrated)
        return
    if migrated:
        logger.warning("平文で保存されていた %d 台分の startup の差分を暗号化しました", migrated)


async def _migrate_legacy_repos() -> None:
    async with AsyncSessionLocal() as db:
        for device_id, name in (await db.execute(select(Device.id, Device.name))).all():
            try:
                migrate_legacy_repo(device_id, name)
            except OSError as e:
                logger.error("Gitリポジトリの移行に失敗しました (%s): %s", name, e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 外部への接続の設定（プロキシはホスト:ポートと認証の有無だけ）。廃止した VULN_HTTPS_PROXY が残っていれば知らせる
    outbound.startup_log(logger)
    # 無操作でのログアウトの時間が、ログインの期限以上なら知らせる
    idle.startup_log(logger)
    # DBスキーマを最新化（Alembic）。Alembic 導入前のDBも自動で引き継ぐ
    await asyncio.to_thread(run_migrations)
    await _encrypt_legacy_passwords()
    await _encrypt_legacy_startup_diffs()
    await _migrate_legacy_repos()
    async with AsyncSessionLocal() as db:
        await auth.ensure_initial_admin(db)
    # worker・スケジューラーの停止などを検出して通知する（API のプロセスで動かす）
    watchdog = asyncio.create_task(system_service.watchdog_loop()) if settings.SYSTEM_WATCHDOG_ENABLED else None
    yield
    if watchdog:
        watchdog.cancel()
    await engine.dispose()


app = FastAPI(
    title="NetConfig Manager API",
    description="ネットワーク機器のコンフィグ収集・世代管理システム",
    version="1.69.0",
    lifespan=lifespan,
    # Swagger UI・ReDoc（CDN のスクリプトを読む）は使わない。API の一覧は DOCS_ENABLED のときだけ、外部のスクリプトを
    # 使わない /docs と /openapi.json を出す（下の install_api_docs）。本番では python -m app.tools.api_list で見る
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,  # 認証は Authorization ヘッダーで行うため Cookie は不要
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

# ルーター全体でログインを必須にし、各エンドポイントで require(Perm.xxx) により権限を確認する。
# API トークン（ncm_…）で呼べるのは app/api/token_policy.py の一覧にあるものだけ（get_current_user で判定）
protected = [Depends(get_current_user)]
# ログインのセッションでだけ使えるもの（API トークンでは 403）。一覧で既に不可だが、念のため重ねる
session_only = [Depends(require_session)]

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(api_tokens.router, prefix="/api/auth/tokens", tags=["auth"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"], dependencies=protected)
app.include_router(
    device_groups.router, prefix="/api/device-groups", tags=["device-groups"], dependencies=protected
)
app.include_router(jump_hosts.router, prefix="/api/jump-hosts", tags=["jump-hosts"], dependencies=protected)
app.include_router(
    credential_profiles.router, prefix="/api/credential-profiles", tags=["credential-profiles"], dependencies=protected
)
app.include_router(configs.router, prefix="/api/configs", tags=["configs"], dependencies=protected)
app.include_router(config_comments.router, prefix="/api/configs", tags=["configs"], dependencies=protected)
app.include_router(config_baselines.router, prefix="/api/configs", tags=["configs"], dependencies=protected)
app.include_router(config_reviews.router, prefix="/api/configs", tags=["configs"], dependencies=protected)
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"], dependencies=protected)
app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"], dependencies=protected)
app.include_router(topology.router, prefix="/api/topology", tags=["topology"], dependencies=protected)
app.include_router(commands.router, prefix="/api/commands", tags=["commands"], dependencies=protected)
app.include_router(compliance.router, prefix="/api/compliance", tags=["compliance"], dependencies=protected)
app.include_router(ignore_rules.router, prefix="/api/ignore-rules", tags=["ignore-rules"], dependencies=protected)
app.include_router(audit.router, prefix="/api/audit", tags=["audit"], dependencies=protected)
app.include_router(activity.router, prefix="/api/activity", tags=["activity"], dependencies=protected)
app.include_router(ping.router, prefix="/api/ping", tags=["ping"], dependencies=protected)
app.include_router(system.router, prefix="/api/system", tags=["system"], dependencies=protected)
app.include_router(mail.router, prefix="/api/mail", tags=["mail"], dependencies=protected + session_only)
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"], dependencies=protected)
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["monitoring"], dependencies=protected)
app.include_router(vulns.router, prefix="/api/vulns", tags=["vulns"], dependencies=protected)
app.include_router(
    notifications.router, prefix="/api/notifications", tags=["notifications"], dependencies=protected
)
app.include_router(
    users.router, prefix="/api/users", tags=["users"], dependencies=[Depends(require(Perm.USER_ADMIN)), *session_only]
)
# WebSocket は接続後の最初のメッセージでトークンを検証する（terminal.py 参照）
app.include_router(terminal.router, prefix="/api/terminal", tags=["terminal"])
app.include_router(ping.ws_router, prefix="/api/ping", tags=["ping"])
# API の一覧（/docs）と OpenAPI のスキーマ（/openapi.json）は、開発用に DOCS_ENABLED のときだけ（app/core/api_docs.py）
if settings.DOCS_ENABLED:
    install_api_docs(app)


@app.get("/api/health")
async def health():
    # 画面のサイドバーに表示するバージョンもここから取る（version は上の FastAPI(...) の1か所で管理）
    return {"status": "ok", "version": app.version,
            # 試験導入中の機能（画面のメニューの表示に使う）
            "features": {"monitoring": settings.MONITORING_ENABLED, "vuln": settings.VULN_ENABLED}}
