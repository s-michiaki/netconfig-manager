import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text

from app.api import (
    audit,
    auth,
    compliance,
    configs,
    device_groups,
    devices,
    jump_hosts,
    ping,
    schedules,
    tasks,
    terminal,
    topology,
    users,
)
from app.api.deps import get_current_user, require
from app.core.config import settings
from app.core.crypto import encrypt, is_encrypted
from app.core.database import AsyncSessionLocal, engine
from app.core.migrate import run_migrations
from app.core.permissions import Perm
from app.models import Device
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


async def _migrate_legacy_repos() -> None:
    async with AsyncSessionLocal() as db:
        for device_id, name in (await db.execute(select(Device.id, Device.name))).all():
            try:
                migrate_legacy_repo(device_id, name)
            except OSError as e:
                logger.error("Gitリポジトリの移行に失敗しました (%s): %s", name, e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # DBスキーマを最新化（Alembic）。Alembic 導入前のDBも自動で引き継ぐ
    await asyncio.to_thread(run_migrations)
    await _encrypt_legacy_passwords()
    await _migrate_legacy_repos()
    async with AsyncSessionLocal() as db:
        await auth.ensure_initial_admin(db)
    yield
    await engine.dispose()


app = FastAPI(
    title="NetConfig Manager API",
    description="ネットワーク機器のコンフィグ収集・世代管理システム",
    version="1.7.0",
    lifespan=lifespan,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,  # 認証は Authorization ヘッダーで行うため Cookie は不要
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

# ルーター全体でログインを必須にし、各エンドポイントで require(Perm.xxx) により権限を確認する
protected = [Depends(get_current_user)]

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"], dependencies=protected)
app.include_router(
    device_groups.router, prefix="/api/device-groups", tags=["device-groups"], dependencies=protected
)
app.include_router(jump_hosts.router, prefix="/api/jump-hosts", tags=["jump-hosts"], dependencies=protected)
app.include_router(configs.router, prefix="/api/configs", tags=["configs"], dependencies=protected)
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"], dependencies=protected)
app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"], dependencies=protected)
app.include_router(topology.router, prefix="/api/topology", tags=["topology"], dependencies=protected)
app.include_router(compliance.router, prefix="/api/compliance", tags=["compliance"], dependencies=protected)
app.include_router(audit.router, prefix="/api/audit", tags=["audit"], dependencies=protected)
app.include_router(ping.router, prefix="/api/ping", tags=["ping"], dependencies=protected)
app.include_router(users.router, prefix="/api/users", tags=["users"], dependencies=[Depends(require(Perm.USER_ADMIN))])
# WebSocket は接続後の最初のメッセージでトークンを検証する（terminal.py 参照）
app.include_router(terminal.router, prefix="/api/terminal", tags=["terminal"])
app.include_router(ping.ws_router, prefix="/api/ping", tags=["ping"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
