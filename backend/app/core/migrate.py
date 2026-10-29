"""起動時のDBマイグレーション（Alembic）

- Alembic 導入前（create_all）に作られたDBは、初期リビジョンとして stamp してから最新化する
- 空のDBは最初から作成する

手動で実行する場合: python -m app.core.migrate
"""
import asyncio
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parents[2]
LEGACY_BASE_REVISION = "0001_initial"


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return cfg


async def _table_names() -> list[str]:
    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())
    finally:
        await engine.dispose()


def run_migrations() -> None:
    """同期関数。イベントループ内からは asyncio.to_thread で呼ぶこと"""
    cfg = _alembic_config()
    tables = asyncio.run(_table_names())
    if "alembic_version" not in tables and "devices" in tables:
        logger.warning("Alembic 導入前のDBを検出したため、%s として登録してから最新化します", LEGACY_BASE_REVISION)
        command.stamp(cfg, LEGACY_BASE_REVISION)
    command.upgrade(cfg, "head")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_migrations()
