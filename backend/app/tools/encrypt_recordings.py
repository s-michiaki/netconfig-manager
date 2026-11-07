"""既存の平文のターミナル記録（.cast）を暗号化する

v1.23.0 より前の記録は平文で保存されている。保持期間（TERMINAL_LOG_RETENTION_DAYS）が過ぎれば
自動で消えるが、すぐに暗号化したい場合に実行する:

    podman exec <backend コンテナ> python -m app.tools.encrypt_recordings
"""
import asyncio

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.audit import TerminalSession
from app.services.audit import encrypt_existing_recordings


async def main() -> None:
    moved = encrypt_existing_recordings()
    async with AsyncSessionLocal() as db:
        by_old = dict(moved)
        rows = (await db.execute(select(TerminalSession).where(TerminalSession.log_file.in_(list(by_old))))).scalars()
        for s in rows:
            s.log_file = by_old[s.log_file]
        await db.commit()
    print(f"{len(moved)} 件の記録を暗号化しました")


if __name__ == "__main__":
    asyncio.run(main())
