"""DBから接続情報（踏み台を含む）を読み出す共通処理（worker / terminal で共用）"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.ssh_jump import JumpHostInfo
from app.models.device import Device, JumpHost
from app.services.config_service import DeviceConnectionInfo


def jump_info(j: JumpHost) -> JumpHostInfo:
    return JumpHostInfo(
        name=j.name,
        hostname=j.hostname,
        port=j.port,
        username=j.username,
        password=j.password,
        private_key=j.private_key,
        key_passphrase=j.key_passphrase,
    )


async def load_connection_info(db: AsyncSession, device_id: str) -> DeviceConnectionInfo | None:
    result = await db.execute(
        select(Device).options(selectinload(Device.jump_host)).where(Device.id == device_id)
    )
    d = result.scalar_one_or_none()
    if d is None:
        return None
    return DeviceConnectionInfo(
        id=d.id,
        name=d.name,
        hostname=d.hostname,
        platform=d.platform,
        port=d.port,
        username=d.username,
        password=d.password,
        enable_secret=d.enable_secret,
        jump=jump_info(d.jump_host) if d.jump_host else None,
    )
