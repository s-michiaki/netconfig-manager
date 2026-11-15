"""DBから接続情報（踏み台を含む）を読み出す共通処理（worker / terminal で共用）

機器の認証情報（ユーザー名・パスワード・enable・SSH 鍵）は effective_credentials で決める。
認証情報プロファイルを選んだ機器はプロファイルの値を、選んでいない機器は機器側の値をそのまま使う。
収集・FW ヒット数（worker）とターミナルはどれも load_connection_info を通るので、ここだけで切り替わる。
画面に出す「パスワードあり」などの表示（api/devices.py）も同じ関数を使い、実際の接続と食い違わないようにする
"""
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.ssh_jump import JumpHostInfo
from app.models.device import CredentialProfile, Device, JumpHost
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


@dataclass(frozen=True)
class Credentials:
    username: str | None
    password: str | None
    enable_secret: str | None
    private_key: str | None
    key_passphrase: str | None


def effective_credentials(d: Device, profile: CredentialProfile | None) -> Credentials:
    """接続に使う認証情報。profile は d.credential_profile_id のプロファイル（呼び出し側で読んでおく）

    プロファイルを選んだ機器は、機器側の値を一切使わない（項目ごとの上書きはしない。どの値で接続するかを明確にするため）
    """
    src = profile if d.credential_profile_id else d
    if d.credential_profile_id and profile is None:
        # 通常は外部キーで起こらない。念のため機器側の値にも戻さない（古い値で接続しない）
        return Credentials(None, None, None, None, None)
    return Credentials(
        username=src.username,
        password=src.password,
        enable_secret=src.enable_secret,
        private_key=src.private_key,
        key_passphrase=src.key_passphrase,
    )


async def load_connection_info(db: AsyncSession, device_id: str) -> DeviceConnectionInfo | None:
    result = await db.execute(
        select(Device)
        .options(selectinload(Device.jump_host), selectinload(Device.credential_profile))
        .where(Device.id == device_id)
    )
    d = result.scalar_one_or_none()
    if d is None:
        return None
    cred = effective_credentials(d, d.credential_profile)
    return DeviceConnectionInfo(
        id=d.id,
        name=d.name,
        hostname=d.hostname,
        platform=d.platform,
        port=d.port,
        username=cred.username or "",
        password=cred.password,
        enable_secret=cred.enable_secret,
        jump=jump_info(d.jump_host) if d.jump_host else None,
        private_key=cred.private_key,
        key_passphrase=cred.key_passphrase,
        read_timeout=d.read_timeout,
    )
