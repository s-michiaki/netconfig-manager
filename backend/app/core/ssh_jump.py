"""踏み台サーバ経由のSSH接続（1段）

1. Paramiko で踏み台にSSH接続する（パスワード・秘密鍵のどちらか、または両方で認証）
2. 踏み台上で機器宛ての direct-tcpip チャネル（OpenSSH の ProxyJump / -J と同じ仕組み）を開く
3. そのチャネルを Netmiko / Paramiko の sock として渡し、機器へは通常どおりSSH接続する

踏み台自身のホスト鍵も known_hosts で検証する（ssh_hostkeys.py）。
"""
from dataclasses import dataclass

import paramiko

from app.core.config import settings
from app.core.ssh_hostkeys import describe_ssh_error, load_known_hosts
from app.core.ssh_keys import (  # noqa: F401 - 既存の import 元との互換のため再エクスポート
    MAX_PRIVATE_KEY_LENGTH,
    PrivateKeyError,
    key_summary,
    load_private_key,
    normalize_private_key,
)

@dataclass
class JumpHostInfo:
    name: str
    hostname: str
    port: int
    username: str
    password: str | None
    private_key: str | None
    key_passphrase: str | None


class JumpHostError(Exception):
    """踏み台に関するエラー。メッセージはそのまま利用者に表示してよい内容にする"""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def connect_jump(jump: JumpHostInfo) -> paramiko.SSHClient:
    """踏み台へ接続した SSHClient を返す（呼び出し側で close すること）"""
    try:
        pkey = load_private_key(jump.private_key, jump.key_passphrase) if jump.private_key else None
    except PrivateKeyError as e:
        raise JumpHostError(f"踏み台サーバ「{jump.name}」: {e}") from e

    client = paramiko.SSHClient()
    load_known_hosts(client)
    try:
        # 鍵とパスワードの両方がある場合、Paramiko は鍵 → パスワードの順に試す
        client.connect(
            hostname=jump.hostname,
            port=jump.port,
            username=jump.username,
            password=jump.password or None,
            pkey=pkey,
            timeout=settings.SSH_TIMEOUT,
            auth_timeout=settings.SSH_AUTH_TIMEOUT,
            banner_timeout=settings.SSH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:  # noqa: BLE001
        client.close()
        retryable = not isinstance(e, (paramiko.AuthenticationException, paramiko.BadHostKeyException))
        raise JumpHostError(f"踏み台サーバ「{jump.name}」: {describe_ssh_error(e)}", retryable) from e

    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(30)  # ターミナルを長時間開いていても踏み台側で切られにくくする
    return client


def open_tunnel(client: paramiko.SSHClient, jump_name: str, dest_host: str, dest_port: int) -> paramiko.Channel:
    """踏み台から機器への direct-tcpip チャネルを開く"""
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise JumpHostError(f"踏み台サーバ「{jump_name}」との接続が切れています", retryable=True)
    try:
        return transport.open_channel(
            "direct-tcpip", (dest_host, dest_port), ("127.0.0.1", 0), timeout=settings.SSH_TIMEOUT
        )
    except paramiko.ChannelException as e:
        reason = {
            1: "踏み台側でポートフォワーディングが禁止されています（sshd の AllowTcpForwarding を確認）",
            2: "踏み台から機器に接続できませんでした",
        }.get(e.code, e.text)
        raise JumpHostError(
            f"踏み台サーバ「{jump_name}」経由で {dest_host}:{dest_port} に接続できません: {reason}",
            retryable=e.code != 1,
        ) from e
    except Exception as e:  # noqa: BLE001
        raise JumpHostError(
            f"踏み台サーバ「{jump_name}」経由で {dest_host}:{dest_port} に接続できません: {describe_ssh_error(e)}",
            retryable=True,
        ) from e


def test_jump_host(jump: JumpHostInfo, dest_host: str | None = None, dest_port: int = 22) -> str:
    """接続テスト。成功時は説明文を返し、失敗時は JumpHostError を送出する"""
    client = connect_jump(jump)
    try:
        if dest_host:
            open_tunnel(client, jump.name, dest_host, dest_port).close()
            return f"踏み台「{jump.name}」経由で {dest_host}:{dest_port} に到達できました"
        return f"踏み台「{jump.name}」に接続・認証できました"
    finally:
        client.close()
