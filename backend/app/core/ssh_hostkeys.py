"""SSHホスト鍵の検証（Paramiko / Netmiko 共通）

- known_hosts は backend と worker で共有するボリュームに置く
- 鍵が登録済みで一致しない場合は Paramiko が BadHostKeyException を送出する（中間者攻撃対策）
- 未登録ホストは SSH_HOST_KEY_POLICY に従い、tofu なら記録して接続、strict なら拒否
"""
import fcntl
import logging
from pathlib import Path

import paramiko

from app.core.config import settings

logger = logging.getLogger(__name__)


class UnknownHostKeyError(paramiko.SSHException):
    pass


def _known_hosts_path() -> Path:
    return Path(settings.SSH_KNOWN_HOSTS)


def _append_known_host(hostname: str, key: paramiko.PKey) -> None:
    path = _known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = f"{hostname} {key.get_name()} {key.get_base64()}\n"
    # 複数ワーカーから同時に追記されても壊れないようにロックする
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            if line not in f.read():
                f.write(line)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


class HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """known_hosts に存在しないホストの扱い"""

    def missing_host_key(self, client, hostname, key):
        fingerprint = key.fingerprint if hasattr(key, "fingerprint") else key.get_base64()[:16]
        if settings.SSH_HOST_KEY_POLICY == "strict":
            raise UnknownHostKeyError(
                f"未登録のホスト鍵です ({hostname} {key.get_name()} {fingerprint})。"
                f"{settings.SSH_KNOWN_HOSTS} に登録してください。"
            )
        logger.warning("新しいホスト鍵を登録しました: %s %s %s", hostname, key.get_name(), fingerprint)
        _append_known_host(hostname, key)
        client.get_host_keys().add(hostname, key.get_name(), key)


def load_known_hosts(client: paramiko.SSHClient) -> None:
    path = _known_hosts_path()
    if path.is_file():
        client.load_host_keys(str(path))
    client.set_missing_host_key_policy(HostKeyPolicy())


def describe_ssh_error(e: Exception) -> str:
    """利用者向けに内部情報を出しすぎないエラーメッセージを返す"""
    if isinstance(e, paramiko.BadHostKeyException):
        return "ホスト鍵が登録済みのものと一致しません（機器の入れ替え、または中間者攻撃の可能性）"
    if isinstance(e, UnknownHostKeyError):
        return str(e)
    if isinstance(e, paramiko.AuthenticationException):
        return "認証に失敗しました"
    if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
        return "接続がタイムアウトしました"
    if isinstance(e, (OSError, paramiko.SSHException)):
        return f"接続できませんでした ({type(e).__name__})"
    return "接続に失敗しました"
