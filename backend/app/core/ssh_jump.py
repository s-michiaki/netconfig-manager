"""踏み台サーバ経由のSSH接続（1段）

1. Paramiko で踏み台にSSH接続する（パスワード・秘密鍵のどちらか、または両方で認証）
2. 踏み台上で機器宛ての direct-tcpip チャネル（OpenSSH の ProxyJump / -J と同じ仕組み）を開く
3. そのチャネルを Netmiko / Paramiko の sock として渡し、機器へは通常どおりSSH接続する

踏み台自身のホスト鍵も known_hosts で検証する（ssh_hostkeys.py）。
"""
import io
from dataclasses import dataclass

import paramiko

from app.core.config import settings
from app.core.ssh_hostkeys import describe_ssh_error, load_known_hosts

MAX_PRIVATE_KEY_LENGTH = 16 * 1024

_KEY_CLASSES: list[type[paramiko.PKey]] = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
if hasattr(paramiko, "DSSKey"):  # Paramiko 4 で削除予定
    _KEY_CLASSES.append(paramiko.DSSKey)


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


class PrivateKeyError(ValueError):
    pass


def normalize_private_key(text: str) -> str:
    return text.replace("\r\n", "\n").strip() + "\n"


def load_private_key(text: str, passphrase: str | None = None) -> paramiko.PKey:
    """OpenSSH / PEM 形式の秘密鍵文字列を読み込む（RSA / ECDSA / Ed25519）"""
    text = normalize_private_key(text)
    if "PuTTY-User-Key-File" in text:
        raise PrivateKeyError("PuTTY形式(.ppk)の鍵は使えません。PuTTYgen で OpenSSH 形式に変換してください")
    if "PRIVATE KEY" not in text:
        raise PrivateKeyError("秘密鍵の形式を認識できません（-----BEGIN ... PRIVATE KEY----- で始まる鍵を貼り付けてください）")

    needs_passphrase = False
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except (paramiko.SSHException, ValueError, TypeError, IndexError):
            continue
    if needs_passphrase and not passphrase:
        raise PrivateKeyError("この秘密鍵はパスフレーズで保護されています。パスフレーズを入力してください")
    raise PrivateKeyError("秘密鍵を読み込めませんでした（形式が不正、またはパスフレーズが違います）")


def key_summary(pkey: paramiko.PKey) -> str:
    """画面表示用（例: ssh-ed25519 SHA256:xxxx）"""
    return f"{pkey.get_name()} {pkey.fingerprint}" if hasattr(pkey, "fingerprint") else pkey.get_name()


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
