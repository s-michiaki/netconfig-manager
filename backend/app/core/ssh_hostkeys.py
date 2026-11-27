"""SSHホスト鍵の検証（Paramiko / Netmiko 共通）

- known_hosts は backend と worker で共有するボリュームに置く
- 鍵が登録済みで一致しない場合は BadHostKeyException（中間者攻撃対策）
- 未登録ホストは SSH_HOST_KEY_POLICY に従い、tofu なら記録して接続、strict なら拒否
- 踏み台経由の機器は、踏み台ごとに別の名前（`jump-<踏み台の ID>/[host]:port`）で記録する。
  拠点ごとに別の踏み台の先に同じ `10.0.0.1:22` があっても、互いの鍵と比べて「一致しない」にならない。
  この版より前の記録（踏み台の区別なし。`[host]:port`）しか無い機器は、その記録と比べ、一致して接続できたら踏み台ごとの
  名前でも記録する（引き継ぎ）。一致しなければ今までどおり拒否する（strict でも、引き継ぎで「未登録」にはならない）
- TOFU で新しく登録したら、指紋などを take_events() で取り出せる形でためる（呼び出し側がアクティビティ・監査ログに残す）
"""
import base64
import fcntl
import hashlib
import logging
import threading
from pathlib import Path

import paramiko

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_PENDING_EVENTS = 1000  # 取り出されないままの記録の上限（取り出す処理が無い経路でも増え続けないように）


class UnknownHostKeyError(paramiko.SSHException):
    pass


def _known_hosts_path() -> Path:
    return Path(settings.SSH_KNOWN_HOSTS)


def host_key_name(host: str, port: int) -> str:
    """Paramiko が known_hosts を引くときの名前（22 番なら host、それ以外は [host]:port）"""
    return host if port == 22 else f"[{host}]:{port}"


def scoped_name(jump_id: str, name: str) -> str:
    """踏み台経由の機器の記録の名前"""
    return f"jump-{jump_id}/{name}"


def fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH と同じ形の指紋（SHA256:...）"""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


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


def _stored_keys() -> paramiko.HostKeys:
    path = _known_hosts_path()
    return paramiko.HostKeys(str(path)) if path.is_file() else paramiko.HostKeys()


# ---------------------------------------------------------------- TOFU の記録

_events: list[dict] = []
_events_mu = threading.Lock()


def _push_event(event: dict) -> None:
    with _events_mu:
        if len(_events) < MAX_PENDING_EVENTS:
            _events.append(event)


def take_events(match=None) -> list[dict]:
    """TOFU で新しく登録した鍵の記録を取り出す（取り出したものは消える）。秘密の値は含まない。

    match: 取り出す記録を選ぶ関数（API のプロセスで、同時に動くほかの接続の記録を取らないように）。None ならすべて
    """
    with _events_mu:
        out = [e for e in _events if match is None or match(e)]
        _events[:] = [e for e in _events if not (match is None or match(e))]
    return out


class HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """known_hosts の検証の設定と、存在しないホストの扱い

    jump_id: 踏み台経由の機器のとき、その踏み台の ID。prepare() でクライアントへ「比べる鍵」（踏み台ごとの記録。無ければ
    以前の版の記録）だけを入れ、比べるのは Paramiko 本体に任せる（鍵の種類の選び方・不一致の判定は今までどおり）。
    以前の記録で接続できたときは after_connect() で踏み台ごとの名前でも記録する（引き継ぎ。比べて一致した鍵だけ）
    context: TOFU の記録に添える情報（機器の ID・名前、踏み台の名前など。秘密の値は入れない）
    """

    def __init__(self, jump_id: str | None = None, context: dict | None = None):
        self.jump_id = jump_id
        self.context = dict(context or {})
        self._migrate_to: str | None = None

    def prepare(self, client: paramiko.SSHClient, host: str, port: int) -> None:
        if not self.jump_id:
            path = _known_hosts_path()
            if path.is_file():
                client.load_host_keys(str(path))
            return
        name = host_key_name(host, port)
        scoped = scoped_name(self.jump_id, name)
        stored = _stored_keys()
        known = stored.lookup(scoped)
        if known is None:
            known = stored.lookup(name)  # 以前の版の記録（踏み台の区別なし）
            self._migrate_to = scoped if known is not None else None
        for key_type in (known.keys() if known is not None else ()):
            client.get_host_keys().add(name, key_type, known[key_type])

    def after_connect(self, client: paramiko.SSHClient) -> None:
        """接続（ホスト鍵の照合）が済んだあとに呼ぶ。以前の記録で照合できた鍵を、踏み台ごとの名前でも記録する"""
        if self._migrate_to is None:
            return
        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport is not None else None
        if key is not None:
            _append_known_host(self._migrate_to, key)
            logger.info("ホスト鍵の記録を踏み台ごとの名前へ引き継ぎました: %s", self._migrate_to)
        self._migrate_to = None

    def missing_host_key(self, client, hostname, key):
        record_as = scoped_name(self.jump_id, hostname) if self.jump_id else hostname
        fp = fingerprint(key)
        if settings.SSH_HOST_KEY_POLICY == "strict":
            raise UnknownHostKeyError(
                f"未登録のホスト鍵です ({record_as} {key.get_name()} {fp})。"
                f"{settings.SSH_KNOWN_HOSTS} に登録してください。"
            )
        logger.warning("新しいホスト鍵を登録しました: %s %s %s", record_as, key.get_name(), fp)
        _append_known_host(record_as, key)
        client.get_host_keys().add(hostname, key.get_name(), key)
        _push_event({**self.context, "host": hostname, "recorded_as": record_as, "key_type": key.get_name(),
                     "fingerprint": fp})


def load_known_hosts(client: paramiko.SSHClient, jump_id: str | None = None, host: str | None = None, port: int = 22,
                     context: dict | None = None) -> HostKeyPolicy:
    """クライアントにホスト鍵の検証を設定する。踏み台経由の機器は jump_id と機器の host・port を渡し、
    接続のあとに戻り値の after_connect(client) を呼ぶ"""
    policy = HostKeyPolicy(jump_id if host else None, context)
    policy.prepare(client, host or "", port)
    client.set_missing_host_key_policy(policy)
    return policy


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
