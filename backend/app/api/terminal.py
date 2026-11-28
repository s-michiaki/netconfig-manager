"""
WebSocket SSHターミナル
- フロントエンドのxterm.jsと双方向通信
- Paramikoでインタラクティブシェルを確立

プロトコル:
  クライアント -> サーバー : すべてJSON
    {"type": "auth", "token": "<JWT>", "cols": 120, "rows": 40}   … 接続直後に1回（10秒以内）
    {"type": "input", "data": "show version\r"}
    {"type": "resize", "cols": 120, "rows": 40}
  サーバー -> クライアント : 端末に表示するテキスト（そのまま xterm に write する）

監査: 接続・切断を操作履歴に残し、画面出力を asciicast v2 形式で記録する（app/services/audit.py）

認証の照合は接続の最初（と SSH の接続後にもう一度）だけ行う。接続中に管理者が強制ログアウト・無効化・
パスワードのリセット・削除をしたときは、close_user_sessions でそのユーザーのターミナルを切る（API が 1 プロセスのとき）。
無操作の時間（IDLE_TIMEOUT_MIN。services/idle.py）は、接続中も idle.watch_ws が定期的に確かめ、過ぎたら切る
（close の reason は "idle_timeout"。記録の終了理由は「無操作による切断」）
"""
import asyncio
import codecs
import json
import logging
import threading
import uuid
from dataclasses import dataclass

import paramiko
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.deps import authenticate_ws
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.permissions import Perm, has_permission
from app.core.ssh_hostkeys import describe_ssh_error, load_known_hosts
from app.core.ssh_hostkeys import take_events as take_hostkey_events
from app.core.ssh_jump import JumpHostError, connect_jump, open_tunnel
from app.core.ssh_keys import PrivateKeyError, load_private_key
from app.core.timeutil import utcnow
from app.models.audit import TerminalSession
from app.models.user import User
from app.services import idle, sessions
from app.services.audit import TerminalRecorder, make_log
from app.services.config_service import DeviceConnectionInfo
from app.services.connection import load_connection_info
from app.services.hostkeys import record_events as record_hostkey_events

logger = logging.getLogger(__name__)
router = APIRouter()

AUTH_TIMEOUT_SEC = 10
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403
WS_CLOSE_NOT_FOUND = 4404
# 本人の操作（パスワード変更・2 段階認証の設定と解除）で、その操作に使ったトークンで開いた接続を切るときのコード。
# 画面には新しいトークンを返しているので、画面側はログイン画面へ移らずに（トークンを消さずに）つなぎ直せる
WS_CLOSE_TOKEN_REFRESHED = 4409
MIN_SIZE, MAX_SIZE = 1, 1000

# 切断後の後片付けタスク（途中で破棄されないよう参照を保持する）
_cleanup_tasks: set[asyncio.Task] = set()


@dataclass(eq=False)
class _LiveTerminal:
    websocket: WebSocket
    revoked: str | None = None  # 管理者の操作・パスワードの変更などで切ったときの理由（記録の終了理由に使う）
    kind: str = "terminal"  # terminal / ping（Ping 監視の WebSocket も同じ表で切る。api/ping.py）
    token_key: str | None = None  # 接続に使ったログインのトークン（sessions.token_key）。本人のログアウトでその接続だけ切る


# 接続中のターミナル・Ping 監視（ユーザー ID ごと）。管理者が強制ログアウト・無効化・パスワードのリセット・削除・
# ターミナルの権限が無いロールへの変更をしたとき、本人がパスワードの変更・2 段階認証の設定と解除・ログアウトをしたときに切るため。
# プロセス内の記録なので、API を 1 プロセスで動かしている場合（既定の構成）だけ有効。
# 複数のプロセス（uvicorn --workers など）にすると、ほかのプロセスが受け持つ接続は切れない
_live: dict[str, set[_LiveTerminal]] = {}
ALL_KINDS = ("terminal", "ping")
# 本人の操作で切ったときの理由（記録の終了理由は「本人の○○で切断」。ほかは「管理者が切断（○○）」）
SELF_REASONS = {"パスワードの変更": "パスワード変更", "2 段階認証の設定": "2 段階認証の設定",
                "2 段階認証の解除": "2 段階認証の解除", "ログアウト": "ログアウト",
                "すべての端末からのログアウト": "すべての端末からのログアウト"}
# 無操作の時間を過ぎたので切ったときの理由（services/idle.py。記録の終了理由は IDLE_END_REASON）
IDLE_END_REASON = "無操作による切断"


async def close_user_sessions(user_id: str, reason: str, kinds: tuple[str, ...] = ALL_KINDS,
                              token_key: str | None = None, refreshed_key: str | None = None,
                              exclude_key: str | None = None) -> int:
    """そのユーザーの接続中のターミナル（と Ping 監視）を切る。切ったターミナルの数を返す

    SSH の切断と記録は各接続の後片付けで行う。

    kinds: 切る種類（ロールの変更でターミナルの権限が無くなったときは terminal だけ）
    token_key: 指定すると、そのトークンで開いた接続だけ（本人のログアウト）
    refreshed_key: このトークンで開いた接続は WS_CLOSE_TOKEN_REFRESHED で切る（本人の操作で新しいトークンを返したとき。
                   ほかのトークンで開いたもの＝ほかの端末は今までどおり 4401）
    exclude_key: このトークンで開いた接続は切らない（本人の操作で、ほかの端末の分だけを応答の前に切るとき）
    """
    targets = [t for t in _live.get(user_id, ()) if t.kind in kinds and (token_key is None or t.token_key == token_key)
               and (exclude_key is None or t.token_key != exclude_key)]
    is_idle = reason == idle.CLOSE_REASON
    for t in targets:
        if is_idle and t.revoked is not None:
            continue  # 切断済み（無操作の確認が重なったときなど）
        t.revoked = reason
        try:
            if t.kind == "terminal":
                msg = "操作が無い時間が続いたため" if is_idle else f"{reason}のため"
                await t.websocket.send_text(f"\r\n[{msg}、ターミナルを切断しました]\r\n")
            refreshed = refreshed_key is not None and t.token_key == refreshed_key
            await t.websocket.close(code=WS_CLOSE_TOKEN_REFRESHED if refreshed else WS_CLOSE_UNAUTHORIZED,
                                    reason="refreshed" if refreshed else idle.REASON_CODE if is_idle else "revoked")
        except Exception:  # noqa: BLE001 - すでに切れている
            pass
    return sum(1 for t in targets if t.kind == "terminal")


def _register(user_id: str, websocket: WebSocket, kind: str = "terminal", token: str | None = None) -> _LiveTerminal:
    live = _LiveTerminal(websocket, kind=kind, token_key=sessions.token_key(token) if token else None)
    _live.setdefault(user_id, set()).add(live)
    return live


def _unregister(user_id: str, live: _LiveTerminal) -> None:
    group = _live.get(user_id)
    if group is not None:
        group.discard(live)
        if not group:
            del _live[user_id]


def _clamp_size(value, default: int) -> int:
    try:
        return max(MIN_SIZE, min(MAX_SIZE, int(value)))
    except (TypeError, ValueError):
        return default


class SSHTerminal:
    """SSHターミナルセッション（ブロッキング処理はすべてスレッド側で呼ぶ）"""

    def __init__(self, device: DeviceConnectionInfo):
        self.device = device
        self.jump_client: paramiko.SSHClient | None = None
        self.ssh: paramiko.SSHClient | None = None
        self.channel: paramiko.Channel | None = None

    def connect(self, cols: int, rows: int) -> None:
        # 秘密鍵は接続前に読み込み、形式・パスフレーズの誤りを分かりやすいエラーにする
        pkey = load_private_key(self.device.private_key, self.device.key_passphrase) if self.device.private_key else None
        sock = None
        if self.device.jump:
            # 踏み台へ接続し、機器宛ての direct-tcpip チャネルをソケットとして使う
            self.jump_client = connect_jump(self.device.jump)
            sock = open_tunnel(self.jump_client, self.device.jump.name, self.device.hostname, self.device.port)
        self.ssh = paramiko.SSHClient()
        jump = self.device.jump
        policy = load_known_hosts(
            self.ssh, jump_id=jump.scope if jump else None, host=self.device.hostname, port=self.device.port,
            context={"target": "device", "device_id": self.device.id, "device_name": self.device.name,
                     "via": jump.name if jump else None},
        )
        self.ssh.connect(
            hostname=self.device.hostname,
            port=self.device.port,
            username=self.device.username,
            password=self.device.password or None,
            pkey=pkey,  # 鍵とパスワードの両方がある場合は鍵 → パスワードの順に試す
            timeout=settings.SSH_TIMEOUT,
            auth_timeout=settings.SSH_AUTH_TIMEOUT,
            banner_timeout=settings.SSH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
            sock=sock,
        )
        policy.after_connect(self.ssh)
        self.channel = self.ssh.get_transport().open_session()
        self.channel.get_pty(term="xterm-256color", width=cols, height=rows)
        self.channel.invoke_shell()
        # recv() を一定時間で戻し、停止フラグを確認できるようにする（ビジーループ防止）
        self.channel.settimeout(0.5)

    def resize(self, cols: int, rows: int) -> None:
        if self.channel and not self.channel.closed:
            self.channel.resize_pty(width=cols, height=rows)

    def send(self, data: str) -> None:
        if self.channel and not self.channel.closed:
            self.channel.sendall(data.encode("utf-8"))

    def close(self) -> None:
        try:
            if self.channel:
                self.channel.close()
        finally:
            if self.ssh:
                self.ssh.close()
            if self.jump_client:
                self.jump_client.close()


async def _load_device(device_id: str) -> DeviceConnectionInfo | None:
    async with AsyncSessionLocal() as db:
        return await load_connection_info(db, device_id)


async def _save(*objs) -> None:
    """監査用の記録を保存する（失敗してもターミナル自体は止めない）"""
    try:
        async with AsyncSessionLocal() as db:
            for o in objs:
                await db.merge(o)
            await db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("ターミナルの監査ログを保存できませんでした")


async def _save_hostkeys(device: DeviceConnectionInfo, user: User, ip: str | None) -> None:
    """この接続で TOFU により新しく登録したホスト鍵（機器・踏み台）を、アクティビティ・監査ログに残す"""
    jump_id = device.jump.id if device.jump else None
    events = take_hostkey_events(lambda e: e.get("device_id") == device.id
                                 or (jump_id is not None and e.get("jump_id") == jump_id))
    if not events:
        return
    try:
        async with AsyncSessionLocal() as db:
            record_hostkey_events(db, events, actor=user.username, user=user, ip=ip)
            await db.commit()
    except Exception:  # noqa: BLE001 - 記録の失敗でターミナルを止めない
        logger.exception("新しいホスト鍵の記録に失敗しました")


@router.websocket("/ws/{device_id}")
async def terminal_ws(websocket: WebSocket, device_id: str):
    await websocket.accept()

    # --- 1. 認証（トークンはURLに載せずメッセージで受け取る。アクセスログに残さないため）
    ip = websocket.client.host if websocket.client else None
    why = "unauthorized"
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SEC))
        user, why = (await authenticate_ws(str(first.get("token", "")), ip)) if first.get("type") == "auth" \
            else (None, why)
    except (TimeoutError, json.JSONDecodeError, AttributeError, WebSocketDisconnect):
        user = None
    if user is None:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason=why)
        return
    if not has_permission(user.role, Perm.TERMINAL):
        logger.warning("ターミナル権限なし user=%s role=%s device=%s", user.username, user.role, device_id)
        await websocket.send_text("\r\nターミナルを使用する権限がありません。\r\n")
        await websocket.close(code=WS_CLOSE_FORBIDDEN, reason="forbidden")
        return
    cols = _clamp_size(first.get("cols"), 120)
    rows = _clamp_size(first.get("rows"), 40)
    # 以降は管理者の強制ログアウトなどで切れるよう登録しておく（解除は _session の終わり）
    live = _register(user.id, websocket, "terminal", str(first.get("token", "")))
    # 無操作の時間を、要求が来なくても確かめる（過ぎたら close_user_sessions で切る）
    watcher = asyncio.create_task(idle.watch_ws(user, str(first.get("token", "")), ip))
    try:
        await _session(websocket, device_id, user, str(first.get("token", "")), cols, rows, live)
    finally:
        watcher.cancel()
        _unregister(user.id, live)


async def _session(websocket: WebSocket, device_id: str, user: User, token: str, cols: int, rows: int,
                   live: _LiveTerminal) -> None:
    # --- 2. デバイス取得
    device = await _load_device(device_id)
    if device is None:
        await websocket.send_text("\r\nDevice not found.\r\n")
        await websocket.close(code=WS_CLOSE_NOT_FOUND)
        return

    # --- 3. SSH接続（ブロッキングなのでスレッドで実行し、イベントループを止めない）
    loop = asyncio.get_running_loop()
    ip = websocket.client.host if websocket.client else None
    via = device.jump.name if device.jump else None
    target = {"target_type": "device", "target_id": device.id, "target_name": device.name}
    session = SSHTerminal(device)
    try:
        await loop.run_in_executor(None, session.connect, cols, rows)
    except Exception as e:  # noqa: BLE001
        await _save_hostkeys(device, user, ip)  # 鍵を登録してから認証などで失敗した場合も残す
        logger.warning("SSH接続失敗 user=%s device=%s: %r", user.username, device.name, e)
        await loop.run_in_executor(None, session.close)
        if isinstance(e, JumpHostError):
            reason = str(e)
        elif isinstance(e, PrivateKeyError):
            reason = f"機器の秘密鍵: {e}"
        else:
            reason = describe_ssh_error(e)
        await _save(make_log("terminal.open", user=user, ip=ip, success=False,
                             detail={"error": reason, "via": via}, **target))
        if live.revoked is None:
            await websocket.send_text(f"\r\nSSH接続に失敗しました: {reason}\r\n")
            await websocket.close()
        return
    await _save_hostkeys(device, user, ip)
    # 接続を待つ間に強制ログアウト・ロールの変更などがあった場合（認証の照合と登録の間に起きた場合も含め、ここで確かめ直す）
    now_user, why = (None, "unauthorized") if live.revoked is not None else await authenticate_ws(token, ip)
    if now_user is None or not has_permission(now_user.role, Perm.TERMINAL):
        await loop.run_in_executor(None, session.close)
        if live.revoked is None:
            await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason=why)
        return

    # --- 監査: セッションを登録し、画面出力の記録を開始する
    started = utcnow()
    record = TerminalSession(
        id=str(uuid.uuid4()), user_id=user.id, username=user.username, device_id=device.id,
        device_name=device.name, device_host=device.hostname, via=via, ip=ip, started_at=started,
        cols=cols, rows=rows, bytes_out=0, truncated=False,
    )
    recorder = TerminalRecorder(record.id, started, cols, rows, f"{user.username}@{device.name}")
    record.log_file = recorder.rel_path if recorder.available else None
    await _save(record, make_log("terminal.open", user=user, ip=ip,
                                 detail={"session_id": record.id, "via": via}, **target))
    logger.info(
        "ターミナル開始 user=%s device=%s(%s)%s",
        user.username,
        device.name,
        device.hostname,
        f" via={device.jump.name}" if device.jump else "",
    )

    stop = threading.Event()
    remote_closed = threading.Event()

    def read_from_ssh() -> None:
        """SSH出力をWebSocketに転送するスレッド"""
        # マルチバイト文字がrecvの境界で分割されても化けないよう、インクリメンタルにデコード
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while not stop.is_set():
                try:
                    data = session.channel.recv(4096)
                except TimeoutError:
                    continue
                if not data:  # リモート側がシェルを閉じた（こちらから閉じた場合は stop が立っている）
                    if not stop.is_set():
                        remote_closed.set()
                    break
                text = decoder.decode(data)
                if text:
                    recorder.output(text)
                    # 送信完了を待つことで順序保証とバックプレッシャーを得る
                    asyncio.run_coroutine_threadsafe(websocket.send_text(text), loop).result(timeout=30)
        except Exception:  # noqa: BLE001 - WebSocket切断等
            pass
        finally:
            if not stop.is_set():
                asyncio.run_coroutine_threadsafe(_close_ws(websocket), loop)

    reader = threading.Thread(target=read_from_ssh, daemon=True)
    reader.start()

    # --- 4. クライアントからの入力
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            kind = msg.get("type")
            if kind == "input" and isinstance(msg.get("data"), str):
                await loop.run_in_executor(None, session.send, msg["data"])
            elif kind == "resize":
                c, r = _clamp_size(msg.get("cols"), cols), _clamp_size(msg.get("rows"), rows)
                recorder.resize(c, r)
                await loop.run_in_executor(None, session.resize, c, r)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        stop.set()

        async def finish() -> None:
            await loop.run_in_executor(None, session.close)
            await loop.run_in_executor(None, reader.join, 2)  # 出力の書き込みが終わるのを待つ
            recorder.close()
            # 読める形のテキストも保存する（大きな記録でも応答を止めないよう、別スレッドで変換する）
            await loop.run_in_executor(None, recorder.write_text)
            ended = utcnow()
            record.ended_at = ended
            record.end_reason = (
                (IDLE_END_REASON if live.revoked == idle.CLOSE_REASON
                 else f"本人の{SELF_REASONS[live.revoked]}で切断" if live.revoked in SELF_REASONS
                 else f"管理者が切断（{live.revoked}）")
                if live.revoked
                else "機器側で終了" if remote_closed.is_set() else "利用者が切断"
            )
            record.bytes_out = recorder.bytes
            record.truncated = recorder.truncated
            await _save(record, make_log(
                "terminal.close", user=user, ip=ip,
                detail={"session_id": record.id, "seconds": int((ended - started).total_seconds()),
                        "reason": record.end_reason},
                **target,
            ))
            logger.info("ターミナル終了 user=%s device=%s", user.username, device.name)

        # 接続が切れたときにこの処理自体がキャンセルされても、SSH の切断と記録の保存は最後まで行う
        task = asyncio.ensure_future(finish())
        _cleanup_tasks.add(task)
        task.add_done_callback(_cleanup_tasks.discard)
        await asyncio.shield(task)


async def _close_ws(websocket: WebSocket) -> None:
    try:
        await websocket.send_text("\r\n[セッションが終了しました]\r\n")
        await websocket.close()
    except Exception:  # noqa: BLE001
        pass
