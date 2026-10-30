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
"""
import asyncio
import codecs
import json
import logging
import socket
import threading
import uuid

import paramiko
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.deps import authenticate_token
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.permissions import Perm, has_permission
from app.core.ssh_hostkeys import describe_ssh_error, load_known_hosts
from app.core.ssh_jump import JumpHostError, connect_jump, open_tunnel
from app.core.ssh_keys import PrivateKeyError, load_private_key
from app.core.timeutil import utcnow
from app.models.audit import TerminalSession
from app.services.audit import TerminalRecorder, make_log
from app.services.config_service import DeviceConnectionInfo
from app.services.connection import load_connection_info

logger = logging.getLogger(__name__)
router = APIRouter()

AUTH_TIMEOUT_SEC = 10
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403
WS_CLOSE_NOT_FOUND = 4404
MIN_SIZE, MAX_SIZE = 1, 1000

# 切断後の後片付けタスク（途中で破棄されないよう参照を保持する）
_cleanup_tasks: set[asyncio.Task] = set()


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
        load_known_hosts(self.ssh)
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


@router.websocket("/ws/{device_id}")
async def terminal_ws(websocket: WebSocket, device_id: str):
    await websocket.accept()

    # --- 1. 認証（トークンはURLに載せずメッセージで受け取る。アクセスログに残さないため）
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SEC))
        user = await authenticate_token(str(first.get("token", ""))) if first.get("type") == "auth" else None
    except (asyncio.TimeoutError, json.JSONDecodeError, AttributeError, WebSocketDisconnect):
        user = None
    if user is None:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason="unauthorized")
        return
    if not has_permission(user.role, Perm.TERMINAL):
        logger.warning("ターミナル権限なし user=%s role=%s device=%s", user.username, user.role, device_id)
        await websocket.send_text("\r\nターミナルを使用する権限がありません。\r\n")
        await websocket.close(code=WS_CLOSE_FORBIDDEN, reason="forbidden")
        return
    cols = _clamp_size(first.get("cols"), 120)
    rows = _clamp_size(first.get("rows"), 40)

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
        await websocket.send_text(f"\r\nSSH接続に失敗しました: {reason}\r\n")
        await websocket.close()
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
                except socket.timeout:
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
            ended = utcnow()
            record.ended_at = ended
            record.end_reason = "機器側で終了" if remote_closed.is_set() else "利用者が切断"
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
