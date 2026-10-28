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
"""
import asyncio
import codecs
import json
import logging
import socket
import threading

import paramiko
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.deps import authenticate_token
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.permissions import Perm, has_permission
from app.core.ssh_hostkeys import describe_ssh_error, load_known_hosts
from app.models.device import Device
from app.services.config_service import DeviceConnectionInfo

logger = logging.getLogger(__name__)
router = APIRouter()

AUTH_TIMEOUT_SEC = 10
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403
WS_CLOSE_NOT_FOUND = 4404
MIN_SIZE, MAX_SIZE = 1, 1000


def _clamp_size(value, default: int) -> int:
    try:
        return max(MIN_SIZE, min(MAX_SIZE, int(value)))
    except (TypeError, ValueError):
        return default


class TerminalSession:
    """SSHターミナルセッション（ブロッキング処理はすべてスレッド側で呼ぶ）"""

    def __init__(self, device: DeviceConnectionInfo):
        self.device = device
        self.ssh: paramiko.SSHClient | None = None
        self.channel: paramiko.Channel | None = None

    def connect(self, cols: int, rows: int) -> None:
        self.ssh = paramiko.SSHClient()
        load_known_hosts(self.ssh)
        self.ssh.connect(
            hostname=self.device.hostname,
            port=self.device.port,
            username=self.device.username,
            password=self.device.password,
            timeout=settings.SSH_TIMEOUT,
            auth_timeout=settings.SSH_AUTH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
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


async def _load_device(device_id: str) -> DeviceConnectionInfo | None:
    async with AsyncSessionLocal() as db:
        d = await db.get(Device, device_id)
        if d is None:
            return None
        return DeviceConnectionInfo(
            id=d.id, name=d.name, hostname=d.hostname, platform=d.platform, port=d.port,
            username=d.username, password=d.password, enable_secret=d.enable_secret,
        )


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
    session = TerminalSession(device)
    try:
        await loop.run_in_executor(None, session.connect, cols, rows)
    except Exception as e:  # noqa: BLE001
        logger.warning("SSH接続失敗 user=%s device=%s: %r", user.username, device.name, e)
        await loop.run_in_executor(None, session.close)
        await websocket.send_text(f"\r\nSSH接続に失敗しました: {describe_ssh_error(e)}\r\n")
        await websocket.close()
        return
    logger.info("ターミナル開始 user=%s device=%s(%s)", user.username, device.name, device.hostname)

    stop = threading.Event()

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
                if not data:  # リモート側がシェルを閉じた
                    break
                text = decoder.decode(data)
                if text:
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
                await loop.run_in_executor(
                    None, session.resize, _clamp_size(msg.get("cols"), cols), _clamp_size(msg.get("rows"), rows)
                )
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        stop.set()
        await loop.run_in_executor(None, session.close)
        logger.info("ターミナル終了 user=%s device=%s", user.username, device.name)


async def _close_ws(websocket: WebSocket) -> None:
    try:
        await websocket.send_text("\r\n[セッションが終了しました]\r\n")
        await websocket.close()
    except Exception:  # noqa: BLE001
        pass
