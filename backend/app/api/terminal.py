"""
WebSocket SSHターミナル
- フロントエンドのxterm.jsと双方向通信
- Paramikoでインタラクティブシェルを確立
"""
import asyncio
import threading

import paramiko
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.device import Device

router = APIRouter()


class TerminalSession:
    """SSHターミナルセッションを管理するクラス"""

    def __init__(self, websocket: WebSocket, device: Device):
        self.websocket = websocket
        self.device = device
        self.ssh: paramiko.SSHClient | None = None
        self.channel: paramiko.Channel | None = None
        self._running = True

    def connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        transport = self.ssh.get_transport()
        self.channel = transport.open_session()
        self.channel.get_pty(term="xterm-256color", width=220, height=50)
        self.channel.invoke_shell()

    def resize(self, width: int, height: int):
        if self.channel:
            self.channel.resize_pty(width=width, height=height)

    def send(self, data: str):
        if self.channel:
            self.channel.send(data)

    def close(self):
        self._running = False
        if self.channel:
            self.channel.close()
        if self.ssh:
            self.ssh.close()


@router.websocket("/ws/{device_id}")
async def terminal_ws(websocket: WebSocket, device_id: str):
    await websocket.accept()

    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)

    if not device:
        await websocket.send_text("\r\nDevice not found.\r\n")
        await websocket.close()
        return

    session = TerminalSession(websocket, device)

    try:
        session.connect()
    except Exception as e:
        await websocket.send_text(f"\r\nSSH connection failed: {e}\r\n")
        await websocket.close()
        return

    loop = asyncio.get_event_loop()

    def read_from_ssh():
        """SSH出力をWebSocketに転送するスレッド"""
        while session._running:
            if session.channel and session.channel.recv_ready():
                data = session.channel.recv(4096).decode("utf-8", errors="replace")
                asyncio.run_coroutine_threadsafe(
                    websocket.send_text(data), loop
                )
            elif session.channel and session.channel.closed:
                break

    reader_thread = threading.Thread(target=read_from_ssh, daemon=True)
    reader_thread.start()

    try:
        while True:
            raw = await websocket.receive_text()

            # JSON形式のコントロールメッセージ処理
            if raw.startswith("{"):
                import json
                try:
                    msg = json.loads(raw)
                    if msg.get("type") == "resize":
                        session.resize(msg["cols"], msg["rows"])
                    continue
                except json.JSONDecodeError:
                    pass

            session.send(raw)
    except WebSocketDisconnect:
        pass
    finally:
        session.close()
