import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class AuditLog(Base):
    """操作履歴（誰が・いつ・何をしたか）

    機器やユーザーが削除されても履歴が残るよう、外部キーは張らずに名前も一緒に保存する
    """

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_at", "at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # 例: device.update（一覧は app/services/audit.py）
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON（秘密情報は含めない）
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)


class TerminalSession(Base):
    """SSH ターミナルのセッション。画面出力は asciicast v2 形式のファイルに記録する"""

    __tablename__ = "terminal_sessions"
    __table_args__ = (Index("ix_terminal_sessions_started_at", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    device_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    via: Mapped[str | None] = mapped_column(String(128), nullable=True)  # 経由した踏み台
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    end_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    log_file: Mapped[str | None] = mapped_column(String(256), nullable=True)  # TERMINAL_LOG_PATH からの相対パス
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)  # 上限に達して記録を打ち切った
    cols: Mapped[int] = mapped_column(Integer, default=120)
    rows: Mapped[int] = mapped_column(Integer, default=40)
