"""表示コマンドの一括実行（services/command_run.py）の実行と、機器ごとの結果"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedText
from app.core.timeutil import utcnow
from app.models.base import Base

# 結果の状態
STATUS_QUEUED, STATUS_RUNNING, STATUS_OK, STATUS_FAILED, STATUS_SKIPPED = "queued", "running", "ok", "failed", "skipped"
ACTIVE_STATUSES = (STATUS_QUEUED, STATUS_RUNNING)


class CommandRun(Base):
    """1 回の実行（コマンドの一覧と対象）。出力は機器ごとの結果（CommandResult）に持つ"""

    __tablename__ = "command_runs"
    __table_args__ = (Index("ix_command_runs_created_at", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    commands: Mapped[list] = mapped_column(JSON, nullable=False)  # 送ったコマンド（検証を通った形）の配列
    target: Mapped[str] = mapped_column(String(16), nullable=False)  # devices / group
    target_name: Mapped[str | None] = mapped_column(String(256), nullable=True)  # 対象の要約（グループ名・機器名など）
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 対象の機器の数（対象外を含む）
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # すべての機器が終わった時刻


class CommandResult(Base):
    """1 台ぶんの結果。出力（設定の中身を含みうる）は DEVICE_ENCRYPTION_KEY で暗号化して保存する"""

    __tablename__ = "command_results"
    __table_args__ = (Index("ix_command_results_run_id", "run_id"), Index("ix_command_results_device_id", "device_id"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("command_runs.id", name="fk_command_results_run_id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_command_results_device_id", ondelete="SET NULL"), nullable=True
    )
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_QUEUED)
    # コマンドごとの出力の JSON 配列 [{command, output, truncated, chars}]。1 コマンドの上限で切ったら truncated
    outputs: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    output_chars: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 保存した出力の文字数（実行全体の上限用）
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
