import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class PingTarget(Base):
    """Ping監視で登録機器以外に PING するアドレス（IP アドレスまたはホスト名）"""

    __tablename__ = "ping_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    address: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 表示上のグループ（機器のグループと共通。NULL なら「その他」）
    group_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("device_groups.id", name="fk_ping_targets_group_id"), nullable=True
    )
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class PingMonitor(Base):
    """常時監視する対象（worker が PING_MONITOR_INTERVAL_SEC ごとに PING し、結果を残して応答なしを通知する）

    key は画面の Ping監視と同じ（d:<機器ID> / t:<追加IPのID>）。対象が削除されたら worker が消す
    """

    __tablename__ = "ping_monitors"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PingResult(Base):
    """常時監視の結果（1 回の PING ごと）。PING_HISTORY_DAYS を過ぎたら毎日の削除で消す"""

    __tablename__ = "ping_results"
    __table_args__ = (Index("ix_ping_results_key_at", "key", "at"), Index("ix_ping_results_at", "at"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    rtt: Mapped[float | None] = mapped_column(Float, nullable=True)  # 応答時間（ms）。応答なしは NULL
