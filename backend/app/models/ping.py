import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
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
