"""収集時に無視する行のルール（管理者が機種・機器ごとに正規表現で追加する）

normalize_config が、保存前に一致した行を取り除く（services/ignore_rules.py）。過去の世代は変えない
"""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utcnow
from app.models.base import Base


class ConfigIgnoreRule(Base):
    __tablename__ = "config_ignore_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scope: Mapped[str] = mapped_column(String(16), nullable=False)  # platform / device
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)  # scope=platform のとき
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_config_ignore_rules_device_id", ondelete="CASCADE"),
        nullable=True, index=True,
    )  # scope=device のとき
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    device = relationship("Device", back_populates="ignore_rules")
