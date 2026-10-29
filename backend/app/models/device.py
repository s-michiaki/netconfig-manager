import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString, EncryptedText
from app.core.timeutil import utcnow
from app.models.base import Base


class JumpHost(Base):
    """踏み台サーバ（1段のみ）。機器は jump_host_id でこれを経由して接続する"""

    __tablename__ = "jump_hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    # 認証はパスワード・秘密鍵のどちらか、または両方（すべて暗号化して保存）
    password: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    private_key: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    key_passphrase: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    devices: Mapped[list["Device"]] = relationship("Device", back_populates="jump_host")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)  # cisco_ios, juniper_junos, etc.
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    # 認証はパスワード・SSH秘密鍵のどちらか、または両方。Fernet で暗号化して保存（DEVICE_ENCRYPTION_KEY）
    password: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    private_key: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    key_passphrase: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    enable_secret: Mapped[str | None] = mapped_column(EncryptedString(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # 経由する踏み台（NULL なら直接接続）
    jump_host_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("jump_hosts.id", name="fk_devices_jump_host_id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    jump_host: Mapped["JumpHost | None"] = relationship("JumpHost", back_populates="devices")
    config_snapshots: Mapped[list["ConfigSnapshot"]] = relationship(
        "ConfigSnapshot", back_populates="device", cascade="all, delete-orphan"
    )
    collect_logs: Mapped[list["CollectLog"]] = relationship(
        "CollectLog", back_populates="device", cascade="all, delete-orphan"
    )


class ConfigSnapshot(Base):
    """Gitコミットハッシュとメタデータを管理する世代テーブル"""

    __tablename__ = "config_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False)
    commit_hash: Mapped[str] = mapped_column(String(40), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    lines_added: Mapped[int] = mapped_column(Integer, default=0)
    lines_removed: Mapped[int] = mapped_column(Integer, default=0)
    triggered_by: Mapped[str] = mapped_column(String(64), default="manual")  # schedule / manual

    device: Mapped["Device"] = relationship("Device", back_populates="config_snapshots")


class CollectLog(Base):
    __tablename__ = "collect_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False)
    status: Mapped[str] = mapped_column(Enum("success", "failed", name="collect_status"), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    device: Mapped["Device"] = relationship("Device", back_populates="collect_logs")


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), default="all")  # "all" or device_id
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
