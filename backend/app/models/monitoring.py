"""モニタリング（試験導入）: SNMP の設定・インタフェースの帯域・FW ルールのヒット数

- SnmpSetting: 機器ごとの SNMP の設定（v2c / v3）。認証情報は暗号化して保存する
- MonInterface: SNMP で見つけたインタフェースと、直近のカウンタ（次回の差分計算用）・直近の bps
- IfSample: 帯域の記録（取得ごとの入出力 bps）。MONITOR_RETENTION_DAYS を過ぎたら削除
- FwRuleHit / FwHitStatus: FW ルールのヒット数（最新の取得結果だけ保持）と、取得の結果・生の出力
"""
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedString
from app.core.timeutil import utcnow
from app.models.base import Base

# SQLite の自動採番は INTEGER PRIMARY KEY だけなので、SQLite では Integer にする
BigId = BigInteger().with_variant(Integer, "sqlite")


class SnmpSetting(Base):
    __tablename__ = "snmp_settings"

    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_snmp_settings_device_id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[str] = mapped_column(String(4), nullable=False, default="2c")  # 2c / 3
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=161)
    community: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)  # v2c
    v3_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    v3_auth_proto: Mapped[str | None] = mapped_column(String(16), nullable=True)  # SHA / SHA256 / MD5 / None
    v3_auth_key: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)
    v3_priv_proto: Mapped[str | None] = mapped_column(String(16), nullable=True)  # AES / AES256 / DES / None
    v3_priv_key: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class MonInterface(Base):
    __tablename__ = "mon_interfaces"
    __table_args__ = (UniqueConstraint("device_id", "if_index", name="uq_mon_interfaces_device_ifindex"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_mon_interfaces_device_id", ondelete="CASCADE"), nullable=False,
        index=True,
    )
    if_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    alias: Mapped[str | None] = mapped_column(String(256), nullable=True)  # ifAlias（description）
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)  # ifHighSpeed
    oper_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_in_octets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_out_octets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # カウンタを読んだ時刻
    in_bps: Mapped[float | None] = mapped_column(Float, nullable=True)  # 直近の値
    out_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class IfSample(Base):
    __tablename__ = "if_samples"
    __table_args__ = (Index("ix_if_samples_interface_at", "interface_id", "at"),)

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    interface_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("mon_interfaces.id", name="fk_if_samples_interface_id", ondelete="CASCADE"),
        nullable=False,
    )
    at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    in_bps: Mapped[float] = mapped_column(Float, nullable=False)
    out_bps: Mapped[float] = mapped_column(Float, nullable=False)


class FwRuleHit(Base):
    __tablename__ = "fw_rule_hits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_fw_rule_hits_device_id", ondelete="CASCADE"), nullable=False,
        index=True,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)  # 出力の順（ルールの並び）
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # FortiGate のポリシー ID
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    hit_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    prev_hit_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # 前回取得時（増加数の計算用）
    prev_collected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    packets: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_hit_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class FwHitStatus(Base):
    __tablename__ = "fw_hit_status"

    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_fw_hit_status_device_id", ondelete="CASCADE"), primary_key=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)  # 解析できないときの確認用（先頭だけ）
