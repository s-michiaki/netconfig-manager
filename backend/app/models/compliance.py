import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, false as sa_false
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class ComplianceRule(Base):
    """コンフィグの検査ルール（評価は app/services/compliance.py）"""

    __tablename__ = "compliance_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 対象プラットフォーム（JSON 配列。空なら全プラットフォーム）
    platforms: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    match_type: Mapped[str] = mapped_column(String(16), nullable=False, default="contains")  # contains / regex
    expect: Mapped[str] = mapped_column(String(16), nullable=False, default="present")  # present / absent
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="config")  # config / section
    section_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)  # scope=section のときの見出し（正規表現）
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")  # high / medium / low
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class ComplianceResult(Base):
    """機器 × ルールの最新の検査結果（検査のたびに置き換える）"""

    __tablename__ = "compliance_results"
    __table_args__ = (UniqueConstraint("device_id", "rule_id", name="uq_compliance_results_device_rule"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_compliance_results_device_id"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_rules.id", name="fk_compliance_results_rule_id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # pass / fail / error
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON 配列（違反箇所など）
    commit_hash: Mapped[str | None] = mapped_column(String(40), nullable=True)  # 検査したコンフィグの世代
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ComplianceException(Base):
    """コンプライアンスの例外（承認済みの逸脱）

    - 該当箇所（ignore_pattern）なし: 機器ではこのルールの違反を「除外」として扱う
    - 該当箇所あり: 一致する箇所だけを検査から外す（セクション検査は見出し、コンフィグ全体の検査は違反行に一致）
    device_id が None なら全機器（このときは該当箇所が必須）。expires_at を過ぎたら無効
    """

    __tablename__ = "compliance_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_rules.id", name="fk_compliance_exceptions_rule_id"), nullable=False,
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_compliance_exceptions_device_id"), nullable=True
    )
    ignore_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)  # 正規表現
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 期限切れ後の再検査を済ませたか（定期処理が1回だけ再検査するため）
    expiry_handled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
