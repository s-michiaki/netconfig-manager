"""ファームウェアの脆弱性（CVE）とサポート終了日（EOL）の管理（services/vuln_*.py）

- VulnAdvisory: 外部から取得した勧告（source ごと。いまは Palo Alto の勧告）。更新で上書きし、消さない
- VulnMatch: 機器 × 勧告の照合結果。機器が消えたら一緒に消える
- EolDate: サポート終了日。自動取得（endoflife.date）と手入力（manual）を同じ表に持ち、手入力を優先する
- VulnSource: 情報源ごとの最後の取得の結果
"""
import uuid
from datetime import date, datetime

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, false
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class VulnAdvisory(Base):
    __tablename__ = "vuln_advisories"
    __table_args__ = (UniqueConstraint("source", "ext_id", name="uq_vuln_advisories_source_ext"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # paloalto（J-2 で fortinet / nvd）
    ext_id: Mapped[str] = mapped_column(String(64), nullable=False)  # CVE-… または PAN-SA-…
    cve_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="none")  # critical/high/medium/low/none
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)  # 出典（https で許可リストのホストだけ）
    products: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # このアプリの platform の値
    # 影響範囲（形は services/vuln_match.py の「影響範囲との照合」の節。元の値は各項目の "src"）:
    #   {"status": "affected", "branch": "10.2", "ge": "10.2.0", "fixes": ["10.2.7-h40", …], "platforms": ["Panorama"]}
    #   {"status": …, "open": true, …} / {"status": …, "all": true} / {"unreadable": true, "branch": "10.2"}
    #   {"kind": "default", "default": "affected"}
    affected: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # CISA の悪用確認済み一覧に載っているか
    # 取り下げ（CVE の state が REJECTED）。照合に使わず、その勧告の判定は解消にする（再び公開されたら false に戻す）
    rejected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    kev_due: Mapped[date | None] = mapped_column(Date, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class VulnMatch(Base):
    __tablename__ = "vuln_matches"
    __table_args__ = (UniqueConstraint("device_id", "advisory_id", name="uq_vuln_matches_device_advisory"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", name="fk_vuln_matches_device_id", ondelete="CASCADE"), nullable=False,
        index=True,
    )
    advisory_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vuln_advisories.id", name="fk_vuln_matches_advisory_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="confirmed")  # confirmed / candidate
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)  # 照合したときのバージョン
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)  # 照合したときの機器のモデル
    # 解消（fixed）の理由。"rejected"＝勧告の取り下げ（再公開で戻すとき、確認済みの印とメモを残す）
    fixed_reason: Mapped[str | None] = mapped_column(String(16), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    state: Mapped[str] = mapped_column(String(8), nullable=False, default="open")  # open / ack / fixed
    note: Mapped[str | None] = mapped_column(Text, nullable=True)  # ack のときのメモ
    acked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 前回（os_version の版で）は該当だったが、機器の版が変わり、いまの版では勧告の範囲を読み取れず判定できない。
    # 該当の件数・一覧からは外し、「判定できない機器」に出す（state・メモはそのまま残す）。版が戻るか判定できれば外す
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())


class EolDate(Base):
    __tablename__ = "eol_dates"
    __table_args__ = (
        UniqueConstraint("platform", "kind", "branch", "model", "source", name="uq_eol_dates_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    platform: Mapped[str] = mapped_column(String(64), nullable=False)  # このアプリの platform の値
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="os")  # os / hardware
    branch: Mapped[str] = mapped_column(String(32), nullable=False, default="")  # リリース系列（os。例 "10.2"）
    model: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # モデル（hardware の手入力）
    eol_date: Mapped[date] = mapped_column(Date, nullable=False)  # サポート終了日
    eos_date: Mapped[date | None] = mapped_column(Date, nullable=True)  # 任意: 販売終了・セキュリティ修正の終了
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")  # endoflife.date / manual
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class VulnSource(Base):
    __tablename__ = "vuln_sources"

    source: Mapped[str] = mapped_column(String(16), primary_key=True)  # paloalto / kev / eol
    last_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # 最後に取得を試みた時刻
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 秘密・URL のクエリ・プロキシの認証情報を含めない短い文
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    last_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 取得したが範囲を読み取れなかった行の数（Palo Alto。該当・非該当のどちらにもせず「判定できない」に数える）
    skipped: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)  # 次回の起点（kev は CVE → 期限の JSON）
