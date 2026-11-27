"""ファームウェアの脆弱性（CVE）とサポート終了日（EOL）の管理: 勧告・照合結果・サポート終了日・情報源の取得記録

Revision ID: 0038_vuln
Revises: 0037_report
"""
import sqlalchemy as sa
from alembic import op

revision = "0038_vuln"
down_revision = "0037_report"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vuln_advisories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("ext_id", sa.String(64), nullable=False),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
        sa.Column("title", sa.String(512), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default="none"),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("modified_at", sa.DateTime(), nullable=True),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("products", sa.JSON(), nullable=False),
        sa.Column("affected", sa.JSON(), nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rejected", sa.Boolean(), nullable=False, server_default=sa.false()),  # 取り下げ（REJECTED）
        sa.Column("kev_due", sa.Date(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source", "ext_id", name="uq_vuln_advisories_source_ext"),
    )
    op.create_table(
        "vuln_matches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", name="fk_vuln_matches_device_id",
                                                             ondelete="CASCADE"), nullable=False),
        sa.Column("advisory_id", sa.String(36), sa.ForeignKey("vuln_advisories.id", name="fk_vuln_matches_advisory_id",
                                                               ondelete="CASCADE"), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="confirmed"),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),  # 照合したときの機器のモデル（変わったら stale の判断に使う）
        sa.Column("fixed_reason", sa.String(16), nullable=True),  # 解消の理由（rejected＝勧告の取り下げ）
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("state", sa.String(8), nullable=False, server_default="open"),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("acked_by", sa.String(64), nullable=True),
        sa.Column("acked_at", sa.DateTime(), nullable=True),
        # 前回は該当だったが、機器の版が変わり、いまの版では範囲を読み取れず判定できない（該当の件数・一覧から外す）
        sa.Column("stale", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("device_id", "advisory_id", name="uq_vuln_matches_device_advisory"),
    )
    op.create_index("ix_vuln_matches_device_id", "vuln_matches", ["device_id"])
    op.create_index("ix_vuln_matches_advisory_id", "vuln_matches", ["advisory_id"])
    op.create_table(
        "eol_dates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("platform", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False, server_default="os"),
        sa.Column("branch", sa.String(32), nullable=False, server_default=""),
        sa.Column("model", sa.String(128), nullable=False, server_default=""),
        sa.Column("eol_date", sa.Date(), nullable=False),
        sa.Column("eos_date", sa.Date(), nullable=True),
        sa.Column("source", sa.String(24), nullable=False, server_default="manual"),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("platform", "kind", "branch", "model", "source", name="uq_eol_dates_key"),
    )
    op.create_table(
        "vuln_sources",
        sa.Column("source", sa.String(16), primary_key=True),
        sa.Column("last_at", sa.DateTime(), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(300), nullable=True),
        sa.Column("last_count", sa.Integer(), nullable=True),
        sa.Column("skipped", sa.Integer(), nullable=True),
        sa.Column("cursor", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("vuln_sources")
    op.drop_table("eol_dates")
    op.drop_index("ix_vuln_matches_advisory_id", table_name="vuln_matches")
    op.drop_index("ix_vuln_matches_device_id", table_name="vuln_matches")
    op.drop_table("vuln_matches")
    op.drop_table("vuln_advisories")
