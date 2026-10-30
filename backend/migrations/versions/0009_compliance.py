"""コンプライアンスチェック: compliance_rules / compliance_results を追加

Revision ID: 0009_compliance
Revises: 0008_audit
"""
import sqlalchemy as sa
from alembic import op

revision = "0009_compliance"
down_revision = "0008_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("platforms", sa.Text(), nullable=False),
        sa.Column("match_type", sa.String(16), nullable=False),
        sa.Column("expect", sa.String(16), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("section_pattern", sa.Text()),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "compliance_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", name="fk_compliance_results_device_id"),
                  nullable=False),
        sa.Column("rule_id", sa.String(36),
                  sa.ForeignKey("compliance_rules.id", name="fk_compliance_results_rule_id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("detail", sa.Text()),
        sa.Column("commit_hash", sa.String(40)),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("device_id", "rule_id", name="uq_compliance_results_device_rule"),
    )


def downgrade() -> None:
    op.drop_table("compliance_results")
    op.drop_table("compliance_rules")
