"""コンプライアンスの例外 compliance_exceptions を追加

Revision ID: 0014_compliance_exceptions
Revises: 0013_activity_logs
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_compliance_exceptions"
down_revision = "0013_activity_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(36),
                  sa.ForeignKey("compliance_rules.id", name="fk_compliance_exceptions_rule_id"), nullable=False),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_compliance_exceptions_device_id")),
        sa.Column("ignore_pattern", sa.Text()),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_compliance_exceptions_rule_id", "compliance_exceptions", ["rule_id"])


def downgrade() -> None:
    op.drop_index("ix_compliance_exceptions_rule_id", table_name="compliance_exceptions")
    op.drop_table("compliance_exceptions")
