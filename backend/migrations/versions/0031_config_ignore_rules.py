"""config_ignore_rules: 収集時に無視する行（機種・機器ごとの正規表現）

Revision ID: 0031_config_ignore_rules
Revises: 0030_config_reviews
"""
import sqlalchemy as sa
from alembic import op

revision = "0031_config_ignore_rules"
down_revision = "0030_config_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "config_ignore_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("platform", sa.String(64), nullable=True),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_config_ignore_rules_device_id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column("pattern", sa.String(500), nullable=False),
        sa.Column("description", sa.String(200), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_by", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("ix_config_ignore_rules_device_id", "config_ignore_rules", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_config_ignore_rules_device_id", table_name="config_ignore_rules")
    op.drop_table("config_ignore_rules")
