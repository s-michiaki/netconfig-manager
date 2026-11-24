"""config_baselines: 機器ごとの基準の世代とずれ、notification_settings に on_drift（基準からのずれの通知）を追加

Revision ID: 0032_config_baselines
Revises: 0031_config_ignore_rules
"""
import sqlalchemy as sa
from alembic import op

revision = "0032_config_baselines"
down_revision = "0031_config_ignore_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "config_baselines",
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_config_baselines_device_id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("commit_hash", sa.String(40), nullable=False),
        sa.Column("note", sa.String(200), nullable=True),
        sa.Column("set_by", sa.String(64), nullable=True),
        sa.Column("set_by_id", sa.String(36), nullable=True),
        sa.Column("set_at", sa.DateTime()),
        sa.Column("drift_added", sa.Integer(), nullable=True),
        sa.Column("drift_removed", sa.Integer(), nullable=True),
        sa.Column("latest_hash", sa.String(40), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
    )
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_drift", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_drift")
    op.drop_table("config_baselines")
