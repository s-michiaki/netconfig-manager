"""アクティビティログ（システムで起きたこと）activity_logs を追加

Revision ID: 0013_activity_logs
Revises: 0012_notifications
"""
import sqlalchemy as sa
from alembic import op

revision = "0013_activity_logs"
down_revision = "0012_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "activity_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("device_id", sa.String(36)),
        sa.Column("device_name", sa.String(128)),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text()),
        sa.Column("actor", sa.String(160)),
        sa.Column("ref", sa.String(64)),
    )
    op.create_index("ix_activity_logs_at", "activity_logs", ["at"])
    op.create_index("ix_activity_logs_device_id", "activity_logs", ["device_id"])
    op.create_index("ix_activity_logs_ref", "activity_logs", ["ref"])


def downgrade() -> None:
    op.drop_index("ix_activity_logs_ref", table_name="activity_logs")
    op.drop_index("ix_activity_logs_device_id", table_name="activity_logs")
    op.drop_index("ix_activity_logs_at", table_name="activity_logs")
    op.drop_table("activity_logs")
