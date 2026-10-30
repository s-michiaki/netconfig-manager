"""Ping監視: 登録機器以外の PING 先 ping_targets を追加

Revision ID: 0011_ping_targets
Revises: 0010_device_groups
"""
import sqlalchemy as sa
from alembic import op

revision = "0011_ping_targets"
down_revision = "0010_device_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ping_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("address", sa.String(256), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("group_id", sa.String(36), sa.ForeignKey("device_groups.id", name="fk_ping_targets_group_id")),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ping_targets")
