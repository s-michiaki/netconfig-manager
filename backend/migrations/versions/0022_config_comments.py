"""config_comments: 世代（Git のコミット）に付ける作業内容のメモ

Revision ID: 0022_config_comments
Revises: 0021_device_inventory
"""
import sqlalchemy as sa
from alembic import op

revision = "0022_config_comments"
down_revision = "0021_device_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "config_comments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_config_comments_device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("commit_hash", sa.String(40), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_by_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("device_id", "commit_hash", name="uq_config_comments_device_commit"),
    )
    op.create_index("ix_config_comments_device_id", "config_comments", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_config_comments_device_id", table_name="config_comments")
    op.drop_table("config_comments")
