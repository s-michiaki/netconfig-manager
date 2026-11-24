"""config_reviews: 変更（世代）の確認の状態（確認済み・想定外）

Revision ID: 0030_config_reviews
Revises: 0029_mail
"""
import sqlalchemy as sa
from alembic import op

revision = "0030_config_reviews"
down_revision = "0029_mail"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "config_reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_config_reviews_device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("commit_hash", sa.String(40), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(64), nullable=True),
        sa.Column("reviewed_by_id", sa.String(36), nullable=True),
        sa.Column("reviewed_at", sa.DateTime()),
        sa.UniqueConstraint("device_id", "commit_hash", name="uq_config_reviews_device_commit"),
    )
    op.create_index("ix_config_reviews_device_id", "config_reviews", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_config_reviews_device_id", table_name="config_reviews")
    op.drop_table("config_reviews")
