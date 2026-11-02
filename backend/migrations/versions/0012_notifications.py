"""コンフィグ変更の通知: ユーザーグループ・所属・通知設定を追加

Revision ID: 0012_notifications
Revises: 0011_ping_targets
"""
import sqlalchemy as sa
from alembic import op

revision = "0012_notifications"
down_revision = "0011_ping_targets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "user_group_members",
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("user_groups.id", name="fk_ugm_group_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("user_id", sa.String(36),
                  sa.ForeignKey("users.id", name="fk_ugm_user_id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_index("ix_user_group_members_user_id", "user_group_members", ["user_id"])
    op.create_table(
        "notification_settings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner_type", sa.String(16), nullable=False),
        sa.Column("owner_id", sa.String(36), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("discord_webhook", sa.String(1024)),
        sa.Column("slack_webhook", sa.String(1024)),
        sa.Column("all_devices", sa.Boolean(), nullable=False),
        sa.Column("device_group_ids", sa.Text()),
        sa.Column("include_ungrouped", sa.Boolean(), nullable=False),
        sa.Column("last_sent_at", sa.DateTime()),
        sa.Column("last_error", sa.Text()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("owner_type", "owner_id", name="uq_notification_owner"),
    )


def downgrade() -> None:
    op.drop_table("notification_settings")
    op.drop_index("ix_user_group_members_user_id", table_name="user_group_members")
    op.drop_table("user_group_members")
    op.drop_table("user_groups")
