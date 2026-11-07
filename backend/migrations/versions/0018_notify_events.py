"""notification_settings に通知する内容（on_change / on_violation / on_failure）を追加

Revision ID: 0018_notify_events
Revises: 0017_group_sort_order
"""
import sqlalchemy as sa
from alembic import op

revision = "0018_notify_events"
down_revision = "0017_group_sort_order"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 既存の設定はこれまでどおりコンフィグの変更だけを通知する
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_change", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("on_violation", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("on_failure", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_failure")
        batch.drop_column("on_violation")
        batch.drop_column("on_change")
