"""notification_settings に on_system（システムの異常の通知）を追加

Revision ID: 0020_notify_system
Revises: 0019_monitoring
"""
import sqlalchemy as sa
from alembic import op

revision = "0020_notify_system"
down_revision = "0019_monitoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 既存の設定にも送る（worker・スケジューラーの停止に気づけるようにするのが目的のため、既定は有効）
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_system", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_system")
