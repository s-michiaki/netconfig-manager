"""notification_settings に on_inventory（機器情報の変化の通知）を追加

Revision ID: 0026_notify_inventory
Revises: 0025_credential_profile_owner
"""
import sqlalchemy as sa
from alembic import op

revision = "0026_notify_inventory"
down_revision = "0025_credential_profile_owner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_inventory", sa.Boolean(), nullable=False, server_default=sa.false()))
    # 既存の設定は「コンフィグの変更」を受け取っているものだけ有効にする（機器の変化を知りたい人とほぼ重なるため）
    op.execute("UPDATE notification_settings SET on_inventory = on_change")


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_inventory")
