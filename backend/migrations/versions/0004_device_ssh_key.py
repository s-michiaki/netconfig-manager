"""機器の SSH 鍵認証: devices.private_key / key_passphrase を追加し、password を任意に変更

Revision ID: 0004_device_ssh_key
Revises: 0003_jump_hosts
"""
import sqlalchemy as sa
from alembic import op

revision = "0004_device_ssh_key"
down_revision = "0003_jump_hosts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("private_key", sa.Text(), nullable=True))
        batch.add_column(sa.Column("key_passphrase", sa.String(256), nullable=True))
        batch.alter_column("password", existing_type=sa.String(256), nullable=True)


def downgrade() -> None:
    # パスワード未設定（鍵のみ）の機器があると NOT NULL に戻せないため、空文字で埋める
    op.execute("UPDATE devices SET password = '' WHERE password IS NULL")
    with op.batch_alter_table("devices") as batch:
        batch.alter_column("password", existing_type=sa.String(256), nullable=False)
        batch.drop_column("key_passphrase")
        batch.drop_column("private_key")
