"""機器ごとの応答待ち時間: devices.read_timeout を追加

Revision ID: 0005_device_read_timeout
Revises: 0004_device_ssh_key
"""
import sqlalchemy as sa
from alembic import op

revision = "0005_device_read_timeout"
down_revision = "0004_device_ssh_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("read_timeout", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("read_timeout")
