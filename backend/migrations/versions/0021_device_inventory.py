"""devices に機器台帳の項目（モデル・シリアル番号・OS バージョン・機器側のホスト名・取得日時）を追加

Revision ID: 0021_device_inventory
Revises: 0020_notify_system
"""
import sqlalchemy as sa
from alembic import op

revision = "0021_device_inventory"
down_revision = "0020_notify_system"
branch_labels = None
depends_on = None

COLUMNS = ("model", "serial_number", "os_version", "reported_hostname")


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        for name in COLUMNS:
            batch.add_column(sa.Column(name, sa.String(128), nullable=True))
        batch.add_column(sa.Column("inventory_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("inventory_at")
        for name in reversed(COLUMNS):
            batch.drop_column(name)
