"""機器のグループ: device_groups を追加し、devices.group_id で所属を表す

Revision ID: 0010_device_groups
Revises: 0009_compliance
"""
import sqlalchemy as sa
from alembic import op

revision = "0010_device_groups"
down_revision = "0009_compliance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("color", sa.String(7)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("group_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_devices_group_id", "device_groups", ["group_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("fk_devices_group_id", type_="foreignkey")
        batch.drop_column("group_id")
    op.drop_table("device_groups")
