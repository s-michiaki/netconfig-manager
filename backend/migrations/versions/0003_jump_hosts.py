"""踏み台サーバ（jump_hosts）と devices.jump_host_id を追加

Revision ID: 0003_jump_hosts
Revises: 0002_users
"""
import sqlalchemy as sa
from alembic import op

revision = "0003_jump_hosts"
down_revision = "0002_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jump_hosts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("hostname", sa.String(256), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password", sa.String(256)),
        sa.Column("private_key", sa.Text()),
        sa.Column("key_passphrase", sa.String(256)),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("jump_host_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_devices_jump_host_id", "jump_hosts", ["jump_host_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("fk_devices_jump_host_id", type_="foreignkey")
        batch.drop_column("jump_host_id")
    op.drop_table("jump_hosts")
