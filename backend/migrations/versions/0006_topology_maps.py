"""構成図: topology_maps を追加

Revision ID: 0006_topology_maps
Revises: 0005_device_read_timeout
"""
import sqlalchemy as sa
from alembic import op

revision = "0006_topology_maps"
down_revision = "0005_device_read_timeout"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "topology_maps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("data", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("topology_maps")
