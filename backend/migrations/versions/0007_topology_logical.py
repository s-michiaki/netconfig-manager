"""構成図: 論理構成 topology_maps.logical_data を追加

Revision ID: 0007_topology_logical
Revises: 0006_topology_maps
"""
import sqlalchemy as sa
from alembic import op

revision = "0007_topology_logical"
down_revision = "0006_topology_maps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("topology_maps") as batch:
        batch.add_column(
            sa.Column("logical_data", sa.Text(), nullable=False, server_default='{"nodes": [], "edges": []}')
        )


def downgrade() -> None:
    with op.batch_alter_table("topology_maps") as batch:
        batch.drop_column("logical_data")
