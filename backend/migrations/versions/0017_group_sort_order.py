"""device_groups.sort_order（グループの表示順）を追加

Revision ID: 0017_group_sort_order
Revises: 0016_exception_expiry
"""
import sqlalchemy as sa
from alembic import op

revision = "0017_group_sort_order"
down_revision = "0016_exception_expiry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device_groups") as batch:
        batch.add_column(sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"))
    # 既存のグループは今までの表示（名前順）のまま番号を振る
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id FROM device_groups ORDER BY name")).fetchall()
    for i, (gid,) in enumerate(rows, 1):
        conn.execute(sa.text("UPDATE device_groups SET sort_order = :o WHERE id = :id"), {"o": i, "id": gid})


def downgrade() -> None:
    with op.batch_alter_table("device_groups") as batch:
        batch.drop_column("sort_order")
