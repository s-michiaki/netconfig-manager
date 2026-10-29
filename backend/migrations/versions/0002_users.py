"""users テーブル（v1.1 で追加。v1.1 を create_all で起動済みのDBには既に存在する）

Revision ID: 0002_users
Revises: 0001_initial
"""
import sqlalchemy as sa
from alembic import op

revision = "0002_users"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "users" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("users")
