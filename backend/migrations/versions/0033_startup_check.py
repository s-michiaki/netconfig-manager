"""devices に startup と running の不一致（保存し忘れ）の状態、notification_settings に on_unsaved を追加

Revision ID: 0033_startup_check
Revises: 0032_config_baselines
"""
import sqlalchemy as sa
from alembic import op

revision = "0033_startup_check"
down_revision = "0032_config_baselines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("startup_state", sa.String(16), nullable=True))
        batch.add_column(sa.Column("startup_added", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("startup_removed", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("startup_diff", sa.Text(), nullable=True))
        batch.add_column(sa.Column("startup_checked_at", sa.DateTime(), nullable=True))
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_unsaved", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_unsaved")
    with op.batch_alter_table("devices") as batch:
        for c in ("startup_checked_at", "startup_diff", "startup_removed", "startup_added", "startup_state"):
            batch.drop_column(c)
