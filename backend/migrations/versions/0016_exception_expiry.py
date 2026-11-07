"""compliance_exceptions.expiry_handled（期限切れ後の再検査を済ませたか）を追加

Revision ID: 0016_exception_expiry
Revises: 0015_schedule_kind
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_exception_expiry"
down_revision = "0015_schedule_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("compliance_exceptions") as batch:
        batch.add_column(sa.Column("expiry_handled", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("compliance_exceptions") as batch:
        batch.drop_column("expiry_handled")
