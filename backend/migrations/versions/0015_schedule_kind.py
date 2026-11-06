"""スケジュールの種類 schedules.kind（collect / compliance）を追加

Revision ID: 0015_schedule_kind
Revises: 0014_compliance_exceptions
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_schedule_kind"
down_revision = "0014_compliance_exceptions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 既存のスケジュールはすべてコンフィグ収集
    with op.batch_alter_table("schedules") as batch:
        batch.add_column(sa.Column("kind", sa.String(16), nullable=False, server_default="collect"))


def downgrade() -> None:
    with op.batch_alter_table("schedules") as batch:
        batch.drop_column("kind")
