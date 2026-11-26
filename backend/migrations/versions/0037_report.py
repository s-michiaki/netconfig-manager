"""定期レポート: notification_settings に report を追加し、送信済みの期間の記録（report_sends）を作る

Revision ID: 0037_report
Revises: 0036_teams_webhook
"""
import sqlalchemy as sa
from alembic import op

revision = "0037_report"
down_revision = "0036_teams_webhook"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        # off / weekly / monthly / both。既存の設定は送らない（off）
        batch.add_column(sa.Column("report", sa.String(8), nullable=False, server_default="off"))
        # 種類ごとに「無効 → 有効」になった時刻。これより前に終わった期間のレポートは送らない
        batch.add_column(sa.Column("report_week_since", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("report_month_since", sa.DateTime(), nullable=True))
    op.create_table(
        "report_sends",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("setting_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("period_start", sa.String(10), nullable=False),
        sa.Column("status", sa.String(8), nullable=False, server_default="sending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("claimed_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("setting_id", "kind", "period_start", name="uq_report_sends_period"),
    )


def downgrade() -> None:
    op.drop_table("report_sends")
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("report_month_since")
        batch.drop_column("report_week_since")
        batch.drop_column("report")
