"""初期スキーマ（v1.0 時点: devices / config_snapshots / collect_logs / schedules）

Alembic 導入前に create_all で作られたDBは、起動時にこのリビジョンとして stamp される。

Revision ID: 0001_initial
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("hostname", sa.String(256), nullable=False),
        sa.Column("platform", sa.String(64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password", sa.String(256), nullable=False),
        sa.Column("enable_secret", sa.String(256)),
        sa.Column("description", sa.Text()),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "config_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("commit_hash", sa.String(40), nullable=False),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.Column("lines_added", sa.Integer(), nullable=False),
        sa.Column("lines_removed", sa.Integer(), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=False),
    )
    op.create_table(
        "collect_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("status", sa.Enum("success", "failed", name="collect_status"), nullable=False),
        sa.Column("message", sa.Text()),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime()),
    )
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("cron_expression", sa.String(64), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("schedules")
    op.drop_table("collect_logs")
    op.drop_table("config_snapshots")
    op.drop_table("devices")
    sa.Enum(name="collect_status").drop(op.get_bind(), checkfirst=True)
