"""監査ログ: audit_logs（操作履歴）と terminal_sessions（ターミナルの記録）を追加

Revision ID: 0008_audit
Revises: 0007_topology_logical
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_audit"
down_revision = "0007_topology_logical"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.String(36)),
        sa.Column("username", sa.String(64)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32)),
        sa.Column("target_id", sa.String(36)),
        sa.Column("target_name", sa.String(256)),
        sa.Column("detail", sa.Text()),
        sa.Column("ip", sa.String(64)),
        sa.Column("success", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_audit_logs_at", "audit_logs", ["at"])
    op.create_table(
        "terminal_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36)),
        sa.Column("username", sa.String(64)),
        sa.Column("device_id", sa.String(36)),
        sa.Column("device_name", sa.String(128)),
        sa.Column("device_host", sa.String(256)),
        sa.Column("via", sa.String(128)),
        sa.Column("ip", sa.String(64)),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime()),
        sa.Column("end_reason", sa.String(128)),
        sa.Column("log_file", sa.String(256)),
        sa.Column("bytes_out", sa.BigInteger(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("cols", sa.Integer(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
    )
    op.create_index("ix_terminal_sessions_started_at", "terminal_sessions", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_terminal_sessions_started_at", "terminal_sessions")
    op.drop_table("terminal_sessions")
    op.drop_index("ix_audit_logs_at", "audit_logs")
    op.drop_table("audit_logs")
