"""command_runs / command_results: 表示コマンドの一括実行と、機器ごとの結果（出力は暗号化して保存）

Revision ID: 0034_command_runs
Revises: 0033_startup_check
"""
import sqlalchemy as sa
from alembic import op

revision = "0034_command_runs"
down_revision = "0033_startup_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "command_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("commands", sa.JSON(), nullable=False),
        sa.Column("target", sa.String(16), nullable=False),
        sa.Column("target_name", sa.String(256), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_by_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_command_runs_created_at", "command_runs", ["created_at"])
    op.create_table(
        "command_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36),
                  sa.ForeignKey("command_runs.id", name="fk_command_results_run_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_command_results_device_id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("device_name", sa.String(128), nullable=False),
        sa.Column("platform", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("outputs", sa.Text(), nullable=True),
        sa.Column("output_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_command_results_run_id", "command_results", ["run_id"])
    op.create_index("ix_command_results_device_id", "command_results", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_command_results_device_id", table_name="command_results")
    op.drop_index("ix_command_results_run_id", table_name="command_results")
    op.drop_table("command_results")
    op.drop_index("ix_command_runs_created_at", table_name="command_runs")
    op.drop_table("command_runs")
