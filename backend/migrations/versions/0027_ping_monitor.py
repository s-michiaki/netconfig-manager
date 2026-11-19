"""Ping監視の常時監視: 監視する対象（ping_monitors）・結果の履歴（ping_results）・通知の種類（on_ping）

Revision ID: 0027_ping_monitor
Revises: 0026_notify_inventory
"""
import sqlalchemy as sa
from alembic import op

revision = "0027_ping_monitor"
down_revision = "0026_notify_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 対象のキーは画面の Ping監視と同じ（d:<機器ID> / t:<追加IPのID>）
    op.create_table(
        "ping_monitors",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "ping_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("rtt", sa.Float(), nullable=True),  # 応答時間（ms）。応答なしは NULL
    )
    op.create_index("ix_ping_results_key_at", "ping_results", ["key", "at"])
    op.create_index("ix_ping_results_at", "ping_results", ["at"])
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_ping", sa.Boolean(), nullable=False, server_default=sa.false()))
    # 既存の設定は「システムの異常」を受け取っているものだけ有効にする（どちらも「止まったこと」の知らせのため）
    op.execute("UPDATE notification_settings SET on_ping = on_system")


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_ping")
    op.drop_index("ix_ping_results_at", table_name="ping_results")
    op.drop_index("ix_ping_results_key_at", table_name="ping_results")
    op.drop_table("ping_results")
    op.drop_table("ping_monitors")
