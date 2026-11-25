"""notification_settings に Teams の Webhook（ワークフローの URL。暗号化して保存）を追加

Revision ID: 0036_teams_webhook
Revises: 0035_api_tokens
"""
import sqlalchemy as sa
from alembic import op

revision = "0036_teams_webhook"
down_revision = "0035_api_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        # URL は sig などを含み長い。暗号化すると 1.4 倍ほどになるので 2048
        batch.add_column(sa.Column("teams_webhook", sa.String(2048), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("teams_webhook")
