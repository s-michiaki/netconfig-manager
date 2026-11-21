"""メール通知: メールサーバーの設定（mail_server）と、通知設定の宛先（notification_settings.email_to）

Revision ID: 0029_mail
Revises: 0028_user_mfa
"""
import sqlalchemy as sa
from alembic import op

revision = "0029_mail"
down_revision = "0028_user_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 秘密の値（password・ms_client_secret・google_*）は DEVICE_ENCRYPTION_KEY で暗号化して保存する
    op.create_table(
        "mail_server",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("auth", sa.String(16), nullable=False, server_default="password"),
        sa.Column("host", sa.String(255), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False, server_default="587"),
        sa.Column("security", sa.String(16), nullable=False, server_default="starttls"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("password", sa.String(1024), nullable=True),
        sa.Column("from_address", sa.String(255), nullable=False, server_default=""),
        sa.Column("from_name", sa.String(128), nullable=True),
        sa.Column("subject_prefix", sa.String(64), nullable=True),
        sa.Column("allowed_domains", sa.Text(), nullable=True),
        sa.Column("ms_tenant_id", sa.String(128), nullable=True),
        sa.Column("ms_client_id", sa.String(128), nullable=True),
        sa.Column("ms_client_secret", sa.String(1024), nullable=True),
        sa.Column("google_sa_json", sa.Text(), nullable=True),
        sa.Column("google_client_id", sa.String(255), nullable=True),
        sa.Column("google_client_secret", sa.String(1024), nullable=True),
        sa.Column("google_refresh_token", sa.String(2048), nullable=True),
        sa.Column("google_authorized_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("email_to", sa.Text(), nullable=True))  # 宛先（カンマ区切り）


def downgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("email_to")
    op.drop_table("mail_server")
