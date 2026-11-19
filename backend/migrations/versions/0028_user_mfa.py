"""users に 2 段階認証（ワンタイムパスワード）の列を追加

Revision ID: 0028_user_mfa
Revises: 0027_ping_monitor
"""
import sqlalchemy as sa
from alembic import op

revision = "0028_user_mfa"
down_revision = "0027_ping_monitor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        # 秘密鍵は DEVICE_ENCRYPTION_KEY で暗号化して保存する（EncryptedString）。設定中（未確認）の鍵は mfa_pending
        batch.add_column(sa.Column("mfa_secret", sa.String(512), nullable=True))
        batch.add_column(sa.Column("mfa_pending", sa.String(512), nullable=True))
        batch.add_column(sa.Column("mfa_last_step", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("mfa_recovery", sa.Text(), nullable=True))  # 予備コードのハッシュ（JSON の配列）
        batch.add_column(sa.Column("mfa_enabled_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        for c in ("mfa_enabled_at", "mfa_recovery", "mfa_last_step", "mfa_pending", "mfa_secret", "mfa_enabled"):
            batch.drop_column(c)
