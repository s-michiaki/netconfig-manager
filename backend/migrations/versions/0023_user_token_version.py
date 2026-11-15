"""users.token_version: 管理者による強制ログアウト用の番号

トークンに発行時の番号（tv）を入れ、照合で一致しないトークンを無効にする。
強制ログアウト・無効化で番号を 1 つ上げる。既存の行と、番号を持たない以前のトークンは 0 として扱う

Revision ID: 0023_user_token_version
Revises: 0022_config_comments
"""
import sqlalchemy as sa
from alembic import op

revision = "0023_user_token_version"
down_revision = "0022_config_comments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("token_version")
