"""認証情報プロファイル（credential_profiles）と devices.credential_profile_id を追加

同じアカウントを使う複数の機器で、ユーザー名・パスワード・enable・SSH 鍵を 1 か所にまとめる。
プロファイルを使う機器は機器側の認証情報を持たないため、devices.username を NULL 可にする
（既存の機器はプロファイルなしのまま、今までどおり機器側の認証情報で接続する）。
外部キーに ondelete は付けない: 使用中のプロファイルは消せない（API でも 409 で断る）。機器の削除には影響しない

Revision ID: 0024_credential_profiles
Revises: 0023_user_token_version
"""
import sqlalchemy as sa
from alembic import op

revision = "0024_credential_profiles"
down_revision = "0023_user_token_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credential_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("username", sa.String(128), nullable=False),
        # 秘密の値は機器と同じく Fernet で暗号化した文字列を入れる
        sa.Column("password", sa.String(256)),
        sa.Column("private_key", sa.Text()),
        sa.Column("key_passphrase", sa.String(256)),
        sa.Column("enable_secret", sa.String(256)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("credential_profile_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_devices_credential_profile_id", "credential_profiles", ["credential_profile_id"], ["id"]
        )
        batch.alter_column("username", existing_type=sa.String(128), nullable=True)


def downgrade() -> None:
    # プロファイルを使っていた機器はユーザー名が NULL なので、空文字で埋めてから NOT NULL に戻す
    # （認証情報はプロファイル側にしか無いため、戻した後はその機器の認証情報を入れ直す必要がある）
    op.execute("UPDATE devices SET username = '' WHERE username IS NULL")
    with op.batch_alter_table("devices") as batch:
        batch.alter_column("username", existing_type=sa.String(128), nullable=False)
        batch.drop_constraint("fk_devices_credential_profile_id", type_="foreignkey")
        batch.drop_column("credential_profile_id")
    op.drop_table("credential_profiles")
