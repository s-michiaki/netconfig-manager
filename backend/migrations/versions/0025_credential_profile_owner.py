"""認証情報プロファイルに所有者（owner_id）と共有範囲（credential_profile_access）を追加

管理者なら誰のプロファイルでも編集・削除・割り当てができたのを、所有者と、所有者が指定した
ユーザーグループに限る。既存のプロファイルの所有者は admin（いなければ最初に作られた管理者）にする。

Revision ID: 0025_credential_profile_owner
Revises: 0024_credential_profiles
"""
import sqlalchemy as sa
from alembic import op

revision = "0025_credential_profile_owner"
down_revision = "0024_credential_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("credential_profiles") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_credential_profiles_owner_id", "users", ["owner_id"], ["id"], ondelete="SET NULL")
    op.create_table(
        "credential_profile_access",
        sa.Column("profile_id", sa.String(36),
                  sa.ForeignKey("credential_profiles.id", name="fk_cpa_profile_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("user_groups.id", name="fk_cpa_group_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("access", sa.String(8), nullable=False),
    )
    # 既存のプロファイルの所有者: ユーザー名 admin。いなければ、最初に作られた管理者
    conn = op.get_bind()
    owner = conn.execute(sa.text("SELECT id FROM users WHERE username = 'admin'")).scalar()
    if owner is None:
        owner = conn.execute(sa.text("SELECT id FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1")).scalar()
    if owner is not None:
        conn.execute(sa.text("UPDATE credential_profiles SET owner_id = :o WHERE owner_id IS NULL"), {"o": owner})


def downgrade() -> None:
    op.drop_table("credential_profile_access")
    with op.batch_alter_table("credential_profiles") as batch:
        batch.drop_constraint("fk_credential_profiles_owner_id", type_="foreignkey")
        batch.drop_column("owner_id")
