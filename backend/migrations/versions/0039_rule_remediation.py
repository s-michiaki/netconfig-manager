"""コンプライアンスのルールに、直し方（remediation）・根拠（reference）・分野（category）を追加する

既存のルールは NULL のまま（ひな形から作ったルールにだけ値が入る）。

Revision ID: 0039_rule_remediation
Revises: 0038_vuln
"""
import sqlalchemy as sa
from alembic import op

revision = "0039_rule_remediation"
down_revision = "0038_vuln"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("compliance_rules") as batch:
        batch.add_column(sa.Column("remediation", sa.Text(), nullable=True))
        batch.add_column(sa.Column("reference", sa.String(255), nullable=True))
        batch.add_column(sa.Column("category", sa.String(32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("compliance_rules") as batch:
        batch.drop_column("category")
        batch.drop_column("reference")
        batch.drop_column("remediation")
