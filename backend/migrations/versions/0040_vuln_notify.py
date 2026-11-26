"""脆弱性（J-2）: 通知（on_vuln・通知済みの印）、候補の理由、Fortinet の勧告の条件つき GET の列

- notification_settings.on_vuln（既定 false）
- vuln_matches.reason（候補の理由の符号）・notified_at（通知済み）。既存の照合結果のうち通知の条件に当たるものは
  「通知済み」にする（この版に上げた直後に、前からある該当がまとめて通知されないように）
- vuln_advisories.doc_url・etag・last_modified・checked_at（勧告 1 件ずつの文書の URL と、条件つき GET の条件）
- vuln_sources.etag・last_modified（一覧の条件つき GET の条件）

Revision ID: 0040_vuln_notify
Revises: 0039_rule_remediation
"""
import sqlalchemy as sa
from alembic import op

revision = "0040_vuln_notify"
down_revision = "0039_rule_remediation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("notification_settings") as batch:
        batch.add_column(sa.Column("on_vuln", sa.Boolean(), nullable=False, server_default=sa.false()))
    with op.batch_alter_table("vuln_matches") as batch:
        batch.add_column(sa.Column("reason", sa.String(24), nullable=True))
        batch.add_column(sa.Column("notified_at", sa.DateTime(), nullable=True))
    # 通知の条件（確定で、重大度が高以上か悪用確認済み）に当たる既存の行だけに印を付ける（候補・中以下の行は、あとで確定・
    # 悪用確認済みになったときに通知されるよう、印を付けない）
    adv = sa.table("vuln_advisories", sa.column("id", sa.String), sa.column("severity", sa.String),
                   sa.column("kev", sa.Boolean))
    vm = sa.table("vuln_matches", sa.column("advisory_id", sa.String), sa.column("confidence", sa.String),
                  sa.column("notified_at", sa.DateTime), sa.column("last_seen", sa.DateTime))
    eligible = sa.select(adv.c.id).where(sa.or_(adv.c.severity.in_(("critical", "high")), adv.c.kev == sa.true()))
    op.execute(vm.update().where(vm.c.confidence == "confirmed", vm.c.advisory_id.in_(eligible))
               .values(notified_at=vm.c.last_seen))
    with op.batch_alter_table("vuln_advisories") as batch:
        batch.add_column(sa.Column("doc_url", sa.String(512), nullable=True))
        batch.add_column(sa.Column("etag", sa.String(256), nullable=True))
        batch.add_column(sa.Column("last_modified", sa.String(64), nullable=True))
        batch.add_column(sa.Column("checked_at", sa.DateTime(), nullable=True))
    with op.batch_alter_table("vuln_sources") as batch:
        batch.add_column(sa.Column("etag", sa.String(256), nullable=True))
        batch.add_column(sa.Column("last_modified", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("vuln_sources") as batch:
        batch.drop_column("last_modified")
        batch.drop_column("etag")
    with op.batch_alter_table("vuln_advisories") as batch:
        batch.drop_column("checked_at")
        batch.drop_column("last_modified")
        batch.drop_column("etag")
        batch.drop_column("doc_url")
    with op.batch_alter_table("vuln_matches") as batch:
        batch.drop_column("notified_at")
        batch.drop_column("reason")
    with op.batch_alter_table("notification_settings") as batch:
        batch.drop_column("on_vuln")
