"""モニタリング（試験導入）: snmp_settings / mon_interfaces / if_samples / fw_rule_hits / fw_hit_status

Revision ID: 0019_monitoring
Revises: 0018_notify_events
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_monitoring"
down_revision = "0018_notify_events"
branch_labels = None
depends_on = None

BigId = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "snmp_settings",
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_snmp_settings_device_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.String(4), nullable=False, server_default="2c"),
        sa.Column("port", sa.Integer(), nullable=False, server_default="161"),
        sa.Column("community", sa.String(512)),
        sa.Column("v3_user", sa.String(128)),
        sa.Column("v3_auth_proto", sa.String(16)),
        sa.Column("v3_auth_key", sa.String(512)),
        sa.Column("v3_priv_proto", sa.String(16)),
        sa.Column("v3_priv_key", sa.String(512)),
        sa.Column("last_polled_at", sa.DateTime()),
        sa.Column("last_error", sa.Text()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "mon_interfaces",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_mon_interfaces_device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("alias", sa.String(256)),
        sa.Column("speed_mbps", sa.Integer()),
        sa.Column("oper_up", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_in_octets", sa.BigInteger()),
        sa.Column("last_out_octets", sa.BigInteger()),
        sa.Column("last_at", sa.DateTime()),
        sa.Column("in_bps", sa.Float()),
        sa.Column("out_bps", sa.Float()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("device_id", "if_index", name="uq_mon_interfaces_device_ifindex"),
    )
    op.create_index("ix_mon_interfaces_device_id", "mon_interfaces", ["device_id"])
    op.create_table(
        "if_samples",
        sa.Column("id", BigId, primary_key=True, autoincrement=True),
        sa.Column("interface_id", sa.String(36),
                  sa.ForeignKey("mon_interfaces.id", name="fk_if_samples_interface_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("in_bps", sa.Float(), nullable=False),
        sa.Column("out_bps", sa.Float(), nullable=False),
    )
    op.create_index("ix_if_samples_interface_at", "if_samples", ["interface_id", "at"])
    op.create_index("ix_if_samples_at", "if_samples", ["at"])
    op.create_table(
        "fw_rule_hits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_fw_rule_hits_device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(64)),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("hit_count", sa.BigInteger()),
        sa.Column("prev_hit_count", sa.BigInteger()),
        sa.Column("prev_collected_at", sa.DateTime()),
        sa.Column("packets", sa.BigInteger()),
        sa.Column("bytes", sa.BigInteger()),
        sa.Column("first_hit_at", sa.DateTime()),
        sa.Column("last_hit_at", sa.DateTime()),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_fw_rule_hits_device_id", "fw_rule_hits", ["device_id"])
    op.create_table(
        "fw_hit_status",
        sa.Column("device_id", sa.String(36),
                  sa.ForeignKey("devices.id", name="fk_fw_hit_status_device_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text()),
        sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("raw_output", sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("fw_hit_status")
    op.drop_index("ix_fw_rule_hits_device_id", table_name="fw_rule_hits")
    op.drop_table("fw_rule_hits")
    op.drop_index("ix_if_samples_at", table_name="if_samples")
    op.drop_index("ix_if_samples_interface_at", table_name="if_samples")
    op.drop_table("if_samples")
    op.drop_index("ix_mon_interfaces_device_id", table_name="mon_interfaces")
    op.drop_table("mon_interfaces")
    op.drop_table("snmp_settings")
