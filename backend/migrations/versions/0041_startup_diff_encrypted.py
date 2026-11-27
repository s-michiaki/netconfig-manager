"""devices.startup_diff（startup → running の差分）を暗号化して保存する（EncryptedText）

列の型（TEXT）は変わらない。暗号化はアプリ（app/core/crypto.py の EncryptedText）が書き込み時に行い、読み込み時は
「enc:」で始まらない値（この版より前の平文）もそのまま読める。既存の平文の値は、backend の起動時
（app/main.py の _encrypt_legacy_startup_diffs。機器パスワードの移行と同じ）と、次に収集して比べ直したときに
暗号化して書き直される（マイグレーションの中では DEVICE_ENCRYPTION_KEY を使わない。鍵を使う前例が無く、
鍵の誤りでマイグレーションが止まる・中途半端に書き換わるのを避けるため）。

downgrade: 前の版は暗号化された値を復号できず「enc:...」をそのまま差分として出してしまうため、暗号化された差分だけを
消す（NULL。状態・行数は残る。次の収集で平文の差分が入る）。平文のままの行は残す

Revision ID: 0041_startup_diff_encrypted
Revises: 0040_vuln_notify
"""
import sqlalchemy as sa
from alembic import op

revision = "0041_startup_diff_encrypted"
down_revision = "0040_vuln_notify"
branch_labels = None
depends_on = None

_devices = sa.table("devices", sa.column("startup_diff", sa.Text))


def upgrade() -> None:
    # 型は TEXT のまま（EncryptedText の impl は Text）。データの書き換えもしない（上の説明のとおり）
    pass


def downgrade() -> None:
    op.execute(_devices.update().where(_devices.c.startup_diff.like("enc:%")).values(startup_diff=None))
