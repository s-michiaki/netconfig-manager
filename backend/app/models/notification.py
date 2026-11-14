"""コンフィグ変更の通知: ユーザーグループと通知設定

- ユーザーグループ（チーム）は複数作成でき、ユーザーは複数のグループに所属できる
- 通知設定はユーザーごと・ユーザーグループごとに1つ（owner_type + owner_id）
  - ユーザーの mode: inherit = 所属グループの設定を使う（既定。設定が無い場合も同じ）
                     custom  = 自分の通知先・対象を使う / off = 通知しない
- 対象は機器のグループ（device_group_ids、未分類は include_ungrouped）。all_devices なら全機器
- 通知する内容は on_change（コンフィグの変更）/ on_violation（コンプライアンス違反の発生）/ on_failure（収集の失敗）/
  on_system（システムの異常。対象の機器グループに関係なく送る）
- Webhook URL は秘密情報（知っていれば誰でも投稿できる）なので暗号化して保存する
"""
import json
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy import false as sa_false
from sqlalchemy import true as sa_true
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedString
from app.core.timeutil import utcnow
from app.models.base import Base


class UserGroup(Base):
    __tablename__ = "user_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class UserGroupMember(Base):
    __tablename__ = "user_group_members"

    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_groups.id", name="fk_ugm_group_id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", name="fk_ugm_user_id", ondelete="CASCADE"), primary_key=True
    )


class NotificationSetting(Base):
    __tablename__ = "notification_settings"
    __table_args__ = (UniqueConstraint("owner_type", "owner_id", name="uq_notification_owner"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_type: Mapped[str] = mapped_column(String(16), nullable=False)  # user / group
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # ユーザー: inherit / custom / off、グループ: custom（有効）/ off（無効）
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="inherit")
    discord_webhook: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    slack_webhook: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    all_devices: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    device_group_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON の配列
    include_ungrouped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    on_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_true())
    on_violation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    # システムの異常（worker・スケジューラーの停止、長期間収集できていない機器、証明書の期限など）。機器のグループに関係なく送る
    on_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_true())
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def group_ids(self) -> list[str]:
        try:
            v = json.loads(self.device_group_ids or "[]")
        except ValueError:
            return []
        return [x for x in v if isinstance(x, str)]

    def wants(self, event: str) -> bool:
        """この設定で通知する内容か（change / violation / failure / system）"""
        return bool(getattr(self, f"on_{event}", False))

    def matches(self, device_group_id: str | None) -> bool:
        """この設定の対象に、指定したグループの機器が含まれるか"""
        if self.all_devices:
            return True
        if device_group_id is None:
            return self.include_ungrouped
        return device_group_id in self.group_ids
