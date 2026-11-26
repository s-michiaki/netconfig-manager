"""コンフィグ変更の通知: ユーザーグループと通知設定

- ユーザーグループ（チーム）は複数作成でき、ユーザーは複数のグループに所属できる
- 通知設定はユーザーごと・ユーザーグループごとに1つ（owner_type + owner_id）
  - ユーザーの mode: inherit = 所属グループの設定を使う（既定。設定が無い場合も同じ）
                     custom  = 自分の通知先・対象を使う / off = 通知しない
- 対象は機器のグループ（device_group_ids、未分類は include_ungrouped）。all_devices なら全機器
- 通知する内容は on_change（コンフィグの変更）/ on_violation（コンプライアンス違反の発生）/ on_failure（収集の失敗）/
  on_system（システムの異常。対象の機器グループに関係なく送る）/ on_inventory（機器情報の変化）/
  on_ping（Ping監視の応答なし・復旧）/ on_drift（基準の世代からのずれ）/ on_unsaved（保存し忘れ）
- 定期レポート（report）: 期間内の状況のまとめを週次・月次で送る（送る内容の選択 on_* とは別。対象の機器の絞り込みは同じ）
- 通知先は Discord / Slack / Teams（ワークフロー）の Webhook と、メールの宛先（email_to。送信の設定は models/mail.py）
- Webhook URL は秘密情報（知っていれば誰でも投稿できる）なので暗号化して保存する
"""
import json
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
    # Teams のワークフロー（Webhook 要求を受信したとき）の URL。sig を含み長いので、暗号化後の長さを見て 2048
    teams_webhook: Mapped[str | None] = mapped_column(EncryptedString(2048), nullable=True)
    # メールの宛先（カンマ区切り。送信はメールサーバーの設定＝mail_server を使う）
    email_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    all_devices: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    device_group_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON の配列
    include_ungrouped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    on_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_true())
    on_violation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    # システムの異常（worker・スケジューラーの停止、長期間収集できていない機器、証明書の期限など）。機器のグループに関係なく送る
    on_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_true())
    # 機器情報の変化（OS バージョン・シリアル番号・モデル・機器側のホスト名）。既存の設定は 0026 で on_change と同じ値にした
    on_inventory: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_false())
    # Ping監視（常時監視）の応答なし・復旧。既存の設定は 0027 で on_system と同じ値にした
    on_ping: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa_false())
    # 基準からのずれ（ずれなし → ずれあり に変わったとき）。既定は無効
    on_drift: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    # 保存し忘れ（startup と running の不一致に変わったとき）。既定は無効
    on_unsaved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    # 定期レポート（services/report.py）。off / weekly / monthly / both。送る日・時刻は REPORT_HOUR（settings.TIMEZONE）
    report: Mapped[str] = mapped_column(String(8), nullable=False, default="off", server_default="off")
    # 種類ごとに、その種類が「無効 → 有効」になった時刻（API が入れる。無効になると NULL）。これより前に終わった期間は送らない
    # （設定した直後に過去の分が届かないように。ほかの種類を足しても止まらない）。
    # updated_at は last_sent_at の更新でも変わるので使わない
    report_week_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    report_month_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
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
        """この設定で通知する内容か（change / violation / failure / system / inventory / ping / drift / unsaved）"""
        return bool(getattr(self, f"on_{event}", False))

    def matches(self, device_group_id: str | None) -> bool:
        """この設定の対象に、指定したグループの機器が含まれるか"""
        if self.all_devices:
            return True
        if device_group_id is None:
            return self.include_ungrouped
        return device_group_id in self.group_ids

    @property
    def report_kinds(self) -> list[str]:
        """送るレポートの種類（week / month）"""
        return {"weekly": ["week"], "monthly": ["month"], "both": ["week", "month"]}.get(self.report, [])

    @property
    def emails(self) -> list[str]:
        return [a.strip() for a in (self.email_to or "").split(",") if a.strip()]


class ReportSend(Base):
    """定期レポートの送信の記録（同じ設定・同じ期間を二重に送らないための印）

    送る前に (setting_id, kind, period_start) の行を作れた worker だけが送る（一意制約。同時に判定しても 1 つだけ）。
    status: sending（送信中）/ sent（送った）/ failed（すべての宛先で失敗。attempts が上限未満なら次の毎時の判定でやり直す）/
    missed（取り戻しの期間を過ぎても送れなかった。アクティビティに 1 回残した）。
    設定を消しても残る（外部キーは張らない）ので、古い行は毎日の掃除で消す
    """

    __tablename__ = "report_sends"
    __table_args__ = (UniqueConstraint("setting_id", "kind", "period_start", name="uq_report_sends_period"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    setting_id: Mapped[str] = mapped_column(String(36), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)  # week / month
    period_start: Mapped[str] = mapped_column(String(10), nullable=False)  # 期間の最初の日（TIMEZONE の日付。YYYY-MM-DD）
    status: Mapped[str] = mapped_column(String(8), nullable=False, default="sending", server_default="sending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    claimed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
