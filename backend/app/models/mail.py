"""メール通知の送信設定（メールサーバー）。システム全体で 1 件（id = "default"）

auth（認証方式）
  none        : 認証しない（社内のリレー）
  password    : SMTP Auth（ユーザー名＋パスワード。アプリパスワードを含む）
  microsoft   : Microsoft 365 の OAuth 2.0（アプリの登録＋client credentials。username は送信に使うメールボックス）
  google_sa   : Google Workspace のサービスアカウント（ドメイン全体の委任。username は送信者として振る舞うユーザー）
  google_user : Google アカウントの同意（OAuth クライアント＋更新用トークン。個人の Gmail でも使える）

パスワード・クライアントシークレット・サービスアカウントの鍵・更新用トークンは DEVICE_ENCRYPTION_KEY で暗号化して保存する
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedString, EncryptedText
from app.core.timeutil import utcnow
from app.models.base import Base

AUTH_TYPES = ("none", "password", "microsoft", "google_sa", "google_user")
SECURITY_TYPES = ("starttls", "ssl", "none")


class MailServer(Base):
    __tablename__ = "mail_server"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="default")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auth: Mapped[str] = mapped_column(String(16), nullable=False, default="password")
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=587)
    security: Mapped[str] = mapped_column(String(16), nullable=False, default="starttls")
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # 証明書を確認する
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    from_address: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    from_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    subject_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 宛先に使えるドメイン（カンマ区切り。空なら制限しない）。閲覧者も自分の宛先を登録できるため、社外へ送らせない
    allowed_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Microsoft 365
    ms_tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ms_client_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ms_client_secret: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    # Google（サービスアカウントの鍵の JSON、または OAuth クライアント＋更新用トークン）
    google_sa_json: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    google_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    google_client_secret: Mapped[str | None] = mapped_column(EncryptedString(1024), nullable=True)
    google_refresh_token: Mapped[str | None] = mapped_column(EncryptedString(2048), nullable=True)
    google_authorized_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
