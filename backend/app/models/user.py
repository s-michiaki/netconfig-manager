import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy import false as sa_false
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedString
from app.core.timeutil import utcnow
from app.models.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # admin / operator / viewer（app/core/permissions.py）
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # トークンに入れて照合する番号。強制ログアウト・無効化で 1 つ上げ、それ以前に発行したトークンを無効にする
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # 2 段階認証（ワンタイムパスワード。app/core/totp.py）。本人が設定し、管理者は解除だけできる
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
    mfa_secret: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)
    mfa_pending: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)  # 設定中（コードの確認前）
    mfa_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 最後に使ったコードの時間枠（再利用の防止）
    mfa_recovery: Mapped[str | None] = mapped_column(Text, nullable=True)  # 予備コードのハッシュ（JSON の配列）
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
