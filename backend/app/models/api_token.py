"""API トークン（スクリプト・ほかのシステムから API を使うための、本人が発行するトークン）

トークンの値（平文）は発行の応答で 1 回だけ返し、DB には SHA-256 のハッシュだけを置く。
検証・権限の判定は app/api/deps.py、発行・失効は app/api/api_tokens.py と app/services/api_tokens.py
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (Index("ix_api_tokens_user_id", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", name="fk_api_tokens_user_id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)  # 用途のメモ（例: 夜間のバックアップ確認）
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # SHA-256 の 16 進
    prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # 表示用の先頭（ncm_ と 8 文字。見分けるためだけ）
    scope: Mapped[str] = mapped_column(String(8), nullable=False)  # read / full（app/core/permissions.py）
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # 1 分に 1 回まで更新
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
