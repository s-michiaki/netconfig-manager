import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.models.base import Base


class ActivityLog(Base):
    """アクティビティログ（システムで起きたこと: 収集の結果・スケジュールの実行・違反の発生など）

    利用者の操作は監査ログ（AuditLog）に記録する。こちらは処理の結果・出来事の記録。
    機器が削除されても残るよう、外部キーは張らずに名前も一緒に保存する
    """

    __tablename__ = "activity_logs"
    __table_args__ = (
        Index("ix_activity_logs_at", "at"),
        Index("ix_activity_logs_device_id", "device_id"),
        Index("ix_activity_logs_ref", "ref"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    category: Mapped[str] = mapped_column(String(32), nullable=False)  # collect / schedule / compliance / notify / system
    event: Mapped[str] = mapped_column(String(64), nullable=False)  # 例: collect.changed（一覧は app/services/activity.py）
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")  # info / warning / error
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    device_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON（秘密情報は含めない）
    # きっかけ（手動ならユーザー名、スケジュールなら「スケジュール: 名前」、自動なら「システム」）
    actor: Mapped[str | None] = mapped_column(String(160), nullable=True)
    # 関連づけ用の ID（収集の実行 = タスク ID。監査ログの「収集の実行」から結果をたどるのに使う）
    ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
