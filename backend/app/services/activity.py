"""アクティビティログ: システムで起きたこと（収集の結果・スケジュールの実行・違反の発生・通知の送信など）を記録する

利用者の操作は監査ログ（app/services/audit.py）に記録する。こちらは処理の結果・出来事。
記録は呼び出し側のトランザクションに追加する（commit は呼び出し側）。
"""
import json

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timeutil import utcnow
from app.models.activity import ActivityLog

# 画面表示用のラベルと既定の重要度（フロントエンドは /api/activity/events から取得する）
EVENTS: dict[str, tuple[str, str]] = {
    "collect.changed": ("収集（変更あり）", "info"),
    "collect.unchanged": ("収集（変更なし）", "info"),
    "collect.first": ("収集（初回取得）", "info"),
    "collect.failed": ("収集失敗", "error"),
    "collect.skipped": ("収集スキップ", "warning"),
    "collect.batch": ("一括収集の開始", "info"),
    "schedule.run": ("スケジュール実行", "info"),
    "schedule.invalid": ("スケジュールの設定エラー", "error"),
    "compliance.violation": ("違反の発生", "warning"),
    "compliance.resolved": ("違反の解消", "info"),
    "compliance.exempted": ("違反の除外（例外）", "info"),
    "compliance.exception_expired": ("例外の期限切れ", "info"),
    "compliance.summary": ("検査結果の変化", "info"),
    "compliance.run": ("コンプライアンスチェックの実行", "info"),
    "notify.sent": ("通知の送信", "info"),
    "notify.failed": ("通知の失敗", "error"),
    "system.purge": ("古いログの削除", "info"),
}
CATEGORIES = {
    "collect": "収集", "schedule": "スケジュール", "compliance": "コンプライアンス", "notify": "通知", "system": "システム",
}
LEVELS = ("info", "warning", "error")
SYSTEM_ACTOR = "システム"
MAX_DETAIL_LENGTH = 4000


def make_activity(
    event: str,
    message: str,
    *,
    level: str | None = None,
    device_id: str | None = None,
    device_name: str | None = None,
    detail: dict | None = None,
    actor: str | None = None,
    ref: str | None = None,
) -> ActivityLog:
    return ActivityLog(
        at=utcnow(),
        category=event.split(".", 1)[0],
        event=event,
        level=level or EVENTS.get(event, ("", "info"))[1],
        device_id=device_id,
        device_name=(device_name or "")[:128] or None,
        message=message[:1000],
        detail=json.dumps(detail, ensure_ascii=False, default=str)[:MAX_DETAIL_LENGTH] if detail else None,
        actor=(actor or SYSTEM_ACTOR)[:160],
        ref=ref[:64] if ref else None,
    )


def record(db: AsyncSession, event: str, message: str, **kw) -> ActivityLog:
    log = make_activity(event, message, **kw)
    db.add(log)
    return log
