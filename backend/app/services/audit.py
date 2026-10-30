"""監査ログ: 操作履歴の記録と、ターミナル画面出力の記録（asciicast v2）

操作履歴は API の処理と同じトランザクションで保存する（処理が失敗してロールバックされたら履歴も残らない）。
ログイン失敗のように処理自体が失敗する操作は、record_now() で個別に保存する。
"""
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.timeutil import utcnow
from app.models.audit import AuditLog, TerminalSession
from app.models.user import User

logger = logging.getLogger(__name__)

# 画面表示用のラベル（フロントエンドの一覧にも同じ表を持つ）
ACTIONS = {
    "auth.login": "ログイン",
    "auth.login_failed": "ログイン失敗",
    "auth.password_change": "パスワード変更",
    "user.create": "ユーザー作成",
    "user.update": "ユーザー変更",
    "user.delete": "ユーザー削除",
    "device.create": "機器登録",
    "device.update": "機器変更",
    "device.delete": "機器削除",
    "device_group.create": "グループ作成",
    "device_group.update": "グループ変更",
    "device_group.delete": "グループ削除",
    "jump_host.create": "踏み台登録",
    "jump_host.update": "踏み台変更",
    "jump_host.delete": "踏み台削除",
    "schedule.create": "スケジュール作成",
    "schedule.update": "スケジュール変更",
    "schedule.delete": "スケジュール削除",
    "collect.run": "収集の実行",
    "terminal.open": "ターミナル接続",
    "terminal.close": "ターミナル切断",
    "topology.create": "構成図作成",
    "topology.update": "構成図変更",
    "topology.delete": "構成図削除",
    "compliance.rule_create": "ルール作成",
    "compliance.rule_update": "ルール変更",
    "compliance.rule_delete": "ルール削除",
    "compliance.run": "再検査",
    "ping.target_create": "Ping対象の追加",
    "ping.target_update": "Ping対象の変更",
    "ping.target_delete": "Ping対象の削除",
    "audit.view_recording": "ターミナル記録の閲覧",
}

MAX_DETAIL_LENGTH = 4000


def client_ip(request: Request | None) -> str | None:
    # uvicorn の --proxy-headers により、nginx 経由でも request.client は利用者の IP になる
    return request.client.host if request is not None and request.client else None


def _detail_json(detail: dict | None) -> str | None:
    if not detail:
        return None
    text = json.dumps(detail, ensure_ascii=False, default=str)
    return text[:MAX_DETAIL_LENGTH]


def make_log(
    action: str,
    *,
    user: User | None = None,
    username: str | None = None,
    ip: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    target_name: str | None = None,
    detail: dict | None = None,
    success: bool = True,
) -> AuditLog:
    return AuditLog(
        at=utcnow(),
        user_id=user.id if user else None,
        username=user.username if user else username,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_name=(target_name or "")[:256] or None,
        detail=_detail_json(detail),
        ip=ip,
        success=success,
    )


class Audit:
    """API から操作履歴を追加する。保存はエンドポイントの commit と一緒に行われる"""

    def __init__(self, db: AsyncSession, user: User, ip: str | None):
        self.db = db
        self.user = user
        self.ip = ip

    def __call__(
        self,
        action: str,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        target_name: str | None = None,
        detail: dict | None = None,
        success: bool = True,
    ) -> None:
        self.db.add(
            make_log(
                action, user=self.user, ip=self.ip, target_type=target_type, target_id=target_id,
                target_name=target_name, detail=detail, success=success,
            )
        )


async def get_audit(
    request: Request, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> Audit:
    """使い方: audit: Audit = Depends(get_audit) → audit("device.update", target_type="device", ...)"""
    return Audit(db, user, client_ip(request))


async def record_now(db: AsyncSession, log: AuditLog) -> None:
    """処理とは別に、すぐ保存する（ログイン失敗など）"""
    db.add(log)
    await db.commit()


def changed_fields(payload: dict, secret_fields: set[str] = frozenset()) -> dict:
    """変更内容を履歴用にまとめる。秘密情報は「変更した」ことだけを残す"""
    out = {}
    for k, v in payload.items():
        if k in secret_fields:
            if v:
                out[k] = "（変更）"
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------- ターミナルの記録


class TerminalRecorder:
    """ターミナルの画面出力を asciicast v2 形式で記録する（asciinema で再生できる形式）

    キー入力は記録しない（enable のパスワードなど、画面に表示されない秘密の入力が含まれるため）。
    入力したコマンドは機器側のエコーとして画面出力に残る。
    """

    def __init__(self, session_id: str, started: datetime, cols: int, rows: int, title: str):
        rel = Path(started.strftime("%Y/%m")) / f"{session_id}.cast"
        self.rel_path = str(rel)
        self.path = Path(settings.TERMINAL_LOG_PATH) / rel
        self.start = time.monotonic()
        self.bytes = 0
        self.truncated = False
        self._lock = threading.Lock()
        self._f = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._f = open(self.path, "w", encoding="utf-8")
            header = {"version": 2, "width": cols, "height": rows, "timestamp": int(started.timestamp()), "title": title}
            self._f.write(json.dumps(header, ensure_ascii=False) + "\n")
            self._f.flush()
        except OSError as e:
            logger.error("ターミナルの記録ファイルを作成できません (%s): %s", self.path, e)
            self._f = None

    @property
    def available(self) -> bool:
        return self._f is not None

    def _event(self, kind: str, data: str) -> None:
        if self._f is None:
            return
        with self._lock:
            if self.truncated or self._f is None:
                return
            line = json.dumps([round(time.monotonic() - self.start, 3), kind, data], ensure_ascii=False) + "\n"
            size = len(line.encode("utf-8"))
            if self.bytes + size > settings.TERMINAL_LOG_MAX_BYTES:
                self.truncated = True
                note = "\r\n[記録の上限に達したため、これ以降は記録していません]\r\n"
                self._f.write(json.dumps([round(time.monotonic() - self.start, 3), "o", note], ensure_ascii=False) + "\n")
                self._f.flush()
                return
            self._f.write(line)
            self.bytes += size
            self._f.flush()

    def output(self, text: str) -> None:
        self._event("o", text)

    def resize(self, cols: int, rows: int) -> None:
        self._event("r", f"{cols}x{rows}")

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                try:
                    self._f.close()
                except OSError:
                    pass
                self._f = None


def recording_path(session: TerminalSession) -> Path | None:
    if not session.log_file:
        return None
    base = Path(settings.TERMINAL_LOG_PATH).resolve()
    p = (base / session.log_file).resolve()
    # DB の値が書き換えられても記録ディレクトリの外は読まない
    if base not in p.parents:
        return None
    return p


# ---------------------------------------------------------------- 保持期間


async def purge_old(db: AsyncSession, now: datetime | None = None) -> dict:
    """保持期間を過ぎた操作履歴・ターミナル記録を削除する（worker から毎日実行）"""
    now = now or utcnow()
    result = {"audit_logs": 0, "terminal_sessions": 0}
    if settings.AUDIT_LOG_RETENTION_DAYS:
        cutoff = now - timedelta(days=settings.AUDIT_LOG_RETENTION_DAYS)
        r = await db.execute(delete(AuditLog).where(AuditLog.at < cutoff))
        result["audit_logs"] = r.rowcount or 0
    if settings.TERMINAL_LOG_RETENTION_DAYS:
        cutoff = now - timedelta(days=settings.TERMINAL_LOG_RETENTION_DAYS)
        old = (await db.execute(select(TerminalSession).where(TerminalSession.started_at < cutoff))).scalars().all()
        for s in old:
            p = recording_path(s)
            if p is not None:
                try:
                    p.unlink(missing_ok=True)
                except OSError as e:
                    logger.warning("ターミナル記録を削除できません (%s): %s", p, e)
            await db.delete(s)
        result["terminal_sessions"] = len(old)
    await db.commit()
    return result
