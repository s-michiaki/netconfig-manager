"""監査ログの閲覧 API（管理者のみ）"""
from datetime import datetime

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import MAX_EXPORT_ROWS, csv_response, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.audit import AuditLog, TerminalSession
from app.services.audit import ACTIONS, Audit, get_audit, read_recording, recording_path

router = APIRouter()


class AuditLogItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    at: datetime
    username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    target_name: str | None
    detail: str | None
    ip: str | None
    success: bool


class AuditLogPage(BaseModel):
    items: list[AuditLogItem]
    total: int


class TerminalSessionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str | None
    device_id: str | None
    device_name: str | None
    device_host: str | None
    via: str | None
    ip: str | None
    started_at: datetime
    ended_at: datetime | None
    end_reason: str | None
    bytes_out: int
    truncated: bool
    has_recording: bool = False


class TerminalSessionPage(BaseModel):
    items: list[TerminalSessionItem]
    total: int


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/actions", dependencies=[Depends(require(Perm.AUDIT_READ))])
async def list_actions() -> dict[str, str]:
    """操作の種類と表示名"""
    return ACTIONS


def _log_conditions(username, action, q, failed_only, since, until) -> list:
    cond = []
    if username:
        cond.append(AuditLog.username == username)
    if action:
        cond.append(AuditLog.action.startswith(action) if action.endswith(".") else AuditLog.action == action)
    if q:
        pat = _like(q)
        cond.append(or_(AuditLog.target_name.like(pat, escape="\\"), AuditLog.detail.like(pat, escape="\\"),
                        AuditLog.ip.like(pat, escape="\\")))
    if failed_only:
        cond.append(AuditLog.success.is_(False))
    if since:
        cond.append(AuditLog.at >= since.replace(tzinfo=None))
    if until:
        cond.append(AuditLog.at < until.replace(tzinfo=None))
    return cond


@router.get("/logs", response_model=AuditLogPage, dependencies=[Depends(require(Perm.AUDIT_READ))])
async def list_logs(
    username: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64, description="完全一致、または「device.」のような前方一致"),
    q: str | None = Query(None, max_length=200, description="対象名・詳細・IP の部分一致"),
    failed_only: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    cond = _log_conditions(username, action, q, failed_only, since, until)
    total = (await db.execute(select(func.count()).select_from(AuditLog).where(*cond))).scalar_one()
    rows = (
        await db.execute(select(AuditLog).where(*cond).order_by(AuditLog.at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    return AuditLogPage(items=[AuditLogItem.model_validate(r) for r in rows], total=total)


@router.get("/logs/export", dependencies=[Depends(require(Perm.AUDIT_READ))])
async def export_logs(
    username: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=200),
    failed_only: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """操作履歴を CSV で出力する（絞り込みは一覧と同じ。新しい順に最大 MAX_EXPORT_ROWS 件）"""
    cond = _log_conditions(username, action, q, failed_only, since, until)
    rows = (
        await db.execute(select(AuditLog).where(*cond).order_by(AuditLog.at.desc()).limit(MAX_EXPORT_ROWS))
    ).scalars().all()
    # 出力したこと自体も残す（記録が持ち出されたことを追えるように）
    audit("audit.export", detail={"kind": "操作履歴", "rows": len(rows), "username": username, "action": action,
                                  "q": q, "failed_only": failed_only or None,
                                  "since": since.isoformat() if since else None,
                                  "until": until.isoformat() if until else None})
    await db.commit()
    header = [f"日時（{settings.TIMEZONE}）", "ユーザー", "操作", "操作コード", "対象の種類", "対象", "対象ID", "詳細", "接続元IP", "結果"]
    data = [[r.at, r.username, ACTIONS.get(r.action, r.action), r.action, r.target_type, r.target_name, r.target_id,
             r.detail, r.ip, "成功" if r.success else "失敗"] for r in rows]
    return csv_response(header, data, export_name("audit_logs"))


def _session_conditions(username, device, since, until) -> list:
    cond = []
    if username:
        cond.append(TerminalSession.username == username)
    if device:
        pat = _like(device)
        cond.append(or_(TerminalSession.device_name.like(pat, escape="\\"),
                        TerminalSession.device_host.like(pat, escape="\\")))
    if since:
        cond.append(TerminalSession.started_at >= since.replace(tzinfo=None))
    if until:
        cond.append(TerminalSession.started_at < until.replace(tzinfo=None))
    return cond


@router.get(
    "/terminal-sessions", response_model=TerminalSessionPage, dependencies=[Depends(require(Perm.AUDIT_READ))]
)
async def list_terminal_sessions(
    username: str | None = Query(None, max_length=64),
    device: str | None = Query(None, max_length=128, description="機器名・ホストの部分一致"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    cond = _session_conditions(username, device, since, until)
    total = (await db.execute(select(func.count()).select_from(TerminalSession).where(*cond))).scalar_one()
    rows = (
        await db.execute(
            select(TerminalSession).where(*cond).order_by(TerminalSession.started_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    items = []
    for r in rows:
        item = TerminalSessionItem.model_validate(r)
        p = recording_path(r)
        item.has_recording = bool(p and p.is_file())
        items.append(item)
    return TerminalSessionPage(items=items, total=total)


@router.get("/terminal-sessions/export", dependencies=[Depends(require(Perm.AUDIT_READ))])
async def export_terminal_sessions(
    username: str | None = Query(None, max_length=64),
    device: str | None = Query(None, max_length=128),
    since: datetime | None = None,
    until: datetime | None = None,
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """ターミナルの接続記録（一覧）を CSV で出力する。画面の記録そのものは含めない"""
    cond = _session_conditions(username, device, since, until)
    rows = (
        await db.execute(select(TerminalSession).where(*cond).order_by(TerminalSession.started_at.desc())
                         .limit(MAX_EXPORT_ROWS))
    ).scalars().all()
    audit("audit.export", detail={"kind": "ターミナルの記録", "rows": len(rows), "username": username,
                                  "device": device})
    await db.commit()
    header = [f"開始（{settings.TIMEZONE}）", f"終了（{settings.TIMEZONE}）", "接続秒数", "ユーザー", "機器", "ホスト",
              "経由", "接続元IP", "終了理由", "出力バイト数", "記録の打ち切り"]
    data = [[r.started_at, r.ended_at,
             int((r.ended_at - r.started_at).total_seconds()) if r.ended_at else None,
             r.username, r.device_name, r.device_host, r.via, r.ip, r.end_reason, r.bytes_out, r.truncated]
            for r in rows]
    return csv_response(header, data, export_name("terminal_sessions"))


@router.get(
    "/terminal-sessions/{session_id}/recording",
    response_class=PlainTextResponse,
    dependencies=[Depends(require(Perm.AUDIT_READ))],
)
async def get_recording(session_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """画面出力の記録（asciicast v2 形式。asciinema でも再生できる）"""
    s = await db.get(TerminalSession, session_id)
    p = recording_path(s) if s else None
    if s is None or p is None or not p.is_file():
        raise HTTPException(status_code=404, detail="記録が見つかりません")
    try:
        text = await run_in_threadpool(read_recording, p)
    except InvalidToken as e:
        raise HTTPException(status_code=500, detail="記録を復号できません（DEVICE_ENCRYPTION_KEY が記録時と違う可能性があります）") from e
    # 記録を見たこと自体も残す（機器の画面には機密情報が含まれ得るため）
    audit("audit.view_recording", target_type="terminal_session", target_id=s.id,
          target_name=f"{s.username}@{s.device_name}")
    await db.commit()
    return PlainTextResponse(text, media_type="application/x-asciicast")
