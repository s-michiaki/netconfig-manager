"""監査ログの閲覧 API（管理者のみ）"""
import time
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import MAX_EXPORT_ROWS, content_disposition, csv_response, export_name, safe_filename
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.audit import AuditLog, TerminalSession
from app.services import config_search
from app.services.audit import ACTIONS, Audit, get_audit, read_recording, read_text_log, recording_path, text_path

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
    has_text: bool = False  # 読める形のテキスト（色や制御文字を除いたもの）があるか


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
    header = [f"日時（{settings.TIMEZONE}）", "ユーザー", "操作", "操作コード", "対象の種類", "対象", "対象ID", "詳細",
              "接続元IP", "結果"]
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
        t = text_path(r)
        item.has_text = bool(t and t.is_file())
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
        raise HTTPException(
            status_code=500, detail="記録を復号できません（DEVICE_ENCRYPTION_KEY が記録時と違う可能性があります）"
        ) from e
    # 記録を見たこと自体も残す（機器の画面には機密情報が含まれ得るため）
    audit("audit.view_recording", target_type="terminal_session", target_id=s.id,
          target_name=f"{s.username}@{s.device_name}")
    await db.commit()
    return PlainTextResponse(text, media_type="application/x-asciicast")


@router.get(
    "/terminal-sessions/{session_id}/text",
    response_class=PlainTextResponse,
    dependencies=[Depends(require(Perm.AUDIT_READ))],
)
async def get_text(session_id: str, download: bool = False, db: AsyncSession = Depends(get_db),
                   audit: Audit = Depends(get_audit)):
    """画面に最終的に出た文字のテキスト（色や制御文字、打ち直しの跡を除いたもの）。download=true でファイルとして返す"""
    s = await db.get(TerminalSession, session_id)
    p = text_path(s) if s else None
    if s is None or p is None or not p.is_file():
        raise HTTPException(status_code=404, detail="テキストの記録が見つかりません（この機能を入れる前の記録にはありません）")
    try:
        text = await run_in_threadpool(read_text_log, p)
    except InvalidToken as e:
        raise HTTPException(
            status_code=500, detail="記録を復号できません（DEVICE_ENCRYPTION_KEY が記録時と違う可能性があります）"
        ) from e
    # 見たこと・持ち出したことを残す（機器の画面には機密情報が含まれ得るため）
    audit("audit.view_recording", target_type="terminal_session", target_id=s.id,
          target_name=f"{s.username}@{s.device_name}", detail={"format": "テキスト", "download": download})
    await db.commit()
    headers = {}
    if download:
        # DB の日時は UTC（タイムゾーンなし）。ファイル名はサーバーのタイムゾーンの時刻にする
        stamp = s.started_at.replace(tzinfo=UTC).astimezone(ZoneInfo(settings.TIMEZONE)).strftime("%Y%m%d-%H%M%S")
        name = safe_filename(f"terminal_{s.username or 'user'}_{s.device_name or 'device'}_{stamp}") + ".txt"
        headers["Content-Disposition"] = content_disposition(name)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8", headers=headers)


class TextSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=200)
    mode: str = Field("contains", pattern="^(contains|regex)$")
    case_sensitive: bool = False
    username: str | None = Field(default=None, max_length=64)
    device: str | None = Field(default=None, max_length=128)  # 機器名・ホストの部分一致
    since: datetime | None = None
    until: datetime | None = None


SEARCH_MAX_SESSIONS = 300  # 新しい順に調べるセッションの上限
SEARCH_MAX_LINES = 20  # 1 セッションで返す一致行の上限（件数は全部数える）
SEARCH_TIMEOUT_SEC = 15.0


def _search_texts(targets: list[tuple[str, str]], body: TextSearchRequest) -> tuple[dict[str, dict], list[str], bool]:
    """テキストの記録を 1 つずつ復号して調べる。戻り値: (一致したセッション, 読めなかったセッション, 時間切れか)"""
    rx = config_search.build_pattern(body.query, body.mode, body.case_sensitive)
    end = time.monotonic() + SEARCH_TIMEOUT_SEC
    hits: dict[str, dict] = {}
    unreadable: list[str] = []
    for session_id, path in targets:
        if time.monotonic() >= end:
            return hits, unreadable, True
        try:
            text = read_text_log(Path(path))
            limit = min(end, time.monotonic() + settings.COMPLIANCE_REGEX_TIMEOUT)
            count, lines = config_search.search_device(rx, text, 0, limit)
        except TimeoutError:
            return hits, unreadable, True
        except (OSError, InvalidToken):
            unreadable.append(session_id)
            continue
        if count:
            hits[session_id] = {"count": count, "lines": [{"line": x["line"], "text": x["text"], "ranges": x["ranges"]}
                                                          for x in lines[:SEARCH_MAX_LINES]]}
    return hits, unreadable, False


# 検索語を URL（アクセスログ）に残さないよう POST にしている
@router.post("/terminal-sessions/search", dependencies=[Depends(require(Perm.AUDIT_READ))])
async def search_texts(body: TextSearchRequest, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """ターミナルの記録（テキスト）の中を検索する。「このコマンドを打ったセッション」を探すため"""
    if not body.query.strip():
        raise HTTPException(status_code=422, detail="検索する文字列を入力してください")
    try:
        config_search.build_pattern(body.query, body.mode, body.case_sensitive)
    except config_search.SearchPatternError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    cond = _session_conditions(body.username, body.device, body.since, body.until)
    rows = (await db.execute(select(TerminalSession).where(*cond).order_by(TerminalSession.started_at.desc())
                             .limit(SEARCH_MAX_SESSIONS + 1))).scalars().all()
    more = len(rows) > SEARCH_MAX_SESSIONS
    rows = rows[:SEARCH_MAX_SESSIONS]
    targets = []
    for r in rows:
        t = text_path(r)
        if t and t.is_file():
            targets.append((r.id, str(t)))
    hits, unreadable, timed_out = await run_in_threadpool(_search_texts, targets, body)
    # 記録の中身を調べたことを残す。検索語そのものは残さない（探している内容が機密のことがあるため）
    audit("audit.search_recording", detail={"sessions": len(targets), "matched": len(hits),
                                           "username": body.username, "device": body.device})
    await db.commit()
    items = []
    for r in rows:
        if r.id in hits:
            item = TerminalSessionItem.model_validate(r)
            item.has_recording = bool((p := recording_path(r)) and p.is_file())
            item.has_text = True
            items.append({**item.model_dump(), **hits[r.id]})
    return {
        "items": items,
        "searched": len(targets),  # テキストがあって調べたセッションの数
        "without_text": len(rows) - len(targets),  # テキストが無い（この機能を入れる前などの）セッション
        "unreadable": len(unreadable),
        "timed_out": timed_out,
        "more": more,  # 上限より古いセッションは調べていない
        "max_lines": SEARCH_MAX_LINES,
    }
