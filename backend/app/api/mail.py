"""メールサーバー（メール通知の送信設定）の API。管理者のみ（USER_ADMIN）

- GET  /server            : 設定（秘密の値は返さず、登録済みかどうかだけ）
- PUT  /server            : 保存。秘密の値は None なら変更しない、空文字なら削除する
- POST /server/test       : テストメールを送る（保存済みの設定で）
- POST /google/authorize  : Google アカウントの同意の画面の URL を作る（auth = google_user）
- POST /google/complete   : 同意のあとのアドレスを受け取り、更新用トークンを保存する
- DELETE /google          : 保存した更新用トークンを消す
"""
import asyncio
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.mail import MailServer
from app.models.user import User
from app.services import mail
from app.services.audit import Audit, get_audit

router = APIRouter()

Str = Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)]
Secret = Annotated[str, StringConstraints(max_length=1000)]


class MailServerIn(BaseModel):
    enabled: bool = False
    auth: Literal["none", "password", "microsoft", "google_sa", "google_user"] = "password"
    host: Str = ""
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    verify_tls: bool = True
    username: Str = ""
    from_address: Str = ""
    from_name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] = ""
    subject_prefix: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)] = "[NetConfig]"
    allowed_domains: Annotated[str, StringConstraints(max_length=2000)] = ""
    ms_tenant_id: Str = ""
    ms_client_id: Str = ""
    google_client_id: Str = ""
    # 秘密の値: None = 変更しない、"" = 削除
    password: Secret | None = None
    ms_client_secret: Secret | None = None
    google_client_secret: Secret | None = None
    google_sa_json: Annotated[str, StringConstraints(max_length=10000)] | None = None


class MailServerOut(BaseModel):
    enabled: bool = False
    auth: str = "password"
    host: str = ""
    port: int = 587
    security: str = "starttls"
    verify_tls: bool = True
    username: str = ""
    from_address: str = ""
    from_name: str = ""
    subject_prefix: str = "[NetConfig]"
    allowed_domains: str = ""
    ms_tenant_id: str = ""
    ms_client_id: str = ""
    google_client_id: str = ""
    has_password: bool = False
    has_ms_client_secret: bool = False
    has_google_client_secret: bool = False
    has_google_sa_json: bool = False
    google_sa_email: str | None = None  # サービスアカウントの鍵の client_email（確認用）
    google_authorized: bool = False
    google_authorized_at: datetime | None = None
    google_redirect_uri: str = mail.GOOGLE_REDIRECT_URI
    updated_at: datetime | None = None
    updated_by: str | None = None
    last_result: dict | None = None  # 最後の送信の結果


class TestIn(BaseModel):
    to: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=254)]


class CompleteIn(BaseModel):
    url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]


def _sa_email(row: MailServer) -> str | None:
    try:
        return mail._google_sa_key(mail.MailConfig(google_sa_json=row.google_sa_json or ""))["client_email"]
    except mail.MailError:
        return None


async def _out(row: MailServer | None) -> MailServerOut:
    try:
        last = await mail.last_result()
    except Exception:  # noqa: BLE001 - Redis に届かなくても設定は表示する
        last = None
    if row is None:
        return MailServerOut(last_result=last)
    return MailServerOut(
        enabled=row.enabled, auth=row.auth, host=row.host, port=row.port, security=row.security,
        verify_tls=row.verify_tls, username=row.username or "", from_address=row.from_address,
        from_name=row.from_name or "", subject_prefix=row.subject_prefix or "", allowed_domains=row.allowed_domains or "",
        ms_tenant_id=row.ms_tenant_id or "", ms_client_id=row.ms_client_id or "",
        google_client_id=row.google_client_id or "",
        has_password=bool(row.password), has_ms_client_secret=bool(row.ms_client_secret),
        has_google_client_secret=bool(row.google_client_secret), has_google_sa_json=bool(row.google_sa_json),
        google_sa_email=_sa_email(row) if row.google_sa_json else None,
        google_authorized=bool(row.google_refresh_token), google_authorized_at=row.google_authorized_at,
        updated_at=row.updated_at, updated_by=row.updated_by, last_result=last,
    )


async def _row(db: AsyncSession) -> MailServer | None:
    return await db.get(MailServer, "default")


@router.get("/server", response_model=MailServerOut)
async def get_server(db: AsyncSession = Depends(get_db), _: User = Depends(require(Perm.USER_ADMIN))):
    return await _out(await _row(db))


@router.put("/server", response_model=MailServerOut)
async def update_server(payload: MailServerIn, db: AsyncSession = Depends(get_db),
                        user: User = Depends(require(Perm.USER_ADMIN)), audit: Audit = Depends(get_audit)):
    row = await _row(db)
    if row is None:
        row = MailServer(id="default")
        db.add(row)
    domains = mail.parse_domains(payload.allowed_domains)
    for d in domains:
        if not mail.EMAIL_RE.match(f"x@{d}"):
            raise HTTPException(status_code=422, detail=f"宛先に使えるドメインの形式が正しくありません: {d}")
    if payload.from_address and not mail.EMAIL_RE.match(payload.from_address):
        raise HTTPException(status_code=422, detail="送信元のメールアドレスの形式が正しくありません")
    if payload.ms_tenant_id and not mail.TENANT_RE.match(payload.ms_tenant_id):
        raise HTTPException(status_code=422, detail="テナント ID の形式が正しくありません")
    if payload.google_sa_json:
        try:
            mail._google_sa_key(mail.MailConfig(google_sa_json=payload.google_sa_json))
        except mail.MailError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
    if row.google_client_id and payload.google_client_id != row.google_client_id:
        row.google_refresh_token = None  # 別のクライアントでは使えない
        row.google_authorized_at = None
    for f in ("enabled", "auth", "host", "port", "security", "verify_tls", "username", "from_address", "from_name",
              "subject_prefix", "ms_tenant_id", "ms_client_id", "google_client_id"):
        setattr(row, f, getattr(payload, f))
    row.allowed_domains = ", ".join(domains) or None
    changes: dict = {"enabled": payload.enabled, "auth": mail.AUTH_LABELS[payload.auth], "host": payload.host,
                     "port": payload.port, "security": payload.security, "verify_tls": payload.verify_tls,
                     "from_address": payload.from_address, "allowed_domains": row.allowed_domains}
    for f in ("password", "ms_client_secret", "google_client_secret", "google_sa_json"):
        v = getattr(payload, f)
        if v is not None:
            setattr(row, f, v or None)
            changes[f] = "（変更）" if v else "（削除）"
    row.updated_at, row.updated_by = utcnow(), user.username
    if payload.enabled and (problem := mail.check_config(mail.MailConfig.from_row(row))):
        raise HTTPException(status_code=422, detail=problem)
    mail.clear_token_cache()
    audit("mail.update", target_type="mail_server", target_id="default", target_name="メールサーバー", detail=changes)
    await db.commit()
    await db.refresh(row)
    return await _out(row)


@router.post("/server/test")
async def test_server(payload: TestIn, db: AsyncSession = Depends(get_db),
                      user: User = Depends(require(Perm.USER_ADMIN)), audit: Audit = Depends(get_audit)):
    cfg = mail.MailConfig.from_row(await _row(db))
    if not cfg.enabled:
        raise HTTPException(status_code=400, detail="メール送信が無効です（「有効にする」を選んで保存してください）")
    body = (f"NetConfig Manager からのテストメールです（{user.username} が送信）。\n"
            f"このメールが届いていれば、通知をメールで受け取れます。")
    err = await asyncio.to_thread(mail.send_notification, cfg, payload.to, {
        "title": "テストメール", "body": body,
        "facts": [("SMTP サーバー", f"{cfg.host}:{cfg.port}"), ("認証", mail.AUTH_LABELS.get(cfg.auth, cfg.auth))]})
    await mail.record_last([err])
    audit("mail.test", target_type="mail_server", target_id="default", target_name="メールサーバー",
          detail={"to_domain": payload.to.rsplit("@", 1)[-1], "result": err or "ok"})
    await db.commit()
    return {"ok": err is None, "error": err}


@router.post("/google/authorize")
async def google_authorize(db: AsyncSession = Depends(get_db), user: User = Depends(require(Perm.USER_ADMIN))):
    try:
        return {"url": await mail.authorize_url(mail.MailConfig.from_row(await _row(db)), user.id)}
    except mail.MailError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/google/complete", response_model=MailServerOut)
async def google_complete(payload: CompleteIn, db: AsyncSession = Depends(get_db),
                          user: User = Depends(require(Perm.USER_ADMIN)), audit: Audit = Depends(get_audit)):
    row = await _row(db)
    if row is None:
        raise HTTPException(status_code=400, detail="先にメールサーバーの設定を保存してください")
    try:
        token = await mail.complete_authorization(mail.MailConfig.from_row(row), user.id, payload.url)
    except mail.MailError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    row.google_refresh_token, row.google_authorized_at = token, utcnow()
    audit("mail.google_authorize", target_type="mail_server", target_id="default", target_name="メールサーバー")
    await db.commit()
    await db.refresh(row)
    return await _out(row)


@router.delete("/google", response_model=MailServerOut)
async def google_revoke(db: AsyncSession = Depends(get_db), _: User = Depends(require(Perm.USER_ADMIN)),
                        audit: Audit = Depends(get_audit)):
    row = await _row(db)
    if row is not None and row.google_refresh_token:
        row.google_refresh_token, row.google_authorized_at = None, None
        mail.clear_token_cache()
        audit("mail.google_revoke", target_type="mail_server", target_id="default", target_name="メールサーバー")
        await db.commit()
        await db.refresh(row)
    return await _out(row)
