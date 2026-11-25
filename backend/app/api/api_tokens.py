"""API トークンの発行・一覧・失効（本人）。管理者の一覧・全失効は users.py

- 発行・失効はログインのセッションからだけ（require_session。トークンでトークンを増やさせない）。
  2 段階認証を設定している人のセッションは 2 段階認証を通ったものなので、発行も 2 段階認証を通ってから
- 発行のときはパスワードを入れ直す（開いたままの画面や、漏れたログインのトークンから長い期限のトークンを作らせない）。
  パスワードの誤りはログインの失敗と同じく数える（総当たりさせない）
- トークンの値は発行の応答で 1 回だけ返す。一覧には先頭 12 文字・名前・範囲・期限・最後に使った日時と接続元だけ
"""
import logging
import unicodedata
from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, StrictInt, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.config_reviews import iso_utc
from app.api.deps import require_session
from app.core.config import settings
from app.core.database import get_db
from app.core.security import verify_password
from app.core.timeutil import utcnow
from app.models.api_token import ApiToken
from app.models.user import User
from app.services import api_tokens, login_limit
from app.services.audit import client_ip, make_log, record_now

logger = logging.getLogger(__name__)
router = APIRouter()


class TokenCreate(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    scope: Literal["read", "full"] = "read"
    days: StrictInt = Field(default=api_tokens.DEFAULT_DAYS, ge=1)  # "7" や 7.5 は受け付けない
    password: str  # 本人の確認（いまのパスワード）

    @field_validator("days")
    @classmethod
    def _max_days(cls, v: int) -> int:
        if v > settings.API_TOKEN_MAX_DAYS:
            raise ValueError(f"期限は {settings.API_TOKEN_MAX_DAYS} 日以内にしてください")
        return v

    @field_validator("name")
    @classmethod
    def _printable(cls, v: str) -> str:
        # 制御文字（Cc）と、見えない書式文字（Cf。右から左への切り替え・ゼロ幅の文字など）は、一覧や監査ログの表示を偽れるので拒否
        if any(unicodedata.category(c) in ("Cc", "Cf") for c in v):
            raise ValueError("名前に制御文字・書式文字は使えません")
        return v


class TokenInfo(BaseModel):
    id: str
    name: str
    prefix: str
    scope: str
    status: Literal["active", "expired", "revoked"]
    created_at: str | None
    expires_at: str | None
    last_used_at: str | None
    last_used_ip: str | None
    revoked_at: str | None


class TokenCreated(TokenInfo):
    token: str  # この応答でだけ返す


class TokenList(BaseModel):
    items: list[TokenInfo]
    max_days: int  # 期限として選べる日数の上限（API_TOKEN_MAX_DAYS）
    default_days: int
    max_tokens: int  # 1 人が持てる有効なトークンの数
    enabled: bool  # API_TOKENS_ENABLED


def token_info(t: ApiToken, now: datetime | None = None) -> dict:
    return dict(
        id=t.id, name=t.name, prefix=t.prefix, scope=t.scope, status=api_tokens.status_of(t, now),
        created_at=iso_utc(t.created_at), expires_at=iso_utc(t.expires_at), last_used_at=iso_utc(t.last_used_at),
        last_used_ip=t.last_used_ip, revoked_at=iso_utc(t.revoked_at),
    )


async def list_for(db: AsyncSession, user_id: str) -> list[dict]:
    """有効なものを先に、新しい順（失効・期限切れも KEEP_DAYS 日は残る）"""
    rows = (await db.execute(
        select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc())
    )).scalars().all()
    now = utcnow()
    infos = [token_info(t, now) for t in rows]
    return sorted(infos, key=lambda x: x["status"] != "active")


@router.get("", response_model=TokenList)
async def list_my_tokens(user: User = Depends(require_session), db: AsyncSession = Depends(get_db)):
    """自分のトークンの一覧と、発行の画面で使う上限（日数・個数）"""
    return TokenList(items=await list_for(db, user.id), max_days=settings.API_TOKEN_MAX_DAYS,
                     default_days=min(api_tokens.DEFAULT_DAYS, settings.API_TOKEN_MAX_DAYS),
                     max_tokens=api_tokens.MAX_TOKENS_PER_USER, enabled=settings.API_TOKENS_ENABLED)


@router.post("", response_model=TokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    request: Request, response: Response, payload: TokenCreate, user: User = Depends(require_session),
    db: AsyncSession = Depends(get_db),
):
    if not settings.API_TOKENS_ENABLED:
        raise HTTPException(status_code=409, detail="API トークンは使えない設定です（API_TOKENS_ENABLED）")
    ip = client_ip(request)
    # パスワードの確認は、ログインと同じ回数の制限の中で行う（漏れたログインのトークンから総当たりさせない）
    wait, _ = await login_limit.begin_attempt(user.username, ip)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"パスワードの誤りが続いたため、一時的に操作できません。{-(-wait // 60)} 分ほど待ってから再度お試しください",
            headers={"Retry-After": str(wait)},
        )
    if not await run_in_threadpool(verify_password, payload.password, user.hashed_password):
        await record_now(db, make_log("api_token.create", user=user, ip=ip, success=False,
                                      detail={"name": payload.name, "reason": "パスワード誤り"}))
        raise HTTPException(status_code=422, detail="パスワードが正しくありません")
    await login_limit.record_success(user.username, ip)
    now = utcnow()
    if await api_tokens.count_active(db, user.id, now) >= api_tokens.MAX_TOKENS_PER_USER:
        raise HTTPException(
            status_code=409,
            detail=f"有効な API トークンは 1 人 {api_tokens.MAX_TOKENS_PER_USER} 個までです。"
                   "使っていないものを失効させてください",
        )
    plain, digest, prefix = api_tokens.new_token()
    t = ApiToken(user_id=user.id, name=payload.name, token_hash=digest, prefix=prefix, scope=payload.scope,
                 expires_at=now + timedelta(days=payload.days), created_at=now)
    db.add(t)
    await db.flush()
    db.add(make_log("api_token.create", user=user, ip=ip, target_type="api_token", target_id=t.id, target_name=t.name,
                    detail={"scope": t.scope, "days": payload.days, "prefix": prefix}))
    await db.commit()
    # 値を含む応答をブラウザ・中継のキャッシュに残さない
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    logger.info("API トークンを発行しました user=%s name=%s prefix=%s scope=%s", user.username, t.name, prefix, t.scope)
    return {**token_info(t, now), "token": plain}


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: str, request: Request, user: User = Depends(require_session), db: AsyncSession = Depends(get_db)
):
    t = await db.get(ApiToken, token_id)
    if t is None or t.user_id != user.id:
        raise HTTPException(status_code=404, detail="API トークンが見つかりません")
    if t.revoked_at is None:
        t.revoked_at = utcnow()
        db.add(make_log("api_token.revoke", user=user, ip=client_ip(request), target_type="api_token",
                        target_id=t.id, target_name=t.name, detail={"prefix": t.prefix}))
        await db.commit()
        logger.info("API トークンを失効させました user=%s name=%s prefix=%s", user.username, t.name, t.prefix)
