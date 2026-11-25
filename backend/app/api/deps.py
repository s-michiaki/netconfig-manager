from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.token_policy import READ_METHODS, token_allowed
from app.core.config import settings
from app.core.database import AsyncSessionLocal, get_db
from app.core.permissions import TOKEN_SCOPE_FULL, Perm, token_permissions
from app.core.security import decode_access_token, password_fingerprint
from app.core.timeutil import utcnow
from app.models.user import User
from app.services import api_tokens, login_limit

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

SESSION_REQUIRED = "この操作は API トークンでは行えません。ログインして操作してください"


async def _load_active_user(db: AsyncSession, token: str) -> User | None:
    # API トークン（ncm_…）はここでは受け付けない（WebSocket などはログインのトークンだけ）
    if api_tokens.looks_like_token(token):
        return None
    payload = decode_access_token(token)
    # purpose 付き（2 段階認証の途中の印など）はログインのトークンとして使わせない
    if not payload or not payload.get("sub") or payload.get("purpose"):
        return None
    user = await db.get(User, payload["sub"])
    if user is None or not user.is_active:
        return None
    # パスワード変更・リセット後は、それ以前に発行されたトークンを無効にする
    if payload.get("pwv") != password_fingerprint(user.hashed_password):
        return None
    # 管理者による強制ログアウト・無効化の後は、それ以前に発行されたトークンを無効にする
    # （tv を持たない以前のトークンは 0 とみなす。列の既定値も 0 なので、更新直後にログイン中の人は切れない）
    try:
        tv = int(payload.get("tv", 0))
    except (TypeError, ValueError):
        return None
    if tv != (user.token_version or 0):
        return None
    return user


def _unauthorized(detail: str = "認証情報が無効です") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def _load_api_token_user(request: Request, db: AsyncSession, value: str) -> User:
    """API トークン（ncm_…）で認証する。値そのものはログ・監査ログ・例外の文言に出さない"""
    from app.services.audit import client_ip, make_log, record_now  # audit.py がこのファイルを読むため、ここで読む

    if not settings.API_TOKENS_ENABLED:
        raise _unauthorized("API トークンは使えない設定です（API_TOKENS_ENABLED）")
    ip = client_ip(request)
    t = await api_tokens.find(db, value)
    if t is None:
        # 照合に失敗したトークンだけを、ログインとは別のカウンタで数える。続いた接続元は一時的に 429
        # （正しいトークンはロック中でも通す。ログインのロックにも影響させない）
        wait, newly = await login_limit.token_failure(ip)
        if newly:
            await record_now(db, make_log("auth.login_locked", ip=ip, success=False,
                                          detail={"unit": "接続元（API トークン）", "minutes": settings.LOGIN_LOCK_MIN}))
        if wait:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"不正な API トークンが続いたため、一時的に受け付けません。{-(-wait // 60)} 分ほど待ってから"
                       "再度お試しください",
                headers={"Retry-After": str(wait)},
            )
        raise _unauthorized()
    now = utcnow()
    if not api_tokens.is_active(t, now):
        raise _unauthorized("API トークンが失効しているか、期限が切れています")
    user = await db.get(User, t.user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    if not token_allowed(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SESSION_REQUIRED)
    if t.scope != TOKEN_SCOPE_FULL and request.method not in READ_METHODS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="読み取り専用（read）の API トークンでは、この操作は行えません")
    if api_tokens.touch(t, ip, now):
        await db.commit()
    user.api_token = t
    return user


async def get_current_user(
    request: Request, token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    if api_tokens.looks_like_token(token):
        return await _load_api_token_user(request, db, token)
    user = await _load_active_user(db, token)
    if user is None:
        raise _unauthorized()
    return user


async def require_session(user: User = Depends(get_current_user)) -> User:
    """ログインのセッションでだけ通す（API トークンでは 403）。

    トークンで呼べる API は token_policy.TOKEN_ALLOWED の一覧で決まる（既定は不可）。
    これは、発行・パスワード変更などトークンで絶対に使わせないものに、念のため重ねて付ける
    """
    if user.api_token is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SESSION_REQUIRED)
    return user


def effective_permissions(user: User) -> frozenset[Perm]:
    """このリクエストで使える権限（API トークンなら、その範囲で絞ったもの）"""
    return token_permissions(user.role, user.api_token.scope if user.api_token is not None else None)


def require(perm: Perm) -> Callable[..., Coroutine[Any, Any, User]]:
    """指定した権限を持つユーザーだけを通す依存関係

    使い方: @router.post("/", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
    API トークンのときは、トークンの範囲（read / full）でも絞る（判定のたびにいまのロールを見る）
    """

    async def checker(user: User = Depends(get_current_user)) -> User:
        if perm not in effective_permissions(user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="この操作を行う権限がありません",
            )
        return user

    checker.perm = perm  # token_policy が「トークンで呼べる API が要求する権限」を集めるときに見る
    return checker


async def authenticate_token(token: str) -> User | None:
    """WebSocket など Depends が使いにくい場所向け。ログインのトークンだけを受け付ける（API トークンは None）"""
    async with AsyncSessionLocal() as db:
        return await _load_active_user(db, token)
