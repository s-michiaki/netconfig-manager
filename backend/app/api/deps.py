from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal, get_db
from app.core.permissions import Perm, has_permission
from app.core.security import decode_access_token, password_fingerprint
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


async def _load_active_user(db: AsyncSession, token: str) -> User | None:
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        return None
    user = await db.get(User, payload["sub"])
    if user is None or not user.is_active:
        return None
    # パスワード変更・リセット後は、それ以前に発行されたトークンを無効にする
    if payload.get("pwv") != password_fingerprint(user.hashed_password):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    user = await _load_active_user(db, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証情報が無効です",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require(perm: Perm) -> Callable[..., Coroutine[Any, Any, User]]:
    """指定した権限を持つユーザーだけを通す依存関係

    使い方: @router.post("/", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
    """

    async def checker(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, perm):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="この操作を行う権限がありません",
            )
        return user

    return checker


async def authenticate_token(token: str) -> User | None:
    """WebSocket など Depends が使いにくい場所向け"""
    async with AsyncSessionLocal() as db:
        return await _load_active_user(db, token)
