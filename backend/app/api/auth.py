"""
認証エンドポイント
ユーザーはDBで管理し、初回起動時に ADMIN_USERNAME / ADMIN_PASSWORD から管理者を作成する。
本番環境ではLDAP/AD連携や MFA の追加を推奨
"""

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import AfterValidator, BaseModel, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, Role, permissions_for
from app.core.security import (
    DUMMY_HASH,
    MAX_PASSWORD_BYTES,
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.services.audit import client_ip, make_log, record_now

logger = logging.getLogger(__name__)
router = APIRouter()


class Token(BaseModel):
    access_token: str
    token_type: str


def _check_password_bytes(v: str) -> str:
    if len(v.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"パスワードは{MAX_PASSWORD_BYTES}バイト以内にしてください")
    return v


# 新しく設定するパスワードの共通ルール（ユーザー管理APIでも使う）
NewPassword = Annotated[str, StringConstraints(min_length=10), AfterValidator(_check_password_bytes)]


class UserInfo(BaseModel):
    id: str
    username: str
    role: str
    role_label: str
    permissions: list[str]


class PasswordChange(BaseModel):
    current_password: str
    new_password: NewPassword


def user_info(user: User) -> UserInfo:
    try:
        label = ROLE_LABELS[Role(user.role)]
    except ValueError:
        label = user.role
    return UserInfo(
        id=user.id,
        username=user.username,
        role=user.role,
        role_label=label,
        permissions=sorted(p.value for p in permissions_for(user.role)),
    )


@router.post("/token", response_model=Token)
async def login(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()
    hashed = user.hashed_password if user else DUMMY_HASH
    # bcrypt は重い処理なのでイベントループを塞がないようスレッドで実行
    ok = await run_in_threadpool(verify_password, form_data.password, hashed)
    if not user or not ok or not user.is_active:
        reason = "ユーザーが存在しない" if not user else "無効なユーザー" if ok else "パスワード誤り"
        await record_now(
            db,
            make_log(
                "auth.login_failed", username=form_data.username[:64], ip=client_ip(request),
                detail={"reason": reason}, success=False,
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが正しくありません",
            headers={"WWW-Authenticate": "Bearer"},
        )
    await record_now(db, make_log("auth.login", user=user, ip=client_ip(request)))
    return {"access_token": create_access_token(user.id, user.hashed_password), "token_type": "bearer"}


@router.get("/me", response_model=UserInfo)
async def me(user: User = Depends(get_current_user)):
    """ログイン中のユーザーとその権限（フロントはこれで表示を切り替える）"""
    return user_info(user)


@router.post("/change-password", response_model=Token)
async def change_password(
    request: Request,
    payload: PasswordChange,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not await run_in_threadpool(verify_password, payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="現在のパスワードが正しくありません")
    user.hashed_password = await run_in_threadpool(hash_password, payload.new_password)
    db.add(make_log("auth.password_change", user=user, ip=client_ip(request), target_type="user",
                    target_id=user.id, target_name=user.username))
    await db.commit()
    logger.info("パスワード変更 user=%s", user.username)
    # 変更前のトークンは無効になるため、新しいトークンを返す
    return {"access_token": create_access_token(user.id, user.hashed_password), "token_type": "bearer"}


async def ensure_initial_admin(db: AsyncSession) -> None:
    """ユーザーが1人もいなければ初期管理者を作成する"""
    count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    if count:
        return
    password = settings.ADMIN_PASSWORD
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(12)
    db.add(User(username=settings.ADMIN_USERNAME, hashed_password=hash_password(password), role=Role.ADMIN.value))
    await db.commit()
    if generated:
        logger.warning(
            "初期管理者を作成しました。ユーザー名: %s / パスワード: %s "
            "（この表示は一度だけです。ログイン後に変更してください）",
            settings.ADMIN_USERNAME,
            password,
        )
    else:
        logger.warning("初期管理者 %s を作成しました（ADMIN_PASSWORD を使用）", settings.ADMIN_USERNAME)
