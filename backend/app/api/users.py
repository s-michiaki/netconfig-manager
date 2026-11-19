"""ユーザー管理（管理者のみ）"""

import logging
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import NewPassword, clear_mfa
from app.api.deps import get_current_user
from app.api.terminal import close_user_sessions
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS, Perm, Role
from app.core.security import hash_password
from app.models.device import CredentialProfile
from app.models.notification import NotificationSetting, UserGroupMember
from app.models.user import User
from app.services.audit import Audit, get_audit

logger = logging.getLogger(__name__)
router = APIRouter()

Username = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@\-]+$")
]


class UserCreate(BaseModel):
    username: Username
    password: NewPassword
    role: Role = Role.VIEWER
    is_active: bool = True


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    # 指定すると管理者によるパスワードリセット（そのユーザーの既存トークンは無効になる）
    password: NewPassword | None = None


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    role_label: str
    is_active: bool
    created_at: datetime | None
    mfa_enabled: bool = False


class ForceLogoutResponse(BaseModel):
    closed_terminals: int  # 切断した、接続中のターミナルの数


class RoleInfo(BaseModel):
    role: str
    label: str
    permissions: list[str]


def _to_response(u: User) -> UserResponse:
    try:
        label = ROLE_LABELS[Role(u.role)]
    except ValueError:
        label = u.role
    return UserResponse(
        id=u.id, username=u.username, role=u.role, role_label=label, is_active=u.is_active, created_at=u.created_at,
        mfa_enabled=bool(u.mfa_enabled),
    )


async def _get_or_404(db: AsyncSession, user_id: str) -> User:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def _other_active_admins(db: AsyncSession, exclude_id: str) -> int:
    q = (
        select(func.count())
        .select_from(User)
        .where(User.role == Role.ADMIN.value, User.is_active.is_(True), User.id != exclude_id)
    )
    return (await db.execute(q)).scalar_one()


@router.get("/roles", response_model=list[RoleInfo])
async def list_roles():
    return [
        RoleInfo(role=r.value, label=ROLE_LABELS[r], permissions=sorted(p.value for p in perms))
        for r, perms in ROLE_PERMISSIONS.items()
    ]


@router.get("/", response_model=list[UserResponse])
async def list_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.username))
    return [_to_response(u) for u in result.scalars().all()]


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    user = User(
        id=str(uuid.uuid4()),
        username=payload.username,
        hashed_password=await run_in_threadpool(hash_password, payload.password),
        role=payload.role.value,
        is_active=payload.is_active,
    )
    db.add(user)
    audit("user.create", target_type="user", target_id=user.id, target_name=user.username,
          detail={"role": user.role, "is_active": user.is_active})
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じユーザー名が既に登録されています") from e
    await db.refresh(user)
    logger.info("ユーザー作成 by=%s user=%s role=%s", me.username, user.username, user.role)
    return _to_response(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    user = await _get_or_404(db, user_id)
    is_self = user.id == me.id

    demoting = payload.role is not None and payload.role != Role.ADMIN
    deactivating = payload.is_active is False
    if is_self and (demoting or deactivating):
        raise HTTPException(status_code=400, detail="自分自身のロール変更・無効化はできません")
    if user.role == Role.ADMIN.value and (demoting or deactivating) and not await _other_active_admins(db, user.id):
        raise HTTPException(status_code=400, detail="有効な管理者が1人もいなくなるため変更できません")

    changes = []
    revoke = ""  # 既存のログイン（トークン・接続中のターミナル）を切る理由
    if payload.role is not None and payload.role.value != user.role:
        changes.append(f"role {user.role}->{payload.role.value}")
        lost_terminal = (Perm.TERMINAL in ROLE_PERMISSIONS[Role(user.role)]
                         and Perm.TERMINAL not in ROLE_PERMISSIONS[payload.role])
        user.role = payload.role.value
        if lost_terminal:
            # ログインはそのまま（以降の操作は新しいロールで判定される）。開いているターミナルだけ切る
            revoke = "ロールの変更"
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes.append(f"is_active->{payload.is_active}")
        user.is_active = payload.is_active
        if not payload.is_active:
            # 無効化の前に発行したトークンが、有効に戻したときに復活しないようにする
            user.token_version = (user.token_version or 0) + 1
            revoke = "ユーザーの無効化"
    if payload.password:
        if is_self:
            raise HTTPException(status_code=400, detail="自分のパスワードは「パスワード変更」から変更してください")
        user.hashed_password = await run_in_threadpool(hash_password, payload.password)
        changes.append("password reset")
        revoke = revoke or "パスワードのリセット"
    if changes:
        audit("user.update", target_type="user", target_id=user.id, target_name=user.username,
              detail={"changes": changes})
    await db.commit()
    await db.refresh(user)
    if revoke:
        await close_user_sessions(user.id, revoke)
    if changes:
        logger.info("ユーザー更新 by=%s user=%s %s", me.username, user.username, ", ".join(changes))
    return _to_response(user)


@router.post("/{user_id}/mfa-reset", response_model=UserResponse)
async def reset_mfa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """2 段階認証を解除する（本人が認証アプリも予備コードも無くしたとき）。本人は次のログインからパスワードだけで入れる"""
    user = await _get_or_404(db, user_id)
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="このユーザーは 2 段階認証を設定していません")
    clear_mfa(user)
    audit("user.mfa_reset", target_type="user", target_id=user.id, target_name=user.username)
    await db.commit()
    await db.refresh(user)
    logger.info("2 段階認証の解除 by=%s user=%s", me.username, user.username)
    return _to_response(user)


@router.post("/{user_id}/logout", response_model=ForceLogoutResponse)
async def force_logout(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """パスワードを変えずに、そのユーザーの既存のログインを切る（再ログインは可能）"""
    user = await _get_or_404(db, user_id)
    if user.id == me.id:
        raise HTTPException(
            status_code=400, detail="自分自身はログアウトさせられません（サイドバーの「ログアウト」を使ってください）"
        )
    user.token_version = (user.token_version or 0) + 1
    await db.commit()
    closed = await close_user_sessions(user.id, "管理者による強制ログアウト")
    audit("user.logout", target_type="user", target_id=user.id, target_name=user.username,
          detail={"closed_terminals": closed})
    await db.commit()
    logger.info("強制ログアウト by=%s user=%s terminals=%d", me.username, user.username, closed)
    return ForceLogoutResponse(closed_terminals=closed)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    user = await _get_or_404(db, user_id)
    if user.id == me.id:
        raise HTTPException(status_code=400, detail="自分自身は削除できません")
    if user.role == Role.ADMIN.value and user.is_active and not await _other_active_admins(db, user.id):
        raise HTTPException(status_code=400, detail="有効な管理者が1人もいなくなるため削除できません")
    # 所属するユーザーグループ・個人の通知設定も消す（SQLite では外部キーの CASCADE が効かないため明示的に）
    await db.execute(delete(UserGroupMember).where(UserGroupMember.user_id == user.id))
    await db.execute(delete(NotificationSetting).where(
        NotificationSetting.owner_type == "user", NotificationSetting.owner_id == user.id
    ))
    # 所有していた認証情報プロファイルは「所有者なし」にする（管理者が引き継ぐ。SQLite では SET NULL が効かないため明示的に）
    await db.execute(update(CredentialProfile).where(CredentialProfile.owner_id == user.id).values(owner_id=None))
    await db.delete(user)
    audit("user.delete", target_type="user", target_id=user.id, target_name=user.username)
    await db.commit()
    await close_user_sessions(user.id, "ユーザーの削除")
    logger.info("ユーザー削除 by=%s user=%s", me.username, user.username)
