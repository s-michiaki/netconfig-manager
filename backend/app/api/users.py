"""ユーザー管理（管理者のみ）"""

import logging
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import NewPassword
from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS, Role
from app.core.security import hash_password
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
        id=u.id, username=u.username, role=u.role, role_label=label, is_active=u.is_active, created_at=u.created_at
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
    if payload.role is not None and payload.role.value != user.role:
        changes.append(f"role {user.role}->{payload.role.value}")
        user.role = payload.role.value
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes.append(f"is_active->{payload.is_active}")
        user.is_active = payload.is_active
    if payload.password:
        if is_self:
            raise HTTPException(status_code=400, detail="自分のパスワードは「パスワード変更」から変更してください")
        user.hashed_password = await run_in_threadpool(hash_password, payload.password)
        changes.append("password reset")
    if changes:
        audit("user.update", target_type="user", target_id=user.id, target_name=user.username,
              detail={"changes": changes})
    await db.commit()
    await db.refresh(user)
    if changes:
        logger.info("ユーザー更新 by=%s user=%s %s", me.username, user.username, ", ".join(changes))
    return _to_response(user)


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
    await db.delete(user)
    audit("user.delete", target_type="user", target_id=user.id, target_name=user.username)
    await db.commit()
    logger.info("ユーザー削除 by=%s user=%s", me.username, user.username)
