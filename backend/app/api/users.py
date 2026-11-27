"""ユーザー管理（管理者のみ）"""

import logging
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_tokens import TokenInfo, list_for
from app.api.auth import NewPassword, clear_mfa, confirm_password
from app.api.deps import get_current_user
from app.api.terminal import ALL_KINDS, close_user_sessions
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS, Perm, Role
from app.core.security import hash_password
from app.models.api_token import ApiToken
from app.models.device import CredentialProfile
from app.models.notification import NotificationSetting, UserGroupMember
from app.models.user import User
from app.services import api_tokens
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
    # 操作する管理者のいまのパスワード（管理者のロールのユーザーを作るときに必要。#29）
    confirm_password: str | None = None


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    # 指定すると管理者によるパスワードリセット（そのユーザーの既存トークンは無効になる）
    password: NewPassword | None = None
    # 操作する管理者のいまのパスワード（パスワードのリセット・管理者への変更のときに必要。#29）
    confirm_password: str | None = None


class AdminConfirm(BaseModel):
    confirm_password: str  # 操作する管理者のいまのパスワード


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    role_label: str
    is_active: bool
    created_at: datetime | None
    mfa_enabled: bool = False
    api_tokens: int = 0  # 有効な API トークンの数


class ForceLogoutResponse(BaseModel):
    closed_terminals: int  # 切断した、接続中のターミナルの数（失効させた API トークンの数は監査ログに残す）


class RevokeTokensResponse(BaseModel):
    revoked_tokens: int


class RoleInfo(BaseModel):
    role: str
    label: str
    permissions: list[str]


def _to_response(u: User, tokens: int = 0) -> UserResponse:
    try:
        label = ROLE_LABELS[Role(u.role)]
    except ValueError:
        label = u.role
    return UserResponse(
        id=u.id, username=u.username, role=u.role, role_label=label, is_active=u.is_active, created_at=u.created_at,
        mfa_enabled=bool(u.mfa_enabled), api_tokens=tokens,
    )


async def _get_or_404(db: AsyncSession, user_id: str) -> User:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def lock_admins_stmt():
    """有効な管理者の行をすべてロックする（PostgreSQL の SELECT ... FOR UPDATE。SQLite では付かない）。

    管理者 A と B が互いを同時に降格・無効化・削除しても、両方の確認が通って管理者が 0 人にならないように（#29）。
    対象の人も含めてロックし、ID の順に取る（同時の操作どうしが同じ順で待つので、デッドロックしない）。
    後から来た方は先の操作の確定を待ち、確定後の値で数え直される（READ COMMITTED の FOR UPDATE の動き）
    """
    return (select(User.id).where(User.role == Role.ADMIN.value, User.is_active.is_(True))
            .order_by(User.id).with_for_update())


async def _other_active_admins(db: AsyncSession, exclude_id: str) -> int:
    ids = (await db.execute(lock_admins_stmt())).scalars().all()
    return sum(1 for i in ids if i != exclude_id)


async def _confirm_admin(db: AsyncSession, request: Request, me: User, value: str | None, what: str,
                         action: str, target: User | None = None) -> None:
    """操作する管理者のパスワードの入れ直し（回数の制限つき。auth.confirm_password）"""
    if not value:
        raise HTTPException(status_code=422, detail=f"{what}には、あなた（操作する管理者）のパスワードの入力が必要です")
    t = {"target_type": "user", "target_id": target.id, "target_name": target.username} if target else {}
    await confirm_password(db, request, me, value, action=action, what=what, target=t)


@router.get("/roles", response_model=list[RoleInfo])
async def list_roles():
    return [
        RoleInfo(role=r.value, label=ROLE_LABELS[r], permissions=sorted(p.value for p in perms))
        for r, perms in ROLE_PERMISSIONS.items()
    ]


@router.get("/", response_model=list[UserResponse])
async def list_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.username))
    counts = await api_tokens.active_counts(db)
    return [_to_response(u, counts.get(u.id, 0)) for u in result.scalars().all()]


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    if payload.role == Role.ADMIN:
        await _confirm_admin(db, request, me, payload.confirm_password, "管理者のユーザーの作成", "user.create")
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
    request: Request,
    user_id: str,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    user = await _get_or_404(db, user_id)
    is_self = user.id == me.id
    if payload.password and is_self:
        raise HTTPException(status_code=400, detail="自分のパスワードは「パスワード変更」から変更してください")
    promoting = payload.role == Role.ADMIN and user.role != Role.ADMIN.value
    # 管理者のロールのまま無効になっている人を有効に戻すのも、実質は管理者の権限を付ける操作（昇格と同じに扱う）
    reactivating_admin = (payload.is_active is True and not user.is_active
                          and (payload.role.value if payload.role else user.role) == Role.ADMIN.value)
    if payload.password or promoting or reactivating_admin:
        what = ("パスワードのリセット" if payload.password else "管理者への変更" if promoting
                else "管理者の有効化")
        await _confirm_admin(db, request, me, payload.confirm_password, what, "user.update", user)

    demoting = payload.role is not None and payload.role != Role.ADMIN
    deactivating = payload.is_active is False
    if is_self and (demoting or deactivating):
        raise HTTPException(status_code=400, detail="自分自身のロール変更・無効化はできません")
    if user.role == Role.ADMIN.value and (demoting or deactivating) and not await _other_active_admins(db, user.id):
        raise HTTPException(status_code=400, detail="有効な管理者が1人もいなくなるため変更できません")

    changes = []
    revoke = ""  # 既存のログイン（トークン・接続中のターミナル）を切る理由
    revoke_tokens = False  # API トークンも失効させるか（ロールの変更・無効化・管理者によるパスワードのリセット）
    if payload.role is not None and payload.role.value != user.role:
        changes.append(f"role {user.role}->{payload.role.value}")
        lost_terminal = (Perm.TERMINAL in ROLE_PERMISSIONS[Role(user.role)]
                         and Perm.TERMINAL not in ROLE_PERMISSIONS[payload.role])
        user.role = payload.role.value
        # API トークンは全失効させる（昇格で以前の full のトークンが強くならないように。降格も同じに扱って単純にする）
        revoke_tokens = True
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
            # API トークンも失効させる（有効に戻したときに、以前のトークンが使えるようにならないように）
            revoke_tokens = True
    if payload.password:
        user.hashed_password = await run_in_threadpool(hash_password, payload.password)
        changes.append("password reset")
        revoke = revoke or "パスワードのリセット"
        # 管理者によるリセットは、パスワードが漏れたときなどに行うので、API トークンも失効させる
        # （本人の「パスワード変更」では失効させない。README の「API トークン」）
        revoke_tokens = True
    detail: dict = {"changes": changes}
    if revoke_tokens:
        detail["revoked_tokens"] = await api_tokens.revoke_all(db, user.id)
    if changes:
        audit("user.update", target_type="user", target_id=user.id, target_name=user.username, detail=detail)
    await db.commit()
    await db.refresh(user)
    if revoke:
        # ロールの変更だけなら、ターミナルだけ切る（Ping監視はどのロールでも使えるので、ログインと同じく切らない）
        await close_user_sessions(user.id, revoke, ("terminal",) if revoke == "ロールの変更" else ALL_KINDS)
    if changes:
        logger.info("ユーザー更新 by=%s user=%s %s", me.username, user.username, ", ".join(changes))
    return _to_response(user, await api_tokens.count_active(db, user.id))


@router.post("/{user_id}/mfa-reset", response_model=UserResponse)
async def reset_mfa(
    request: Request,
    user_id: str,
    payload: AdminConfirm,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """2 段階認証を解除する（本人が認証アプリも予備コードも無くしたとき）。本人は次のログインからパスワードだけで入れる。

    操作する管理者のパスワードを入れ直す。自分自身は対象にできない（本人の解除 /auth/mfa/disable はコードも確かめる。
    管理者のトークンだけで、自分の 2 段階認証を外させない。#29）。解除した人のログイン中のトークンは使えなくする
    """
    user = await _get_or_404(db, user_id)
    if user.id == me.id:
        raise HTTPException(status_code=400, detail="自分の 2 段階認証は、サイドバーの「2 段階認証」から解除してください"
                                                    "（パスワードと確認コードで確かめます）")
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="このユーザーは 2 段階認証を設定していません")
    await _confirm_admin(db, request, me, payload.confirm_password, "2 段階認証の解除", "user.mfa_reset", user)
    clear_mfa(user)
    user.token_version = (user.token_version or 0) + 1
    audit("user.mfa_reset", target_type="user", target_id=user.id, target_name=user.username)
    await db.commit()
    await db.refresh(user)
    await close_user_sessions(user.id, "2 段階認証の強制解除")
    logger.info("2 段階認証の解除 by=%s user=%s", me.username, user.username)
    return _to_response(user, await api_tokens.count_active(db, user.id))


@router.post("/{user_id}/logout", response_model=ForceLogoutResponse)
async def force_logout(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """パスワードを変えずに、そのユーザーの既存のログインを切る（再ログインは可能）。API トークンもすべて失効させる"""
    user = await _get_or_404(db, user_id)
    if user.id == me.id:
        raise HTTPException(
            status_code=400, detail="自分自身はログアウトさせられません（サイドバーの「ログアウト」を使ってください）"
        )
    user.token_version = (user.token_version or 0) + 1
    revoked = await api_tokens.revoke_all(db, user.id)
    await db.commit()
    closed = await close_user_sessions(user.id, "管理者による強制ログアウト")
    audit("user.logout", target_type="user", target_id=user.id, target_name=user.username,
          detail={"closed_terminals": closed, "revoked_tokens": revoked})
    await db.commit()
    logger.info("強制ログアウト by=%s user=%s terminals=%d tokens=%d", me.username, user.username, closed, revoked)
    return ForceLogoutResponse(closed_terminals=closed)


@router.get("/{user_id}/tokens", response_model=list[TokenInfo])
async def list_user_tokens(user_id: str, db: AsyncSession = Depends(get_db)):
    """そのユーザーの API トークンの一覧（値は返さない。失効・期限切れも一定期間は残る）"""
    user = await _get_or_404(db, user_id)
    return await list_for(db, user.id)


@router.delete("/{user_id}/tokens", response_model=RevokeTokensResponse)
async def revoke_user_tokens(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    me: User = Depends(get_current_user),
    audit: Audit = Depends(get_audit),
):
    """そのユーザーの有効な API トークンをすべて失効させる（ログインはそのまま）"""
    user = await _get_or_404(db, user_id)
    n = await api_tokens.revoke_all(db, user.id)
    audit("api_token.revoke_all", target_type="user", target_id=user.id, target_name=user.username,
          detail={"revoked_tokens": n})
    await db.commit()
    logger.info("API トークンの全失効 by=%s user=%s tokens=%d", me.username, user.username, n)
    return RevokeTokensResponse(revoked_tokens=n)


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
    # API トークンも消す（SQLite では外部キーの CASCADE が効かないため明示的に）
    await db.execute(delete(ApiToken).where(ApiToken.user_id == user.id))
    await db.delete(user)
    audit("user.delete", target_type="user", target_id=user.id, target_name=user.username)
    await db.commit()
    await close_user_sessions(user.id, "ユーザーの削除")
    logger.info("ユーザー削除 by=%s user=%s", me.username, user.username)
