"""
認証エンドポイント
ユーザーはDBで管理し、初回起動時に ADMIN_USERNAME / ADMIN_PASSWORD から管理者を作成する。

2 段階認証（ワンタイムパスワード。app/core/totp.py）
- 本人が「アカウント」画面で設定する（/mfa/setup → 認証アプリで読み取り → /mfa/enable でコードを確認）。
  設定すると予備コード（10 個・1 回ずつ使える）を 1 度だけ表示する
- 設定した人のログインは 2 段階: /token でパスワードを確かめると mfa_token（5 分・API には使えない）を返し、
  /mfa/verify でワンタイムパスワード（または予備コード）を確かめてからトークンを発行する。
  コードの誤りもログインの失敗として数え、続けば一時停止する（パスワードが漏れていてもコードを総当たりさせない）
- 管理者は本人に代わって解除できる（認証アプリを無くしたとき。users.py の /{id}/mfa-reset）
"""

import json
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
from app.api.terminal import close_user_sessions
from app.core import totp
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, Role, permissions_for
from app.core.security import (
    DUMMY_HASH,
    MAX_PASSWORD_BYTES,
    create_access_token,
    create_mfa_token,
    decode_access_token,
    hash_password,
    password_fingerprint,
    verify_password,
)
from app.core.timeutil import utcnow
from app.models.user import User
from app.services import login_limit
from app.services.audit import client_ip, make_log, record_now

logger = logging.getLogger(__name__)
router = APIRouter()


class Token(BaseModel):
    access_token: str | None = None  # 2 段階認証が必要なときは None（mfa_token でコードを送る）
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


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
    mfa_enabled: bool = False


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
        mfa_enabled=bool(user.mfa_enabled),
    )


@router.post("/token", response_model=Token)
async def login(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    ip = client_ip(request)
    # 照合の前に試行を数え、上限を超えたらパスワードを照合せずに止める（存在しないユーザー名でも同じ応答）。
    # 照合の後に数えると、同時に送られた大量のリクエストがすべて照合まで進んでしまう
    wait, newly = await login_limit.begin_attempt(form_data.username, ip)
    if newly:
        await record_now(
            db,
            make_log(
                "auth.login_locked", username=form_data.username[:64], ip=ip, success=False,
                detail={"unit": "接続元" if newly == ["ip"] else "ユーザー名と接続元" if newly == ["user"] else "両方",
                        "minutes": settings.LOGIN_LOCK_MIN},
            ),
        )
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"ログインの失敗が続いたため、一時的にログインできません。{-(-wait // 60)} 分ほど待ってから再度お試しください",
            headers={"Retry-After": str(wait)},
        )
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
                "auth.login_failed", username=form_data.username[:64], ip=ip,
                detail={"reason": reason}, success=False,
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが正しくありません",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.mfa_enabled and user.mfa_secret:
        # 失敗の回数はまだ消さない（コードの確認が済んでから消す）
        return {"mfa_required": True, "mfa_token": create_mfa_token(user.id, user.hashed_password, user.token_version)}
    await login_limit.record_success(form_data.username, ip)
    await record_now(db, make_log("auth.login", user=user, ip=ip))
    return {"access_token": create_access_token(user.id, user.hashed_password, user.token_version), "token_type": "bearer"}


class MfaVerify(BaseModel):
    mfa_token: str
    code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)]


def _check_code(user: User, code: str) -> str | None:
    """ワンタイムパスワードか予備コードを確かめる。正しければ使った種類（totp / recovery）を返し、使用済みにする"""
    if totp.looks_like_recovery(code):
        hashes = json.loads(user.mfa_recovery or "[]")
        h = totp.hash_recovery(code)
        if h in hashes:
            hashes.remove(h)
            user.mfa_recovery = json.dumps(hashes)
            return "recovery"
        return None
    step = totp.verify(user.mfa_secret or "", code, user.mfa_last_step)
    if step is None:
        return None
    user.mfa_last_step = step
    return "totp"


@router.post("/mfa/verify", response_model=Token)
async def mfa_verify(request: Request, payload: MfaVerify, db: AsyncSession = Depends(get_db)):
    """2 段階認証の 2 段目: ワンタイムパスワード（または予備コード）を確かめてトークンを発行する"""
    ip = client_ip(request)
    claims = decode_access_token(payload.mfa_token)
    user = await db.get(User, claims["sub"]) if claims and claims.get("purpose") == "mfa" and claims.get("sub") else None
    if (user is None or not user.is_active or not user.mfa_enabled
            or claims.get("pwv") != password_fingerprint(user.hashed_password)
            or int(claims.get("tv", 0)) != (user.token_version or 0)):
        raise HTTPException(status_code=401, detail="時間が経ったため、もう一度ユーザー名とパスワードを入力してください")
    wait, newly = await login_limit.begin_attempt(user.username, ip)
    if newly:
        await record_now(db, make_log("auth.login_locked", username=user.username, ip=ip, success=False,
                                      detail={"unit": "ワンタイムパスワード", "minutes": settings.LOGIN_LOCK_MIN}))
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"ログインの失敗が続いたため、一時的にログインできません。{-(-wait // 60)} 分ほど待ってから再度お試しください",
            headers={"Retry-After": str(wait)},
        )
    kind = _check_code(user, payload.code)
    if kind is None:
        await record_now(db, make_log("auth.login_failed", username=user.username, ip=ip, success=False,
                                      detail={"reason": "ワンタイムパスワード誤り"}))
        raise HTTPException(status_code=401, detail="確認コードが正しくありません")
    await login_limit.record_success(user.username, ip)
    detail = {"mfa": "予備コード", "recovery_left": len(json.loads(user.mfa_recovery or "[]"))} if kind == "recovery" \
        else {"mfa": "ワンタイムパスワード"}
    db.add(make_log("auth.login", user=user, ip=ip, detail=detail))
    await db.commit()
    return {"access_token": create_access_token(user.id, user.hashed_password, user.token_version), "token_type": "bearer"}


class MfaSetup(BaseModel):
    secret: str
    uri: str
    qr_svg: str


class MfaCode(BaseModel):
    code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)]


class MfaDisable(MfaCode):
    password: str


class RecoveryCodes(BaseModel):
    recovery_codes: list[str]


@router.post("/mfa/setup", response_model=MfaSetup)
async def mfa_setup(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """2 段階認証の設定を始める（新しい秘密鍵を作り、認証アプリで読み取る QR コードを返す。まだ有効にはしない）"""
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証は設定済みです（設定し直すときは、いったん解除してください）")
    secret = totp.new_secret()
    user.mfa_pending = secret
    await db.commit()
    uri = totp.provisioning_uri(secret, user.username, settings.MFA_ISSUER)
    return MfaSetup(secret=secret, uri=uri, qr_svg=totp.qr_svg(uri))


@router.post("/mfa/enable", response_model=RecoveryCodes)
async def mfa_enable(
    request: Request, payload: MfaCode, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """認証アプリに表示されたコードで確認して、2 段階認証を有効にする。予備コードを返す（この 1 回だけ表示）"""
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証は設定済みです")
    if not user.mfa_pending:
        raise HTTPException(status_code=409, detail="先に「設定を始める」で QR コードを表示してください")
    step = totp.verify(user.mfa_pending, payload.code)
    if step is None:
        raise HTTPException(status_code=422,
                            detail="確認コードが正しくありません（認証アプリの時刻がずれていないかも確認してください）")
    codes = totp.new_recovery_codes()
    user.mfa_secret, user.mfa_pending, user.mfa_last_step = user.mfa_pending, None, step
    user.mfa_enabled, user.mfa_enabled_at = True, utcnow()
    user.mfa_recovery = json.dumps([totp.hash_recovery(c) for c in codes])
    db.add(make_log("auth.mfa_enable", user=user, ip=client_ip(request), target_type="user",
                    target_id=user.id, target_name=user.username))
    await db.commit()
    logger.info("2 段階認証を有効にしました user=%s", user.username)
    return RecoveryCodes(recovery_codes=codes)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodes)
async def mfa_new_recovery_codes(
    request: Request, payload: MfaCode, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """予備コードを作り直す（以前の予備コードは使えなくなる）。いまのワンタイムパスワードで確認する"""
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証を設定していません")
    if _check_code(user, payload.code) != "totp":
        await db.rollback()
        raise HTTPException(status_code=422, detail="確認コードが正しくありません（認証アプリのコードを入力してください）")
    codes = totp.new_recovery_codes()
    user.mfa_recovery = json.dumps([totp.hash_recovery(c) for c in codes])
    db.add(make_log("auth.mfa_recovery", user=user, ip=client_ip(request), target_type="user",
                    target_id=user.id, target_name=user.username))
    await db.commit()
    return RecoveryCodes(recovery_codes=codes)


@router.post("/mfa/disable", status_code=204)
async def mfa_disable(
    request: Request, payload: MfaDisable, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """本人が 2 段階認証を解除する（パスワードと、ワンタイムパスワードか予備コードで確認する）"""
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証を設定していません")
    if not await run_in_threadpool(verify_password, payload.password, user.hashed_password):
        raise HTTPException(status_code=422, detail="パスワードが正しくありません")
    if _check_code(user, payload.code) is None:
        await db.rollback()
        raise HTTPException(status_code=422, detail="確認コードが正しくありません")
    clear_mfa(user)
    db.add(make_log("auth.mfa_disable", user=user, ip=client_ip(request), target_type="user",
                    target_id=user.id, target_name=user.username))
    await db.commit()


def clear_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = user.mfa_pending = user.mfa_recovery = None
    user.mfa_last_step = None
    user.mfa_enabled_at = None


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
    # 変更前のパスワードで開いたターミナル（ほかの PC で開いたままのものを含む）も切る
    closed = await close_user_sessions(user.id, "パスワードの変更")
    logger.info("パスワード変更 user=%s terminals=%d", user.username, closed)
    # 変更前のトークンは無効になるため、新しいトークンを返す
    return {"access_token": create_access_token(user.id, user.hashed_password, user.token_version), "token_type": "bearer"}


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
