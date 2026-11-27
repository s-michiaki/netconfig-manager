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
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import AfterValidator, BaseModel, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import effective_permissions, get_current_user, oauth2_scheme, require_session
from app.api.terminal import close_user_sessions
from app.api.token_policy import token_route_perms
from app.core import totp
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import ROLE_LABELS, Role
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
from app.services import api_tokens, login_limit, sessions
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
    # API トークンで呼んだときは、その範囲（read / full）。permissions もその範囲で絞ったもの
    api_token_scope: str | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: NewPassword
    revoke_api_tokens: bool = False  # API トークンもすべて失効させる（漏れた疑いがあるとき）


def user_info(user: User, token_perms: frozenset | None = None) -> UserInfo:
    """token_perms: API トークンのときに、トークンで呼べる API が要求する権限（これと重なるものだけ返す）"""
    try:
        label = ROLE_LABELS[Role(user.role)]
    except ValueError:
        label = user.role
    return UserInfo(
        id=user.id,
        username=user.username,
        role=user.role,
        role_label=label,
        permissions=sorted(p.value for p in effective_permissions(user)
                           if user.api_token is None or token_perms is None or p in token_perms),
        mfa_enabled=bool(user.mfa_enabled),
        api_token_scope=user.api_token.scope if user.api_token is not None else None,
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
    # パスワードの確認（/token）と、この確認コードの 2 回分を戻す（#13。1 回分だけだと接続元の回数が増えて残る）
    await login_limit.record_success(user.username, ip, attempts=2)
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


class PasswordConfirm(BaseModel):
    """重い操作の前の本人の確認（いまのパスワード）"""

    password: str


class RecoveryCodes(BaseModel):
    recovery_codes: list[str]
    # 2 段階認証を有効にしたときは、それまでのトークンが使えなくなるので、新しいトークンを返す
    access_token: str | None = None


# ---------------------------------------------------------------- 本人の確認のやり直し（step-up）
# パスワード・確認コードを照合する API は、ログインと同じ回数の制限（login_limit）の中で照合する（#28）。
# 漏れたログインのトークンから総当たりさせないため。成功したら、その試行は数えない（正しい利用者を締め出さない）


def _locked(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"確認の誤りが続いたため、一時的に操作できません。{-(-wait // 60)} 分ほど待ってから再度お試しください",
        headers={"Retry-After": str(wait)},
    )


async def begin_step_up(db: AsyncSession, user: User, ip: str | None, what: str) -> None:
    """照合の前に試行を数える。上限を超えていたら照合せずに 429（ロックの開始は監査ログに残す）"""
    wait, newly = await login_limit.begin_attempt(user.username, ip, per_ip=False)
    if newly:
        await record_now(db, make_log("auth.login_locked", user=user, ip=ip, success=False,
                                      detail={"unit": f"本人の確認（{what}）", "minutes": settings.LOGIN_LOCK_MIN}))
    if wait:
        raise _locked(wait)


async def confirm_password(db: AsyncSession, request: Request, user: User, password: str, *, action: str,
                           what: str, status_code: int = 422, target: dict | None = None) -> None:
    """いまのパスワードで本人を確かめる（回数の制限つき）。誤りは action の失敗として監査ログに残す。

    呼ぶのは DB を変える前（誤りの記録で commit するため）
    """
    ip = client_ip(request)
    await begin_step_up(db, user, ip, what)
    if not await run_in_threadpool(verify_password, password, user.hashed_password):
        await record_now(db, make_log(action, user=user, ip=ip, success=False, **(target or {}),
                                      detail={"reason": "パスワード誤り", "step": what}))
        raise HTTPException(status_code=status_code, detail="パスワードが正しくありません")
    await login_limit.step_up_success(user.username, ip)


async def _close_sessions_for_self(background: BackgroundTasks, user: User, reason: str, token: str) -> None:
    """本人の操作で、開いているターミナル・Ping 監視を切る。

    - ほかの端末（操作に使ったトークン以外）で開いたもの: 応答の**前**に 4401 で切る（後回しの処理が動かない経路でも残さない）
    - 操作に使ったトークンで開いたもの: 応答（新しいトークン・予備コード）を返した**あと**に 4409 で切る。先に切ると、
      同じブラウザの Ping 監視などの画面が、新しいトークンを受け取る前に古いトークンのままログイン画面へ移ってしまう
    """
    key = sessions.token_key(token)
    await close_user_sessions(user.id, reason, exclude_key=key)
    background.add_task(close_user_sessions, user.id, reason, token_key=key, refreshed_key=key)


def _bump_token_version(user: User) -> None:
    user.token_version = (user.token_version or 0) + 1


def _self_target(user: User) -> dict:
    return {"target_type": "user", "target_id": user.id, "target_name": user.username}


@router.post("/mfa/setup", response_model=MfaSetup)
async def mfa_setup(
    request: Request, payload: PasswordConfirm, user: User = Depends(require_session), db: AsyncSession = Depends(get_db)
):
    """2 段階認証の設定を始める（新しい秘密鍵を作り、認証アプリで読み取る QR コードを返す。まだ有効にはしない）。

    パスワードを入れ直す（漏れたログインのトークンから、攻撃者が自分の認証アプリを登録して本人を締め出せないように。#29）
    """
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証は設定済みです（設定し直すときは、いったん解除してください）")
    await confirm_password(db, request, user, payload.password, action="auth.mfa_enable", what="2 段階認証の設定",
                           target=_self_target(user))
    secret = totp.new_secret()
    user.mfa_pending = secret
    await db.commit()
    uri = totp.provisioning_uri(secret, user.username, settings.MFA_ISSUER)
    return MfaSetup(secret=secret, uri=uri, qr_svg=totp.qr_svg(uri))


@router.post("/mfa/enable", response_model=RecoveryCodes)
async def mfa_enable(
    request: Request, payload: MfaCode, background: BackgroundTasks, token: str = Depends(oauth2_scheme),
    user: User = Depends(require_session), db: AsyncSession = Depends(get_db),
):
    """認証アプリに表示されたコードで確認して、2 段階認証を有効にする。予備コードを返す（この 1 回だけ表示）。

    それまでのログインのトークン（2 段階認証を通っていないもの）は使えなくする。自分には新しいトークンを返す
    """
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証は設定済みです")
    if not user.mfa_pending:
        raise HTTPException(status_code=409, detail="先に「設定を始める」で QR コードを表示してください")
    # コードの照合も、ほかの本人の確認と同じ回数の制限の中で行う
    ip = client_ip(request)
    await begin_step_up(db, user, ip, "2 段階認証の有効化")
    step = totp.verify(user.mfa_pending, payload.code)
    if step is None:
        await record_now(db, make_log("auth.mfa_enable", user=user, ip=ip, success=False, **_self_target(user),
                                      detail={"reason": "確認コード誤り"}))
        raise HTTPException(status_code=422,
                            detail="確認コードが正しくありません（認証アプリの時刻がずれていないかも確認してください）")
    await login_limit.step_up_success(user.username, ip)
    codes = totp.new_recovery_codes()
    user.mfa_secret, user.mfa_pending, user.mfa_last_step = user.mfa_pending, None, step
    user.mfa_enabled, user.mfa_enabled_at = True, utcnow()
    user.mfa_recovery = json.dumps([totp.hash_recovery(c) for c in codes])
    _bump_token_version(user)
    db.add(make_log("auth.mfa_enable", user=user, ip=client_ip(request), **_self_target(user)))
    await db.commit()  # 失効（tv の +1）は応答の前に確定させる
    await _close_sessions_for_self(background, user, "2 段階認証の設定", token)
    logger.info("2 段階認証を有効にしました user=%s", user.username)
    return RecoveryCodes(recovery_codes=codes,
                         access_token=create_access_token(user.id, user.hashed_password, user.token_version))


@router.post("/mfa/recovery-codes", response_model=RecoveryCodes)
async def mfa_new_recovery_codes(
    request: Request, payload: MfaCode, user: User = Depends(require_session), db: AsyncSession = Depends(get_db)
):
    """予備コードを作り直す（以前の予備コードは使えなくなる）。いまのワンタイムパスワードで確認する（回数の制限つき）"""
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証を設定していません")
    ip = client_ip(request)
    await begin_step_up(db, user, ip, "予備コードの作り直し")
    if _check_code(user, payload.code) != "totp":
        await db.rollback()  # 予備コードを使用済みにした変更を戻す
        await db.refresh(user)
        await record_now(db, make_log("auth.mfa_recovery", user=user, ip=ip, success=False, **_self_target(user),
                                      detail={"reason": "確認コード誤り"}))
        raise HTTPException(status_code=422, detail="確認コードが正しくありません（認証アプリのコードを入力してください）")
    await login_limit.step_up_success(user.username, ip)
    codes = totp.new_recovery_codes()
    user.mfa_recovery = json.dumps([totp.hash_recovery(c) for c in codes])
    db.add(make_log("auth.mfa_recovery", user=user, ip=ip, **_self_target(user)))
    await db.commit()
    return RecoveryCodes(recovery_codes=codes)


@router.post("/mfa/disable", response_model=Token)
async def mfa_disable(
    request: Request, payload: MfaDisable, background: BackgroundTasks, token: str = Depends(oauth2_scheme),
    user: User = Depends(require_session), db: AsyncSession = Depends(get_db),
):
    """本人が 2 段階認証を解除する（パスワードと、ワンタイムパスワードか予備コードで確認する。回数の制限つき）。

    それまでのログインのトークンは使えなくする。自分には新しいトークンを返す
    """
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="2 段階認証を設定していません")
    ip = client_ip(request)
    # パスワードとコードで 1 回と数える（どちらの誤りも同じ回数の制限の中）
    await begin_step_up(db, user, ip, "2 段階認証の解除")
    if not await run_in_threadpool(verify_password, payload.password, user.hashed_password):
        await record_now(db, make_log("auth.mfa_disable", user=user, ip=ip, success=False, **_self_target(user),
                                      detail={"reason": "パスワード誤り"}))
        raise HTTPException(status_code=422, detail="パスワードが正しくありません")
    if _check_code(user, payload.code) is None:
        await db.rollback()
        await db.refresh(user)
        await record_now(db, make_log("auth.mfa_disable", user=user, ip=ip, success=False, **_self_target(user),
                                      detail={"reason": "確認コード誤り"}))
        raise HTTPException(status_code=422, detail="確認コードが正しくありません")
    await login_limit.step_up_success(user.username, ip)
    clear_mfa(user)
    _bump_token_version(user)
    db.add(make_log("auth.mfa_disable", user=user, ip=ip, **_self_target(user)))
    await db.commit()
    await _close_sessions_for_self(background, user, "2 段階認証の解除", token)
    return {"access_token": create_access_token(user.id, user.hashed_password, user.token_version), "token_type": "bearer"}


def clear_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = user.mfa_pending = user.mfa_recovery = None
    user.mfa_last_step = None
    user.mfa_enabled_at = None


@router.get("/me", response_model=UserInfo)
async def me(request: Request, user: User = Depends(get_current_user)):
    """ログイン中のユーザーとその権限（フロントはこれで表示を切り替える）。

    API トークンのときは、範囲で絞ったうえで、トークンで呼べる API が要求する権限だけを返す（user:admin などは出さない）
    """
    if user.api_token is not None:
        return user_info(user, token_route_perms(request.app))
    return user_info(user)


@router.post("/change-password", response_model=Token)
async def change_password(
    request: Request,
    payload: PasswordChange,
    background: BackgroundTasks,
    token: str = Depends(oauth2_scheme),
    user: User = Depends(require_session),
    db: AsyncSession = Depends(get_db),
):
    # 現在のパスワードの照合は、ログインと同じ回数の制限の中で行う（#28）
    await confirm_password(db, request, user, payload.current_password, action="auth.password_change",
                           what="パスワード変更", status_code=400, target=_self_target(user))
    user.hashed_password = await run_in_threadpool(hash_password, payload.new_password)
    detail: dict = {}
    if payload.revoke_api_tokens:
        detail["revoked_tokens"] = await api_tokens.revoke_all(db, user.id)
    db.add(make_log("auth.password_change", user=user, ip=client_ip(request), **_self_target(user), detail=detail or None))
    await db.commit()
    # 変更前のパスワードで開いたターミナル（ほかの PC で開いたままのものを含む）も切る（応答を返したあと）
    await _close_sessions_for_self(background, user, "パスワードの変更", token)
    logger.info("パスワード変更 user=%s tokens=%s", user.username, detail.get("revoked_tokens", "-"))
    # 変更前のトークンは無効になるため、新しいトークンを返す
    return {"access_token": create_access_token(user.id, user.hashed_password, user.token_version), "token_type": "bearer"}


# ---------------------------------------------------------------- ログアウト（本人）


class LogoutResult(BaseModel):
    scope: Literal["session", "all"]  # session = この画面のログインだけ / all = すべての端末（Redis に書けなかったときも）
    closed_terminals: int = 0
    revoked_tokens: int = 0


class LogoutAll(BaseModel):
    revoke_api_tokens: bool = False  # API トークンも失効させる


@router.post("/logout", response_model=LogoutResult)
async def logout(
    request: Request, token: str = Depends(oauth2_scheme), user: User = Depends(require_session),
    db: AsyncSession = Depends(get_db),
):
    """このログイン（いま使っているトークン）を失効させる。ほかの端末のログインと API トークンはそのまま。

    失効は Redis に期限つきで残す（services/sessions.py）。Redis に書けないときは、すべての端末からログアウトさせる
    （token_version を上げる。ログアウトしたつもりのトークンが使えたままにならないように）。
    このトークンで開いたターミナル・Ping 監視も切る
    """
    claims = decode_access_token(token) or {}
    ip = client_ip(request)
    if await sessions.revoke(token, claims.get("exp")):
        closed = await close_user_sessions(user.id, "ログアウト", token_key=sessions.token_key(token))
        db.add(make_log("auth.logout", user=user, ip=ip, detail={"scope": "この端末"}))
        await db.commit()
        return LogoutResult(scope="session", closed_terminals=closed)
    _bump_token_version(user)
    db.add(make_log("auth.logout", user=user, ip=ip, detail={"scope": "すべての端末（失効の記録に失敗したため）"}))
    await db.commit()
    closed = await close_user_sessions(user.id, "ログアウト")
    return LogoutResult(scope="all", closed_terminals=closed)


@router.post("/logout-all", response_model=LogoutResult)
async def logout_all(
    request: Request, payload: LogoutAll, user: User = Depends(require_session), db: AsyncSession = Depends(get_db),
):
    """すべての端末からログアウトする（token_version を上げる。この画面のログインも切れる）。

    管理者の強制ログアウトと同じく、開いているターミナル・Ping 監視も切る。API トークンは選んだときだけ失効させる
    """
    _bump_token_version(user)
    revoked = await api_tokens.revoke_all(db, user.id) if payload.revoke_api_tokens else 0
    await db.commit()
    closed = await close_user_sessions(user.id, "すべての端末からのログアウト")
    db.add(make_log("auth.logout_all", user=user, ip=client_ip(request), **_self_target(user),
                    detail={"closed_terminals": closed, "revoked_tokens": revoked}))
    await db.commit()
    logger.info("すべての端末からログアウト user=%s terminals=%d tokens=%d", user.username, closed, revoked)
    return LogoutResult(scope="all", closed_terminals=closed, revoked_tokens=revoked)


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
