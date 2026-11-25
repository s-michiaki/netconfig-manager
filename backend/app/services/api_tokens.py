"""API トークンの発行・照合・失効（スクリプト・ほかのシステムから API を使うため）

- 形式: "ncm_" ＋ secrets.token_urlsafe(32)（43 文字・256 ビットの乱数）。値は発行の応答で 1 回だけ返す
- DB にはハッシュ（SHA-256 の 16 進）と、見分けるための先頭 12 文字（ncm_ ＋ 8 文字）だけを置く。
  乱数が十分に長いので、パスワードのような遅いハッシュ（bcrypt）は要らない（総当たりで当てられない）
- 範囲（scope）: read（ロールの権限のうち閲覧だけ・GET だけ）/ full（ロールの権限。ただしトークンで使えない API は除く）。
  判定のたびに、発行した人のいまのロール・有効かどうかを見る（app/api/deps.py）
- 失効: 本人・管理者（ユーザー管理）・強制ログアウト・無効化・管理者によるパスワードのリセット。
  本人のパスワード変更では失効させない（スクリプトを止めないため。漏れが疑われるときは本人か管理者が失効させる）
"""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timeutil import utcnow
from app.models.api_token import ApiToken

TOKEN_PREFIX = "ncm_"
# token_urlsafe(32) は 43 文字（base64url・パディングなし）
_TOKEN_RE = re.compile(r"^ncm_[A-Za-z0-9_-]{43}$")
PREFIX_LEN = 12  # 表示用に残す先頭の長さ（ncm_ ＋ 8 文字）
MAX_TOKENS_PER_USER = 10  # 1 人が同時に持てる有効なトークンの数
DEFAULT_DAYS = 90
LAST_USED_INTERVAL = timedelta(minutes=1)  # 最後に使った日時の更新は 1 分に 1 回まで（毎回 DB に書かない）
KEEP_DAYS = 30  # 失効・期限切れのトークンを一覧に残す日数（過ぎたら毎日の掃除で消す）


def looks_like_token(value: str) -> bool:
    """Authorization の値が API トークンとして扱うものか（ncm_ で始まるか）。形式の正しさは見ない"""
    return value.startswith(TOKEN_PREFIX)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token() -> tuple[str, str, str]:
    """（平文, ハッシュ, 表示用の先頭）"""
    plain = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return plain, hash_token(plain), plain[:PREFIX_LEN]


def is_active(t: ApiToken, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return t.revoked_at is None and t.expires_at > now


def status_of(t: ApiToken, now: datetime | None = None) -> str:
    now = now or utcnow()
    if t.revoked_at is not None:
        return "revoked"
    if t.expires_at <= now:
        return "expired"
    return "active"


async def find(db: AsyncSession, value: str) -> ApiToken | None:
    """値からトークンを引く（形式が違えば DB を見ずに None）。見つかってもハッシュを定数時間で比べ直す"""
    if not _TOKEN_RE.match(value):
        return None
    h = hash_token(value)
    t = (await db.execute(select(ApiToken).where(ApiToken.token_hash == h))).scalar_one_or_none()
    if t is None or not hmac.compare_digest(t.token_hash, h):
        return None
    return t


async def count_active(db: AsyncSession, user_id: str, now: datetime | None = None) -> int:
    now = now or utcnow()
    q = select(func.count()).select_from(ApiToken).where(
        ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None), ApiToken.expires_at > now
    )
    return (await db.execute(q)).scalar_one()


async def active_counts(db: AsyncSession, now: datetime | None = None) -> dict[str, int]:
    """ユーザーごとの有効なトークンの数（ユーザー管理の一覧用）"""
    now = now or utcnow()
    q = (select(ApiToken.user_id, func.count()).where(ApiToken.revoked_at.is_(None), ApiToken.expires_at > now)
         .group_by(ApiToken.user_id))
    return dict((await db.execute(q)).all())


async def revoke_all(db: AsyncSession, user_id: str, now: datetime | None = None) -> int:
    """そのユーザーの有効なトークンをすべて失効させる（commit は呼び出し側）。失効させた数を返す"""
    now = now or utcnow()
    r = await db.execute(
        update(ApiToken)
        .where(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None), ApiToken.expires_at > now)
        .values(revoked_at=now)
    )
    return r.rowcount or 0


def touch(t: ApiToken, ip: str | None, now: datetime | None = None) -> bool:
    """最後に使った日時・接続元を更新する（前回の更新から 1 分未満なら何もしない）。更新したら True"""
    now = now or utcnow()
    if t.last_used_at is not None and now - t.last_used_at < LAST_USED_INTERVAL:
        return False
    t.last_used_at = now
    t.last_used_ip = (ip or "")[:64] or None
    return True


async def purge_old(db: AsyncSession, now: datetime | None = None) -> int:
    """失効・期限切れから KEEP_DAYS 日を過ぎたトークンを消す（worker の毎日の掃除。commit は呼び出し側）"""
    now = now or utcnow()
    cutoff = now - timedelta(days=KEEP_DAYS)
    r = await db.execute(delete(ApiToken).where(or_(ApiToken.revoked_at < cutoff, ApiToken.expires_at < cutoff)))
    return r.rowcount or 0
