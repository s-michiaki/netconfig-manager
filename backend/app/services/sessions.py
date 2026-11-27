"""ログインのセッション（JWT）の失効（本人の「ログアウト」）

- ログアウトしたトークンを Redis に「失効」として残す。キーはトークンの SHA-256 の先頭（値そのものは残さない）、
  キーの期限はそのトークンの残りの有効期間（期限が切れたトークンはもともと使えないので、キーも自然に消える）
- 認証のたび（app/api/deps.py の _load_active_user。WebSocket の認証も同じ関数）に確かめる
- Redis に届かないときは確かめずに通す（login_limit と同じ方針。Redis が止まっても管理者が入れるように）。
  その後 SKIP_SEC 秒は確かめるのを休む（Redis が応答しないときに、すべての要求が待たされないように）
- ログアウトで Redis に書けなかったときは、呼び出し側が token_version を上げる（＝すべての端末からログアウト）で代える。
  DB の列は増やさない（token_version・パスワードの指紋で失効させる今の仕組みはそのまま）
"""
import hashlib
import logging
import time

from redis.exceptions import RedisError

from app.services import login_limit

logger = logging.getLogger(__name__)

PREFIX = "netconfig:session:revoked"
SKIP_SEC = 30
_skip_until = 0.0
_warned = False  # 届かないことを警告済みか（毎要求・30 秒ごとにログを出さない）


def token_key(token: str) -> str:
    """トークンを識別する値（ハッシュの先頭。ターミナル・Ping の WebSocket の登録にも使う）"""
    return hashlib.sha256(token.encode()).hexdigest()[:32]


async def revoke(token: str, exp: int | float | None) -> bool:
    """このトークンを失効させる。書けたら True（Redis に届かなければ False）"""
    ttl = int((exp or 0) - time.time()) + 5
    if ttl <= 5:
        return True  # 期限切れ（ほぼ切れる）トークンは、もう使えない
    try:
        await login_limit.client().set(f"{PREFIX}:{token_key(token)}", "1", ex=ttl)
        return True
    except (RedisError, OSError) as e:
        logger.warning("ログアウトしたトークンを記録できませんでした: %s", e)
        return False


async def is_revoked(token: str) -> bool:
    """Redis に届かない間は確かめずに通す（False）。警告のログは、届かなくなったときに 1 回だけ（戻ったら 1 回）"""
    global _skip_until, _warned
    if time.monotonic() < _skip_until:
        return False
    try:
        found = bool(await login_limit.client().exists(f"{PREFIX}:{token_key(token)}"))
    except (RedisError, OSError) as e:
        _skip_until = time.monotonic() + SKIP_SEC
        if not _warned:
            _warned = True
            logger.warning("ログアウトしたトークンの確認ができません。Redis に届くまで、確かめずに通します"
                           "（%d 秒ごとに確かめ直します）: %s", SKIP_SEC, e)
        return False
    if _warned:
        _warned = False
        logger.warning("ログアウトしたトークンの確認を再開しました（Redis に届きました）")
    return found
