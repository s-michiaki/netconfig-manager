"""ログインの失敗回数の制限（総当たり・リスト型攻撃の対策）

- 失敗を Redis で数える。数える単位は2つ
    「ユーザー名 × 接続元 IP」: LOGIN_MAX_FAILURES 回（既定 5 回）
    「接続元 IP」           : LOGIN_MAX_FAILURES_PER_IP 回（既定 20 回。ユーザー名を変えながらの試行を止める）
  いずれも LOGIN_FAILURE_WINDOW_MIN 分（既定 10 分）の間の回数
- 上限に達したら LOGIN_LOCK_MIN 分（既定 15 分）、その単位でのログインを止める（正しいパスワードでも 429）
- ユーザー名だけでは止めない（他人が管理者を締め出せてしまうため）。接続元 IP は nginx が付ける値を使う
- 存在しないユーザー名でも同じように数え・止めるので、応答からユーザーの有無は分からない
- 成功したら「ユーザー名 × 接続元 IP」の回数を消す
- Redis に接続できないときは制限せずにログインを通す（警告をログに出す）。Redis が止まっても管理者が入れるように
"""
import hashlib
import logging

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

PREFIX = "netconfig:login"
_client: aioredis.Redis | None = None


def client() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(settings.REDIS_URL, socket_timeout=2, socket_connect_timeout=2)
    return _client


def _keys(username: str, ip: str | None) -> list[tuple[str, int]]:
    """（キーの名前, 上限回数）。ユーザー名は長さ・文字種を問わず扱えるようハッシュにする"""
    ip = ip or "unknown"
    user = hashlib.sha256(username.strip().lower().encode()).hexdigest()[:32]
    return [(f"user:{user}:{ip}", settings.LOGIN_MAX_FAILURES), (f"ip:{ip}", settings.LOGIN_MAX_FAILURES_PER_IP)]


async def locked(username: str, ip: str | None) -> int:
    """ロック中なら残り秒数（ロックしていなければ 0）"""
    try:
        r = client()
        ttls = [await r.ttl(f"{PREFIX}:lock:{k}") for k, _ in _keys(username, ip)]
    except RedisError as e:
        logger.warning("ログイン失敗回数の確認に失敗しました（制限せずに続行）: %s", e)
        return 0
    return max([t for t in ttls if t > 0], default=0)


async def record_failure(username: str, ip: str | None) -> list[str]:
    """失敗を数える。今回の失敗でロックした単位（"user" / "ip"）を返す"""
    newly: list[str] = []
    try:
        r = client()
        for key, limit in _keys(username, ip):
            n = await r.incr(f"{PREFIX}:fail:{key}")
            if n == 1:
                await r.expire(f"{PREFIX}:fail:{key}", settings.LOGIN_FAILURE_WINDOW_MIN * 60)
            if limit > 0 and n >= limit:
                # nx: ロック中に失敗が重なっても期限を延ばさない（同じロックの記録も1回だけ）
                if await r.set(f"{PREFIX}:lock:{key}", "1", ex=settings.LOGIN_LOCK_MIN * 60, nx=True):
                    newly.append(key.split(":", 1)[0])
                await r.delete(f"{PREFIX}:fail:{key}")
    except RedisError as e:
        logger.warning("ログイン失敗回数の記録に失敗しました: %s", e)
    return newly


async def record_success(username: str, ip: str | None) -> None:
    try:
        key, _ = _keys(username, ip)[0]
        await client().delete(f"{PREFIX}:fail:{key}")
    except RedisError as e:
        logger.warning("ログイン失敗回数の消去に失敗しました: %s", e)
