"""ログインの試行回数の制限（総当たり・リスト型攻撃の対策）

- 試行を Redis で数える。数える単位は2つ
    「ユーザー名 × 接続元 IP」: LOGIN_MAX_FAILURES 回（既定 5 回）
    「接続元 IP」           : LOGIN_MAX_FAILURES_PER_IP 回（既定 20 回。ユーザー名を変えながらの試行を止める）
  いずれも LOGIN_FAILURE_WINDOW_MIN 分（既定 10 分）の間の回数
- パスワードを照合する**前に**数える（begin_attempt）。上限を超えた試行は照合せずに止め、
  LOGIN_LOCK_MIN 分（既定 15 分）その単位でのログインを止める（正しいパスワードでも 429）
  照合の後に数えると、同時に大量に送られたリクエストがすべて照合まで進んでしまうため
- 成功したら、その試行は数えない（「ユーザー名 × 接続元」の回数は消し、「接続元」は1回分戻す）。
  同じ接続元（NAT の内側など）から普通にログインする人が多くても止まらないように
- ユーザー名だけでは止めない（他人が管理者を締め出せてしまうため）。接続元 IP は nginx が付ける値を使う
- 存在しないユーザー名でも同じように数え・止めるので、応答からユーザーの有無は分からない
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


async def begin_attempt(username: str, ip: str | None) -> tuple[int, list[str]]:
    """照合の前に試行を数える。（止める場合の残り秒数（通すなら 0）, 今回ロックした単位 "user" / "ip"）"""
    keys = _keys(username, ip)
    try:
        r = client()
        ttls = [await r.ttl(f"{PREFIX}:lock:{k}") for k, _ in keys]
        wait = max([t for t in ttls if t > 0], default=0)
        if wait:
            return wait, []
        # 数えると同時に期限を付ける（INCR と EXPIRE を1つのトランザクションで。期限の無いカウンタが残らないように）
        pipe = r.pipeline(transaction=True)
        for k, _ in keys:
            pipe.incr(f"{PREFIX}:fail:{k}")
            pipe.expire(f"{PREFIX}:fail:{k}", settings.LOGIN_FAILURE_WINDOW_MIN * 60, nx=True)
        counts = (await pipe.execute())[0::2]
        newly: list[str] = []
        over = False
        for (k, limit), n in zip(keys, counts, strict=True):
            if limit > 0 and n > limit:
                over = True
                # nx: 同時に上限を超えた試行が重なっても、ロックの開始（と監査ログの記録）は1回だけ
                if await r.set(f"{PREFIX}:lock:{k}", "1", ex=settings.LOGIN_LOCK_MIN * 60, nx=True):
                    newly.append(k.split(":", 1)[0])
        return (settings.LOGIN_LOCK_MIN * 60 if over else 0), newly
    except RedisError as e:
        logger.warning("ログインの試行回数の確認に失敗しました（制限せずに続行）: %s", e)
        return 0, []


async def record_success(username: str, ip: str | None) -> None:
    """成功した試行は数えない"""
    (user_key, _), (ip_key, _) = _keys(username, ip)
    try:
        r = client()
        await r.delete(f"{PREFIX}:fail:{user_key}")
        if await r.decr(f"{PREFIX}:fail:{ip_key}") <= 0:
            await r.delete(f"{PREFIX}:fail:{ip_key}")
    except RedisError as e:
        logger.warning("ログインの試行回数の消去に失敗しました: %s", e)
