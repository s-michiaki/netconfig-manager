"""無操作によるタイムアウト（ログアウト）

- ログイン（JWT）ごとに、最後の操作の時刻を Redis に持つ。キーは netconfig:idle:<jti>（jti の無い古いトークンは
  トークンのハッシュの先頭。sessions.token_key）、値はエポック秒。キーの期限はトークンの残りの寿命（それより長く残さない）
- 時刻を進めるのは明示の合図だけ: ログインの完了・新しいトークンを返す所（start）と、画面が利用者の操作のあとに送る
  POST /api/auth/activity（touch）、Ping 監視の WebSocket で監視が動いている間（api/ping.py が touch する）。
  ふつうの API の要求では進めない（ダッシュボードの再読み込みなど、画面の自動の更新で延びないように）
- 判定（enforce）は認証のたび（app/api/deps.py の _load_active_user。WebSocket の認証も同じ）。
  IDLE_TIMEOUT_MIN 分を過ぎていたら、値を "expired" に書き換え（あとから touch しても生き返らない）、そのトークンを
  失効させ（sessions.revoke）、監査ログに「ログアウト（無操作）」を 1 回だけ残し、そのトークンで開いたターミナル・
  Ping 監視を切る
- 記録が無いとき（この機能の前からのログイン・Redis の再起動）は切らずに「いま」として記録を始める
- 判定と書き込みは Lua のスクリプト 1 本（_SCRIPT）で不可分に行う（読んでから書くまでの間に、ほかの要求の判定・
  書き込みが割り込まないように）。時刻を進める（touch）ときも期限を確かめ、過ぎていれば書かずに「過ぎた」とする
  （止めていた Ping 監視の start・遅れて届いた /activity で生き返らない）
- 画面の時計で時間が来たとき（POST /api/auth/logout に {"reason": "idle"}。expire_now）は、このログインだけを
  失効させる。Redis に届かなくても、ほかの端末まで切らない（ふつうのログアウトと違い token_version を上げない）
- Redis に届かないときは確かめずに通す（login_limit・sessions と同じ方針）。警告のログは届かなくなったときに 1 回だけ
- API トークン（ncm_…）は対象外（deps が呼ばない）
"""
import asyncio
import logging
import time
from typing import Literal

from redis.exceptions import RedisError, ResponseError

from app.core.config import settings
from app.core.security import decode_access_token
from app.services import login_limit, sessions

logger = logging.getLogger(__name__)

PREFIX = "netconfig:idle"
EXPIRED = b"expired"
# 画面が理由を見分けるための値（401 の X-Logout-Reason ヘッダー・WebSocket の close の reason）
REASON_CODE = "idle_timeout"
DETAIL = "操作が無い時間が続いたため、ログアウトしました"
# ターミナル・Ping 監視を切るときの理由（api/terminal.py の close_user_sessions に渡す。記録の終了理由は「無操作による切断」）
CLOSE_REASON = "無操作"
# WebSocket の側で時間を過ぎていないかを確かめる間隔（秒）。要求が来なくても切れるように
WS_CHECK_SEC = 30.0
# Ping 監視が動いている間に時刻を進める間隔（秒。tick のたびに Redis へ書かないように）
PING_TOUCH_SEC = 20.0

# 判定と書き込みを不可分にするスクリプト。KEYS[1]=キー、ARGV = いまの時刻・時間（秒）・キーの期限（秒）・mode
#   mode=check : 判定だけ（記録が無ければ「いま」として記録を始める）
#   mode=touch : 時間内なら「いま」にする（ログインの完了・/activity・Ping 監視）
#   mode=expire: 時間に関係なく、いま過ぎた扱いにする（画面の時計で時間が来たとき）
# 戻り値: ok / expired（失効済み）/ first（いま過ぎたと判定した。後始末はこの 1 回だけ）
_SCRIPT = """
local v = redis.call('GET', KEYS[1])
if v == 'expired' then return 'expired' end
if ARGV[4] == 'expire' then
  if v then redis.call('SET', KEYS[1], 'expired', 'KEEPTTL') else redis.call('SET', KEYS[1], 'expired', 'EX', ARGV[3]) end
  return 'first'
end
if not v then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
  return 'ok'
end
local last = tonumber(v)
if not last then
  -- 数字でない記録（壊れた値）: 記録が無いときと同じく「いま」から数える
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
  return 'ok'
end
if tonumber(ARGV[1]) - last > tonumber(ARGV[2]) then
  redis.call('SET', KEYS[1], 'expired', 'KEEPTTL')
  return 'first'
end
if ARGV[4] == 'touch' then redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3]) end
return 'ok'
"""
State = Literal["ok", "expired", "first", "unavailable"]
# 後始末（失効・監査ログ・WebSocket の切断）のタスク。呼び出し元（WebSocket の監視）が取り消されても、最後まで切る
_close_tasks: set[asyncio.Task] = set()

SKIP_SEC = 30
_skip_until = 0.0
_warned = False  # 届かないことを警告済みか（毎要求にログを出さない）


def _now() -> float:
    """いまの時刻（テストで差し替える）"""
    return time.time()


def enabled() -> bool:
    return settings.IDLE_TIMEOUT_MIN > 0


def _key(token: str, claims: dict) -> str:
    jti = claims.get("jti")
    return f"{PREFIX}:{jti if isinstance(jti, str) and jti else sessions.token_key(token)}"


def _ttl(claims: dict) -> int:
    """キーの期限（秒）。トークンの残りの寿命を超えない"""
    try:
        left = int(float(claims.get("exp")) - _now())
    except (TypeError, ValueError):
        left = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return max(1, left)


def _down(e: Exception) -> None:
    global _skip_until, _warned
    _skip_until = time.monotonic() + SKIP_SEC
    if not _warned:
        _warned = True
        logger.warning("無操作の時間を確かめられません。Redis に届くまで、無操作では切らずに通します"
                       "（%d 秒ごとに確かめ直します）: %s", SKIP_SEC, e)


ERROR_LOG_SEC = 300  # スクリプトの実行エラーのログを繰り返す間隔（秒）
_error_logged = -1e9


def _script_error(e: Exception) -> None:
    """Redis には届いたが、スクリプトの実行が断られた（Lua のエラー・EVAL を禁じた設定など）。

    届かないときと同じく切らずに通すが、機能が黙って働かなくならないよう、error のログを間引いて繰り返す
    """
    global _error_logged
    if time.monotonic() - _error_logged >= ERROR_LOG_SEC:
        _error_logged = time.monotonic()
        logger.error("無操作の時間の確認でスクリプトを実行できませんでした（無操作では切らずに通します。"
                     "Redis の設定で EVAL が使えるかを確かめてください）: %s", e)


def _up() -> None:
    global _warned
    if _warned:
        _warned = False
        logger.warning("無操作の時間の確認を再開しました（Redis に届きました）")


def _skipping() -> bool:
    return time.monotonic() < _skip_until


async def _run(token: str, claims: dict, mode: str) -> State:
    """スクリプトを 1 回実行する。無効の設定・Redis に届かないときは unavailable（呼び出し側は通す）"""
    if not enabled() or _skipping():
        return "unavailable"
    try:
        res = await login_limit.client().eval(_SCRIPT, 1, _key(token, claims), repr(_now()),
                                              settings.IDLE_TIMEOUT_MIN * 60, _ttl(claims), mode)
    except ResponseError as e:  # 届いてはいる（「Redis に届かない」とは分ける）
        _script_error(e)
        return "unavailable"
    except (RedisError, OSError) as e:
        _down(e)
        return "unavailable"
    _up()
    res = res.decode() if isinstance(res, bytes) else str(res)
    return res if res in ("ok", "expired", "first") else "ok"  # type: ignore[return-value]


async def touch(user, token: str, claims: dict | None = None, ip: str | None = None) -> bool:
    """最後の操作の時刻を「いま」にする（/activity・Ping 監視）。時間を過ぎていれば書かずに False

    いま過ぎたと判定したときは、enforce と同じ後始末（失効・監査ログ・WebSocket の切断）を 1 回だけ行う
    """
    claims = claims if claims is not None else (decode_access_token(token) or {})
    state = await _run(token, claims, "touch")
    if state == "first":
        await _expire(user, token, claims, ip)
    return state in ("ok", "unavailable")


async def start(token: str) -> None:
    """ログインの完了・新しいトークンを返したとき。そのログインの数え始め（新しい jti なので過ぎていることは無い）"""
    await _run(token, decode_access_token(token) or {}, "touch")


async def expire_now(user, token: str, claims: dict, ip: str | None = None) -> bool:
    """画面の時計で時間が来た（POST /api/auth/logout の reason=idle）。このログインだけを過ぎた扱いにする。

    Redis に届かないときは何もしない（False。ほかの端末まで切らない。画面は手元のトークンを捨てる）
    """
    state = await _run(token, claims, "expire")
    if state == "first":
        await _expire(user, token, claims, ip)
    return state != "unavailable"


async def is_expired(token: str, claims: dict) -> bool:
    """無操作で失効させたログインか（失効済みのトークンの 401 に、理由を付けるため。判定はしない）"""
    if not enabled() or _skipping():
        return False
    try:
        return await login_limit.client().get(_key(token, claims)) == EXPIRED
    except ResponseError as e:
        _script_error(e)
        return False
    except (RedisError, OSError) as e:
        _down(e)
        return False


async def enforce(user, token: str, claims: dict, ip: str | None = None) -> bool:
    """時間内なら True。過ぎていれば False（初めて過ぎたと判定したときは、失効・監査ログ・WebSocket の切断も行う）"""
    state = await _run(token, claims, "check")
    if state == "first":
        await _expire(user, token, claims, ip)
    return state in ("ok", "unavailable")


async def close_token_sessions(user_id: str, token: str) -> None:
    """そのトークンで開いたターミナル・Ping 監視をすべて切る。

    切られた接続の後片付けが、呼び出し元（その接続の watch_ws）を取り消しても、残りの接続まで切り終える（shield）
    """
    from app.api.terminal import close_user_sessions

    task = asyncio.ensure_future(close_user_sessions(user_id, CLOSE_REASON, token_key=sessions.token_key(token)))
    _close_tasks.add(task)
    task.add_done_callback(_close_tasks.discard)
    await asyncio.shield(task)


async def _expire(user, token: str, claims: dict, ip: str | None) -> None:
    """いま過ぎたと判定した 1 回だけの後始末。呼び出し元（WebSocket の監視）が途中で取り消されても最後まで行う
    （同じトークンのほかの接続の監視が先に切ると、こちらの監視が取り消されて、監査ログが残らないことがあるため）"""
    task = asyncio.ensure_future(_expire_body(user, token, claims, ip))
    _close_tasks.add(task)
    task.add_done_callback(_close_tasks.discard)
    await asyncio.shield(task)


async def _expire_body(user, token: str, claims: dict, ip: str | None) -> None:
    # 遅く読む（audit → api.deps → このファイルの順に読まれるため）
    from app.core.database import AsyncSessionLocal
    from app.services.audit import make_log, record_now

    await sessions.revoke(token, claims.get("exp"))
    log = make_log("auth.logout", user=user, ip=ip,
                   detail={"scope": "この端末", "reason": "無操作", "minutes": settings.IDLE_TIMEOUT_MIN})
    try:
        # 自前のセッションで残す（呼び出し元のセッションは、取り消されたときに閉じられることがあるため）
        async with AsyncSessionLocal() as db:
            await record_now(db, log)
    except Exception:  # noqa: BLE001 - 記録に失敗しても、ログアウトは進める
        logger.exception("無操作のログアウトを監査ログに残せませんでした")
    await close_token_sessions(user.id, token)
    logger.info("無操作のためログアウト user=%s", user.username)


async def watch_ws(user, token: str, ip: str | None) -> None:
    """WebSocket（ターミナル・Ping 監視）の側で、定期的に時間を確かめる。過ぎていればそのトークンの接続を切る"""

    if not enabled():
        return
    claims = decode_access_token(token) or {}
    while True:
        await asyncio.sleep(WS_CHECK_SEC)
        try:
            ok = await enforce(user, token, claims, ip)
        except Exception:  # noqa: BLE001 - 確認の失敗で接続は切らない
            logger.exception("無操作の時間の確認に失敗しました")
            continue
        if not ok:
            # 初めての判定なら enforce が切っている。ほかで判定済みだった場合に備えて、ここでも切る（切れていれば何もしない）
            await close_token_sessions(user.id, token)
            return


def startup_log(log: logging.Logger) -> None:
    """起動時に 1 回。ログインの期限（ACCESS_TOKEN_EXPIRE_MINUTES）以上の時間は、実質効かないことを知らせる"""
    if enabled() and settings.IDLE_TIMEOUT_MIN >= settings.ACCESS_TOKEN_EXPIRE_MINUTES:
        log.warning("IDLE_TIMEOUT_MIN（%d 分）がログインの期限 ACCESS_TOKEN_EXPIRE_MINUTES（%d 分）以上のため、"
                    "無操作でのログアウトは実質働きません", settings.IDLE_TIMEOUT_MIN, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
