"""収集の進み具合（待ち・収集中・再試行待ち）

収集の結果（成功・失敗）は collect_logs に残るが、「いま動いているか」はどこにも残っていなかった。
機器ごとの状態を Redis に短い期限つきで置き、デバイス管理の画面が読めるようにする。

- queued  : 収集を依頼した（worker が取りかかるのを待っている）
- running : worker が収集している（ほかの SSH 処理の終わりを待っている間も含む）
- retry   : 一時的な失敗で、少し待ってからやり直す
終わったら消す。worker が途中で落ちても残り続けないよう、どの状態にも期限を付ける。
"""
import json
import logging
import time

import redis

logger = logging.getLogger(__name__)

PREFIX = "netconfig:collect:state:"
# 期限（秒）。queued: worker が止まっているときに「待ち」のまま残り続けないための上限
# running: 収集のロック（900 秒）＋ほかの SSH 処理を待つ時間（300 秒）
# retry: やり直しまでの待ち時間（60 秒）に余裕を足したもの
TTL = {"queued": 1800, "running": 1200, "retry": 300}


def key(device_id: str) -> str:
    return PREFIX + device_id


def _value(state: str, triggered_by: str | None) -> str:
    return json.dumps({"state": state, "since": time.time(), "triggered_by": triggered_by})


def mark(r: redis.Redis, device_id: str, state: str, triggered_by: str | None = None, only_if_idle: bool = False) -> None:
    """状態を書く。only_if_idle: すでに状態がある（収集中など）ときは上書きしない"""
    try:
        r.set(key(device_id), _value(state, triggered_by), ex=TTL[state], nx=only_if_idle)
    except redis.RedisError:  # 表示用の情報なので、書けなくても収集は続ける
        logger.warning("収集の状態を記録できませんでした device=%s state=%s", device_id, state)


def clear(r: redis.Redis, device_id: str) -> None:
    try:
        r.delete(key(device_id))
    except redis.RedisError:
        logger.warning("収集の状態を消せませんでした device=%s", device_id)


def parse(raw: bytes | str | None) -> dict | None:
    if not raw:
        return None
    try:
        v = json.loads(raw)
        return v if v.get("state") in TTL else None
    except (ValueError, AttributeError):
        return None
