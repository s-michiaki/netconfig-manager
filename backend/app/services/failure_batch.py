"""収集失敗の通知を短い時間でまとめる

ネットワーク障害などで一括収集・スケジュール収集の多くの機器が同時に失敗すると、機器ごとに通知が飛んで
通知先があふれる。失敗をいったん Redis にためて、最初の失敗から NOTIFY_FAILURE_BATCH_SEC 秒後に
通知先ごとに 1 通へまとめて送る（1 台だけなら、これまでどおり機器ごとの詳しい通知）。

- 失敗の記録: リスト KEY_ITEMS に 1 件ずつ追加する
- まとめる時間の始まり: KEY_WINDOW を SET NX で作れた失敗だけが、送信のタスクを予約する
- 送信: KEY_WINDOW を消してから KEY_ITEMS を取り出す（この順なら、送信の途中に来た失敗も取りこぼさない。
  取り出した後に来た失敗は、新しい時間の始まりとして次の送信を予約する）
- 予約した送信のタスクが worker の再起動などで失われても、beat の定期実行（flush_stale）が拾う
"""
import json
import logging
import time

import redis

logger = logging.getLogger(__name__)

KEY_ITEMS = "netconfig:notify:failures"
KEY_WINDOW = "netconfig:notify:failures:window"
KEY_TAKING = "netconfig:notify:failures:taking"
MAX_ITEMS = 2000  # ためておく上限（壊れた状態で際限なく増えないように。超えた分は古いものから捨てる）


def add(r: redis.Redis, device_id: str, error: str, triggered_by: str, ref: str | None, window_sec: int) -> bool:
    """失敗を記録する。まとめる時間の最初の失敗なら True（呼び出し側が送信を予約する）"""
    item = json.dumps({"device_id": device_id, "error": error[:1000], "triggered_by": triggered_by, "ref": ref,
                       "at": time.time()}, ensure_ascii=False)
    pipe = r.pipeline()
    pipe.rpush(KEY_ITEMS, item)
    pipe.ltrim(KEY_ITEMS, -MAX_ITEMS, -1)
    # 窓の期限は送信の予定より長くする（予約したタスクが失われたときは flush_stale が拾う）
    pipe.set(KEY_WINDOW, "1", nx=True, ex=window_sec + 600)
    return bool(pipe.execute()[2])


def take(r: redis.Redis) -> list[dict]:
    """たまっている失敗をすべて取り出す（窓を閉じてから取り出す）"""
    r.delete(KEY_WINDOW)
    pipe = r.pipeline()
    pipe.lrange(KEY_ITEMS, 0, -1)
    pipe.delete(KEY_ITEMS)
    raw, _ = pipe.execute()
    items = []
    for x in raw:
        try:
            items.append(json.loads(x))
        except (TypeError, ValueError):
            logger.warning("収集失敗の記録を読めませんでした: %r", x[:200])
    return items


def stale(r: redis.Redis) -> bool:
    """窓が閉じている（期限切れ・送信のタスクが失われた）のに、失敗が残っているか"""
    return not r.exists(KEY_WINDOW) and r.llen(KEY_ITEMS) > 0
