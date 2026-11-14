"""更新後の自己診断: 収集などのバックグラウンド処理が実際に動くかを確かめる

使い方（scripts/setup.sh が更新の最後に実行する）:
    podman exec <backend のコンテナ> python -m app.tools.selfcheck

API が応答していても、worker が Redis に接続できない・スケジューラーが起動していない、といった状態では
収集が動かない（依存パッケージの更新で実際に起きた）。ここでは次を確かめ、1つでも失敗したら終了コード 1 で終わる。
  1. Redis に接続できる
  2. タスクを登録でき、worker が受け取って実行する
  3. スケジューラー（beat）からの定期実行が届く
"""
import sys
import time
from datetime import datetime

from app.core.timeutil import utcnow

WORKER_TIMEOUT = 60
BEAT_TIMEOUT = 150


def main() -> int:
    started = utcnow()
    try:
        from app.services.system import HEARTBEAT_KEY
        from app.worker import _redis, heartbeat
        _redis().ping()
        print("[OK] Redis に接続できます")
    except Exception as e:  # noqa: BLE001
        print(f"[NG] Redis に接続できない、または worker のプログラムを読み込めません: {type(e).__name__}: {e}")
        return 1
    try:
        heartbeat.delay(record=False).get(timeout=WORKER_TIMEOUT)
        print("[OK] worker がタスクを受け取って実行しました")
    except Exception as e:  # noqa: BLE001
        print(f"[NG] worker がタスクを実行しません（{WORKER_TIMEOUT} 秒待機）: {type(e).__name__}: {e}")
        print("     収集・通知・スケジュールが動きません。worker のログを確認してください")
        return 1
    deadline = time.monotonic() + BEAT_TIMEOUT
    while time.monotonic() < deadline:
        raw = _redis().get(HEARTBEAT_KEY)
        try:
            if raw and datetime.fromisoformat(raw.decode()) >= started:
                print("[OK] スケジューラー（beat）からの定期実行が届きました")
                return 0
        except ValueError:
            pass
        time.sleep(3)
    print(f"[NG] スケジューラー（beat）からの定期実行が届きません（{BEAT_TIMEOUT} 秒待機）")
    print("     スケジュール収集が実行されません。beat のログを確認してください")
    return 1


if __name__ == "__main__":
    sys.exit(main())
