"""機器ごとのロック（同じ機器へ SSH で入る処理を 1 つずつにする）の保持と延長

ロックの期限（LOCK_TTL）は短くし、処理の間は別スレッドで定期的に延長する（LockKeeper）。
- 処理がどれだけ長くても（応答の遅い機器へのコマンド実行など）、途中でロックが外れない
- worker のプロセスが落ちる・強制終了されると延長が止まり、LOCK_TTL 秒で自然に外れる（長く残らない）
延長に失敗した（期限が切れて、ほかの処理が取った）ときと、解放のときに自分のロックでなかったときは「途中で外れた」として
lost に残す。呼び出し側はそれをログ・アクティビティに残す（黙って握りつぶさない）。

延長は別スレッドから行うため、ロックは thread_local=False で作る（redis-py の既定はスレッドごとにトークンを持ち、
別スレッドからは延長できない）。
"""
import logging
import threading

import redis

logger = logging.getLogger(__name__)

LOCK_TTL = 120  # ロックの期限（秒）。worker が落ちたときは、この時間で外れる
EXTEND_INTERVAL = 30  # 延長する間隔（秒）。LOCK_TTL の 1/4。Redis の一時的な失敗が 2〜3 回続いても外れない


def make_lock(r: redis.Redis, name: str, ttl: float | None = None):
    """LockKeeper で延長できるロック（まだ取得しない）。ttl の既定は LOCK_TTL"""
    return r.lock(name, timeout=ttl or LOCK_TTL, thread_local=False)


class LockKeeper:
    """取得済みのロックを、処理の間 別スレッドで延長し続ける。

    使い方:
        keeper = LockKeeper()
        keeper.hold("ssh", lock)       # 取得できたロックを渡す
        ...                            # 長い処理
        keeper.release(lock)           # 解放（途中で外れていたら keeper.lost に名前が入る）
        keeper.close()                 # 残りをすべて解放し、延長のスレッドを止める（finally で必ず呼ぶ）
    """

    def __init__(self, interval: float | None = None):
        self.interval = interval or EXTEND_INTERVAL
        self.lost: list[str] = []  # 途中で外れていたロックの名前（hold で付けた名前）
        self._held: dict[int, tuple[str, object]] = {}
        self._mu = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def hold(self, label: str, lock) -> None:
        with self._mu:
            self._held[id(lock)] = (label, lock)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="lock-keeper", daemon=True)
                self._thread.start()

    def _mark_lost(self, label: str, lock) -> None:
        if label not in self.lost:
            self.lost.append(label)
        logger.warning("ロックが途中で外れていました（期限切れ・ほかの処理が取得）: %s", getattr(lock, "name", label))

    def extend_now(self) -> None:
        """保持しているロックをすべて延長する（延長のスレッドが呼ぶ。テストからも呼べる）。

        解放（release）と同時に走って「解放したばかりのロック」を外れたと誤って判定しないよう、Redis への操作は
        すべて self._mu の中で行う
        """
        with self._mu:
            for key, (label, lock) in list(self._held.items()):
                try:
                    lock.reacquire()
                except redis.exceptions.LockNotOwnedError:
                    # 期限が切れて、ほかの処理が取った（または消えた）。以後は延長も解放もしない
                    self._held.pop(key, None)
                    self._mark_lost(label, lock)
                except (redis.exceptions.RedisError, OSError) as e:  # Redis の一時的な失敗。次の回でまた延長する
                    logger.warning("ロックを延長できませんでした（次の回で再試行します）: %s (%s)",
                                   getattr(lock, "name", label), type(e).__name__)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.extend_now()
            except Exception:  # noqa: BLE001 - 想定外の失敗でも延長のスレッドを止めない（次の回でまた延長する）
                logger.exception("ロックの延長で想定外のエラーが起きました（次の回で再試行します）")

    def release(self, lock) -> None:
        """ロックを解放する。自分のロックでなくなっていたら lost に残す"""
        with self._mu:
            item = self._held.pop(id(lock), None)
            if item is None:
                return  # 延長の途中で外れていたことが分かっているもの（lost に記録済み）
            label, _ = item
            try:
                lock.release()
            except redis.exceptions.LockError:
                self._mark_lost(label, lock)
            except (redis.exceptions.RedisError, OSError) as e:  # 解放できなくても期限（LOCK_TTL）で外れる
                logger.warning("ロックを解放できませんでした（期限で外れます）: %s (%s)",
                               getattr(lock, "name", label), type(e).__name__)

    def close(self) -> None:
        self._stop.set()
        with self._mu:
            locks = [lk for _, lk in self._held.values()]
        for lk in locks:
            self.release(lk)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
