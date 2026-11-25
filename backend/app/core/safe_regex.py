"""利用者が入力した正規表現を安全に読み込む（無視する行・コンプライアンス・コンフィグ検索・ターミナル記録の検索で共通）

扱い方は「読み込み（compile）の重さを確かめる → compile → 時間切れ付きの照合」の順。
照合の時間切れ（regex の timeout）は打ち切れるが、compile（regex.compile）は打ち切れない。回数指定の繰り返しの入れ子
（`(((a{100}){100}){100}){10}` など）や `+` の入れ子（`((((a)+)+)+)+` …。1 段ごとに大きさが倍になる）は、compile だけで
数秒・数 GB を使う。文字列として数える検査では、コメント・`(?x)` の空白などで抜けられ、普通のルール（IP アドレスを
いくつも含むもの）を誤って弾くため、実際に読み込んで測る。

- 速い経路: `{` が無く、`+` が FAST_MAX_PLUS 個以下のパターンは、このプロセスでそのまま compile する
  （このとき compile の大きさはパターンの長さにほぼ比例することを、1000 文字まで実測で確かめてある）
- 遅い経路: それ以外は、新しい Python のプロセスで compile して、メモリ（VmHWM の増分）と CPU 時間を測る。
  判定の主はメモリ（PROBE_MAX_MEMORY_MB）。子プロセスには regex を読み込んだあとの VmSize ＋余裕の RLIMIT_AS（超えたら
  MemoryError＝重い）と RLIMIT_CPU（超えたら SIGXCPU＝重い）、親からは時間切れを付ける
- 確定した判定（通す・重い・不正）だけをプロセスの中に覚え（VERDICT_CACHE_SIZE 件）、同じパターンで子プロセスを何度も起動しない。
  親からの時間切れ・そのほかの異常終了・出力が読めない・起動できない・空き待ちの時間切れは、覚えずに PatternUnavailable
  （確かめられなかった。API は 503、次にまた試す）。子プロセスの同時起動は MAX_PROBES 個まで
- 通ったパターンは cache_pattern=False で compile し（regex の内部キャッシュに残さない）、compile 済みのものは
  COMPILED_CACHE_SIZE 件・測ったメモリの合計 COMPILED_CACHE_MAX_MB まで使い回す（検査で機器ごとに同じルールを読み込んでも
  重くならないように。積み上がってメモリを使い続けないように）
- 括弧の入れ子が深すぎる（RecursionError）・メモリ不足（MemoryError）は regex.error（不正な正規表現）にそろえる

`(a+)+$` のような照合が重いだけのパターン、regex のあいまい一致（`{e<=3}` など）の照合の重さは、照合の時間切れで守る。
compile は同期処理（遅い経路は子プロセスを待つ）なので、API からは run_in_threadpool で呼ぶ（イベントループを止めない）。
Linux 前提（resource モジュール。コンテナ・CI とも Linux）。
"""
import hashlib
import json
import logging
import signal
import subprocess
import sys
import threading
from collections import OrderedDict

import regex

logger = logging.getLogger(__name__)

MAX_PATTERN_LENGTH = 500
FAST_MAX_PLUS = 6  # 速い経路で受け付ける `+` の数（入れ子 1 段ごとに大きさが倍になるため。6 段で 1000 文字なら約 4MB）
PROBE_MAX_MEMORY_MB = 16  # 子プロセスでの compile の前後のメモリ（VmHWM＝最大 RSS）の増分の上限。判定の主
PROBE_MAX_CPU_SEC = 0.5  # 子プロセスでの compile の CPU 時間の上限（メモリを使わずに時間だけかかるものへの歯止め）
PROBE_LIMIT_AS_MB = 512  # 子プロセスの regex を読み込むまでのメモリの上限（RLIMIT_AS）
PROBE_HEADROOM_MB = 64  # regex を読み込んだあと、RLIMIT_AS を「いまの VmSize ＋ これ」へ締め直す（二重の歯止め）
PROBE_LIMIT_CPU_SEC = 2  # 子プロセスの CPU 時間の上限（RLIMIT_CPU。超えると SIGXCPU で止まる）
PROBE_TIMEOUT_SEC = 3.0  # 親が子プロセスを待つ時間（起動の時間を含む）
PROBE_WAIT_SEC = 3.0  # 子プロセスの同時起動の空きを待つ時間
MAX_PROBES = 2
VERDICT_CACHE_SIZE = 2048
COMPILED_CACHE_SIZE = 16
COMPILED_CACHE_MAX_MB = 64  # compile 済みのものの、測ったメモリの合計の上限

HEAVY_MESSAGE = "この正規表現は読み込みが重すぎます（回数指定の繰り返しや「+」の入れ子を減らしてください）"
UNAVAILABLE_MESSAGE = "正規表現を確かめられませんでした。しばらくしてからもう一度お試しください"
DEEP_MESSAGE = "括弧の入れ子が深すぎます"

# 子プロセスで実行するコード。メモリは /proc/self/status の VmHWM（最大 RSS。exec で 0 から数え直す。ru_maxrss は
# exec のあとも親の値を引き継ぐので使えない）の compile 前後の差で測る。regex を読み込んだあとに RLIMIT_AS を
# 「いまの VmSize ＋ 余裕」へ締め直し、それを超えたら MemoryError（重い）。/proc が読めなければ RLIMIT_AS の歯止めだけで判定する
_PROBE = f"""
import json, resource, sys
MB = 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, ({PROBE_LIMIT_AS_MB} * MB,) * 2)
resource.setrlimit(resource.RLIMIT_CPU, ({PROBE_LIMIT_CPU_SEC}, {PROBE_LIMIT_CPU_SEC} + 1))
import regex
def status(key):
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1])  # kB
    except (OSError, ValueError, IndexError):
        pass
    return None
def cpu():
    u = resource.getrusage(resource.RUSAGE_SELF)
    return u.ru_utime + u.ru_stime
d = json.loads(sys.stdin.read())
size = status("VmSize")
if size is not None:
    resource.setrlimit(resource.RLIMIT_AS, (size * 1024 + {PROBE_HEADROOM_MB} * MB,) * 2)
try:
    with open("/proc/self/clear_refs", "w") as f:
        f.write("5")  # 最大 RSS（VmHWM）をいまの RSS に戻す（読み込み中の一時的な山を数えないように）
except OSError:
    pass
h0, c0 = status("VmHWM"), cpu()
out = {{"status": "ok"}}
try:
    regex.compile(d["pattern"], d["flags"], cache_pattern=False)
except regex.error as e:
    out = {{"status": "invalid", "message": str(e)}}
except RecursionError:
    out = {{"status": "invalid", "message": "deep"}}
except MemoryError:
    out = {{"status": "heavy"}}
h1 = status("VmHWM")
out["cpu"] = cpu() - c0
out["kb"] = (h1 - h0) if h0 is not None and h1 is not None else None
sys.stdout.write(json.dumps(out))
"""


class PatternRejected(ValueError):
    """利用者の正規表現を使えない（下の 2 つの共通の親）"""


class PatternTooHeavy(PatternRejected):
    """読み込み（compile）だけで時間・メモリを使い切るおそれがある（確定した判定。覚える）"""


class PatternUnavailable(PatternRejected):
    """重さを確かめられなかった（子プロセスの起動・時間切れ・空き待ちなど一時的なもの。覚えず、次にまた試す）"""

    def __init__(self, message: str = UNAVAILABLE_MESSAGE):
        super().__init__(message)


_lock = threading.Lock()
_probes = threading.BoundedSemaphore(MAX_PROBES)
# 確定した判定: キー → ("ok", 測ったメモリ kB) / ("heavy", 理由) / ("invalid", 理由)
_verdicts: "OrderedDict[str, tuple[str, object]]" = OrderedDict()
# compile 済み: (パターン, フラグ) → (compile 済み, 測ったメモリ kB)
_compiled: "OrderedDict[tuple[str, int], tuple[regex.Pattern, int]]" = OrderedDict()


def _key(pattern: str, flags: int) -> str:
    return hashlib.sha256(f"{flags}\0{pattern}".encode("utf-8", "surrogatepass")).hexdigest()


def needs_probe(pattern: str) -> bool:
    """子プロセスで測る必要があるか（`{` がある、または `+` が多い）。エスケープ・文字クラスの中も数える（安全側）"""
    return "{" in pattern or pattern.count("+") > FAST_MAX_PLUS


def _probe(pattern: str, flags: int) -> tuple[str, object]:
    """子プロセスで compile して測る。確定した判定を返す。確かめられなかったときは PatternUnavailable（覚えない）"""
    if not _probes.acquire(timeout=PROBE_WAIT_SEC):
        logger.warning("正規表現の重さを測る子プロセスの空きを待ちきれませんでした")
        raise PatternUnavailable()
    try:
        # fork ではなく新しい Python を起動する（親のスレッド・ロックの状態を引き継がない）。
        # -I で PYTHON* の環境変数・カレントディレクトリの影響を受けない
        r = subprocess.run([sys.executable, "-I", "-c", _PROBE], input=json.dumps({"pattern": pattern, "flags": flags}),
                           capture_output=True, text=True, timeout=PROBE_TIMEOUT_SEC)
    except subprocess.TimeoutExpired as e:
        logger.warning("正規表現の重さを測る子プロセスが時間内に終わりませんでした（受け付けません）")
        raise PatternUnavailable() from e
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("正規表現の重さを測る子プロセスを起動できませんでした（安全のため受け付けません）: %s", e)
        raise PatternUnavailable() from e
    finally:
        _probes.release()
    if r.returncode == -signal.SIGXCPU:
        return ("heavy", HEAVY_MESSAGE)  # CPU 時間の上限で止まった（確定）
    try:
        out = json.loads(r.stdout) if r.returncode == 0 else None
    except ValueError:
        out = None
    if not isinstance(out, dict):
        logger.warning("正規表現の重さを測る子プロセスが異常終了しました（受け付けません）: 終了コード %s", r.returncode)
        raise PatternUnavailable()
    if out.get("status") == "invalid":
        return ("invalid", DEEP_MESSAGE if out.get("message") == "deep" else str(out.get("message")))
    if out.get("status") != "ok":
        return ("heavy", HEAVY_MESSAGE)  # MemoryError（RLIMIT_AS の歯止め）
    kb = out.get("kb")
    if float(out.get("cpu") or 0) > PROBE_MAX_CPU_SEC or (kb is not None and int(kb) > PROBE_MAX_MEMORY_MB * 1024):
        return ("heavy", HEAVY_MESSAGE)
    return ("ok", int(kb or 0))


def _verdict(pattern: str, flags: int) -> tuple[str, object]:
    key = _key(pattern, flags)
    with _lock:
        if key in _verdicts:
            _verdicts.move_to_end(key)
            return _verdicts[key]
    v = _probe(pattern, flags)  # PatternUnavailable はそのまま上へ（覚えない）
    with _lock:
        _verdicts[key] = v
        while len(_verdicts) > VERDICT_CACHE_SIZE:
            _verdicts.popitem(last=False)
    return v


def _keep_compiled(key: tuple[str, int], rx: regex.Pattern, kb: int) -> None:
    """件数と、測ったメモリの合計の両方に上限を設けて覚える（古いものから捨てる）"""
    with _lock:
        _compiled[key] = (rx, kb)
        _compiled.move_to_end(key)
        while len(_compiled) > COMPILED_CACHE_SIZE or (
                len(_compiled) > 1 and sum(v[1] for v in _compiled.values()) > COMPILED_CACHE_MAX_MB * 1024):
            _compiled.popitem(last=False)


def safe_compile(pattern: str, flags: int = 0, max_length: int = MAX_PATTERN_LENGTH) -> regex.Pattern:
    """重さを確かめてから compile する

    重すぎる → PatternTooHeavy、確かめられない → PatternUnavailable、不正 → regex.error
    """
    if len(pattern) > max_length:
        raise PatternTooHeavy(f"正規表現は {max_length} 文字までです")
    key = (pattern, flags)
    with _lock:
        hit = _compiled.get(key)
        if hit is not None:
            _compiled.move_to_end(key)
            return hit[0]
    kb = 0
    if needs_probe(pattern):
        kind, value = _verdict(pattern, flags)
        if kind == "invalid":
            raise regex.error(str(value))
        if kind == "heavy":
            raise PatternTooHeavy(str(value))
        kb = int(value)
    try:
        rx = regex.compile(pattern, flags, cache_pattern=False)
    except RecursionError as e:
        raise regex.error(DEEP_MESSAGE) from e
    except MemoryError as e:
        raise regex.error("正規表現を読み込めませんでした（メモリが足りません）") from e
    _keep_compiled(key, rx, kb)
    return rx


def clear_caches() -> None:
    """覚えた判定と compile 済みのものを消す（テスト用）"""
    with _lock:
        _verdicts.clear()
        _compiled.clear()
