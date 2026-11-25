"""利用者が入力する正規表現の読み込み（app.core.safe_regex）のテスト"""
import signal
import subprocess
import sys
import uuid

import pytest
import regex
import regex_cases

from app.core import safe_regex as sr


def _unique(body: str) -> str:
    # 判定を覚えているので、テストごとに別のパターンにする（先頭の省略できるグループは照合に影響しない）
    return f"(?:{uuid.uuid4().hex})?" + body


def _count_probes(monkeypatch) -> list:
    calls = []
    orig = subprocess.run

    def run(*a, **kw):
        calls.append(a)
        return orig(*a, **kw)
    monkeypatch.setattr(sr.subprocess, "run", run)
    return calls


def test_fast_and_slow_path(monkeypatch):
    """{ が無く + が少ないものはこのプロセスで compile し、それ以外は子プロセスで測る"""
    calls = _count_probes(monkeypatch)
    assert sr.safe_compile(_unique(r"^\s+description \S+ ")).search(" description uplink x")
    assert calls == []
    assert not sr.needs_probe(r"^\S+\s+\S+") and sr.needs_probe(r"\d{1,3}") and sr.needs_probe("a+" * 7)
    assert sr.safe_compile(_unique(r"^\d{1,3}\.")).search("10.0.0.1")
    assert len(calls) == 1 and calls[0][0][0] == sys.executable


def test_verdict_is_remembered(monkeypatch):
    """同じパターン（とフラグ）では子プロセスを 2 度起動しない。compile 済みのものを消しても、判定は覚えている"""
    calls = _count_probes(monkeypatch)
    p = _unique(r"x{2}")
    sr.safe_compile(p)
    sr.safe_compile(p)
    with sr._lock:
        sr._compiled.clear()
    sr.safe_compile(p)
    assert len(calls) == 1
    sr.safe_compile(p, regex.IGNORECASE)  # フラグが違えば別に測る
    assert len(calls) == 2
    heavy = regex_cases.HEAVY[0]
    for _ in range(2):
        with pytest.raises(sr.PatternTooHeavy, match="重すぎます"):
            sr.safe_compile(heavy)
    assert len(calls) <= 3  # 重いものも覚える（ほかのテストで覚えていれば 0 回）


def test_regex_internal_cache_not_used():
    """通ったパターンを regex の内部キャッシュに残さない（違うパターンを読み込み続けてもメモリが増えない）"""
    internal = sys.modules[regex.compile.__module__]._cache
    before = len(internal)
    for body in (r"^a\S+", r"^b{2}", r"(?i)c{1,3}"):
        sr.safe_compile(_unique(body))
    assert len(internal) == before


def test_probe_unavailable_rejects(monkeypatch, caplog):
    """子プロセスを起動できないときは「確かめられなかった」で拒否し、ログに残す。判定は覚えない（直れば通る）"""
    p = _unique(r"y{3}")

    def broken(*a, **kw):
        raise PermissionError("起動できない")
    monkeypatch.setattr(sr.subprocess, "run", broken)
    with pytest.raises(sr.PatternUnavailable, match="確かめられませんでした"):
        sr.safe_compile(p)
    assert not issubclass(sr.PatternUnavailable, sr.PatternTooHeavy)
    assert issubclass(sr.PatternUnavailable, sr.PatternRejected) and issubclass(sr.PatternTooHeavy, sr.PatternRejected)
    assert any("子プロセスを起動できませんでした" in r.getMessage() for r in caplog.records)
    monkeypatch.undo()
    assert sr.safe_compile(p).search("yyy")


@pytest.mark.parametrize("failure", ["timeout", "killed", "garbage"])
def test_probe_transient_failures_not_remembered(monkeypatch, failure):
    """親からの時間切れ・SIGXCPU 以外の異常終了・読めない出力は「確かめられなかった」。覚えないので、次に成功すれば通る"""
    p = _unique(r"z{4}")

    def fail(*a, **kw):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(a[0], 3)
        if failure == "killed":
            return subprocess.CompletedProcess(a[0], -signal.SIGKILL, "", "")
        return subprocess.CompletedProcess(a[0], 0, "not json", "")
    monkeypatch.setattr(sr.subprocess, "run", fail)
    with pytest.raises(sr.PatternUnavailable):
        sr.safe_compile(p)
    monkeypatch.undo()
    assert sr.safe_compile(p).search("zzzz")


def test_probe_cpu_limit_is_remembered(monkeypatch):
    """RLIMIT_CPU で止まった（SIGXCPU）ものは重いと確定し、覚える"""
    calls = []

    def xcpu(*a, **kw):
        calls.append(1)
        return subprocess.CompletedProcess(a[0], -signal.SIGXCPU, "", "")
    monkeypatch.setattr(sr.subprocess, "run", xcpu)
    p = _unique(r"q{4}")
    for _ in range(2):
        with pytest.raises(sr.PatternTooHeavy):
            sr.safe_compile(p)
    assert len(calls) == 1


def test_memory_measured_with_large_parent():
    """親が大きく（300MB 以上）ても、子の compile のメモリを正しく測って 40MB 級のものを弾く

    ru_maxrss は exec のあとも親の値を引き継ぐため、それで測ると親より小さい compile は増分 0 に見えてしまう
    """
    big = bytearray(b"\x01") * (300 * 1024 * 1024)  # 実際に触ったページで親を膨らませる
    try:
        with pytest.raises(sr.PatternTooHeavy):
            sr.safe_compile(_unique("(?:(?:" + "a." * 16 + "){100}){100}"))  # compile で約 45MB
        sr.safe_compile(_unique(r"^access-list \d+ permit ip \d{1,3}\.\d{1,3}"))
    finally:
        del big


def test_compiled_cache_bounded():
    """違うパターンを続けて読み込んでも、compile 済みのものは件数・測ったメモリの合計の上限までしか残さない"""
    def rss_mb():
        with open("/proc/self/status") as f:
            return next(int(x.split()[1]) for x in f if x.startswith("VmRSS:")) // 1024
    body = "(?:(?:" + "a." * 4 + "){100}){100}"  # compile で約 12MB（しきい値の内側）
    for _ in range(8):
        sr.safe_compile(_unique(body))
    mid = rss_mb()
    for _ in range(12):
        sr.safe_compile(_unique(body))
    assert len(sr._compiled) <= sr.COMPILED_CACHE_SIZE
    assert sum(v[1] for v in sr._compiled.values()) <= sr.COMPILED_CACHE_MAX_MB * 1024
    assert rss_mb() - mid < 40  # 12 個 × 12MB を足しても増え続けない


def test_invalid_and_deep_patterns():
    """不正な正規表現・括弧の入れ子が深すぎるもの（RecursionError）は、速い経路・遅い経路とも regex.error"""
    for p in ("(", "[a{2", "(" * 400 + "a" + ")" * 400, "(" * 400 + "a{2}" + ")" * 400):
        with pytest.raises(regex.error):
            sr.safe_compile(p, max_length=1000)
    with pytest.raises(sr.PatternTooHeavy, match="500 文字まで"):
        sr.safe_compile("a" * 501)


def test_thresholds_on_real_patterns():
    """しきい値の確認: 重いものは子プロセスの上限で止まり、普通のルールは十分に下回る"""
    for p in regex_cases.HEAVY:
        with pytest.raises(sr.PatternTooHeavy):
            sr.safe_compile(p)
    for p in regex_cases.NORMAL:
        sr.safe_compile(p)
