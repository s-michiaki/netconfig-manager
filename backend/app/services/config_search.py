"""コンフィグの横断検索

各機器の最後に保存したコンフィグ（リポジトリの作業ツリー）を1行ずつ調べる。
- 文字列（そのまま含む）と正規表現のどちらも regex パッケージで照合し、時間を制限する
  （利用者が入力した正規表現で CPU を使い切らないため。コンプライアンスと同じ考え方）
- 結果が大きくなりすぎないよう、機器ごとの表示行数と行の長さに上限を設ける
"""
import time
from dataclasses import dataclass, field

import git
import regex

from app.core.config import settings
from app.services.config_service import CONFIG_FILENAME, repo_path

MAX_LINES_PER_DEVICE = 50  # 機器ごとに返す一致行の上限（件数は全部数える）
MAX_LINE_LENGTH = 400  # 1行の表示上限（証明書などの長い行）
MAX_RANGES_PER_LINE = 10
TOTAL_TIMEOUT_SEC = 15.0  # 検索全体の上限


class SearchPatternError(ValueError):
    pass


@dataclass
class Target:
    id: str
    name: str
    hostname: str
    platform: str
    group: str | None


@dataclass
class DeviceHit:
    target: Target
    count: int = 0
    commit: str | None = None
    lines: list[dict] = field(default_factory=list)


@dataclass
class SearchResult:
    hits: list[DeviceHit] = field(default_factory=list)
    unmatched: list[Target] = field(default_factory=list)
    not_collected: list[Target] = field(default_factory=list)
    timed_out: list[Target] = field(default_factory=list)  # 時間切れで調べきれなかった機器
    total_lines: int = 0


def build_pattern(query: str, mode: str, case_sensitive: bool) -> regex.Pattern:
    flags = 0 if case_sensitive else regex.IGNORECASE
    try:
        return regex.compile(query if mode == "regex" else regex.escape(query), flags)
    except regex.error as e:
        raise SearchPatternError(f"正規表現が正しくありません: {e}") from e


def _read(device_id: str) -> str | None:
    try:
        f = repo_path(device_id) / CONFIG_FILENAME
    except ValueError:
        return None
    if not f.is_file():
        return None
    return f.read_text(encoding="utf-8", errors="replace")


def _commit(device_id: str) -> str | None:
    try:
        return git.Repo(repo_path(device_id)).head.commit.hexsha
    except (ValueError, git.InvalidGitRepositoryError, git.NoSuchPathError, git.GitCommandError):
        return None


def _clip(text: str) -> str:
    return text if len(text) <= MAX_LINE_LENGTH else text[:MAX_LINE_LENGTH] + "…"


def search_device(rx: regex.Pattern, text: str, context: int, end: float) -> tuple[int, list[dict]]:
    """1台分。戻り値は (一致した行数, 表示する行)。時間切れは TimeoutError"""
    lines = text.splitlines()
    count, out = 0, []
    for i, line in enumerate(lines):
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        ranges = []
        for m in rx.finditer(line, timeout=left, concurrent=True):
            if m.end() > m.start():
                ranges.append([m.start(), m.end()])
            elif not ranges:
                ranges.append([m.start(), m.start()])  # 空文字に一致（^ など）も「一致した行」に数える
            if len(ranges) >= MAX_RANGES_PER_LINE:
                break
        if not ranges:
            continue
        count += 1
        if len(out) < MAX_LINES_PER_DEVICE:
            out.append({
                "line": i + 1, "text": _clip(line),
                "ranges": [[s, min(e, MAX_LINE_LENGTH)] for s, e in ranges if s < MAX_LINE_LENGTH and e > s],
                "before": [_clip(x) for x in lines[max(0, i - context):i]] if context else [],
                "after": [_clip(x) for x in lines[i + 1:i + 1 + context]] if context else [],
            })
    return count, out


def search(targets: list[Target], query: str, mode: str = "contains", case_sensitive: bool = False,
           context: int = 0) -> SearchResult:
    rx = build_pattern(query, mode, case_sensitive)
    res = SearchResult()
    overall = time.monotonic() + TOTAL_TIMEOUT_SEC
    for t in targets:
        if time.monotonic() >= overall:
            res.timed_out.append(t)
            continue
        text = _read(t.id)
        if text is None:
            res.not_collected.append(t)
            continue
        try:
            # 1台あたりの上限はコンプライアンスの正規表現と同じ設定を使う
            count, lines = search_device(rx, text, context, min(overall, time.monotonic() + settings.COMPLIANCE_REGEX_TIMEOUT))
        except TimeoutError:
            res.timed_out.append(t)
            continue
        if not count:
            res.unmatched.append(t)
            continue
        res.hits.append(DeviceHit(target=t, count=count, commit=_commit(t.id), lines=lines))
        res.total_lines += count
    return res
