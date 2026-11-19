"""コンフィグの横断検索

各機器の最後に保存したコンフィグ（リポジトリの作業ツリー）を1行ずつ調べる。
- 文字列（そのまま含む）と正規表現のどちらも regex パッケージで照合し、時間を制限する
  （利用者が入力した正規表現で CPU を使い切らないため。コンプライアンスと同じ考え方）
- 結果が大きくなりすぎないよう、機器ごとの表示行数と行の長さに上限を設ける
  （CSV 出力では max_lines・max_total_lines を指定して一致した行をすべて受け取る。時間の制限は同じ）

過去の世代も含める検索（search_history）は、各機器の世代（git のコミット）を新しい順に調べ、
一致した行ごとに「いつから入っていて（初めて見つかった世代）、いつまであったか（最後に見つかった世代）、
いまもあるか」をまとめる。世代が多いと時間がかかるため、期間と調べる世代数に上限を設ける。
同じ内容の世代（blob が同じ）は 1 回だけ調べる
"""
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import git
import regex

from app.core.config import settings
from app.services.config_service import CONFIG_FILENAME, repo_path

MAX_LINES_PER_DEVICE = 50  # 機器ごとに返す一致行の上限（件数は全部数える）
MAX_LINE_LENGTH = 400  # 1行の表示上限（証明書などの長い行）
MAX_RANGES_PER_LINE = 10
TOTAL_TIMEOUT_SEC = 15.0  # 検索全体の上限
HISTORY_TIMEOUT_SEC = 30.0  # 過去の世代も含める検索の上限
MAX_HISTORY_COMMITS = 500  # 機器ごとに調べる世代の上限（新しい順）


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
    commits_searched: int = 0  # 過去の世代も含める検索で調べた世代の数（全機器の合計）
    partial: list[Target] = field(default_factory=list)  # 世代の上限・時間切れで古い世代まで調べきれなかった機器


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


def search_device(rx: regex.Pattern, text: str, context: int, end: float,
                  max_lines: int = MAX_LINES_PER_DEVICE) -> tuple[int, list[dict]]:
    """1台分。戻り値は (一致した行数, 表示する行（max_lines まで）)。時間切れは TimeoutError"""
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
        if len(out) < max_lines:
            out.append({
                "line": i + 1, "text": _clip(line),
                "ranges": [[s, min(e, MAX_LINE_LENGTH)] for s, e in ranges if s < MAX_LINE_LENGTH and e > s],
                "before": [_clip(x) for x in lines[max(0, i - context):i]] if context else [],
                "after": [_clip(x) for x in lines[i + 1:i + 1 + context]] if context else [],
            })
    return count, out


def search(targets: list[Target], query: str, mode: str = "contains", case_sensitive: bool = False,
           context: int = 0, max_lines: int = MAX_LINES_PER_DEVICE, max_total_lines: int | None = None) -> SearchResult:
    """max_lines: 機器ごとに返す行の上限。max_total_lines: 全機器で返す行の合計の上限（CSV 出力用。件数は全部数える）"""
    rx = build_pattern(query, mode, case_sensitive)
    res = SearchResult()
    overall = time.monotonic() + TOTAL_TIMEOUT_SEC
    returned = 0
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
            limit = max_lines if max_total_lines is None else max(0, min(max_lines, max_total_lines - returned))
            count, lines = search_device(rx, text, context,
                                         min(overall, time.monotonic() + settings.COMPLIANCE_REGEX_TIMEOUT), limit)
        except TimeoutError:
            res.timed_out.append(t)
            continue
        if not count:
            res.unmatched.append(t)
            continue
        res.hits.append(DeviceHit(target=t, count=count, commit=_commit(t.id), lines=lines))
        res.total_lines += count
        returned += len(lines)
    return res


def _ranges(rx: regex.Pattern, line: str, end: float) -> list[list[int]]:
    left = end - time.monotonic()
    if left <= 0:
        raise TimeoutError()
    ranges: list[list[int]] = []
    for m in rx.finditer(line, timeout=left, concurrent=True):
        if m.end() > m.start():
            ranges.append([m.start(), m.end()])
        elif not ranges:
            ranges.append([m.start(), m.start()])
        if len(ranges) >= MAX_RANGES_PER_LINE:
            break
    return ranges


def _commit_info(c: git.Commit) -> dict:
    return {"hash": c.hexsha[:8], "full_hash": c.hexsha,
            "date": datetime.fromtimestamp(c.committed_date, tz=UTC).isoformat()}


def search_device_history(rx: regex.Pattern, device_id: str, since: datetime | None, until: datetime | None,
                          end: float, max_commits: int | None = None) -> tuple[list[dict], int, bool] | None:
    """1台分の過去の世代を新しい順に調べる。戻り値は (一致した行, 調べた世代数, 古い世代まで調べきれなかったか)。

    一致した行は内容（前後の空白を除く）ごとにまとめ、最後（新しい側）と最初（古い側）に見つかった世代、
    最新の世代にもあるかを付ける。リポジトリが無ければ None
    """
    try:
        repo = git.Repo(repo_path(device_id))
        head = repo.head.commit
    except (ValueError, git.InvalidGitRepositoryError, git.NoSuchPathError, git.GitCommandError):
        return None
    max_commits = max_commits or MAX_HISTORY_COMMITS
    kw: dict = {"paths": CONFIG_FILENAME, "max_count": max_commits + 1}
    if since:
        kw["since"] = since.isoformat()
    if until:
        kw["until"] = until.isoformat()
    commits = list(repo.iter_commits(head, **kw))
    partial = len(commits) > max_commits
    commits = commits[:max_commits]
    found: dict[str, dict] = {}  # 行の内容 → 情報
    cache: dict[str, list[tuple[int, str, list[list[int]]]]] = {}  # blob → 一致した行

    def matches(blob) -> list[tuple[int, str, list[list[int]]]]:
        if blob.hexsha not in cache:
            text = blob.data_stream.read().decode("utf-8", errors="replace")
            cache[blob.hexsha] = [(i + 1, line, r) for i, line in enumerate(text.splitlines())
                                  if (r := _ranges(rx, line, end))]
        return cache[blob.hexsha]

    # 最新の世代にある行（期間で最新の世代が外れていても「いまもあるか」は最新で判定する）
    try:
        current_keys = {line.strip() for _, line, _ in matches(head.tree / CONFIG_FILENAME)}
    except KeyError:
        current_keys = set()
    searched = 0
    for c in commits:  # 新しい順
        if time.monotonic() >= end:
            partial = True
            break
        try:
            blob = c.tree / CONFIG_FILENAME
        except KeyError:
            continue
        searched += 1
        for no, line, r in matches(blob):
            key = line.strip()
            info = found.get(key)
            if info is None:
                found[key] = {"line": no, "text": _clip(line),
                              "ranges": [[a, min(b, MAX_LINE_LENGTH)] for a, b in r if a < MAX_LINE_LENGTH and b > a],
                              "last_seen": _commit_info(c), "first_seen": _commit_info(c), "current": key in current_keys,
                              "before": [], "after": []}
            else:
                info["first_seen"] = _commit_info(c)  # 古い世代へ進むので、見つかるたびに「最初」を更新する
    # いまもある行を先に（行番号順）、そのあとに消えた行（最後にあった世代が新しい順）
    items = list(found.values())
    lines = sorted([x for x in items if x["current"]], key=lambda x: x["line"]) + \
        sorted([x for x in items if not x["current"]], key=lambda x: x["last_seen"]["date"], reverse=True)
    return lines, searched, partial


def search_history(targets: list[Target], query: str, mode: str = "contains", case_sensitive: bool = False,
                   since: datetime | None = None, until: datetime | None = None,
                   max_lines: int = MAX_LINES_PER_DEVICE, max_total_lines: int | None = None) -> SearchResult:
    """過去の世代も含めて検索する。DeviceHit.count は一致した行（内容ごと）の数"""
    rx = build_pattern(query, mode, case_sensitive)
    res = SearchResult()
    overall = time.monotonic() + HISTORY_TIMEOUT_SEC
    returned = 0
    for t in targets:
        if time.monotonic() >= overall:
            res.timed_out.append(t)
            continue
        try:
            got = search_device_history(rx, t.id, since, until, overall)
        except TimeoutError:
            res.timed_out.append(t)
            continue
        if got is None:
            res.not_collected.append(t)
            continue
        lines, searched, partial = got
        res.commits_searched += searched
        if partial:
            res.partial.append(t)
        if not lines:
            res.unmatched.append(t)
            continue
        limit = max_lines if max_total_lines is None else max(0, min(max_lines, max_total_lines - returned))
        res.hits.append(DeviceHit(target=t, count=len(lines), commit=_commit(t.id), lines=lines[:limit]))
        res.total_lines += len(lines)
        returned += min(limit, len(lines))
    return res
