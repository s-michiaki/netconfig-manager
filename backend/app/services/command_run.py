"""表示コマンドの一括実行: 送れるコマンドの検証と、出力の扱い

目的は「設定を変えないコマンドだけを機器へ送る」こと。検証は許可リスト方式（先頭の語が許可された読み取りの語で、
危険な文字を含まず、パイプの後が許可された絞り込みと引数だけ）で、迷うものは拒否する。

検証は 3 か所で同じ関数を使う:
  1. API（実行を作る前。入力中の確認の /check も）
  2. worker（機器へ接続する直前。キューから受け取った値も信用しない）
機器には enable・設定モードへ入るコマンド（enable / configure / conf t / system-view など）を送らない。
接続時の enable（特権モード）は、収集と同じ既存の仕組み（Enable パスワードを設定した機器のみ）に従う。

機種ごとの違い（先頭に使える語・パイプの後に使える絞り込みと引数）は RULES にまとめる。
先頭の語の省略形（sh / sho / dis など）は、CLI の解釈器が確実にある機種（ABBREV_PLATFORMS）だけに許す。
それ以外は完全一致（show など）だけ。省略形を許すと、Linux のシェルに落ちる機種で `sh -c …` が通ってしまうため。
"""
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.command_run import ACTIVE_STATUSES, STATUS_FAILED, STATUS_QUEUED, STATUS_RUNNING, CommandResult, CommandRun
from app.services.config_service import PLATFORMS

MAX_COMMANDS = 5  # 1 回に送れるコマンドの数
MAX_COMMAND_LENGTH = 200  # 1 コマンドの文字数

SHOW_WORDS = frozenset({"sh", "sho", "show"})  # show の省略形（ABBREV_PLATFORMS だけ）
DISPLAY_WORDS = frozenset({"dis", "disp", "displ", "displa", "display"})  # display の省略形（Cisco では dis は disable）

# 先頭の語の省略形を許す機種（CLI の解釈器が確実にある機種を明示する。それ以外は完全一致だけ）
ABBREV_PLATFORMS = frozenset({
    "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa", "arista_eos", "huawei", "huawei_vrpv8", "hp_comware",
})
# bash（シェル）を経由しうる機種。文字を厳しく絞り、`-` で始まる語（-c など）を拒否する
SHELL_PLATFORMS = frozenset({"vyos", "ubiquiti_edgerouter", "checkpoint_gaia"})
# 対象外の機種（理由つき）
UNSUPPORTED: dict[str, str] = {
    "mikrotik_routeros": "MikroTik RouterOS は、この機能の対象外です（コマンドの安全な許可リストを作れていないため）",
}

# パイプ（|）の後ろの絞り込みの引数の決まり
NONE = "none"  # 引数なし（count・no-more など）
ONE = "one"  # 引数ちょうど 1 個（検索する語）
NUM = "num"  # 数字 1 個（last 10 など）
# frozenset は、許す語の中から 1 個（Junos の display set など）

_CISCO_FILTERS = {"include": ONE, "exclude": ONE, "begin": ONE, "section": ONE, "count": NONE}
_NXOS_FILTERS = {
    **_CISCO_FILTERS, "grep": ONE, "egrep": ONE, "last": NUM, "no-more": NONE, "json": NONE, "json-pretty": NONE,
    "xml": NONE, "head": NUM, "tail": NUM, "wc": NONE,
}
_ARISTA_FILTERS = {**_CISCO_FILTERS, "grep": ONE, "egrep": ONE, "json": NONE, "no-more": NONE}
_JUNOS_FILTERS = {
    "match": ONE, "except": ONE, "find": ONE, "count": NONE, "last": NUM, "trim": NUM, "no-more": NONE,
    "display": frozenset({"set", "xml", "json", "detail", "inheritance", "omit", "changed"}),
}
_PANOS_FILTERS = {"match": ONE, "except": ONE, "last": NUM}
_FORTI_FILTERS = {"grep": ONE}
_VYOS_FILTERS = {"match": ONE, "no-more": NONE, "count": NONE}  # bash を経由するので最小限
_YAMAHA_FILTERS = {"grep": ONE, "include": ONE, "exclude": ONE}
_NETSCALER_FILTERS = {"grep": ONE}

# 絞り込み語の省略形（abbrev の機種だけ）: 語 → 最短の長さ。前方一致で、機種の中で 1 つに決まるものだけ
_FILTER_ABBREV = {"include": 1, "exclude": 1, "begin": 1, "section": 3}

# シェルの特殊文字（`$` `~` は全機種で拒否済み）。no_meta の機種で拒否する
_META_CHARS = set("*{}\"'")
# シェルを経由する機種で使える文字
_SHELL_SAFE_RE = re.compile(r"^[A-Za-z0-9 _.:/@%+=,^|-]+$")
# 全機種で拒否する語（巨大な出力）。tech-support とその省略形（tec 以上）
_TECH_FULL = "tech-support"
# 全機種で拒否する語: ファイル名を付けると機器内に書き出せる診断情報（Huawei・Comware の display diagnostic-information）
_DIAG_FULL = "diagnostic-information"
DIAG_MESSAGE = ("diagnostic-information（とその省略形。Huawei・Comware では di 以上）は、"
                "ファイルへ書き出せ出力も大きいため使えません")
# 本体の語で、ファイル名・記憶装置名らしい語を拒否する機種（display の引数でファイルを指定できるもの）
FILE_WORD_PLATFORMS = frozenset({"huawei", "huawei_vrpv8", "hp_comware"})
# 絞り込み語の短縮を認める機種（NX-OS・Arista は、本物の grep などへ渡るため完全一致だけ）
FILTER_ABBREV_PLATFORMS = frozenset({"cisco_ios", "cisco_xe", "cisco_xr", "cisco_asa", "huawei", "huawei_vrpv8", "hp_comware"})


@dataclass(frozen=True)
class CommandRule:
    """機種ごとの、送れるコマンドの決まり"""

    heads: frozenset[str] = frozenset({"show"})  # 先頭に使える語（小文字）
    prefixes: tuple[tuple[str, ...], ...] = ()  # 先頭の 2 語（"admin show" のように、1 語目だけでは許せないもの）
    filters: dict[str, object] = field(default_factory=lambda: dict(_CISCO_FILTERS))
    abbrev: bool = False  # 先頭の語・絞り込み語の省略形を許す
    shell: bool = False  # シェル経由: 使える文字を絞り、`-` で始まる語を拒否
    no_meta: bool = False  # パイプの後ろで実際の grep が動きうる機種: `* { } " '` を拒否
    hint: str = "show"  # 画面に出す「先頭に使える語」の例


def _rule(platform: str, **kw) -> CommandRule:
    if platform in ABBREV_PLATFORMS:
        kw.setdefault("abbrev", True)
    if kw.get("abbrev") and "heads" not in kw:
        kw["heads"] = SHOW_WORDS
    if platform in SHELL_PLATFORMS:
        kw.update(shell=True, no_meta=True)
    return CommandRule(**kw)


_SPECIAL: dict[str, dict] = {
    "cisco_nxos": {"filters": dict(_NXOS_FILTERS), "no_meta": True},
    "arista_eos": {"filters": dict(_ARISTA_FILTERS), "no_meta": True},
    "juniper_junos": {"filters": dict(_JUNOS_FILTERS)},
    "juniper_screenos": {"heads": frozenset({"get"}), "hint": "get"},
    "fortinet": {"heads": frozenset({"get", "show"}), "filters": dict(_FORTI_FILTERS), "no_meta": True, "hint": "get / show"},
    "paloalto_panos": {"filters": dict(_PANOS_FILTERS)},
    "hp_comware": {"heads": DISPLAY_WORDS, "hint": "display"},
    "huawei": {"heads": DISPLAY_WORDS, "hint": "display"},
    "huawei_vrpv8": {"heads": DISPLAY_WORDS, "hint": "display"},
    "vyos": {"filters": dict(_VYOS_FILTERS)},
    "ubiquiti_edgerouter": {"filters": dict(_VYOS_FILTERS)},
    "checkpoint_gaia": {"filters": {}},  # clish は bash 経由で動くため、パイプは使わせない
    "nokia_sros": {"prefixes": (("admin", "show"),), "hint": "show / admin show"},
    "yamaha": {"filters": dict(_YAMAHA_FILTERS), "no_meta": True},
    "netscaler": {"filters": dict(_NETSCALER_FILTERS), "no_meta": True},
}
RULES: dict[str, CommandRule] = {
    p: _rule(p, **_SPECIAL.get(p, {})) for p in PLATFORMS if p not in UNSUPPORTED
}


def rule_for(platform: str) -> CommandRule | None:
    """機種の決まり。未対応・対象外の機種なら None"""
    return RULES.get(platform)


class CommandError(ValueError):
    """送れないコマンド。reason は画面に出す日本語の理由"""

    def __init__(self, reason: str, index: int | None = None, command: str | None = None):
        self.reason = reason
        self.index = index  # 0 始まりの位置
        self.command = command
        super().__init__(reason)

    def __str__(self) -> str:
        return (f"{self.index + 1} 個目のコマンド: " if self.index is not None else "") + self.reason


# ---------------------------------------------------------------- 機種に関係なく拒否するもの


def _is_tech_support(word: str) -> bool:
    """tech-support に解釈されうる語（tec 以上の前方一致）。

    先頭の語の省略形を許さない機種でも、引数の語は CLI が省略形として解釈しうる（Dell OS9・Ruckus・Aruba OS など
    IOS 風の CLI の `show tec`）。そのため全機種で 3 文字から拒否する
    """
    w = word.lower()
    return w == "techsupport" or (len(w) >= 3 and _TECH_FULL.startswith(w))


# diagnostic-information の省略形として拒否する長さ。Huawei・Comware（ファイル名を付けると機器内へ書き出せる機種）は
# di から（`dis di` は CLI の補完で diagnostic-information に解釈されうる。dialer など dial 以上の語は
# 前方一致にならないので通る）。それ以外の機種には diagnostic-information が無いので、Cisco の `show diag`・
# `show diagnostic result …` を通し、「diagnostic-」（11 文字）以上の前方一致だけを念のため拒否する
_DIAG_MIN = 2
_DIAG_MIN_OTHER = len("diagnostic-")


def _is_diagnostic(word: str, platform: str = "") -> bool:
    """diagnostic-information に解釈されうる語（Huawei・Comware は di 以上、それ以外は diagnostic- 以上の前方一致）。
    platform を省略したとき（機種を問わない検査）は、全機種に共通の diagnostic- 以上だけを見る"""
    w = word.lower()
    n = _DIAG_MIN if platform in FILE_WORD_PLATFORMS else _DIAG_MIN_OTHER
    return len(w) >= n and _DIAG_FULL.startswith(w)


# 「ファイル名・記憶装置名らしい語」（Huawei・Comware の display の本体の語で拒否する）
# - 記憶装置名: 最初の「:」の前に「/」が無く、英字を含む語（`flash:` `cfa0:` `cfcard:` `sd1:` `slot1#flash:` など）。
#   IPv4 / IPv6 のアドレス・プレフィックス（ipaddress で判定）は通す。`Serial1/0/0:0`・`100GE1/0/1:1` のような
#   分割ポート・チャネル化したインタフェース（「:」の前に「/」がある）、`100:1`（RD）・`10:00:00`（時刻）のような
#   数字だけの語も通す
# - 「/」で始まる語（絶対パス）、ファイルの拡張子で終わる語
_FILE_EXT_RE = re.compile(
    r"\.(txt|cfg|conf|log|zip|gz|tgz|tar|dat|bin|cc|bak|xml|json|py|sh|pem|key|crt|db|boot|img|pat|mod)$", re.IGNORECASE)


def _is_ip(word: str) -> bool:
    try:
        ipaddress.ip_network(word, strict=False)
        return True
    except ValueError:
        return False


def _looks_like_file(word: str) -> bool:
    if word.startswith("/") or _FILE_EXT_RE.search(word):
        return True
    if ":" not in word or _is_ip(word):
        return False
    before = word.split(":", 1)[0]
    return "/" not in before and any(c.isalpha() for c in before)


def _is_path_word(word: str) -> bool:
    """シェル経由の機種で拒否する「/」を含む語（IP アドレスのプレフィックス 10.0.0.0/24 などは通す）"""
    return "/" in word and not ("/" in word and _is_ip(word))


def check_universal(command: str) -> str:
    """どの機種でも送れない形を拒否し、前後の空白を除いたコマンドを返す。拒否するときは CommandError"""
    if not isinstance(command, str):
        raise CommandError("コマンドは文字列で指定してください")
    cmd = command.strip(" ")
    if not cmd.strip():
        raise CommandError("空のコマンドは送れません")
    if "\n" in cmd or "\r" in cmd:
        raise CommandError("改行は入れられません（1 行に 1 つのコマンドを入力してください）")
    if len(cmd) > MAX_COMMAND_LENGTH:
        raise CommandError(f"コマンドが長すぎます（{MAX_COMMAND_LENGTH} 文字まで。{len(cmd)} 文字あります）")
    for ch in cmd:
        o = ord(ch)
        if o < 0x20 or o == 0x7F:
            raise CommandError("制御文字（タブなど）は使えません")
        if o > 0x7E:
            raise CommandError("半角の英数字と記号だけ使えます（全角文字・全角の空白は使えません）")
    if "?" in cmd:
        raise CommandError("「?」（ヘルプ）は使えません")
    if ";" in cmd:
        raise CommandError("「;」は使えません（コマンドは 1 行に 1 つだけにしてください）")
    if "&" in cmd:
        raise CommandError("「&」は使えません")
    if "`" in cmd or "$" in cmd:
        raise CommandError("「$」とバッククォート（コマンドや変数の置き換え）は使えません")
    if "~" in cmd:
        raise CommandError("「~」は使えません")
    if ">" in cmd or "<" in cmd:
        raise CommandError("「>」「<」（ファイルへの出力・入力）は使えません")
    if "\\" in cmd:
        raise CommandError("「\\」は使えません")
    if any(_is_tech_support(w) for w in cmd.replace("|", " ").split()):
        raise CommandError("tech-support（とその省略形。tec 以上）は、出力が非常に大きくなるため使えません")
    if any(_is_diagnostic(w) for w in cmd.replace("|", " ").split()):
        raise CommandError(DIAG_MESSAGE)
    return cmd


def check_universal_all(commands: list[str]) -> list[str]:
    """コマンドの一覧（件数・各コマンド）を検査して、整えた一覧を返す。拒否するときは CommandError"""
    if not isinstance(commands, list) or not commands:
        raise CommandError("コマンドを 1 つ以上指定してください")
    if len(commands) > MAX_COMMANDS:
        raise CommandError(f"1 回に送れるコマンドは {MAX_COMMANDS} 個までです（{len(commands)} 個あります）")
    out = []
    for i, c in enumerate(commands):
        try:
            out.append(check_universal(c))
        except CommandError as e:
            raise CommandError(e.reason, i, c if isinstance(c, str) else None) from None
    return out


# ---------------------------------------------------------------- 機種ごとの検査


def _filter_name(rule: CommandRule, word: str, platform: str = "") -> str | None:
    """絞り込み語を正式な語にする（省略形は abbrev の機種だけ。1 つに決まらなければ None）"""
    w = word.lower()
    if w in rule.filters:
        return w
    if not rule.abbrev or platform not in FILTER_ABBREV_PLATFORMS:
        return None
    hits = [k for k, n in _FILTER_ABBREV.items() if k in rule.filters and len(w) >= n and k.startswith(w)]
    others = [k for k in rule.filters if k.startswith(w)]
    return hits[0] if len(hits) == 1 and len(set(others) | set(hits)) == 1 else None


def _check_filter(rule: CommandRule, words: list[str], platform: str = "") -> None:
    name = _filter_name(rule, words[0], platform)
    if name is None:
        names = " / ".join(sorted(rule.filters))
        raise CommandError(f"「|」の後ろに使えるのは {names} だけです（「{words[0]}」は使えません）")
    spec, args = rule.filters[name], words[1:]
    if spec == NONE:
        if args:
            raise CommandError(f"「| {name}」には引数を付けられません")
        return
    if isinstance(spec, frozenset):
        if len(args) != 1 or args[0].lower() not in spec:
            raise CommandError(f"「| {name}」の後ろに使えるのは {' / '.join(sorted(spec))} のどれか 1 つだけです")
        return
    if len(args) != 1:
        raise CommandError(f"「| {name}」の後ろには、引数をちょうど 1 個だけ指定してください（語を分けて複数にはできません）")
    arg = args[0]
    if spec == NUM:
        if not arg.isdigit():
            raise CommandError(f"「| {name}」の後ろには、数字を 1 個だけ指定してください")
        return
    if arg.startswith("-"):
        raise CommandError("絞り込みの引数は「-」で始められません（オプションは使えません）")
    if "/" in arg or ":" in arg:
        raise CommandError("絞り込みの引数に「/」「:」は使えません（ファイル名・URL は渡せません）")


def check_platform(platform: str, cmd: str) -> None:
    """機種ごとの検査（check_universal を通った 1 コマンドが対象）。送れないときは CommandError"""
    rule = rule_for(platform)
    if rule is None:
        raise CommandError(UNSUPPORTED.get(platform) or f"未対応の機種です: {platform}")
    if rule.shell and not _SHELL_SAFE_RE.match(cmd):
        raise CommandError("この機種では、英数字と空白と _ . : / @ % + = , ^ - 以外の文字は使えません")
    if rule.no_meta and any(c in _META_CHARS for c in cmd):
        raise CommandError("この機種では「*」「{」「}」と引用符（' \"）は使えません")
    parts = cmd.split("|")
    body = parts[0].split()
    if not body:
        raise CommandError("コマンドが空です")
    first = body[0].lower()
    ok_head = first in rule.heads
    ok_prefix = any(len(body) >= len(p) and tuple(w.lower() for w in body[: len(p)]) == p for p in rule.prefixes)
    if not (ok_head or ok_prefix):
        raise CommandError(
            f"「{body[0]}」から始まるコマンドは送れません（この機種で送れるのは {rule.hint} から始まるコマンドだけです）"
        )
    if rule.shell:
        for w in cmd.split():
            if w.startswith("-"):
                raise CommandError("この機種では、「-」で始まる語（オプション）は使えません")
        if any(_is_path_word(w) for w in body):
            raise CommandError("この機種では、「/」を含む語（ファイルのパス）は使えません"
                               "（10.0.0.0/24 のような IP アドレスのプレフィックスは使えます）")
    if platform in FILE_WORD_PLATFORMS and any(_is_diagnostic(w, platform) for w in cmd.replace("|", " ").split()):
        raise CommandError(DIAG_MESSAGE)
    if platform in FILE_WORD_PLATFORMS and any(_looks_like_file(w) for w in body):
        raise CommandError("この機種では、ファイル名・記憶装置名（flash: など）らしい語は使えません"
                           "（機器内のファイルの読み書きにつながるため）")
    for seg in parts[1:]:
        words = seg.split()
        if not words:
            raise CommandError("「|」の後ろに絞り込みの指定がありません")
        if not rule.filters:
            raise CommandError("この機種では「|」は使えません")
        _check_filter(rule, words, platform)


def check(platform: str, command: str) -> str:
    """1 コマンドを、機種を指定して検査する。送れるなら整えたコマンドを返し、送れないなら CommandError"""
    cmd = check_universal(command)
    check_platform(platform, cmd)
    return cmd


def validate_for_platform(platform: str, commands: list[str]) -> list[str]:
    """コマンドの一覧を、機種を指定して検査し、整えた一覧を返す。送れないものがあれば CommandError（最初の 1 つ）"""
    cmds = check_universal_all(commands)
    for i, c in enumerate(cmds):
        try:
            check_platform(platform, c)
        except CommandError as e:
            raise CommandError(e.reason, i, c) from None
    return cmds


# ---------------------------------------------------------------- 出力の扱い


def clip_output(text: str, limit: int) -> tuple[str, bool]:
    """出力を limit 文字までにする。(出力, 切ったか)"""
    if limit < 0:
        limit = 0
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def trim_blank_lines(text: str) -> str:
    """出力の先頭・末尾の空行（空白だけの行）を取り除く。最初・最後の文字のある行の中（インデントなど）と、間の空行は残す"""
    stripped = text.strip()
    if not stripped:
        return ""
    first = len(text) - len(text.lstrip())  # 最初の文字のある位置
    last = len(text.rstrip())  # 最後の文字のある位置の次
    start = text.rfind("\n", 0, first) + 1
    start = max(start, text.rfind("\r", 0, first) + 1)
    end_candidates = [i for i in (text.find("\n", last), text.find("\r", last)) if i != -1]
    end = min(end_candidates) if end_candidates else len(text)
    return text[start:end]


def build_outputs(commands: list[str], raw: list[str], run_budget: int) -> tuple[list[dict], int]:
    """機器の出力を、1 コマンドの上限（COMMAND_RUN_MAX_OUTPUT）と、実行全体の残りの枠（run_budget）で切る

    先頭・末尾の空行は、切る前に取り除く（上限・枠・chars・「切り捨て」の判定は、取り除いたあとの文字数で行う）

    戻り値: (コマンドごとの {command, output, truncated, chars}、保存した文字数の合計)
    """
    items, used = [], 0
    for cmd, text in zip(commands, raw, strict=False):
        text = trim_blank_lines(text or "")
        remaining = max(run_budget - used, 0)
        clipped, cut = clip_output(text, min(settings.COMMAND_RUN_MAX_OUTPUT, remaining))
        used += len(clipped)
        items.append({"command": cmd, "output": clipped, "truncated": cut, "chars": len(text)})
    return items, used


def dumps_outputs(items: list[dict]) -> str:
    return json.dumps(items, ensure_ascii=False)


def loads_outputs(text: str | None) -> list[dict]:
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def normalize_for_compare(text: str) -> str:
    """出力の比較用: 行末の空白と、末尾の空行を除く（それ以外は完全一致）"""
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")).rstrip("\n")


def group_outputs(commands: list[str], results: list[dict]) -> list[dict]:
    """コマンドごとに、同じ出力の機器をまとめる（出力の本文は入れない。result_id の結果の outputs[index] を見る）。

    results: 成功した機器の {"result_id", "device_id", "device_name", "outputs": [...]}。
    戻り値: コマンドごとの {index, command, groups: [{result_id（代表の結果）, truncated, count, devices}]}（多い順）
    """
    out = []
    for i, cmd in enumerate(commands):
        buckets: dict[str, dict] = {}
        for r in results:
            items = r["outputs"]
            if i >= len(items):
                continue
            it = items[i]
            key = normalize_for_compare(it.get("output", "")) + ("\0切り捨て" if it.get("truncated") else "")
            b = buckets.setdefault(key, {"result_id": r["result_id"], "truncated": bool(it.get("truncated")),
                                         "devices": []})
            b["devices"].append({"id": r["device_id"], "name": r["device_name"], "result_id": r["result_id"]})
        groups = sorted(buckets.values(), key=lambda b: (-len(b["devices"]), b["devices"][0]["name"]))
        for g in groups:
            g["count"] = len(g["devices"])
        out.append({"index": i, "command": cmd, "groups": groups})
    return out


# ---------------------------------------------------------------- 実行の終わりの判定・古い結果の掃除

STALE_RUNNING = timedelta(hours=2)  # 実行中のまま、この時間を過ぎた機器は、worker の停止などで中断されたとして失敗にする
STALE_IDLE = timedelta(minutes=60)  # 待機中の機器は、実行に動きが無く実行中の機器も無いまま、この時間を過ぎたら失敗にする
STALE_MESSAGE = "実行が途中で止まりました（worker の再起動などで中断された可能性があります）"


async def mark_finished_if_done(db: AsyncSession, run_id: str) -> bool:
    """実行のすべての機器が終わっていれば、実行の終了時刻を入れる。終わっていれば True（commit は呼び出し側）"""
    active = (await db.execute(
        select(func.count()).select_from(CommandResult)
        .where(CommandResult.run_id == run_id, CommandResult.status.in_(ACTIVE_STATUSES))
    )).scalar_one()
    if active:
        return False
    await db.execute(
        update(CommandRun).where(CommandRun.id == run_id, CommandRun.finished_at.is_(None)).values(finished_at=utcnow())
    )
    return True


async def fail_stale(db: AsyncSession, now: datetime | None = None, stale_running: timedelta | None = None,
                     waiting_runs: set[str] | frozenset[str] = frozenset(), system_active: bool = False) -> int:
    """止まった機器（worker の停止などで終わらないもの）を失敗にして、実行を終わらせる。失敗にした件数を返す

    - 実行中: 機器ごとの started_at から stale_running（worker はコマンド実行の時間の上限から計算した値を渡す。
      既定は STALE_RUNNING）を過ぎたもの（台数が多くて長く動いている実行は、機器が次々に始まり・終わるので失敗にしない）
    - 待機中: その実行に動き（開始・終了・作成）が STALE_IDLE なく、実行中の機器も無いもの。
      ただし、同時実行の枠を待っているだけの実行（waiting_runs: worker の待ち行列に機器がある・枠を予約している）は、
      全体が進んでいる（枠を使っている処理がある system_active、またはどれかの実行の機器が STALE_IDLE 以内に
      始まった・終わった）間は失敗にしない（遅い実行が枠を占めている間に、待っている実行を止まったとみなさない）。
      全体が止まっていれば、今までどおり失敗にする
    """
    now = now or utcnow()
    stale_running = stale_running or STALE_RUNNING
    touched: set[str] = set()
    n = 0
    # 全体が進んでいるかは、下で止まった機器を失敗にする（終了時刻に now が入る）前の時刻で見る。
    # 後で見ると、いま失敗にした機器を「最近の動き」と数えてしまい、待っている実行を STALE_IDLE だけ余計に残す
    g_start, g_end = (await db.execute(
        select(func.max(CommandResult.started_at), func.max(CommandResult.finished_at)))).one()
    running = (await db.execute(
        select(CommandResult.id, CommandResult.run_id)
        .where(CommandResult.status == STATUS_RUNNING, CommandResult.started_at < now - stale_running)
    )).all()
    if running:
        await db.execute(update(CommandResult).where(CommandResult.id.in_([r[0] for r in running]))
                         .values(status=STATUS_FAILED, error=STALE_MESSAGE, finished_at=now))
        touched |= {r[1] for r in running}
        n += len(running)
    run_ids = list((await db.execute(
        select(CommandResult.run_id).where(CommandResult.status == STATUS_QUEUED).distinct()
    )).scalars().all())
    progressing = system_active or any(t is not None and t >= now - STALE_IDLE for t in (g_start, g_end))
    for run_id in run_ids:
        run = await db.get(CommandRun, run_id)
        if run is None:
            continue
        busy = (await db.execute(
            select(func.count()).select_from(CommandResult)
            .where(CommandResult.run_id == run_id, CommandResult.status == STATUS_RUNNING)
        )).scalar_one()
        last_start, last_end = (await db.execute(
            select(func.max(CommandResult.started_at), func.max(CommandResult.finished_at))
            .where(CommandResult.run_id == run_id)
        )).one()
        last = max(t for t in (run.created_at, last_start, last_end) if t is not None)
        if busy or last >= now - STALE_IDLE or (run_id in waiting_runs and progressing):
            continue
        r = await db.execute(update(CommandResult).where(CommandResult.run_id == run_id, CommandResult.status == STATUS_QUEUED)
                             .values(status=STATUS_FAILED, error=STALE_MESSAGE, finished_at=now))
        touched.add(run_id)
        n += r.rowcount or 0
    # 実行中・待機中の機器が 1 台も無いのに終了時刻が空の実行も終わらせる（実行数の上限の枠を占め続けないように）
    orphans = (await db.execute(
        select(CommandRun.id).where(CommandRun.finished_at.is_(None), CommandRun.created_at < now - timedelta(minutes=1))
    )).scalars().all()
    for run_id in set(touched) | set(orphans):
        if await mark_finished_if_done(db, run_id) and run_id not in touched:
            n += 1
    return n


async def purge_old_runs(db: AsyncSession, now: datetime | None = None) -> int:
    """保持期間（COMMAND_RUN_RETENTION_DAYS）を過ぎた実行を、機器ごとの結果（出力）ごと削除する。削除した実行の数を返す"""
    now = now or utcnow()
    cutoff = now - timedelta(days=settings.COMMAND_RUN_RETENTION_DAYS)
    ids = list((await db.execute(select(CommandRun.id).where(CommandRun.created_at < cutoff))).scalars().all())
    if not ids:
        return 0
    # SQLite では外部キーの連鎖削除が効かないことがあるため、結果を先に消す
    await db.execute(delete(CommandResult).where(CommandResult.run_id.in_(ids)))
    await db.execute(delete(CommandRun).where(CommandRun.id.in_(ids)))
    return len(ids)
