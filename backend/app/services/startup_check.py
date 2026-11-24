"""保存し忘れの検出（startup-config と running-config の不一致）

running-config を変えて startup-config に保存（write memory / copy running-config startup-config）し忘れると、
再起動のときに変更が消える。収集のついでに show startup-config も読み、running と比べて状態を出す。
- 対象は PlatformSpec.startup_command のある機種（Cisco IOS / IOS-XE / NX-OS・Arista EOS・AlliedWare Plus）
- 状態: synced（一致）/ unsaved（running にだけある変更がある）/ unknown（比べられなかった）/ None（対象外・無効）
- 保存する running のコンフィグ（世代）は変えない。ここでの整形は比べるときだけ
- 差分の本文はコンフィグの中身（秘密の値を含みうる）。画面で閲覧権限のある人にだけ返し、通知・記録には行数だけを入れる
"""
import logging
import re
from dataclasses import dataclass

from app.core.config import settings
from app.services.config_service import PLATFORMS, compare_texts, count_changes, normalize_config

logger = logging.getLogger(__name__)

SYNCED, UNSAVED, UNKNOWN = "synced", "unsaved", "unknown"
MAX_DIFF_LINES = 200  # 保存する差分の行数（超えた分は切る）

# running の出力にだけ付く行・startup にだけ付く行（保存の有無と関係なく毎回変わる、または片方にしかない）
COMPARE_IGNORE = [
    r"^Building configuration\.\.\.",
    r"^Current configuration\s*:\s*\d+ bytes",
    r"^Using \d+ out of \d+ bytes",
    r"^! Last configuration change at ",
    r"^! NVRAM config last updated at ",
    r"^! No configuration change since last restart",
    r"^!Time: ",  # NX-OS
    r"^!Running configuration last done at: ",  # NX-OS
    r"^!Startup config saved at: ",  # NX-OS
    r"^!Command: show (running|startup)-config",  # NX-OS
    r"^! Command: show (running|startup)-config",  # EOS
    r"^! Startup-config last modified at ",  # EOS
    # 以下は実機で未確認の推測（機種・OS のバージョンで running と startup の見出しが違う例）
    r"^Uncompressed configuration from \d+ bytes to \d+ bytes",  # IOS（圧縮して保存した startup の見出し）
    r"^! device: ",  # EOS
    r"^! boot system ",  # EOS
    r"^\s*!\s*$",  # 「!」だけの行（区切り。running と startup で数が違うことがある）
]
_COMPARE_IGNORE_RES = [re.compile(p) for p in COMPARE_IGNORE]

# startup-config が無い・読めないときの応答（出力の最初の数行にだけ当てる。コンフィグの本文には当てない）
_NOT_PRESENT_RE = re.compile(
    r"startup[- ]config(uration)? (is )?(not present|not found|does not exist|is empty)|no startup[- ]config|"
    r"nvram is empty|invalid input|unknown command|unrecognized command|incomplete command|ambiguous command|"
    r"^%|^error[: ]|no such file",
    re.IGNORECASE,
)
_HEAD_LINES = 3
MIN_STARTUP_LINES = 5  # これより行数が少ない startup は、コンフィグではなくエラーの文言などとみなして比べない
MIN_STARTUP_RATIO = 0.1  # running の行数のこの割合に満たない startup も同様


@dataclass
class StartupCheck:
    state: str | None  # synced / unsaved / unknown。対象外・無効は None
    added: int | None = None  # running にだけある行（保存されていない追加）
    removed: int | None = None  # startup にだけある行
    diff: str | None = None  # unified diff（startup → running）。unsaved のときだけ
    reason: str | None = None  # unknown の理由（記録用。コンフィグの中身は入れない）


def enabled_for(platform: str) -> bool:
    """この機種で startup の取得・比較をするか"""
    spec = PLATFORMS.get(platform)
    return bool(settings.STARTUP_CHECK_ENABLED and spec and spec.startup_command)


def _strip_for_compare(text: str) -> str:
    lines = [ln for ln in text.split("\n") if ln.strip() and not any(p.match(ln) for p in _COMPARE_IGNORE_RES)]
    return "\n".join(lines) + "\n" if lines else ""


def _is_not_present(raw: str) -> bool:
    head = [ln for ln in raw.splitlines() if ln.strip()][:_HEAD_LINES]
    return any(_NOT_PRESENT_RE.search(ln.strip()) for ln in head)


def compare(running_raw: str, startup_raw: str | None, platform: str, extra_ignore: list[str] | None = None) -> StartupCheck:
    """running と startup（どちらも機器の生の出力）を比べる

    どちらにも同じ整形（機種の無視する行・画面で設定した無視する行）を当ててから、比べるときだけの行を除く
    """
    if startup_raw is None:
        return StartupCheck(UNKNOWN, reason="取得できませんでした")
    if not startup_raw.strip():
        return StartupCheck(UNKNOWN, reason="startup-config が空でした")
    if _is_not_present(startup_raw):
        return StartupCheck(UNKNOWN, reason="startup-config がありません")
    try:
        skipped: list = []
        run = _strip_for_compare(normalize_config(running_raw, platform, extra_ignore, skipped))
        start = _strip_for_compare(normalize_config(startup_raw, platform, extra_ignore, skipped))
        if skipped:  # 時間切れなどで片方にだけ当たらないと偽の不一致になる
            return StartupCheck(UNKNOWN, reason="無視する行を適用できませんでした")
        if not start.strip() or not run.strip():
            return StartupCheck(UNKNOWN, reason="比べる内容がありませんでした")
        n_start, n_run = len(start.splitlines()), len(run.splitlines())
        if n_start < MIN_STARTUP_LINES or n_start < n_run * MIN_STARTUP_RATIO:
            # 想定していないエラーの文言などを startup とみなして「未保存」にしない
            return StartupCheck(UNKNOWN, reason=f"startup-config の行数が少なすぎます（{n_start} 行 / running {n_run} 行）")
        added, removed = count_changes(start, run)
        if not added and not removed:
            return StartupCheck(SYNCED, 0, 0)
        diff, _ = compare_texts(start, run, "startup-config", "running-config")
        lines = diff.split("\n")
        if len(lines) > MAX_DIFF_LINES:
            lines = [*lines[:MAX_DIFF_LINES], f"（{MAX_DIFF_LINES} 行を超える分は省略しました）"]
        return StartupCheck(UNSAVED, added, removed, "\n".join(lines))
    except Exception as e:  # noqa: BLE001 - 比較の失敗で収集を失敗にしない
        logger.warning("startup と running を比べられませんでした: %s: %s", type(e).__name__, e)
        return StartupCheck(UNKNOWN, reason="比較に失敗しました")
