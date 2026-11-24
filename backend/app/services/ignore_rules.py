"""収集時に無視する行: 管理者が機種・機器ごとに追加した正規表現に一致する行を、保存前に取り除く

機器の出力に利用者が入れた正規表現を当てるので、必ず時間切れ付き（compliance.Deadline）で実行する。
時間の上限は 1 ルールあたり（全行の合計。IGNORE_RULE_TIMEOUT）と全ルールの合計（IGNORE_TOTAL_TIMEOUT）の 2 つ。
照合の時間切れは打ち切れるが、コンパイル（regex.compile）は打ち切れない。回数指定の繰り返しを入れ子にすると
（`(((a{100}){100}){100}){10}` など）コンパイルだけで数秒・数 GB を使うため、コンパイルの前に check_repeats で弾く。
適用できなかったルール（時間切れ・不正・繰り返しの上限超え）があれば、呼び出し側はその回のコンフィグを保存しない
（消える回と消えない回が混ざると、偽の変更になるため）。
"""
import logging
import time
from dataclasses import dataclass

import regex
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import Device
from app.models.ignore_rule import ConfigIgnoreRule
from app.services.compliance import Deadline, RegexTimeout, compile_pattern, latest_config

logger = logging.getLogger(__name__)

MAX_PATTERN_LENGTH = 500
MAX_REPEAT = 100  # 回数指定の繰り返し {n,m} の 1 つの数値の上限
MAX_REPEAT_PRODUCT = 10000  # パターン全体の繰り返しの回数（上限側）の積の上限
PREVIEW_MAX_DEVICES = 50
PREVIEW_MAX_EXAMPLES = 5
PREVIEW_EXAMPLE_LENGTH = 200
WARN_RATIO = 0.5  # 全行のこの割合以上に一致する（消える）機器があれば警告・確認する

# 飛ばした理由（アクティビティ・収集の失敗の理由に使う）
SKIP_TIMEOUT = "timeout"
SKIP_INVALID = "invalid"
SKIP_TOO_HEAVY = "too_heavy"
SKIP_LABELS = {
    SKIP_TIMEOUT: "無視する行の照合が時間切れになりました",
    SKIP_INVALID: "無視する行の正規表現が正しくありません",
    SKIP_TOO_HEAVY: "無視する行の正規表現の繰り返しの回数が上限を超えています",
}

_REPEAT = regex.compile(r"\{(\d*)(?:(,)(\d*))?\}")


class PatternTooHeavy(ValueError):
    """繰り返しの回数が上限を超えている（コンパイルだけで時間・メモリを使い切るおそれがある）"""


@dataclass
class Skipped:
    pattern: str
    reason: str  # SKIP_TIMEOUT / SKIP_INVALID / SKIP_TOO_HEAVY


def check_repeats(pattern: str) -> None:
    """コンパイルの前に、回数指定の繰り返し {n} {n,} {n,m} {,m} を数えて、重すぎるものを弾く（PatternTooHeavy）

    エスケープした文字（\\{ など）と文字クラス [...] の中は数えない。入れ子かどうかは見ず、
    パターン全体の数値（上限側。{n,} は n）の積で判断する（入れ子でなくても積に数えるので、安全側に倒れる）。
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PatternTooHeavy(f"正規表現は {MAX_PATTERN_LENGTH} 文字までです")
    product = 1
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2  # エスケープされた次の 1 文字は数えない
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            # 先頭の ^ と、直後の ] は文字クラスの中身（[]a] や [^]a]）
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue
        if c == "{":
            m = _REPEAT.match(pattern, i)
            if m and (m.group(1) or m.group(3)):
                nums = [int(x) for x in (m.group(1), m.group(3)) if x]
                if any(x > MAX_REPEAT for x in nums):
                    raise PatternTooHeavy(f"繰り返しの回数（{{...}} の数値）は {MAX_REPEAT} までです")
                upper = int(m.group(3)) if m.group(3) else int(m.group(1) or 0)
                product *= max(upper, 1)
                if product > MAX_REPEAT_PRODUCT:
                    raise PatternTooHeavy(
                        f"繰り返しの回数（{{...}} の数値）の積が大きすぎます（{MAX_REPEAT_PRODUCT} まで）")
                i = m.end()
                continue
        i += 1


def safe_compile(pattern: str) -> regex.Pattern:
    """check_repeats を通ったものだけをコンパイルする（PatternTooHeavy / regex.error）"""
    check_repeats(pattern)
    return compile_pattern(pattern)


def validate_pattern(pattern: str) -> None:
    """保存・試す前の検証（ValueError）。コンパイルできること、空の行に一致しないこと（全行が消えてしまう）

    コンパイル・照合をするので同期処理。API からは run_in_threadpool で呼ぶ（イベントループを止めない）
    """
    if not pattern:
        raise ValueError("正規表現を入力してください")
    try:
        rx = safe_compile(pattern)
    except PatternTooHeavy:
        raise
    except regex.error as e:
        raise ValueError(f"正規表現が正しくありません: {e}") from e
    try:
        matches_empty = Deadline(settings.IGNORE_RULE_TIMEOUT).search(rx, "")
    except RegexTimeout as e:
        # 空文字への照合すら終わらないものは、実際の行ではもっと時間がかかる
        raise ValueError("照合に時間がかかりすぎる正規表現です。単純にしてください") from e
    if matches_empty:
        raise ValueError("空の行にも一致する正規表現は、すべての行が消えてしまうため使えません")


def drop_lines(lines: list[str], patterns: list[str], skipped: list[Skipped] | None = None) -> list[str]:
    """patterns のどれかに一致する行（search）を取り除く。適用できなかったルールは飛ばし、理由付きで skipped に積む"""
    total_end = time.monotonic() + settings.IGNORE_TOTAL_TIMEOUT
    for pattern in patterns:
        left = total_end - time.monotonic()
        try:
            if left <= 0:
                raise RegexTimeout()
            rx = safe_compile(pattern)  # DB から読んだものも、コンパイルの前に検査する
            deadline = Deadline(min(settings.IGNORE_RULE_TIMEOUT, left))
            lines = [line for line in lines if not deadline.search(rx, line)]
        except (RegexTimeout, PatternTooHeavy, regex.error) as e:
            # 途中まで消した結果は使わず（一部の行だけ消えると変更扱いになる）、ルールごと飛ばす
            reason = (SKIP_TIMEOUT if isinstance(e, RegexTimeout)
                      else SKIP_TOO_HEAVY if isinstance(e, PatternTooHeavy) else SKIP_INVALID)
            logger.warning("無視する行のルールを適用できませんでした reason=%s", reason)
            if skipped is not None:
                skipped.append(Skipped(pattern, reason))
            continue
        # 次のルールへ（このルールで消えた行は、次のルールの対象から外れる）
    return lines


def skipped_message(skipped: list[Skipped]) -> str:
    """収集の失敗の理由（理由ごとに 1 文。ルールは 3 件・100 文字まで）"""
    parts = []
    for reason, label in SKIP_LABELS.items():
        pats = [s.pattern for s in skipped if s.reason == reason]
        if pats:
            shown = ", ".join(p[:100] for p in pats[:3]) + (f" ほか {len(pats) - 3} 件" if len(pats) > 3 else "")
            parts.append(f"{label}（ルール: {shown}）")
    return "。".join(parts) + "。コンフィグは保存していません"


async def load_patterns(db: AsyncSession, device_id: str, platform: str) -> list[str]:
    """機器に効く有効なルール（機種のもの＋機器のもの）の正規表現。作成順"""
    rows = await db.execute(
        select(ConfigIgnoreRule.pattern)
        .where(
            ConfigIgnoreRule.enabled.is_(True),
            or_(
                (ConfigIgnoreRule.scope == "platform") & (ConfigIgnoreRule.platform == platform),
                (ConfigIgnoreRule.scope == "device") & (ConfigIgnoreRule.device_id == device_id),
            ),
        )
        .order_by(ConfigIgnoreRule.created_at, ConfigIgnoreRule.id)
    )
    return [p for (p,) in rows.all()]


async def preview_targets(db: AsyncSession, scope: str, platform: str | None, device_id: str | None) -> list[Device]:
    """「試す」の対象の機器。機種なら同じ機種の機器（最大 PREVIEW_MAX_DEVICES 台）、機器ならその 1 台"""
    if scope == "device":
        d = await db.get(Device, device_id) if device_id else None
        return [d] if d else []
    rows = await db.execute(
        select(Device).where(Device.platform == platform).order_by(Device.name).limit(PREVIEW_MAX_DEVICES)
    )
    return list(rows.scalars())


def preview_device(device_id: str, pattern: str, deadline_total: float) -> dict:
    """1 台の最新の世代に正規表現を当てる（同期処理。threadpool から呼ぶ）。deadline_total は全体の締め切り（monotonic）"""
    loaded = latest_config(device_id)
    if loaded is None:
        return {"has_config": False, "total_lines": 0, "matched_lines": 0, "examples": [], "timeout": False}
    lines = loaded[0].splitlines()
    left = deadline_total - time.monotonic()
    out = {"has_config": True, "total_lines": len(lines), "matched_lines": 0, "examples": [], "timeout": False}
    try:
        if left <= 0:
            raise RegexTimeout()
        rx = safe_compile(pattern)  # 呼び出し側で validate_pattern を通しているが、念のためコンパイルの前に検査する
        deadline = Deadline(min(settings.IGNORE_RULE_TIMEOUT, left))
        matched = [line for line in lines if deadline.search(rx, line)]
    except RegexTimeout:
        out["timeout"] = True
        return out
    out["matched_lines"] = len(matched)
    out["examples"] = [m[:PREVIEW_EXAMPLE_LENGTH] for m in matched[:PREVIEW_MAX_EXAMPLES]]
    return out
