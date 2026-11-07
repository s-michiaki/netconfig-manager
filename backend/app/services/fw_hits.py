"""FW ルールのヒット数の取得（試験導入）: PAN-OS・FortiGate に SSH で接続して運用コマンドの出力を解析する

- PAN-OS : show rule-hit-count vsys vsys-name <vsys> rule-base security rules all
            （列の見出しの位置で各列を切り出す。ルール名に空白があっても読める）
- FortiGate: show firewall policy（ID・名前・並び順）+ diagnose firewall iprope list 100004（ID ごとの統計）
            VDOM を使っている機器は未対応

機種・バージョンで出力の形が違うことがあるため、取得した生の出力（先頭）を FwHitStatus に残し、
画面から確認できるようにしている（解析できない場合の調整用）
"""
import re
from dataclasses import dataclass, field
from datetime import datetime

from app.core.config import settings
from app.services.config_service import DeviceConnectionInfo, describe_failure, run_commands

SUPPORTED = {"paloalto_panos": "Palo Alto PAN-OS", "fortinet": "Fortinet FortiGate"}
RAW_LIMIT = 200_000  # 生の出力を残す上限（文字）


@dataclass
class RuleHit:
    position: int
    name: str
    hit_count: int | None = None
    rule_id: str | None = None
    packets: int | None = None
    bytes: int | None = None
    first_hit_at: datetime | None = None
    last_hit_at: datetime | None = None


@dataclass
class FwHitResult:
    rules: list[RuleHit] = field(default_factory=list)
    raw: str = ""
    error: str | None = None


# ---------------------------------------------------------------- 日時


_TS_FORMATS = ("%a %b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_ts(text: str | None) -> datetime | None:
    """機器の出力の日時（機器のローカル時刻）。読めない・未使用（- など）は None"""
    if not text:
        return None
    t = " ".join(text.split())
    if not t or t in ("-", "0", "N/A", "n/a"):
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            continue
    if t.isdigit() and len(t) >= 9:  # epoch 秒
        try:
            return datetime.fromtimestamp(int(t))
        except (OverflowError, OSError, ValueError):
            return None
    return None


# 出力の中の日時（曜日 月 日 時刻 年 / 年-月-日 時刻）または未使用を表す「-」
_TS_TOKEN = re.compile(
    r"[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} [\d:]{8} \d{4}|\d{4}[/-]\d{2}[/-]\d{2} [\d:]{8}|(?<!\S)-(?!\S)"
)


def _int(text: str | None) -> int | None:
    if text is None:
        return None
    t = text.replace(",", "").strip()
    return int(t) if t.isdigit() else None


# ---------------------------------------------------------------- PAN-OS


def parse_panos(output: str) -> list[RuleHit]:
    lines = output.splitlines()
    head = next((i for i, line in enumerate(lines) if "Rule Name" in line and "Hit Count" in line), None)
    rules: list[RuleHit] = []
    if head is not None:
        header = lines[head]
        cols = [(m.start(), m.group(0).strip()) for m in re.finditer(r"\S+(?: \S+)*", header)]
        starts = [c[0] for c in cols] + [10**6]
        names = [c[1] for c in cols]
        for line in lines[head + 1:]:
            if not line.strip() or set(line.strip()) <= {"-", "="}:
                continue
            if re.match(r"^\S+@\S+[>#]", line):  # 次のプロンプト
                break
            row = {names[i]: line[starts[i]:starts[i + 1]].strip() for i in range(len(names))}
            hits = _int(row.get("Hit Count"))
            name = row.get("Rule Name", "")
            if not name or hits is None:
                # 列幅を超えたルール名などで位置がずれた行は「名前 ヒット数  日時  日時 …」として読む
                m = re.match(r"^(.*?\S)\s+(\d+)(?:\s{2,}(.*))?$", line.strip())
                if not m:
                    continue
                name, hits = m.group(1), int(m.group(2))
                # 日時（曜日 月 日 時刻 年、日付の形式）または「-」を順に拾う（日の前の空白が2つのことがある）
                rest = _TS_TOKEN.findall(m.group(3) or "")
                row = {"Last Hit Timestamp": rest[0] if rest else None,
                       "First Hit Timestamp": rest[2] if len(rest) > 2 else None}
            rules.append(RuleHit(
                position=len(rules) + 1, name=name, hit_count=hits,
                last_hit_at=parse_ts(row.get("Last Hit Timestamp")),
                first_hit_at=parse_ts(row.get("First Hit Timestamp")),
            ))
    return rules


def collect_panos(device: DeviceConnectionInfo) -> FwHitResult:
    cmd = f"show rule-hit-count vsys vsys-name {settings.MONITOR_PANOS_VSYS} rule-base security rules all"
    out = run_commands(device, [cmd])[0]
    rules = parse_panos(out)
    return FwHitResult(rules, out, None if rules else "ヒット数の出力を解析できませんでした（生の出力を確認してください）")


# ---------------------------------------------------------------- FortiGate


def parse_forti_policies(show_output: str) -> list[tuple[str, str]]:
    """show firewall policy → [(ID, 名前)]（設定の並び順）"""
    out: list[tuple[str, str]] = []
    current: str | None = None
    name = ""
    for line in show_output.splitlines():
        s = line.strip()
        m = re.match(r"^edit (\d+)$", s)
        if m:
            current, name = m.group(1), ""
            continue
        m = re.match(r'^set name "(.*)"$', s)
        if m and current:
            name = m.group(1)
            continue
        if s == "next" and current:
            out.append((current, name))
            current = None
    return out


def parse_forti_iprope(output: str) -> dict[str, dict]:
    """diagnose firewall iprope list 100004 → {ポリシーID: {hit_count, packets, bytes, first_hit_at, last_hit_at}}"""
    stats: dict[str, dict] = {}
    blocks = re.split(r"(?m)^(?=policy index=)", output)
    for b in blocks:
        m = re.match(r"policy index=(\d+)", b)
        if not m:
            continue
        st: dict = {}
        if (pb := re.search(r"(?<!_)pkts/bytes=(\d+)/(\d+)", b)):
            st["packets"], st["bytes"] = int(pb.group(1)), int(pb.group(2))
        if (h := re.search(r"hit[ _]count[:=]\s*(\d+)", b)):
            st["hit_count"] = int(h.group(1))
        if (f := re.search(r"first[ _]hit[:=]\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", b)):
            st["first_hit_at"] = parse_ts(f.group(1))
        if (lh := re.search(r"last[ _]hit[:=]\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", b)):
            st["last_hit_at"] = parse_ts(lh.group(1))
        # 同じポリシーが複数のエントリに分かれることがあるため合算する
        prev = stats.setdefault(m.group(1), {})
        for k in ("packets", "bytes", "hit_count"):
            if k in st:
                prev[k] = prev.get(k, 0) + st[k]
        for k, pick in (("first_hit_at", min), ("last_hit_at", max)):
            if st.get(k):
                prev[k] = pick(prev[k], st[k]) if prev.get(k) else st[k]
    return stats


def collect_fortigate(device: DeviceConnectionInfo) -> FwHitResult:
    show, iprope = run_commands(device, ["show firewall policy", "diagnose firewall iprope list 100004"])
    raw = f"### show firewall policy\n{show}\n\n### diagnose firewall iprope list 100004\n{iprope}"
    policies = parse_forti_policies(show)
    stats = parse_forti_iprope(iprope)
    if not stats:
        # 統計を1件も読めないとき（権限不足・VDOM 構成の Command fail・出力形式の違いなど）は、
        # 全ポリシーを「ヒット 0（未使用）」と誤って表示しないよう、取得の失敗として扱う
        return FwHitResult([], raw, "ヒット数の統計（diagnose firewall iprope list）を解析できませんでした"
                                    "（「取得した出力」を確認してください）")
    if not policies:  # 名前が取れなくても統計は出す
        policies = [(pid, "") for pid in sorted(stats, key=int)]
    rules = []
    for i, (pid, name) in enumerate(policies, 1):
        st = stats.get(pid, {})
        rules.append(RuleHit(
            position=i, rule_id=pid, name=name or f"ポリシー {pid}",
            # 統計が1件以上読めたときだけ、統計に出ないポリシーを「一度も通っていない」= 0 とする
            hit_count=st.get("hit_count", 0 if not st else None),
            packets=st.get("packets"), bytes=st.get("bytes"),
            first_hit_at=st.get("first_hit_at"), last_hit_at=st.get("last_hit_at"),
        ))
    return FwHitResult(rules, raw)


# ---------------------------------------------------------------- 取得


def collect_fw_hits(device: DeviceConnectionInfo) -> FwHitResult:
    """同期で取得する（worker から呼ぶ）。失敗は error に入れて返す"""
    if device.platform not in SUPPORTED:
        return FwHitResult(error=f"この機種はヒット数の取得に対応していません（対応: {'・'.join(SUPPORTED.values())}）")
    try:
        if device.platform == "paloalto_panos":
            res = collect_panos(device)
        else:
            res = collect_fortigate(device)
    except Exception as e:  # noqa: BLE001
        msg, _ = describe_failure(e, device)
        return FwHitResult(error=msg)
    res.raw = res.raw[:RAW_LIMIT]
    return res
