"""機器台帳の自動取得（モデル・シリアル番号・OS バージョン・機器側のホスト名）

コンフィグ収集と同じ SSH セッションで、機種ごとの表示コマンド（show version など）を実行して読み取る。
- 読み取り専用のコマンドだけを使う
- 取得できなくても収集は失敗にしない（呼び出し側で例外を握る）。読み取れなかった項目は None のまま
- 対応していない機種は何も実行しない（SPECS に無いプラットフォーム）
"""
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

FIELDS = ("model", "serial_number", "os_version", "reported_hostname")
LABELS = {"model": "モデル", "serial_number": "シリアル番号", "os_version": "OS バージョン",
          "reported_hostname": "機器側のホスト名"}
MAX_LENGTH = 128


@dataclass
class Facts:
    model: str | None = None
    serial_number: str | None = None
    os_version: str | None = None
    reported_hostname: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)

    def empty(self) -> bool:
        return not any(asdict(self).values())


def _find(text: str, *patterns: str) -> str | None:
    """最初に一致したパターンの 1 番目のグループ（行単位・大文字小文字は区別しない）"""
    for p in patterns:
        m = re.search(p, text, re.MULTILINE | re.IGNORECASE)
        if m:
            return _clean(m.group(1))
    return None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().strip('"').strip()
    # 制御文字が混じった値・長すぎる値は読み取りの失敗とみなして捨てる
    if not value or len(value) > MAX_LENGTH or re.search(r"[\x00-\x1f\x7f]", value):
        return None
    return value


def parse_cisco_ios(out: list[str]) -> Facts:
    t = out[0]
    return Facts(
        model=_find(t, r"^Model number\s*:\s*(\S+)", r"^cisco (\S+) .*processor"),
        serial_number=_find(t, r"^System serial number\s*:\s*(\S+)", r"^Processor board ID (\S+)"),
        os_version=_find(t, r"^Cisco IOS XE Software, Version (\S+)", r"^Cisco IOS.*?, Version ([^,\s]+)"),
        reported_hostname=_find(t, r"^(\S+) uptime is "),
    )


def parse_cisco_nxos(out: list[str]) -> Facts:
    t = out[0]
    return Facts(
        model=_find(t, r"^\s*cisco (.+?) chassis"),
        serial_number=_find(t, r"^\s*Processor Board ID (\S+)"),
        os_version=_find(t, r"^\s*NXOS:\s+version (\S+)", r"^\s*system:\s+version (\S+)"),
        reported_hostname=_find(t, r"^\s*Device name:\s*(\S+)"),
    )


def parse_cisco_asa(out: list[str]) -> Facts:
    t = out[0]
    return Facts(
        model=_find(t, r"^Hardware:\s+([^,\s]+)"),
        serial_number=_find(t, r"^Serial Number:\s*(\S+)"),
        os_version=_find(t, r"^Cisco Adaptive Security Appliance Software Version (\S+)"),
        reported_hostname=_find(t, r"^(\S+) up \d+ "),
    )


def parse_junos(out: list[str]) -> Facts:
    ver, hw = out[0], out[1] if len(out) > 1 else ""
    return Facts(
        model=_find(ver, r"^Model:\s*(\S+)"),
        serial_number=_find(hw, r"^Chassis\s+(\S+)"),
        os_version=_find(ver, r"^Junos:\s*(\S+)", r"^JUNOS .*\[(\S+)\]"),
        reported_hostname=_find(ver, r"^Hostname:\s*(\S+)"),
    )


def parse_arista(out: list[str]) -> Facts:
    t = out[0]
    return Facts(
        model=_find(t, r"^\s*Arista (\S+)"),
        serial_number=_find(t, r"^Serial number:\s*(\S+)"),
        os_version=_find(t, r"^Software image version:\s*(\S+)"),
    )


def parse_fortinet(out: list[str]) -> Facts:
    t = out[0]
    m = re.search(r"^Version:\s*(\S+)\s+v([\d.]+)(?:,(build\d+))?", t, re.MULTILINE)
    return Facts(
        model=_clean(m.group(1)) if m else None,
        serial_number=_find(t, r"^Serial-Number:\s*(\S+)"),
        os_version=_clean(" ".join(x for x in (m.group(2), m.group(3)) if x)) if m else None,
        reported_hostname=_find(t, r"^Hostname:\s*(\S+)"),
    )


def parse_panos(out: list[str]) -> Facts:
    t = out[0]
    return Facts(
        model=_find(t, r"^model:\s*(\S+)"),
        serial_number=_find(t, r"^serial:\s*(\S+)"),
        os_version=_find(t, r"^sw-version:\s*(\S+)"),
        reported_hostname=_find(t, r"^hostname:\s*(\S+)"),
    )


def parse_awplus(out: list[str]) -> Facts:
    t = out[0]
    # Board  ID  Bay  Board Name  Rev  Serial number の表から、本体（Base）の行を読む
    m = re.search(r"^Base\s+\d+\s+(.*?)\s+(\S+)\s+(\S+)\s*$", t, re.MULTILINE)
    return Facts(
        model=_clean(m.group(1).split()[-1]) if m and m.group(1).split() else None,
        serial_number=_clean(m.group(3)) if m else None,
        os_version=_find(t, r"^Software version\s*:\s*(\S+)"),
        reported_hostname=_find(t, r"^System Name\s*\r?\n\s*(\S+)"),
    )


def parse_yamaha(out: list[str]) -> Facts:
    t = out[0]
    m = re.search(r"^(\S+) Rev\.(\S+)", t, re.MULTILINE)
    return Facts(
        model=_clean(m.group(1)) if m else None,
        serial_number=_find(t, r"\bserial=(\S+)"),
        os_version=_clean("Rev." + m.group(2)) if m else None,
    )


# プラットフォーム → (実行するコマンド, 出力の読み取り)
SPECS: dict[str, tuple[list[str], Callable[[list[str]], Facts]]] = {
    "cisco_ios": (["show version"], parse_cisco_ios),
    "cisco_xe": (["show version"], parse_cisco_ios),
    "cisco_nxos": (["show version"], parse_cisco_nxos),
    "cisco_asa": (["show version"], parse_cisco_asa),
    "juniper_junos": (["show version", "show chassis hardware"], parse_junos),
    "arista_eos": (["show version"], parse_arista),
    "fortinet": (["get system status"], parse_fortinet),
    "paloalto_panos": (["show system info"], parse_panos),
    "allied_telesis_awplus": (["show system"], parse_awplus),
    "yamaha": (["show environment"], parse_yamaha),
}


def supported(platform: str) -> bool:
    return platform in SPECS


def gather(platform: str, send: Callable[[str], str]) -> dict[str, str | None] | None:
    """send(コマンド) で出力を得て読み取る。対応していない機種・何も読み取れなかった場合は None"""
    spec = SPECS.get(platform)
    if spec is None:
        return None
    commands, parse = spec
    facts = parse([send(c) for c in commands])
    return None if facts.empty() else facts.as_dict()


def changes(old: dict[str, str | None], new: dict[str, str | None]) -> list[tuple[str, str, str]]:
    """以前の値がある項目のうち、変わったもの（項目, 以前, 今回）。初めて取得した項目・今回読めなかった項目は含めない"""
    return [(f, old[f], new[f]) for f in FIELDS if old.get(f) and new.get(f) and old[f] != new[f]]
