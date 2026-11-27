"""コンプライアンスのルールのひな形（app/services/compliance_templates/）を、全件まとめて確かめる

合格・違反の例（good / bad）は、実機の出力に見立てた短い作り物。evaluate で期待どおり判定されることを全件で確かめる
"""
import re

import pytest

from app.services.compliance import RuleSpec, evaluate, validate_spec
from app.services.compliance_templates import ALL_TEMPLATES, CATEGORIES, TEMPLATES
from app.services.config_service import PLATFORMS

IDS = [t["name"] for t in ALL_TEMPLATES]

REQUIRED = ["name", "severity", "platforms", "category", "description", "match_type", "expect", "pattern", "scope",
            "remediation", "reference"]

# 機種のまとまり（件数の確認用）
GROUPS = {
    "Cisco IOS / IOS-XE": ["cisco_ios", "cisco_xe"], "Cisco NX-OS": ["cisco_nxos"], "Cisco ASA": ["cisco_asa"],
    "Arista EOS": ["arista_eos"], "JunOS": ["juniper_junos"], "FortiGate": ["fortinet"],
    "PAN-OS": ["paloalto_panos"], "AlliedWare Plus": ["allied_telesis_awplus"], "Yamaha": ["yamaha"],
}

# 最初の 15 件（v1.64.1 までのひな形）。ひな形から作ったルールの「同じ名前」の判定に使われるので、名前も条件も変えない
IOS = ["cisco_ios", "cisco_xe"]
MULTI = [*IOS, "cisco_nxos", "arista_eos", "allied_telesis_awplus"]
ORIGINAL = {  # 名前: (重要度, パターン, 条件, 範囲, 一致方法, platforms, 見出し)
    "パスワードの暗号化表示": ("medium", r"^service password-encryption", "present", "config", "regex", IOS, None),
    "enable secret を使う": ("high", r"^enable password ", "absent", "config", "regex", IOS, None),
    "HTTP サーバーの無効化": ("medium", r"^ip http server", "absent", "config", "regex", IOS, None),
    "SSH バージョン2": ("high", r"^ip ssh version 2", "present", "config", "regex", IOS, None),
    "VTY で Telnet を許可しない": ("high", r"transport input .*(telnet|all)", "absent", "section", "regex", IOS,
                          r"^line vty"),
    "NTP サーバーの設定": ("low", r"^ntp server ", "present", "config", "regex", MULTI, None),
    "Syslog の転送先": ("low", r"^logging (host )?\d", "present", "config", "regex", IOS, None),
    "既定の SNMP コミュニティを使わない": ("high", r"^snmp-server community (public|private)\b", "absent", "config",
                              "regex", MULTI, None),
    "物理インターフェースに説明を付ける": ("low", r"^\s+description ", "present", "section", "regex",
                            [*IOS, "cisco_nxos", "arista_eos"],
                            r"^interface (GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet)"),
    "PAN-OS: Telnet 管理を無効化": ("high", "deviceconfig system service disable-telnet yes", "present", "config",
                              "contains", ["paloalto_panos"], None),
    "FortiGate: 管理アクセスに Telnet / HTTP を許可しない": ("high", r"^\s*set allowaccess .*\b(telnet|http)\b", "absent",
                                           "config", "regex", ["fortinet"], None),
    "FortiGate: 管理者のアイドルタイムアウト": ("low", r"^\s*set admintimeout (\d{3,}|[3-9]\d)$", "absent", "config",
                                 "regex", ["fortinet"], None),
    "AW+: Telnet サーバーを無効化": ("high", r"^no service telnet", "present", "config", "regex",
                           ["allied_telesis_awplus"], None),
    "AW+: HTTP サーバーを無効化": ("medium", r"^no service http\b", "present", "config", "regex",
                          ["allied_telesis_awplus"], None),
    "JunOS: root の SSH ログイン禁止": ("high", "set system services ssh root-login deny", "present", "config",
                                 "contains", ["juniper_junos"], None),
}


def spec_of(t: dict) -> RuleSpec:
    return RuleSpec(t["match_type"], t["expect"], t["pattern"], t.get("scope", "config"), t.get("section_pattern"),
                    list(t["platforms"]))


def test_original_templates_unchanged():
    by = {t["name"]: t for t in TEMPLATES}
    for name, (sev, pattern, expect, scope, match_type, platforms, section) in ORIGINAL.items():
        t = by[name]
        assert (t["severity"], t["pattern"], t["expect"], t["scope"]) == (sev, pattern, expect, scope), name
        assert t["match_type"] == match_type and t["platforms"] == platforms, name
        assert t.get("section_pattern") == section, name


def test_counts_and_report(capsys):
    """機種ごとの件数（共通のものは、それぞれの機種に数える）。表示は pytest -s で見る"""
    counts = {g: sum(1 for t in TEMPLATES if set(t["platforms"]) & set(ids)) for g, ids in GROUPS.items()}
    print("ひな形の件数:", len(TEMPLATES), counts)
    assert len(TEMPLATES) >= 80
    assert all(n >= 6 for n in counts.values()), counts


def test_names_unique_and_required_fields():
    assert len(set(IDS)) == len(IDS), [n for n in IDS if IDS.count(n) > 1]
    for t in ALL_TEMPLATES:
        for k in REQUIRED:
            assert t.get(k) not in (None, "", []), (t["name"], k)
        assert t["severity"] in ("high", "medium", "low"), t["name"]
        assert t["match_type"] in ("contains", "regex") and t["expect"] in ("present", "absent"), t["name"]
        assert t["category"] in CATEGORIES, t["name"]
        assert len(t["name"]) <= 128 and len(t["description"]) <= 1000 and len(t["reference"]) <= 255
        assert "環境に合わせて調整してください" in t["description"], t["name"]
        assert t["good"].strip() and t["bad"].strip(), t["name"]
        assert t["scope"] == "section" or "section_pattern" not in t, t["name"]
        # 根拠には、出どころの種類だけを書く（特定の文書の節番号・URL を書かない）
        assert not re.search(r"https?://|\d+\.\d+(\.\d+)?|第\s*\d|節|§", t["reference"]), t["name"]


def test_api_form_has_no_examples():
    for t in TEMPLATES:
        assert not {"good", "bad", "extra_good", "extra_bad"} & set(t)


@pytest.mark.parametrize("t", ALL_TEMPLATES, ids=IDS)
def test_platform_and_regex(t):
    assert t["platforms"], t["name"]
    for p in t["platforms"]:
        assert p in PLATFORMS, (t["name"], p)
    validate_spec(spec_of(t))  # safe_regex の検査（重い正規表現・不正な正規表現は ValueError / regex.error）


@pytest.mark.parametrize("t", ALL_TEMPLATES, ids=IDS)
def test_examples_are_judged_as_expected(t):
    """合格する例は pass、違反する例は fail（section では違反のセクションが 1 つ以上）"""
    spec = spec_of(t)
    good, bad = evaluate(spec, t["good"]), evaluate(spec, t["bad"])
    assert good.status == "pass", (t["name"], good)
    assert bad.status == "fail", (t["name"], bad)
    assert bad.details
    for text in t["extra_good"]:
        assert evaluate(spec, text).status == "pass", (t["name"], text)
    for text in t["extra_bad"]:
        assert evaluate(spec, text).status == "fail", (t["name"], text)


# 例の中の値が「実在らしい」ものにならないための検査（remediation はプレースホルダだけ）
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SECRET_WORD = re.compile(r"\b(?:password|secret|community|key|passphrase|psk|string|value)\s+(\S+)")
SAFE_AFTER = {"generate"}  # crypto key generate など、値ではなく動作を表す語


@pytest.mark.parametrize("t", ALL_TEMPLATES, ids=IDS)
def test_remediation_is_placeholder_only(t):
    r = t["remediation"]
    assert 0 < len(r) <= 4000
    lines = [x for x in r.splitlines() if x.strip()]
    commands = [x for x in lines if not x.lstrip().startswith("#")]
    assert 1 <= len(commands) <= 12, (t["name"], len(commands))
    for line in lines:
        assert not IPV4.search(line.replace("0.0.0.0", "")), (t["name"], line)
    for line in commands:
        for m in SECRET_WORD.finditer(line):
            v = m.group(1).strip('"')
            assert v.startswith("<") or v in SAFE_AFTER, (t["name"], line)


@pytest.mark.parametrize("t", ALL_TEMPLATES, ids=IDS)
def test_remediation_comment_marker(t):
    """説明の行は「# 」（# と空白）で始まり、命令の行は「#」で始まらない（画面のコピーは「# 」の行だけを除く）"""
    for line in t["remediation"].splitlines():
        if line.lstrip().startswith("#"):
            assert line.lstrip().startswith("# "), (t["name"], line)
    assert [x for x in t["remediation"].splitlines() if x.strip() and not x.lstrip().startswith("# ")], t["name"]
