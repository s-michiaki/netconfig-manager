"""脆弱性の照合（services/vuln_match.py）のテスト: バージョンの分解・大小・影響範囲の判定（純粋な関数。DB・通信は使わない）"""
import json
import random
from pathlib import Path
from typing import ClassVar

import pytest

from app.services import vuln_fetch as vf
from app.services import vuln_match as vm

PAN = "paloalto_panos"
# 影響範囲の見本（tests/fixtures/vuln/paloalto_panos.json の勧告 A と同じ形）
RANGES_A = [
    {"branch": "10.2", "ge": "10.2.0", "lt": "10.2.5-h2"},
    {"branch": "10.2", "ge": "10.2.6", "lt": "10.2.9"},
    {"branch": "11.1", "ge": "11.1.0", "lt": "11.1.2-h3"},
]


@pytest.mark.parametrize("platform,text,key,branch", [
    (PAN, "10.2.14-h2", (10, 2, 14, 2), "10.2"),
    (PAN, "11.1.2", (11, 1, 2, 0), "11.1"),
    (PAN, " 9.1.16-H3 ", (9, 1, 16, 3), "9.1"),
    ("fortinet", "7.2.5 build1517", (7, 2, 5), "7.2"),
    ("fortinet", "7.4.1", (7, 4, 1), "7.4"),
    ("cisco_xe", "17.9.4a", (17, 9, 4, 1), "17.9"),
    ("cisco_xe", "17.06.05", (17, 6, 5, 0), "17.6"),  # 0 埋めは外す（サポート終了日の系列 "17.6" と合わせる）
    ("cisco_ios", "17.9.4a", (17, 9, 4, 1), "17.9"),  # IOS XE を cisco_ios で登録していても読める
    ("cisco_ios", "15.2(7)E7", (15, 2, 7, "", "E", 7, ""), "15.2"),
    ("cisco_nxos", "9.3(10)", (9, 3, 10, "", "", 0, 0, ""), "9.3"),
    ("cisco_nxos", "7.0(3)I7(9)", (7, 0, 3, "", "I", 7, 9, ""), "7.0"),
    ("cisco_asa", "9.18(3)56", (9, 18, 3, 0, 56), "9.18"),
    ("juniper_junos", "21.4R3-S5.4", (21, 4, 5, 3, 5, 4), "21.4"),
    ("arista_eos", "4.28.3M", (4, 28, 3, 0, "M"), "4.28"),
])
def test_parse_versions(platform, text, key, branch):
    p = vm.parse_version(platform, text)
    assert p is not None and p.key == key and p.branch == branch


@pytest.mark.parametrize("platform,text", [
    (PAN, "10.2"), (PAN, "10.2.14-x1"), (PAN, "PAN-OS 10.2.14"), (PAN, ""), (PAN, None), (PAN, "10.2.14\n"[:-1] + "\x00"),
    ("fortinet", "v7"), ("fortinet", "7.2.5 build"),
    ("cisco_xe", "17.9"), ("cisco_ios", "garbage"), ("cisco_nxos", "9.3"), ("cisco_asa", "9.18"), ("arista_eos", "4.28"),
    ("juniper_junos", "21.4"), ("allied_telesis_awplus", "5.5.3-1.1"), ("yamaha", "Rev.15.02.17"), ("unknown_platform", "1.2.3"),
    (PAN, "1" * 200 + ".0.0"),
])
def test_unparseable_is_none(platform, text):
    assert vm.parse_version(platform, text) is None


def test_unknown_reason():
    assert vm.unknown_reason(PAN, "10.2.5") is None
    assert vm.unknown_reason(PAN, None) == "no_version"
    assert vm.unknown_reason(PAN, "  ") == "no_version"
    assert vm.unknown_reason(PAN, "weird") == "unparseable"
    assert vm.unknown_reason("yamaha", "Rev.15.02.17") == "unsupported"


def test_compare_orders_within_scheme():
    p = lambda t: vm.parse_version(PAN, t)  # noqa: E731
    assert vm.compare(p("10.2.14"), p("10.2.14-h1")) < 0  # ホットフィックスは付いた方が新しい
    assert vm.compare(p("10.2.14-h2"), p("10.2.14-h10")) < 0  # 数として比べる（文字列ではない）
    assert vm.compare(p("10.2.14-h9"), p("10.2.15")) < 0
    assert vm.compare(p("10.10.0"), p("10.2.0")) > 0
    assert vm.compare(p("11.0.0"), p("11.0.0")) == 0
    x = lambda t: vm.parse_version("cisco_xe", t)  # noqa: E731
    assert vm.compare(x("17.9.4"), x("17.9.4a")) < 0 < vm.compare(x("17.9.5"), x("17.9.4a"))
    assert vm.compare(x("17.06.05"), x("17.6.5")) == 0
    with pytest.raises(ValueError):
        vm.compare(p("10.2.14"), x("17.9.4"))


@pytest.mark.parametrize("version,expected", [
    # 境界: ちょうど修正版・1 つ前・ホットフィックス
    ("10.2.5-h1", "affected"), ("10.2.5-h2", "unaffected"), ("10.2.5-h3", "unaffected"), ("10.2.5", "affected"),
    ("10.2.0", "affected"), ("10.2.0-h1", "affected"),
    # 2 つ目の範囲（同じ系列に修正版が複数ある）。間（10.2.5-h2 以上 10.2.6 未満）は該当しない
    ("10.2.5-h9", "unaffected"), ("10.2.6", "affected"), ("10.2.8-h99", "affected"), ("10.2.9", "unaffected"),
    ("10.2.14-h2", "unaffected"),
    # 別の系列: 勧告に載っていない系列は該当にしない
    ("10.1.9", "unaffected"), ("10.3.0", "unaffected"), ("9.1.0", "unaffected"), ("11.0.5", "unaffected"),
    ("11.1.0", "affected"), ("11.1.2-h2", "affected"), ("11.1.2-h3", "unaffected"), ("11.1.3", "unaffected"),
    # 判定できない
    ("10.2", "unknown"), ("", "unknown"), (None, "unknown"), ("not a version", "unknown"),
])
def test_panos_boundaries(version, expected):
    assert vm.evaluate(PAN, version, RANGES_A) == expected


def test_all_versions_and_empty_and_unreadable_ranges():
    assert vm.evaluate(PAN, "9.0.1", [{"all": True}]) == "affected"
    assert vm.evaluate(PAN, "x", [{"all": True}]) == "unknown"  # バージョンが読めなければ「すべて」でも判定しない
    assert vm.evaluate(PAN, "10.2.5", []) == "unaffected"
    # 範囲の書き方が読めない・上限が無いものは、該当にも非該当にもしない（判定できない）
    assert vm.evaluate(PAN, "10.2.5", [{"branch": "10.2", "ge": "10.2.x", "lt": "10.2.9"}]) == "unreadable"
    assert vm.evaluate(PAN, "10.2.5", [{"branch": "10.2", "ge": "10.2.0"}]) == "unreadable"
    assert vm.evaluate(PAN, "10.2.5", [{"branch": "10.2", "ge": "10.2.0", "lt": "bad"}]) == "unreadable"
    assert vm.evaluate(PAN, "10.2.5", ["broken", None]) == "unreadable"
    # 別の系列の読めない範囲は関係ない。系列が分からない読めない行は、どの系列の機器にも影響しうる
    assert vm.evaluate(PAN, "10.2.5", [{"unreadable": True, "branch": "11.1"}]) == "unaffected"
    assert vm.evaluate(PAN, "10.2.5", [{"unreadable": True, "branch": "10.2"}]) == "unreadable"
    assert vm.evaluate(PAN, "10.2.5", [{"unreadable": True}]) == "unreadable"
    # 読める範囲に当たれば、ほかに読めない行があっても「該当」
    assert vm.evaluate(PAN, "10.2.5", [{"unreadable": True}, {"all": True}]) == "affected"


# 本物の形（CVE-2026-0331 の PAN-OS 10.2 の行）を写した、作り物ではない構造（版の並びは降順。順序には頼らない）
FIXES_DESC = ["10.2.18-h14", "10.2.16-h13", "10.2.13-h28", "10.2.10-h43", "10.2.7-h40"]
HOTFIX_RANGE = {"branch": "10.2", "ge": "10.2.0", "lt": "10.2.18-h14", "fixes": FIXES_DESC}


@pytest.mark.parametrize("fixes", [FIXES_DESC, list(reversed(FIXES_DESC)), [FIXES_DESC[2], FIXES_DESC[0], FIXES_DESC[4], FIXES_DESC[1],
                                                                            FIXES_DESC[3]]])
@pytest.mark.parametrize("version,expected", [
    # ホットフィックスで修正済み: 修正点と同じ x.y.z で、hN が修正点以上
    ("10.2.13-h28", "unaffected"), ("10.2.13-h29", "unaffected"), ("10.2.7-h40", "unaffected"),
    ("10.2.16-h13", "unaffected"), ("10.2.18-h14", "unaffected"), ("10.2.10-h43", "unaffected"),
    # 修正点より前のホットフィックス・ホットフィックスなし
    ("10.2.13-h27", "affected"), ("10.2.13", "affected"), ("10.2.7", "affected"), ("10.2.16-h12", "affected"),
    ("10.2.18-h13", "affected"), ("10.2.18", "affected"),
    # 同じ x.y.z に修正点が無い版は該当（隣の版に修正点があっても）
    ("10.2.14", "affected"), ("10.2.14-h5", "affected"), ("10.2.17", "affected"), ("10.2.0", "affected"), ("10.2.8-h99", "affected"),
    # 範囲の外
    ("10.2.19", "unaffected"), ("10.2.18-h15", "unaffected"), ("10.1.14", "unaffected"), ("10.3.0", "unaffected"),
    ("11.1.0", "unaffected"),
])
def test_hotfix_changes_boundaries(version, expected, fixes):
    assert vm.evaluate(PAN, version, [{**HOTFIX_RANGE, "fixes": fixes}]) == expected


def test_after_all_and_wildcard_upper_bound():
    r = [{"branch": "10.2", "ge": "10.2.5", "after_all": True}]  # lessThan が "*" や "10.2.*"
    assert vm.evaluate(PAN, "10.2.5", r) == "affected" and vm.evaluate(PAN, "10.2.99-h9", r) == "affected"
    assert vm.evaluate(PAN, "10.2.4", r) == "unaffected" and vm.evaluate(PAN, "10.3.0", r) == "unaffected"


class TestPanoramaOnly:
    R: ClassVar[list[dict]] = [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.9", "platforms": ["Panorama"]}]

    @pytest.mark.parametrize("model,expected", [
        ("Panorama", "affected"), ("M-600", "affected"), ("M-200", "affected"), ("Panorama (virtual)", "affected"),
        ("PA-440", "unaffected"), ("PA-3220", "unaffected"), ("VM-50", "unaffected"), ("VM-Series", "unaffected"),
        ("", "candidate"), (None, "candidate"), ("something-else", "candidate"),
    ])
    def test_model_decides(self, model, expected):
        assert vm.evaluate(PAN, "10.2.5", self.R, model) == expected

    def test_out_of_range_is_not_a_candidate(self):
        assert vm.evaluate(PAN, "10.2.9", self.R, None) == "unaffected"

    def test_without_platforms_all_models_hit(self):
        r = [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.9"}]
        assert vm.evaluate(PAN, "10.2.5", r, "PA-440") == "affected" and vm.evaluate(PAN, "10.2.5", r, None) == "affected"

    def test_confirmed_by_another_row_wins_over_candidate(self):
        r = [*self.R, {"branch": "10.2", "ge": "10.2.0", "lt": "10.2.9"}]
        assert vm.evaluate(PAN, "10.2.5", r, None) == "affected"

    @pytest.mark.parametrize("model,kind", [
        ("Panorama", "panorama"), ("Panorama (virtual)", "panorama"), ("m-700", "panorama"), ("M-100", "panorama"),
        ("PAN-M-600", "panorama"),
        ("PA-5450", "firewall"), ("PA-440", "firewall"), ("pa-220", "firewall"), ("PA 3220", "firewall"),
        ("VM-300", "firewall"), ("VM-Series", "firewall"), ("PA-VM", "firewall"), ("PA-VM-300", "firewall"), ("PAVM", "firewall"),
        ("PAN-PA-440", "firewall"), ("PAN-PA-VM", "firewall"), ("PA-SERIES", "firewall"),
        ("", None), (None, None), ("FortiGate", None), ("PAX", None), ("M-1", None), ("something-else", None), (123, None),
    ])
    def test_device_kind(self, model, kind):
        assert vm.device_kind(model) == kind


def test_le_bound_and_single_version():
    r = [{"branch": "10.2", "ge": "10.2.3", "le": "10.2.3"}]  # 単独の版
    assert vm.evaluate(PAN, "10.2.3", r) == "affected"
    assert vm.evaluate(PAN, "10.2.3-h1", r) == "unreadable"  # le が h なしで、同じ x.y.z のホットフィックス: 決められない
    assert vm.evaluate(PAN, "10.2.4", r) == "unaffected"
    assert vm.evaluate(PAN, "10.2.2", r) == "unaffected"
    r2 = [{"branch": "10.2", "ge": "10.2.0", "le": "10.2.4"}]
    assert vm.evaluate(PAN, "10.2.4", r2) == "affected" and vm.evaluate(PAN, "10.2.4-h1", r2) == "unreadable"
    r3 = [{"branch": "10.2", "ge": "10.2.0", "le": "10.2.4-h2"}]  # le にホットフィックスがあれば決められる
    assert vm.evaluate(PAN, "10.2.4-h2", r3) == "affected" and vm.evaluate(PAN, "10.2.4-h3", r3) == "unaffected"


def test_eol_platform_mapping():
    assert vm.eol_platform(vm.parse_version(PAN, "10.2.1")) == "paloalto_panos"
    assert vm.eol_platform(vm.parse_version("fortinet", "7.2.5")) == "fortinet"
    assert vm.eol_platform(vm.parse_version("cisco_ios", "17.9.4a")) == "cisco_xe"
    assert vm.eol_platform(vm.parse_version("cisco_ios", "15.2(7)E7")) is None  # IOS はサポート終了日の自動取得の対象外


# ================================================================ 本物の応答の形に基づく表（tests/fixtures/vuln/paloalto_panos_shapes.json）
# 見本の ID・題は作り物。行の形は 2026-11 に Palo Alto の API で確認したもの（勧告のページの表と突き合わせ済み）を写した

SHAPES = {a["ext_id"]: a["affected"]
          for a in vf.parse_paloalto(json.loads((Path(__file__).parent / "fixtures/vuln/paloalto_panos_shapes.json").read_text("utf-8")))}
A, U, C, R = "affected", "unaffected", "candidate", "unreadable"
FW = "PA-440"

SHAPE_TABLE = [
    # (a) lessThan が修正点の最大（CVE-2026-0331 の形）
    *[("CVE-2099-2001", v, FW, U) for v in ("10.2.13-h28", "10.2.13-h29", "10.2.7-h40", "10.2.16-h13", "10.2.18-h14",
                                             "10.2.10-h43", "10.2.18-h15", "10.2.19", "11.1.4-h39", "11.1.16-h5", "11.1.17",
                                             "12.2.4-h2", "12.2.5")],
    *[("CVE-2099-2001", v, FW, A) for v in ("10.2.13-h27", "10.2.7", "10.2.14", "10.2.17", "10.2.18-h13", "10.2.18", "10.2.0",
                                             "10.2.0-h1", "11.1.4-h38", "11.1.5", "11.1.0", "12.2.0", "12.2.4-h1")],
    *[("CVE-2099-2001", v, FW, U) for v in ("11.2.5", "12.1.3", "9.1.0", "10.1.14")],  # 載っていない系列（既定は影響なし）
    # (b) lessThan が修正点の最小（CVE-2026-0273 の形）。lessThan で打ち切らない
    *[("CVE-2099-2002", v, FW, U) for v in ("12.1.4-h7", "12.1.4-h8", "12.1.7", "12.1.7-h1", "12.1.8", "11.1.4-h34",
                                             "11.1.6-h33", "11.1.13-h7", "11.1.15", "11.1.16", "10.2.7-h35", "10.2.18-h7", "10.2.19")],
    *[("CVE-2099-2002", v, FW, A) for v in ("12.1.4-h6", "12.1.4", "12.1.3", "12.1.0", "12.1.5", "12.1.6-h1", "11.1.5",
                                             "11.1.6-h32", "11.1.12", "11.1.13-h6", "11.1.14", "10.2.7-h34", "10.2.17")],
    ("CVE-2099-2002", "11.2.5", FW, U),
    # (c) defaultStatus が affected・修正版の無い系列（CVE-2026-0279 の形）
    *[("CVE-2099-2003", v, FW, A) for v in ("10.2.0", "10.2.18-h15", "10.2.99-h9", "12.1.7-h5", "11.1.15", "11.2.12")],
    *[("CVE-2099-2003", v, FW, U) for v in ("12.1.8", "12.1.9", "11.1.16", "11.2.13")],
    *[("CVE-2099-2003", v, FW, C) for v in ("11.0.3", "10.1.14", "9.1.0", "12.2.0")],  # 記載のない系列 → 候補
    # (d) changes だけ・ホットフィックスの無い修正点（CVE-2026-0321 の形）
    *[("CVE-2099-2004", v, FW, A) for v in ("12.2.0", "12.2.3", "12.2.3-h9", "12.1.4-h11", "12.1.5", "12.1.8", "12.1.10-h1")],
    *[("CVE-2099-2004", v, FW, U) for v in ("12.2.4", "12.2.4-h1", "12.2.5", "12.1.4-h12", "12.1.7-h8", "12.1.10-h2",
                                             "12.1.11", "11.1.0")],
    # (e) 途中の版から影響・影響なしの行（CVE-2026-123633 の形）
    *[("CVE-2099-2005", v, FW, U) for v in ("12.1.4", "12.1.4-h9", "12.1.7-h15", "12.1.10-h6", "12.1.11", "11.2.7",
                                             "11.2.10-h19", "11.2.16-h3", "11.1.6", "11.1.0", "10.2.18", "12.2.4-h3")],
    *[("CVE-2099-2005", v, FW, A) for v in ("12.1.5", "12.1.7-h14", "12.1.8", "12.1.10-h5", "11.2.8", "11.2.10-h18",
                                             "11.2.14", "12.2.4-h2")],
    # (f) version が "12.2"・系列つきの製品名で影響なし（CVE-2026-111497 の形）
    *[("CVE-2099-2006", v, FW, A) for v in ("12.2.0", "12.2.3", "12.1.4-h12", "12.1.5", "12.1.10-h2")],
    *[("CVE-2099-2006", v, FW, U) for v in ("12.2.4-h1", "12.1.4-h13", "12.1.7-h11", "12.1.10-h3", "11.1.5", "10.2.5")],
    # (g) status が unknown（PAN-SA の形）: どの版も判定できない
    *[("PAN-SA-2099-2007", v, FW, R) for v in ("10.2.5", "12.1.0", "9.0.0")],
    # (h) Panorama だけ（CVE-2026-0330 の形）
    ("CVE-2099-2008", "10.2.7", "Panorama", A), ("CVE-2099-2008", "10.2.7", "M-600", A), ("CVE-2099-2008", "10.2.7", None, C),
    ("CVE-2099-2008", "10.2.7", "PA-440", U), ("CVE-2099-2008", "10.2.7", "PA-VM", U), ("CVE-2099-2008", "10.2.7", "PAN-PA-440", U),
    ("CVE-2099-2008", "10.2.7-h40", "Panorama", U), ("CVE-2099-2008", "10.2.18-h14", None, U),
    # 本物に無い形は判定できない（その系列だけ）
    ("CVE-2099-2009", "10.1.5", FW, R), ("CVE-2099-2009", "9.1.3", FW, R), ("CVE-2099-2009", "11.0.2", FW, R),
    ("CVE-2099-2009", "10.2.5", FW, U),
    # (i) 古い形 "x.y All"（CVE-2024-3400 の形）: 載っている系列はその行で、"x.y All" の影響なしは系列すべて非該当
    *[("CVE-2099-2010", v, FW, U) for v in ("10.2.9-h1", "10.2.5-h6", "10.2.0-h3", "10.2.10", "11.1.2-h3", "11.1.3", "9.1.17",
                                             "9.0.17", "10.1.14-h5", "10.0.12")],
    *[("CVE-2099-2010", v, FW, A) for v in ("10.2.0", "10.2.1", "10.2.5-h5", "10.2.9", "11.1.0-h2", "11.1.2")],
    ("CVE-2099-2010", "11.0.4-h1", FW, U),  # 載っていない系列（defaultStatus なし）
    # (i) "x.y All" 影響ありと "x.y None" 影響なしの組（CVE-2024-9471 の形）: 食い違いにせず「該当」
    *[("CVE-2099-2011", v, FW, A) for v in ("9.1.17", "9.1.0", "9.0.16", "11.0.2", "10.2.7-h8", "10.1.10")],
    *[("CVE-2099-2011", v, FW, U) for v in ("11.1.2-h3", "11.0.3", "10.2.8", "10.1.11", "10.2.13-h1", "11.2.0")],
    # (i)+(h) Panorama だけの行と古い形の行（CVE-2024-3387 の形）: ファイアウォールはすべて非該当
    *[("CVE-2099-2012", v, m, U) for v in ("10.2.7", "10.2.7-h3", "10.2.8", "11.0.3", "11.0.4", "10.1.11", "11.1.2", "9.1.17")
      for m in ("PA-440", "PA-VM", "PA-5450")],
    *[("CVE-2099-2012", v, "Panorama", A) for v in ("10.2.7", "11.0.3", "10.1.11")],
    *[("CVE-2099-2012", v, "M-200", U) for v in ("10.2.7-h3", "10.2.8", "11.0.4", "11.1.2", "9.1.17")],
    ("CVE-2099-2012", "10.2.7", None, C), ("CVE-2099-2012", "9.1.17", None, U),
    # (j) 特定の機種だけ（PAN-SA-2025-0003 の形）: 機種を自動では決めず候補。Panorama には当てない
    *[("PAN-SA-2099-2013", "11.1.6-h3", m, C) for m in ("PA-440", "PA-3220", "PA-5250", "PA-7050", "PA-VM", None)],
    ("PAN-SA-2099-2013", "11.1.6-h3", "Panorama", U), ("PAN-SA-2099-2013", "9.0.1", "M-600", U),
]


@pytest.mark.parametrize("adv,version,model,expected", SHAPE_TABLE)
def test_real_shapes_table(adv, version, model, expected):
    assert vm.evaluate(PAN, version, SHAPES[adv], model) == expected


def test_candidate_reasons():
    assert vm.candidate_reason(PAN, "11.0.3", SHAPES["CVE-2099-2003"], FW) == "勧告は、記載のない系列も影響ありとしています（この機器の系列は勧告の表に載っていません）"
    assert "Panorama だけに影響する勧告です" in vm.candidate_reason(PAN, "10.2.7", SHAPES["CVE-2099-2008"], None)
    assert vm.candidate_reason(PAN, "10.2.7", SHAPES["CVE-2099-2001"], FW) is None  # 該当（候補ではない）
    assert vm.candidate_reason(PAN, "garbage", SHAPES["CVE-2099-2003"], FW) is None


def test_old_all_none_pairs_both_ways():
    """古い形の組: "x.y All" 影響あり＋"x.y None" 影響なし → 該当。逆（"x.y None" 影響あり＋"x.y All" 影響なし）→ 非該当"""
    hit = vf.ranges_from_versions([{"status": "affected", "version": "9.1 All"}, {"status": "unaffected", "version": "9.1 None"}])
    miss = vf.ranges_from_versions([{"status": "affected", "version": "9.1 none"}, {"status": "unaffected", "version": " 9.1  ALL "}],
                                   default_status="affected")
    for v in ("9.1.0", "9.1.17", "9.1.17-h3"):
        assert vm.evaluate(PAN, v, hit) == "affected" and vm.evaluate(PAN, v, miss) == "unaffected"
    assert vm.evaluate(PAN, "10.2.5", hit) == "unaffected"  # 別の系列
    assert vm.evaluate(PAN, "10.2.5", miss) == "candidate"  # 既定が affected で、系列が載っていない
    assert hit[1]["none"] is True and hit[1]["src"]["version"] == "9.1 None"  # 判定に使わない行も元の値を残す
    # 上限・修正点が付いた古い形は読まない
    bad = vf.ranges_from_versions([{"status": "affected", "version": "9.1 All", "lessThan": "9.1.9"}])
    assert bad[0]["unreadable"] and bad[0]["branch"] == "9.1" and vm.evaluate(PAN, "10.2.5", bad) == "unaffected"


def test_product_wide_all_without_platforms():
    r = vf.ranges_from_versions([{"status": "affected", "version": " All"}], default_status="affected")
    assert all(vm.evaluate(PAN, v, r, m) == "affected" for v in ("9.0.1", "12.1.4-h2") for m in ("PA-440", "Panorama", None))


def test_specific_model_candidate_reason():
    reason = vm.candidate_reason(PAN, "11.1.6-h3", SHAPES["PAN-SA-2099-2013"], "PA-440")
    assert reason == "特定の機種だけに影響する勧告です（対象: PA-3200, PA-5200, PA-7000）。機種を確かめてください"
    # 既定（記載のない系列）の行にも同じ扱い
    r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"}], ["PA-3200"],
                                default_status="affected")
    assert vm.evaluate(PAN, "11.0.1", r, "PA-440") == "candidate" and vm.evaluate(PAN, "11.0.1", r, "Panorama") == "unaffected"
    assert "PA-3200" in vm.candidate_reason(PAN, "11.0.1", r, None)
    # Panorama と機種が混ざった行: Panorama には当たり、ほかは候補
    mixed = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"}], ["Panorama", "PA-7000"])
    assert vm.evaluate(PAN, "10.2.5", mixed, "M-600") == "affected" and vm.evaluate(PAN, "10.2.5", mixed, "PA-440") == "candidate"


def test_default_affected_is_limited_by_platforms():
    r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"}], ["Panorama"],
                                default_status="affected")
    assert vm.evaluate(PAN, "11.0.1", r, "PA-440") == "unaffected"  # Panorama だけの製品の既定は、ファイアウォールに当たらない
    assert vm.evaluate(PAN, "11.0.1", r, "M-600") == "candidate"
    unknown = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"}], default_status="unknown")
    assert vm.evaluate(PAN, "11.0.1", unknown) == "unreadable"
    assert vm.evaluate(PAN, "10.2.9", unknown) == "unreadable"  # changes に無い lessThan 以上は既定（unknown）に従う


def test_conflicting_rows_are_unreadable():
    """影響ありの行と影響なしの行が同じ版に重なる（本物では見ていない形）: どちらにもせず判定できない"""
    r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"},
                                 {"status": "unaffected", "version": "10.2.5"}])
    assert vm.evaluate(PAN, "10.2.6", r) == "unreadable" and vm.judge_detail(vm.parse_version(PAN, "10.2.6"), r)[1] == "conflict"
    assert vm.evaluate(PAN, "10.2.4", r) == "affected" and vm.evaluate(PAN, "10.2.9", r) == "unaffected"


# ================================================================ 性質のテスト（作った行で何度も確かめる）


def _random_row(rng: random.Random) -> tuple[str, list[str]]:
    """系列 10.2 の、ランダムな修正点（保守版ごとに 1 つまで）と始まりの版"""
    maints = sorted(rng.sample(range(1, 30), rng.randint(1, 6)))
    fixes = [f"10.2.{z}" + (f"-h{rng.randint(1, 50)}" if rng.random() < 0.8 else "") for z in maints]
    start = "10.2.0" if rng.random() < 0.7 else f"10.2.{rng.randint(0, maints[0] - 1)}"
    return start, fixes


def _row_items(start, fixes, rng, use_lt):
    changes = [{"at": f, "status": "unaffected"} for f in fixes]
    rng.shuffle(changes)
    row = {"status": "affected", "version": start, "versionType": "custom", "changes": changes}
    if use_lt:
        row["lessThan"] = rng.choice(fixes)  # 最大のことも最小のこともある
    return vf.ranges_from_versions([row])


def _grid():
    return [f"10.2.{z}" + (f"-h{h}" if h else "") for z in range(0, 32) for h in (0, 1, 2, 5, 20, 49, 50, 51)] + ["10.1.9", "10.3.0"]


@pytest.mark.parametrize("seed", range(40))
def test_properties_of_fix_points(seed):
    rng = random.Random(seed)
    start, fixes = _random_row(rng)
    items = _row_items(start, fixes, rng, use_lt=seed % 2 == 0)
    assert not items[0].get("unreadable"), items
    ev = lambda v: vm.evaluate(PAN, v, items)  # noqa: E731
    top = max(fixes, key=lambda f: vm.parse_version(PAN, f).key)
    for f in fixes:
        assert ev(f) == "unaffected", f  # (i) 修正点そのものは必ず非該当
        base, _, h = f.partition("-h")
        for k in (1, 2, 30):  # (ii) 同じ保守版で、修正点より後のホットフィックスは必ず非該当
            assert ev(f"{base}-h{int(h or 0) + k}") == "unaffected", (f, k)
    tp = vm.parse_version(PAN, top)
    for v in _grid():  # (iii) 最大の修正点以上は必ず非該当
        p = vm.parse_version(PAN, v)
        if p.branch == "10.2" and p.key >= tp.key:
            assert ev(v) == "unaffected", v
    # (iv) changes の並びを入れ替えても結果が変わらない
    want = [ev(v) for v in _grid()]
    for _ in range(3):
        again = _row_items(start, fixes, rng, use_lt=False)
        again_lt = [{**again[0], "fixes": list(reversed(again[0]["fixes"]))}]
        assert [vm.evaluate(PAN, v, again) for v in _grid()] == want
        assert [vm.evaluate(PAN, v, again_lt) for v in _grid()] == want
    # 始まりより前は非該当・別の系列は非該当
    assert ev("10.1.9") == "unaffected" and ev("10.3.0") == "unaffected"


_JUNK = [None, "", "x", "10.2", "10.2.0", "10.2.5-h1", "*", "All", 1, 1.5, True, [], {}, ["10.2.1"], {"at": "10.2.1"},
         "11.1.0", "10.2.99-h99", "\x00", "1" * 300]


@pytest.mark.parametrize("seed", range(30))
def test_judge_never_raises_on_junk(seed):
    """(v) 判定の関数は例外を出さない（読めない入力は「判定できない」など、決まった値のどれか）"""
    rng = random.Random(1000 + seed)
    keys = ["status", "branch", "ge", "lt", "le", "fixes", "open", "all", "unreadable", "kind", "default", "platforms", "after_all"]
    for _ in range(200):
        items = []
        for _ in range(rng.randint(0, 4)):
            if rng.random() < 0.1:
                items.append(rng.choice(_JUNK))
                continue
            items.append({k: rng.choice([*_JUNK, "affected", "unaffected", "10.2", "default"]) for k in rng.sample(keys, rng.randint(1, 6))})
        rows = [{k: rng.choice([*_JUNK, "affected", "unaffected"]) for k in rng.sample(
            ["status", "version", "lessThan", "lessThanOrEqual", "changes", "versionType"], rng.randint(1, 5))} for _ in range(3)]
        for target in (items, vf.ranges_from_versions(rows, default_status=rng.choice(_JUNK)), rng.choice(_JUNK)):
            for v in ("10.2.5", "10.2.0", "11.1.3-h2"):
                assert vm.evaluate(PAN, v, target, rng.choice([None, "PA-440", "Panorama", 5])) in (
                    "affected", "unaffected", "candidate", "unreadable")


# ================================================================ 4 回目のレビューの反例（作り物の ID。行の形はレビューの反例と同じ）


def _adv(*entries) -> list[dict]:
    """製品行（affected[] の 1 件）を並べた作り物の勧告を、取得のときと同じ解析にかけて影響範囲にする"""
    rec = {"cveMetadata": {"cveId": "CVE-2099-3001", "state": "PUBLISHED"},
           "containers": {"cna": {"title": "作り物", "affected": list(entries), "metrics": []}}}
    try:
        return vf.parse_paloalto({"success": True, "data": [rec]})[0]["affected"]
    except vf.FetchError:  # 影響ありになりうる行が無い勧告は保存しない（＝どの機器にも当たらない）
        return []


def _row(version, lt=None, status="affected", **kw):
    r = {"version": version, "status": status, "versionType": "custom", **kw}
    if lt:
        r["lessThan"] = lt
    return r


def _p(*rows, **kw):
    return {"product": "PAN-OS", "versions": list(rows), **kw}


REVIEW4_TABLE = [
    # 中-1: platforms の 6 件目が Panorama（全件で判定する）
    ([_p(_row("10.2.0", "10.2.5"), platforms=["PA-220", "PA-800", "PA-3200", "PA-5200", "PA-7000", "Panorama"])],
     "10.2.3", "Panorama", A),
    ([_p(_row("10.2.0", "10.2.5"), platforms=["PA-220", "PA-800", "PA-3200", "PA-5200", "PA-7000", "Panorama"])],
     "10.2.3", "M-600", A),
    # 中-2: defaultStatus は同じ製品行の系列だけで判断する（Panorama だけの別の製品行の系列に打ち消されない）
    ([_p(_row("10.2.0", "10.2.5"), defaultStatus="affected"), _p(_row("11.1.0", "11.1.3"), platforms=["Panorama"])],
     "11.1.5", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.5"), defaultStatus="affected"), _p(_row("11.1.0", "11.1.3"), platforms=["Panorama"])],
     "11.1.5", None, C),
    ([_p(_row("10.2.0", "10.2.5"), defaultStatus="affected", platforms=["Panorama"]), _p(_row("11.1.0", "11.1.3"))],
     "11.1.5", "Panorama", C),
    ([_p(_row("10.2.0", "10.2.5"), defaultStatus="affected", platforms=["Panorama"]), _p(_row("11.1.0", "11.1.3"))],
     "11.1.5", "PA-440", U),  # Panorama だけの製品行の既定は、ファイアウォールに当たらない。11.1 は別の製品行で範囲の外
    # 中-3: "x.y None" の影響なしだけ（対の行が無い）→ 判定できない。影響ありの "x.y None" だけ → 非該当
    ([_p(_row("9.1 None", status="unaffected"), _row("10.2.0"))], "9.1.17", "PA-440", R),
    ([_p(_row("9.1 None", status="unaffected"), _row("10.2.0"), defaultStatus="affected")], "9.1.17", "PA-440", R),
    ([_p(_row("9.1 None"), _row("10.2.0"))], "9.1.17", "PA-440", U),
    ([_p(_row("11.1 None"), _row("11.1 All", status="unaffected"), _row("10.2.0"))], "11.1.2", "PA-440", U),
    ([_p(_row("9.1 None"), _row("9.1 None", status="unaffected"))], "9.1.3", "PA-440", R),  # どちらの列も「無し」
    # 中-4: 系列をまたぐ行・語句つきの行は、全系列で判定できない
    ([_p(_row("10.1 and earlier"), _row("11.1.0", "11.1.5"), defaultStatus="unaffected")], "9.1.17", "PA-440", R),
    ([_p(_row("10.1 and earlier"), _row("11.1.0", "11.1.5"), defaultStatus="unaffected")], "10.1.3", "PA-440", R),
    ([_p(_row("10.1 and earlier"), _row("11.1.0", "11.1.5"), defaultStatus="unaffected")], "11.1.3", "PA-440", A),
    ([_p(_row("10.2 and later"), defaultStatus="unaffected")], "11.1.3", "PA-440", R),
    ([_p(_row("10.2.0 - 10.2.5"), defaultStatus="unaffected")], "11.1.0", "PA-440", R),
    ([_p(_row("10.2abc"), defaultStatus="unaffected")], "11.0.1", "PA-440", R),
    ([_p(_row("9.1.0", "11.0.0"), _row("11.1.0", "11.1.3"), defaultStatus="unaffected")], "10.1.3", "PA-440", R),
    ([_p(_row("9.1.0", "11.0.0"), _row("11.1.0", "11.1.3"), defaultStatus="unaffected")], "10.2.3", "PA-440", R),
    ([_p(_row("9.1.0", lessThanOrEqual="10.2.5"), defaultStatus="unaffected")], "10.1.3", "PA-440", R),
    ([_p(_row("9.1.0", "*"), defaultStatus="unaffected")], "10.1.3", "PA-440", R),
    ([_p(_row("9.1.0", "*"), defaultStatus="unaffected")], "9.1.5", "PA-440", R),
    ([_p(_row("10.2.0", "10.2.9", changes=[{"at": "11.1.5", "status": "unaffected"}]))], "12.1.0", "PA-440", R),
    # L-3: Panorama を含むか決められない・形の違う platforms は、Panorama の機器を非該当にしない（候補）
    ([_p(_row("10.2.0", "10.2.5"), platforms=["All"])], "10.2.3", "Panorama", C),
    ([_p(_row("10.2.0", "10.2.5"), platforms=["PA-Series", "VM-Series"])], "10.2.3", "Panorama", C),
    ([_p(_row("10.2.0", "10.2.5"), platforms=[None, 5])], "10.2.3", "Panorama", C),
    ([_p(_row("10.2.0", "10.2.5"), platforms="Panorama")], "10.2.3", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.5"), platforms=["PA-3200", "Firewall"])], "10.2.3", "Panorama", C),
    ([_p(_row("10.2.0", "10.2.5"), platforms=["PA-3200", "PA-VM", "VM-300"])], "10.2.3", "Panorama", U),  # 機種名と言い切れる
    ([_p(_row("10.2.0", "10.2.5"), platforms=[])], "10.2.3", "PA-440", A),  # 空の配列は絞り込みなし
]


@pytest.mark.parametrize("entries,version,model,expected", REVIEW4_TABLE)
def test_review4_counterexamples(entries, version, model, expected):
    assert vm.evaluate(PAN, version, _adv(*entries), model) == expected


def test_all_platforms_are_kept_for_judging():
    plats = [f"PA-{i}00" for i in range(1, 9)] + ["Panorama"]
    items = _adv(_p(_row("10.2.0", "10.2.5"), platforms=plats))
    assert items[0]["platforms"] == plats and not items[0].get("platforms_bad")
    reason = vm.candidate_reason(PAN, "10.2.3", items, "PA-440")
    assert reason.startswith("特定の機種だけに影響する勧告です（対象: PA-100, PA-200")


# ================================================================ 性質: 読めない行を足しても、安全側から外れない

_READABLE_ROWS = [
    _row("10.2.0", "10.2.9"), _row("10.2.0", "10.2.4-h3", changes=[{"at": "10.2.7-h2", "status": "unaffected"}]),
    _row("11.1.0"), _row("11.1.2", status="unaffected"), _row("9.1 All"), _row("9.1 None", status="unaffected"),
    _row("10.1 All", status="unaffected"), _row("10.1 None"), _row(" All"), _row("12.1.0", "12.1.5"),
]
_UNREADABLE_ROWS = [
    _row(""), _row("10.1 and earlier"), _row("garbage"), _row("10.2.0", "zzz"), _row("9.1.0", "11.0.0"), _row("9.1.0", "*"),
    {**_row("10.2.0", "10.2.9"), "versionType": "semver"}, _row("11.1.0", "11.1.5", status="unknown"),
    _row("10.2.0", "10.2.9", changes=[{"at": "10.2.5", "status": "affected"}]), "broken",
]
_ORDER = {"affected": 3, "candidate": 2, "unreadable": 2, "unaffected": 0}


@pytest.mark.parametrize("seed", range(40))
def test_adding_unreadable_row_never_moves_to_unaffected(seed):
    """読めない行を 1 つ足しても、該当 → 非該当・判定できない → 非該当・候補 → 非該当 には決して変わらない"""
    rng = random.Random(5000 + seed)
    versions = ["9.1.3", "10.1.4", "10.2.0", "10.2.3", "10.2.4-h3", "10.2.7-h1", "10.2.9", "11.0.2", "11.1.1", "11.1.3",
                "12.1.2", "12.1.7"]
    for _ in range(30):
        n_entries = rng.randint(1, 3)
        entries = []
        for _e in range(n_entries):
            kw = {}
            if rng.random() < 0.3:
                kw["defaultStatus"] = rng.choice(["affected", "unaffected", "unknown"])
            if rng.random() < 0.25:
                kw["platforms"] = rng.choice([["Panorama"], ["PA-3200"], ["Panorama", "PA-3200"], ["All"]])
            entries.append(_p(*rng.sample(_READABLE_ROWS, rng.randint(1, 4)), **kw))
        base = _adv(*entries)
        i = rng.randrange(n_entries)
        more = [dict(e, versions=[*e["versions"], rng.choice(_UNREADABLE_ROWS)]) if j == i else e
                for j, e in enumerate(entries)]
        added = _adv(*more)
        for v in versions:
            for model in ("PA-440", "Panorama", None):
                before, after = vm.evaluate(PAN, v, base, model), vm.evaluate(PAN, v, added, model)
                if before != "unaffected":
                    assert after != "unaffected", (v, model, before, after, more)


# ================================================================ 5 回目のレビューの反例（作り物の ID。行の形はレビューの反例と同じ）

REVIEW5_TABLE = [
    # M1: 既定が affected / unknown の製品行では、行の始まりより前・lessThanOrEqual より後は既定に従う。修正点以上は非該当
    ([_p(_row("9.1.3-h1"), defaultStatus="affected")], "9.1.0", "PA-440", C),
    ([_p(_row("9.1.3-h1"), defaultStatus="affected")], "9.1.3-h1", "PA-440", A),
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="affected")], "10.2.1", "PA-440", C),
    # M1': 既定より優先してよい修正点は changes の at だけ。changes に無い lessThan 以上は既定に従う
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="affected")], "10.2.12", "PA-440", C),
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="affected")], "10.2.9", "PA-440", C),
    ([_p(_row("10.2", "10.2.4", changes=[]), defaultStatus="unknown")], "10.2.4", "PA-440", R),
    ([_p(_row("10.2.5", "10.2.9", changes=[{"at": "10.2.9", "status": "unaffected"}]), defaultStatus="affected")],
     "10.2.12", "PA-440", U),  # 本物の形（changes に lessThan と同じ at）: changes の根拠で非該当
    ([_p(_row("10.2.0", "10.2.4-h7", changes=[{"at": "10.2.4-h7", "status": "unaffected"}, {"at": "10.2.7", "status": "unaffected"}]),
         defaultStatus="affected")], "10.2.8", "PA-440", U),
    ([_p(_row("10.2.0", "10.2.9"), defaultStatus="unaffected")], "10.2.12", "PA-440", U),  # 既定が影響なし: lessThan 以上は非該当
    ([_p(_row("10.2.0", "10.2.9"))], "10.2.12", "PA-440", U),
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="affected")], "11.1.1", "PA-440", C),
    ([_p(_row("10.2.0", lessThanOrEqual="10.2.4-h2"), defaultStatus="affected")], "10.2.5", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.9"), defaultStatus="unknown")], "10.2.10", "PA-440", R),  # lessThan だけ: 既定（unknown）
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="unknown")], "10.2.1", "PA-440", R),  # 始まりより前は既定（unknown）
    ([_p(_row("10.2.5", "10.2.9"), defaultStatus="unaffected")], "10.2.1", "PA-440", U),  # 既定が影響なし
    ([_p(_row("10.2.5", "10.2.9"))], "10.2.1", "PA-440", U),  # 既定が無い（規則 6。README の限界 L1）
    # M2: 影響なしの "x.y None" は、"x.y All" の影響ありだけと組のときに限って確定。それ以外は判定できない
    ([_p(_row("9.1 None", status="unaffected"), _row("9.1.5", status="unaffected"))], "9.1.3", "PA-440", R),
    ([_p(_row("9.1 None", status="unaffected"), _row("9.1.5", status="unaffected"))], "9.1.6", "PA-440", R),
    ([_p(_row("9.1 None", status="unaffected"), _row("9.1.0", "9.1.5"))], "9.1.7", "PA-440", R),
    ([_p(_row("9.1 None", status="unaffected"), _row("9.1 All"))], "9.1.7", "PA-440", A),
    ([_p(_row("9.1 None", status="unaffected"), _row("9.1 All"), _row("9.1.0", "9.1.5"))], "9.1.7", "PA-440", A),  # 該当が先
    # M3: 製品名の系列と版の系列が違う行は、全系列で判定できない
    ([{"product": "PAN-OS 11.1", "versions": [_row("10.0.0", "11.1.5")]}], "11.1.2", "PA-440", R),
    ([{"product": "PAN-OS 11.1", "versions": [_row("11.0.0", "11.1.5")]}], "11.1.2", "PA-440", R),
    # M4: 要素の全体が「Panorama」のときだけ、ファイアウォールを当てない根拠にする
    ([_p(_row("10.2.0", "10.2.9"), platforms=["Firewalls managed by Panorama"])], "10.2.3", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["Firewalls managed by Panorama"])], "10.2.3", None, C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=[" panorama "])], "10.2.3", "PA-440", U),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["Panorama M-Series"])], "10.2.3", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["Panorama M-Series"])], "10.2.3", "M-600", A),
    # M5: ファイアウォールの機種名は要素の全体で確かめる（" Series" つきは認識する）
    ([_p(_row("10.2.0", "10.2.9"), platforms=["PA-VM / M-600"])], "10.2.3", "M-600", C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["VM-50 and M-Series appliances"])], "10.2.3", "M-600", C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["PA-3200 Series"])], "10.2.3", "M-600", U),
    ([_p(_row("10.2.0", "10.2.9"), platforms=["PA-3200 Series"])], "10.2.3", "PA-440", C),
    ([_p(_row("10.2.0", "10.2.9"), platforms=[""])], "10.2.3", "PA-440", C),
    # M6: 製品名に pan-os を含むのに決まった形でない製品行は、全系列で判定できない
    ([{"product": "PAN-OS 11.1.x", "versions": [_row("11.1.0", "11.1.5")]}], "11.1.2", "PA-440", R),
    ([{"product": "PAN-OS®", "versions": [_row("11.1.0", "11.1.5")]}], "10.2.2", "PA-440", R),
    ([_p(_row("11.1 All", status="unaffected")), {"product": "PAN-OS (Panorama)", "versions": [_row("11.1.0", "11.1.5")]}],
     "11.1.2", "Panorama", R),
    # L2: lessThan が changes に無く、changes の最大より前 → その系列は判定できない（changes が空なら lessThan だけで読む）
    ([_p(_row("10.2.0", "10.2.9", changes=[{"at": "10.2.12", "status": "unaffected"}]))], "10.2.10", "PA-440", R),
    ([_p(_row("10.2.0", "10.2.9", changes=[{"at": "10.2.12", "status": "unaffected"}]))], "11.1.1", "PA-440", U),
    ([_p(_row("10.2.0", "10.2.12", changes=[{"at": "10.2.7-h3", "status": "unaffected"}]))], "10.2.8", "PA-440", A),  # 最大の lessThan
    ([_p(_row("10.2.0", "10.2.9"))], "10.2.9", "PA-440", U),
    # L3: le が h なしの x.y.z で、同じ x.y.z のホットフィックスは決められない
    ([_p(_row("10.2.0", lessThanOrEqual="10.2.9"))], "10.2.9-h1", "PA-440", R),
    ([_p(_row("10.2.0", lessThanOrEqual="10.2.9"))], "10.2.9", "PA-440", A),
    ([_p(_row("10.2.0", lessThanOrEqual="10.2.9"))], "10.2.10", "PA-440", U),
    # そのほか（レビューの t.py）
    ([_p({"version": "10.2.0", "lessThan": "10.2.9"})], "10.2.3", "PA-440", R),  # status の無い行
    ([_p(_row("10.2.0", "10.2.9"), defaultStatus="unaffected"), _p(defaultStatus="unknown")], "11.1.1", "PA-440", R),
    ([_p(_row("10.2.0", status="unaffected"), _row("10.2.0", "10.2.9"))], "10.2.3", "PA-440", R),  # 食い違い
    ([_p(_row(" All"), platforms=["PA-3200"], defaultStatus="affected")], "11.1.1", "Panorama", U),
    ([_p(_row(" All"), platforms=["PA-3200"], defaultStatus="affected")], "11.1.1", "PA-VM", C),
]


@pytest.mark.parametrize("entries,version,model,expected", REVIEW5_TABLE)
def test_review5_counterexamples(entries, version, model, expected):
    assert vm.evaluate(PAN, version, _adv(*entries), model) == expected


# ================================================================ 性質: 読める行を足したときに非該当へ変わってよい場合

def _states_unaffected(row: dict, v: str) -> bool:
    """足した行が、この版について「影響なし」と明記する読める行か

    次のどれかのときだけ（それ以外で 該当・候補・判定できない → 非該当 になるのは誤り）:
      - その版を含む、読める影響なし（unaffected）の行
      - 影響ありの "x.y None"（その系列に影響ありの版は無い）
      - 修正点（changes の at・lessThan）として、その版以下の点を持つ読める影響ありの行（修正点以上は影響なし）
    """
    p = vm.parse_version(PAN, v)
    for it in vf.ranges_from_versions([row]):
        if it.get("unreadable") or "kind" in it:
            continue
        if it.get("none") and it.get("status") == "affected" and it.get("branch") == p.branch:
            return True
        sp = vm._span(p, it)
        if (sp == "in" and it.get("status") == "unaffected") or (sp == "out_fix" and it.get("status") == "affected"):
            return True
    return False


@pytest.mark.parametrize("seed", range(40))
def test_adding_readable_row_moves_to_unaffected_only_when_row_says_so(seed):
    rng = random.Random(9000 + seed)
    versions = ["9.1.3", "10.1.4", "10.2.0", "10.2.3", "10.2.4-h3", "10.2.7-h1", "10.2.9", "11.0.2", "11.1.1", "11.1.3",
                "12.1.2", "12.1.7"]
    for _ in range(30):
        entries = []
        for _e in range(rng.randint(1, 2)):
            kw = {}
            if rng.random() < 0.5:
                kw["defaultStatus"] = rng.choice(["affected", "unaffected", "unknown"])
            if rng.random() < 0.25:
                kw["platforms"] = rng.choice([["Panorama"], ["PA-3200 Series"], ["Panorama", "PA-3200"], ["All"]])
            entries.append(_p(*rng.sample(_READABLE_ROWS + _UNREADABLE_ROWS[:3], rng.randint(0, 3)), **kw))
        add = rng.choice(_READABLE_ROWS)
        i = rng.randrange(len(entries))
        more = [dict(e, versions=[*e["versions"], add]) if j == i else e for j, e in enumerate(entries)]
        base, added = _adv(*entries), _adv(*more)
        for v in versions:
            for model in ("PA-440", "Panorama", None):
                before, after = vm.evaluate(PAN, v, base, model), vm.evaluate(PAN, v, added, model)
                if before != "unaffected" and after == "unaffected":
                    assert _states_unaffected(add, v), (v, model, before, more)
