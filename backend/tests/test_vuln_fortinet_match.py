"""Fortinet（FortiOS）の勧告の解析と照合のテスト（services/vuln_fetch.parse_fortinet_csaf・services/vuln_match.judge_fortios）

純粋な関数だけ（DB・通信は使わない）。見本の勧告は作り物の ID（FG-IR-99-…・CVE-2099-…）で、行の形だけを本物
（2026-11 に取得した CSAF。FG-IR-24-015・22-398・23-097・24-259・26-193・26-195・26-273・26-279・21-190 の形）に合わせる
"""
import random

import pytest

from app.services import vuln_fetch as vf
from app.services import vuln_match as vm

A, U, C, R = "affected", "unaffected", "candidate", "unreadable"
FG = "FortiGate-60F"


def vuln(product: str, affected: list[str], not_affected: list[str], cve: str = "CVE-2099-0001", score: float = 9.1,
         other_keys: dict | None = None) -> dict:
    """本物と同じ形の vulnerabilities[] の 1 件（CVE × 製品）"""
    ps = {"known_affected": affected, "known_not_affected": not_affected, **(other_keys or {})}
    return {"cve": cve, "title": f"{product} - {vf.severity_of(score).upper()} - FG-IR-99-001",
            "scores": [{"products": [product], "cvss_v3": {"version": "3.1", "baseScore": score, "baseSeverity": "CRITICAL"}}],
            "product_status": ps,
            "remediations": [{"category": "vendor_fix", "details": "作り物", "product_ids": [product]}]}


def csaf(*vulns, ext_id: str = "FG-IR-99-001", status: str = "final", tree: list | None = None, drop_vulns=False) -> dict:
    doc = {"document": {"title": "作り物の勧告", "category": "Fortinet PSIRT Advisories", "csaf_version": "2.0",
                        "tracking": {"id": ext_id, "initial_release_date": "2099-01-10T00:00:00",
                                     "current_release_date": "2099-01-12T00:00:00", "status": status, "version": "0"}},
           "product_tree": {"branches": [{"category": "vendor", "name": "Fortinet PSIRT", "branches": tree or []}]}}
    if not drop_vulns:
        doc["vulnerabilities"] = list(vulns)
    return doc


def ranges(*vulns, **kw) -> list[dict]:
    adv = vf.parse_fortinet_csaf(csaf(*vulns, **kw))
    assert adv["products"] == ["fortinet"]
    return adv["affected"]


def ev(version: str, rows, model: str | None = FG) -> str:
    return vm.evaluate("fortinet", version, rows, model)


# ---------------------------------------------------------------- 見本（本物の勧告の形）

# FG-IR-24-015 の形: 系列ごとの範囲と修正版 ＋ FortiProxy（all versions・移行）
S_015 = [vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.2", "FortiOS >=7.2.0|<=7.2.6", "FortiOS >=6.0.0|<=6.0.17"],
              ["FortiOS-7.4.3", "FortiOS-7.2.7", "FortiOS-6.0.18"]),
         vuln("FortiProxy", ["FortiProxy >=7.4.0|<=7.4.2", "FortiProxy 1.2 all versions"], ["FortiProxy-7.4.3"])]
# FG-IR-22-398 の形: 5.x が all versions（修正版なし）。6K7K は別の脆弱性の記載。7.4 以上の行は無い
S_398 = [vuln("FortiOS", ["FortiOS >=7.2.0|<=7.2.2", "FortiOS >=7.0.0|<=7.0.8", "FortiOS 5.6 all versions", "FortiOS 5.4 all versions"],
              ["FortiOS-7.2.3", "FortiOS-7.0.9"]),
         vuln("FortiOS-6K7K", ["FortiOS-6K7K >=7.0.0|<=7.0.8"], ["FortiOS-6K7K-7.0.9"])]
# FG-IR-23-097 の形: 7.4 は影響なし（スラッシュ＋空白）。6K7K は単独の版の列挙
S_097 = [vuln("FortiOS", ["FortiOS >=7.2.0|<=7.2.4", "FortiOS >=7.0.0|<=7.0.11"],
              ["FortiOS/ 7.4 all versions", "FortiOS-7.2.5", "FortiOS-7.0.12"]),
         vuln("FortiOS-6K7K", ["FortiOS-6K7K 7.0.10", "FortiOS-6K7K 7.0.5"], ["FortiOS-6K7K-7.0.12", "FortiOS-6K7K-7.0.12"])]
# FG-IR-24-259 の形: 単独の版 7.6.0 ＋ 多製品の混在（FortiManager など）＋ CVE が 2 つ
S_259 = [vuln("FortiManager", ["FortiManager 7.6.0"], ["FortiManager-7.6.1"], cve="CVE-2099-0002", score=6.7),
         vuln("FortiOS", ["FortiOS 7.6.0", "FortiOS >=7.4.0|<=7.4.4", "FortiOS >=6.4.0|<=6.4.15"],
              ["FortiOS-7.6.1", "FortiOS-7.4.5", "FortiOS-6.4.16"], cve="CVE-2099-0003", score=6.7),
         vuln("FortiProxy", ["FortiProxy 7.6.0"], ["FortiProxy-7.6.1"], cve="CVE-2099-0003", score=6.7)]
# FG-IR-26-193 の形: 修正版が未公開（空白 2 つ）・8.0 は影響なし・CSAF に 7.0 と 6.4 の行が無い（勧告のページの表にはある）
S_193 = [vuln("FortiOS", ["FortiOS >=7.6.0|<=7.6.4", "FortiOS >=7.4.0|<=7.4.9", "FortiOS >=7.2.0|<=7.2.13"],
              ["FortiOS/ 8.0 all versions", "FortiOS-7.6.5", "FortiOS-7.4.10", "FortiOS-upcoming  7.2.14"], score=7.7)]
# FG-IR-26-195 の形: 7.6 だけ影響あり。7.4・7.2 は影響なし
S_195 = [vuln("FortiOS", ["FortiOS >=7.6.0|<=7.6.6"],
              ["FortiOS/ 8.0 all versions", "FortiOS-7.6.7", "FortiOS/ 7.4 all versions", "FortiOS/ 7.2 all versions"], score=5.9)]
# FG-IR-26-273 の形: 8.0.0 は単独の版、7.0 は all versions（修正版なし）
S_273 = [vuln("FortiOS", ["FortiOS 8.0.0", "FortiOS >=7.6.0|<=7.6.7", "FortiOS >=7.2.0|<=7.2.13", "FortiOS 7.0 all versions"],
              ["FortiOS-8.0.1", "FortiOS-7.6.8", "FortiOS-7.2.14"], score=9.0)]

SHAPES = {"015": S_015, "398": S_398, "097": S_097, "259": S_259, "193": S_193, "195": S_195, "273": S_273}

SHAPE_TABLE = [
    # 015: 範囲の両端・修正版ちょうど・1 つ前・載っていない系列
    ("015", "7.4.0", A), ("015", "7.4.2", A), ("015", "7.4.3", U), ("015", "7.4.9", U), ("015", "7.2.6", A),
    ("015", "7.2.7", U), ("015", "6.0.0", A), ("015", "6.0.17", A), ("015", "6.0.18", U),
    ("015", "7.6.0", C), ("015", "7.0.5", C), ("015", "5.6.14", C), ("015", "8.0.0", C),
    # 398: all versions（修正版なし）。6K7K の行は FortiOS の判定に使わない
    ("398", "5.6.14", A), ("398", "5.6.0", A), ("398", "5.4.13", A), ("398", "5.2.1", C), ("398", "7.0.8", A),
    ("398", "7.0.9", U), ("398", "7.2.3", U), ("398", "7.4.1", C), ("398", "6.4.1", C),
    # 097: スラッシュ＋空白の all versions は影響なし
    ("097", "7.4.0", U), ("097", "7.4.9", U), ("097", "7.2.4", A), ("097", "7.2.5", U), ("097", "7.0.10", A),
    ("097", "7.0.11", A), ("097", "7.0.12", U),
    # 259: 単独の版
    ("259", "7.6.0", A), ("259", "7.6.1", U), ("259", "7.6.2", U), ("259", "7.4.4", A), ("259", "7.4.5", U),
    ("259", "6.4.15", A), ("259", "6.4.16", U), ("259", "6.2.16", C), ("259", "8.0.0", C),
    # 193: 未公開の修正版。それ以上の版は判定できない。載っていない 7.0・6.4 は候補（非該当にしない）
    ("193", "8.0.0", U), ("193", "8.0.2", U), ("193", "7.6.4", A), ("193", "7.6.5", U), ("193", "7.4.9", A),
    ("193", "7.4.10", U), ("193", "7.2.0", A), ("193", "7.2.13", A), ("193", "7.2.14", R), ("193", "7.2.15", R),
    ("193", "7.0.17", C), ("193", "6.4.16", C),
    # 195: 影響なしの系列
    ("195", "7.6.6", A), ("195", "7.6.7", U), ("195", "7.4.5", U), ("195", "7.2.9", U), ("195", "8.0.0", U),
    ("195", "7.0.1", C),
    # 273: 単独の版 8.0.0・修正版なしの 7.0
    ("273", "8.0.0", A), ("273", "8.0.1", U), ("273", "7.6.7", A), ("273", "7.6.8", U), ("273", "7.2.14", U),
    ("273", "7.0.0", A), ("273", "7.0.17", A), ("273", "6.4.1", C), ("273", "7.4.1", C),
]


@pytest.mark.parametrize("shape,version,expected", SHAPE_TABLE)
def test_real_shapes_table(shape, version, expected):
    assert ev(version, ranges(*SHAPES[shape])) == expected


def test_parse_keeps_scores_cves_dates_and_link():
    adv = vf.parse_fortinet_csaf(csaf(*S_259), "FG-IR-99-001")
    assert adv["source"] == "fortinet" and adv["ext_id"] == "FG-IR-99-001"
    assert adv["cve_ids"] == ["CVE-2099-0003"]  # FortiOS の脆弱性の CVE だけ（FortiManager の CVE は入れない）
    assert adv["cvss"] == 6.7 and adv["severity"] == "medium"
    assert adv["published_at"].isoformat() == "2099-01-10T00:00:00" and adv["modified_at"].isoformat() == "2099-01-12T00:00:00"
    assert adv["url"] == "https://www.fortiguard.com/psirt/FG-IR-99-001" and vf.safe_url(adv["url"])
    assert adv["unreadable"] == 0
    with pytest.raises(vf.FetchError, match="違います"):
        vf.parse_fortinet_csaf(csaf(*S_259), "FG-IR-99-002")
    for bad in ([], "x", {"document": {"tracking": {"id": "PAN-SA-2099-0001"}}}, {"document": {"tracking": {}}}):
        with pytest.raises(vf.FetchError):
            vf.parse_fortinet_csaf(bad)


def test_cvss_v4_is_used_when_present():
    v = vuln("FortiOS", ["FortiOS 7.4.0"], ["FortiOS-7.4.1"])
    v["scores"] = [{"products": ["FortiOS"], "cvss_v4": {"baseScore": 9.8}}, {"products": ["FortiProxy"], "cvss_v3": {"baseScore": 10}}]
    adv = vf.parse_fortinet_csaf(csaf(v))
    assert adv["cvss"] == 9.8 and adv["severity"] == "critical"  # FortiProxy の点は採らない


# ---------------------------------------------------------------- FortiOS の勧告かどうか（別の製品の取り違え）


def test_other_products_only_are_not_fortios():
    for doc in (csaf(vuln("FortiProxy", ["FortiProxy >=7.4.0|<=7.4.2"], ["FortiProxy-7.4.3"])),  # FortiProxy だけ
                csaf(vuln("FortiOS-6K7K", ["FortiOS-6K7K 7.0.10"], ["FortiOS-6K7K-7.0.12"])),  # 6K7K だけ（FG-IR-21-190 の形も同じ）
                csaf(vuln("FortiClientWindows", ["FortiClientWindows 6.2 all versions"], ["FortiClientWindows/ 6.0 all versions"]))):
        adv = vf.parse_fortinet_csaf(doc)
        assert adv["products"] == [] and adv["affected"] == []


@pytest.mark.parametrize("doc", [csaf(drop_vulns=True), csaf()])
def test_documents_without_vulnerabilities_are_notices(doc):
    """vulnerabilities が無い・空で、製品の一覧にも FortiOS が無い文書（FG-IR-26-279 の NGINX などの告知）は「要確認の告知」。
    機器ごとの照合には使わない（products は空・影響範囲は告知の印だけ）"""
    adv = vf.parse_fortinet_csaf(doc)
    assert adv["notice"] is True and adv["products"] == [] and adv["affected"][0]["notice"] is True
    assert ev("7.4.1", adv["affected"]) == R  # 照合には使わない（products が空）。仮に渡しても非該当にはしない


def test_document_without_vulnerabilities_but_fortios_in_tree_is_unreadable():
    tree = [{"category": "product_name", "name": "FortiOS", "branches": [{"name": "FortiOS/>=7.4.0|<=7.4.2"}]}]
    adv = vf.parse_fortinet_csaf(csaf(tree=tree, drop_vulns=True))
    assert adv["products"] == ["fortinet"] and not adv.get("notice")
    assert ev("7.4.1", adv["affected"]) == R


@pytest.mark.parametrize("doc,why", [
    (csaf(vuln("FortiOS", ["FortiOS 7.4.0"], ["FortiOS-7.4.1"]), status="interim"), "final でない"),
    (csaf(vuln("FortiProxy", ["FortiProxy 7.4.0"], []), tree=[{"category": "product_name", "name": "FortiOS",
                                                               "branches": [{"name": "FortiOS/>=7.4.0|<=7.4.2"}]}]),
     "製品の一覧に FortiOS があるのに FortiOS の脆弱性の記載が無い"),
    (csaf({"cve": "CVE-2099-0009"}), "製品を決められない脆弱性"),
    (csaf({"cve": "CVE-2099-0009", "title": "FortiProxy - HIGH", "product_status": "x"}), "product_status の形が違う"),
])
def test_unreadable_documents_are_kept_as_fortios_unreadable(doc, why):
    adv = vf.parse_fortinet_csaf(doc)
    assert adv["products"] == ["fortinet"], why
    for v in ("7.4.1", "7.4.5", "8.0.0", "6.4.3"):
        # 非該当にはしない（読めた行で「載っていない系列」の候補になる版は候補のまま）
        assert ev(v, adv["affected"]) in ((R, C) if "final" in why else (R,)), (why, v)
    assert ev("7.4.1", adv["affected"]) == R  # 修正版以上でも、文書の全体が読めなければ判定できない
    # 影響ありと読めた行は該当のまま（final でない文書でも、該当を消して見落とすほうに倒さない）
    assert ev("7.4.0", adv["affected"]) == (A if "final" in why else R)


def test_fortios_named_by_title_or_score_without_rows_is_unreadable():
    v = vuln("FortiOS", [], [])
    rows = ranges(v)
    assert ev("7.4.1", rows) == R
    v2 = vuln("FortiProxy", ["FortiProxy 7.4.0"], [])
    v2["scores"][0]["products"] = ["FortiProxy", "FortiOS"]  # 点の製品に厳密に FortiOS がある
    assert ev("7.4.1", ranges(v2)) == R


def test_fortios_prefix_is_matched_with_its_delimiter():
    """'FortiOS' で始まるかだけで見分けない（FortiOS-6K7K は厳密に一致するときだけ別製品）。FortiOS-数字・FortiOS 空白・
    FortiOS/ は FortiOS。正規化すると fortios を含むほかの文字列も FortiOS（読めない行。黙って無視しない）"""
    assert vf._is_fortios_name("FortiOS 7.4.0") and vf._is_fortios_name("FortiOS-7.4.3") and vf._is_fortios_name("FortiOS/ 7.4 all versions")
    assert vf._is_fortios_name("FortiOS-upcoming  7.2.14") and vf._is_fortios_name("FortiOS")
    assert not vf._is_fortios_name("FortiOS-6K7K 7.0.10") and not vf._is_fortios_name("FortiOS-6K7K-7.0.12")
    assert not vf._is_fortios_name("FortiOS-6K7K") and not vf._is_fortios_name("FortiProxy 7.4.0")
    for t in (" FortiOS 7.4.0", "fortios 7.2.4", "FORTIOS >=7.2.0|<=7.2.4", "FortiOSxxx 7.2.4", "ＦｏｒｔｉＯＳ 7.2.4",
              "Forti\u00a0OS 7.2.4", "\ufeffFortiOS 7.2.4", "FortiOS-6k7k 7.0.10", "FortiOS-6K7Kx 7.0.10", "Forti\u200bOS 7.2.4"):
        assert vf.product_kind(t) == "fortios", t


# ---------------------------------------------------------------- 読めない行（空白・スラッシュ・ハイフンの違い）

UNREADABLE_STRINGS = [
    ("known_affected", "FortiOS 7.4.0 to 7.4.2"),
    ("known_affected", "FortiOS >= 7.4.0|<= 7.4.2"),  # FortiMail の書き方（空白入り）
    ("known_affected", "FortiOS >= 7.4.0 and <= 7.4.2"),
    ("known_affected", "FortiOS >=7.4|<=7.4.2"),  # 3 要素でない
    ("known_affected", "FortiOS 7.4"),
    ("known_affected", "FortiOS 7.4.0.1"),
    ("known_affected", "FortiOS/ 7.4 all versions"),  # 影響なしの書き方が影響ありの欄に
    ("known_affected", "FortiOS-7.4.3"),
    ("known_affected", "FortiOS >=7.2.0|<=7.4.2"),  # 系列をまたぐ
    ("known_affected", "FortiOS >=7.4.5|<=7.4.2"),  # 始まりが終わりより後
    ("known_not_affected", "FortiOS 7.4 all versions"),  # スラッシュなし（影響ありの書き方）
    ("known_not_affected", "FortiOS/7.4 all versions"),  # スラッシュの後に空白なし（product_tree の書き方）
    ("known_not_affected", "FortiOS-7.4 all versions"),
    ("known_not_affected", "FortiOS-7.4"),
    ("known_not_affected", "FortiOS 7.4.3"),
    ("known_not_affected", "FortiOS-upcoming"),
    ("fixed", "FortiOS-7.4.3"),  # 想定していないキー
    ("first_fixed", "FortiOS 7.4.3"),
    ("under_investigation", "FortiOS 7.4.1"),
    ("known_affected", "FortiOS"),
]


@pytest.mark.parametrize("key,text", UNREADABLE_STRINGS)
def test_unreadable_rows_are_never_unaffected_in_their_branch(key, text):
    """読めない行: 系列を読み取れる形（版の数字が 1 つの系列だけ）はその系列だけ、それ以外は全系列を判定できないにする"""
    base = {"known_affected": ["FortiOS >=7.2.0|<=7.2.6"], "known_not_affected": ["FortiOS-7.2.7", "FortiOS/ 8.0 all versions",
                                                                                 "FortiOS/ 7.4 all versions"]}
    base.setdefault(key, []).append(text)
    v = vuln("FortiOS", base.pop("known_affected"), base.pop("known_not_affected"), other_keys=base)
    rows = ranges(v)
    bad = [r for r in rows if r.get("unreadable")]
    assert len(bad) == 1
    scope = bad[0].get("branch")
    assert scope == vf._branch_of_text(text) and scope in (None, "7.4")
    assert ev("7.4.3", rows) == R  # 読めない行の系列（7.4 は影響なしの系列だが、非該当にしない）
    other = U if scope == "7.4" else R  # 別の系列は、系列を読み取れたときだけ読める行で決める
    assert ev("7.2.7", rows) == other and ev("8.0.1", rows) == other
    assert ev("7.2.3", rows) == A  # 該当は該当のまま


def test_upcoming_spacing_is_tolerated_only_because_it_never_clears():
    for t in ("FortiOS-upcoming  7.2.14", "FortiOS-upcoming 7.2.14"):
        rows = ranges(vuln("FortiOS", ["FortiOS >=7.2.0|<=7.2.13"], [t]))
        assert ev("7.2.13", rows) == A and ev("7.2.14", rows) == R and ev("7.2.20", rows) == R


# ---------------------------------------------------------------- 系列の中で決まらない版・食い違い


def test_not_decided_and_conflicts():
    gap = ranges(vuln("FortiOS", ["FortiOS >=7.4.2|<=7.4.4"], ["FortiOS-7.4.5"]))
    assert ev("7.4.1", gap) == C  # 範囲の始まりより前で、修正版より前（本物では範囲は必ず x.y.0 から）
    assert vm.candidate_reason("fortinet", "7.4.1", gap, FG) == vm.CANDIDATE_REASONS["not_decided"]
    nofix = ranges(vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.4"], []))
    assert ev("7.4.4", nofix) == A and ev("7.4.5", nofix) == C  # 範囲の外だが、影響なしの記載が無い
    clash = ranges(vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.5"], ["FortiOS-7.4.3"]))
    assert ev("7.4.4", clash) == R and ev("7.4.2", clash) == A
    assert ev("7.4.6", clash) == C  # 修正版（7.4.3）が影響ありの上限（7.4.5）より前: 修正版を根拠に非該当にしない（M2）
    both = ranges(vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS/ 7.4 all versions"]))
    assert ev("7.4.1", both) == R and ev("7.4.5", both) == R
    assert vm.candidate_reason("fortinet", "7.0.5", ranges(*S_015), FG) == vm.CANDIDATE_REASONS["not_listed"]
    # 勧告に載っているどの系列（最大 7.4）よりも新しい系列は newer_branch（判定は候補のまま）
    assert vm.candidate_reason("fortinet", "7.6.0", ranges(*S_015), FG) == vm.CANDIDATE_REASONS["newer_branch"]
    assert vm.candidate_code("fortinet", "8.0.1", ranges(*S_015), FG)[0] == "newer_branch"
    assert vm.candidate_code("fortinet", "5.6.1", ranges(*S_015), FG)[0] == "not_listed"


def test_multiple_fortios_vulnerabilities_are_judged_separately():
    """CVE ごとの記載は別々に判定する（片方の修正版で、もう片方の影響ありを打ち消さない）"""
    rows = ranges(vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3"], cve="CVE-2099-0011"),
                  vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.4"], ["FortiOS-7.4.5"], cve="CVE-2099-0012"))
    assert ev("7.4.3", rows) == A and ev("7.4.5", rows) == U
    rows2 = ranges(vuln("FortiOS", ["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3"], cve="CVE-2099-0011"),
                   vuln("FortiOS", ["FortiOS >=7.6.0|<=7.6.1"], ["FortiOS-7.6.2"], cve="CVE-2099-0012"))
    assert ev("7.4.3", rows2) == C  # 2 つ目の記載に 7.4 が無い（載っていない系列）


# ---------------------------------------------------------------- 機器のモデル・版の書き方


@pytest.mark.parametrize("model,kind", [
    ("FortiGate-60F", "std"), ("FortiGate-600F", "std"), ("FortiGate-1000D", "std"), ("FortiGate-VM64-KVM", "std"),
    ("FortiWiFi-60E", "std"), ("FortiGateRugged-60F", "std"),
    ("FortiGate-7121F", "6k7k"), ("FortiGate-6500F", "6k7k"), ("FortiGate-7040E", "6k7k"), ("FortiGate-6300F", "6k7k"),
    ("", None), (None, None), ("FGT60F", None), ("PA-440", None), (5, None),
])
def test_model_kind(model, kind):
    assert vm.fortios_model_kind(model) == kind


def test_model_6k7k_and_unknown_model():
    rows = ranges(*S_015)
    for v, want in (("7.4.2", A), ("7.4.3", U), ("7.6.0", C)):
        assert ev(v, rows, "FortiGate-7121F") == R  # 6000 / 7000 系は別系統（判定できない）
        assert ev(v, rows, "") == {A: C, U: R}.get(want, want)  # モデルを判別できない: 該当は候補・非該当は判定できない
        assert ev(v, rows, "FortiGate-VM64") == want
    assert vm.candidate_reason("fortinet", "7.4.2", rows, None) == vm.CANDIDATE_REASONS["model_unknown"]
    assert vm.unknown_reason("fortinet", "7.4.2 build2000", "FortiGate-7121F", vuln=True) == "fortios_6k7k"
    assert vm.unknown_reason("fortinet", "7.4.2 build2000", "FortiGate-7121F") is None  # サポート終了日には使う
    assert vm.judgeable("fortinet", "7.4.2", "FortiGate-7121F") is None
    assert vm.judgeable("fortinet", "7.4.2", "FortiGate-60F").key == (7, 4, 2)


@pytest.mark.parametrize("text,key", [
    ("7.4.3 build2573", (7, 4, 3)), ("v7.4.3,build2573,240201 (GA.F)", (7, 4, 3)), ("v7.4.3,build2573", (7, 4, 3)),
    ("7.4.3", (7, 4, 3)), ("v7.2.5,build1517,230606 (GA.M)", (7, 2, 5)),
])
def test_device_version_strings(text, key):
    assert vm.parse_version("fortinet", text).key == key


@pytest.mark.parametrize("text", ["7.4", "7.4.3 (Interim)", "7.4.3 build", "4.0 build0678", "v7.4.3,build2573,24 (GA.F)", "7.4.3-beta"])
def test_device_version_unreadable(text):
    assert vm.parse_version("fortinet", text) is None


def test_source_mismatch_is_unreadable():
    p = vm.parse_version("fortinet", "7.4.1")
    assert vm.judge_source("paloalto", p, ranges(*S_015))[0] == R
    assert vm.judge_source("nvd", p, ranges(*S_015))[0] == R
    assert vm.judge_fortios(vm.parse_version("paloalto_panos", "10.2.3"), ranges(*S_015))[0] == R


# ---------------------------------------------------------------- 性質（PAN-OS と同じ流儀）

BRANCHES = ["6.4", "7.0", "7.2", "7.4", "7.6", "8.0"]


def _rand_branch_rows(rng: random.Random, b: str) -> tuple[list[str], list[str]]:
    """系列 b の行（本物の形のどれか）。(known_affected, known_not_affected)"""
    k = rng.randint(1, 12)
    kind = rng.choice(["range_fix", "range_fix", "all", "clear", "single", "upcoming", "range_only"])
    if kind == "range_fix":
        return [f"FortiOS >={b}.0|<={b}.{k}"], [f"FortiOS-{b}.{k + 1}"]
    if kind == "all":
        return [f"FortiOS {b} all versions"], []
    if kind == "clear":
        return [], [f"FortiOS/ {b} all versions"]
    if kind == "single":
        return [f"FortiOS {b}.{k}"], [f"FortiOS-{b}.{k + 1}"]
    if kind == "upcoming":
        return [f"FortiOS >={b}.0|<={b}.{k}"], [f"FortiOS-upcoming  {b}.{k + 1}"]
    return [f"FortiOS >={b}.0|<={b}.{k}"], []


def _rand_vuln(rng: random.Random, n_branches: int | None = None) -> tuple[list[str], list[str]]:
    aff: list[str] = []
    na: list[str] = []
    for b in rng.sample(BRANCHES, n_branches or rng.randint(1, 4)):
        a, n = _rand_branch_rows(rng, b)
        aff += a
        na += n
    return aff, na


def _grid() -> list[str]:
    return [f"{b}.{z}" for b in BRANCHES for z in range(0, 16)] + ["5.6.3", "9.0.0"]


def _states_unaffected(key: str, text: str, version: str) -> bool:
    """足した行が、この版について「影響なし」と明記する読める行か（影響なしの all versions か、この版以下の修正版）"""
    row = vf.fortios_row(key, text, 0)
    p = vm.parse_version("fortinet", version)
    if row.get("unreadable") or row.get("status") != "unaffected" or row.get("branch") != p.branch:
        return False
    return row.get("all") is True or (row.get("fix") is not None and vm.compare(p, vm.parse_version("fortinet", row["fix"])) >= 0)


@pytest.mark.parametrize("seed", range(40))
def test_adding_unreadable_row_never_moves_to_unaffected(seed):
    """読めない行を足しても、該当 → 非該当・判定できない → 非該当・候補 → 非該当 には決して変わらない"""
    rng = random.Random(7000 + seed)
    for _ in range(20):
        vulns = [_rand_vuln(rng) for _ in range(rng.randint(1, 2))]
        base = ranges(*[vuln("FortiOS", a, n, cve=f"CVE-2099-{i:04d}") for i, (a, n) in enumerate(vulns)])
        key, text = rng.choice(UNREADABLE_STRINGS)
        i = rng.randrange(len(vulns))
        more = []
        for j, (a, n) in enumerate(vulns):
            other = {}
            if j == i:
                if key == "known_affected":
                    a = [*a, text]
                elif key == "known_not_affected":
                    n = [*n, text]
                else:
                    other = {key: [text]}
            more.append(vuln("FortiOS", a, n, cve=f"CVE-2099-{j:04d}", other_keys=other))
        added = ranges(*more)
        for v in _grid():
            before, after = ev(v, base), ev(v, added)
            if before != U:
                assert after != U, (v, before, after, more)


@pytest.mark.parametrize("seed", range(40))
def test_adding_readable_row_moves_to_unaffected_only_when_row_says_so(seed):
    rng = random.Random(8000 + seed)
    for _ in range(20):
        aff, na = _rand_vuln(rng)
        base = ranges(vuln("FortiOS", aff, na))
        b = rng.choice(BRANCHES)
        add_a, add_n = _rand_branch_rows(rng, b)
        k = rng.randint(0, 14)
        extra = rng.choice([("known_affected", x) for x in add_a] + [("known_not_affected", x) for x in add_n]
                           + [("known_not_affected", f"FortiOS-{b}.{k}"), ("known_not_affected", f"FortiOS/ {b} all versions"),
                              ("known_affected", f"FortiOS {b}.{k}")])
        aff2 = [*aff, extra[1]] if extra[0] == "known_affected" else aff
        na2 = [*na, extra[1]] if extra[0] == "known_not_affected" else na
        added = ranges(vuln("FortiOS", aff2, na2))
        for v in _grid():
            before, after = ev(v, base), ev(v, added)
            if before != U and after == U:
                assert _states_unaffected(extra[0], extra[1], v), (v, before, extra, aff, na)


@pytest.mark.parametrize("seed", range(30))
def test_unlisted_branch_is_never_unaffected(seed):
    """勧告に載っていない系列の版は、決して非該当にならない（FG-IR-26-193 のように、CSAF に無い系列がありうる）"""
    rng = random.Random(9100 + seed)
    for _ in range(20):
        aff, na = _rand_vuln(rng)
        rows = ranges(vuln("FortiOS", aff, na))
        listed = {r["branch"] for r in rows if r.get("branch")}
        for v in _grid():
            if ".".join(v.split(".")[:2]) not in listed:
                assert ev(v, rows) == C, (v, aff, na)


@pytest.mark.parametrize("seed", range(20))
def test_row_order_does_not_matter(seed):
    rng = random.Random(9300 + seed)
    for _ in range(10):
        aff, na = _rand_vuln(rng)
        want = [ev(v, ranges(vuln("FortiOS", aff, na))) for v in _grid()]
        a2, n2 = list(aff), list(na)
        rng.shuffle(a2)
        rng.shuffle(n2)
        assert [ev(v, ranges(vuln("FortiOS", a2, n2))) for v in _grid()] == want


_JUNK = [None, "", "x", "7.4", "7.4.0", "*", True, 1, 1.5, [], {}, ["7.4.1"], "\x00", "1" * 300, "affected", "unaffected"]


@pytest.mark.parametrize("seed", range(30))
def test_judge_never_raises_on_junk(seed):
    rng = random.Random(9500 + seed)
    keys = ["fmt", "v", "kind", "status", "branch", "ge", "le", "eq", "all", "fix", "upcoming", "unreadable"]
    for _ in range(200):
        items = []
        for _ in range(rng.randint(0, 5)):
            if rng.random() < 0.1:
                items.append(rng.choice(_JUNK))
                continue
            it = {k: rng.choice([*_JUNK, "fortios", 0, "7.4", "vuln"]) for k in rng.sample(keys, rng.randint(1, 7))}
            items.append(it)
        p = vm.parse_version("fortinet", rng.choice(["7.4.1", "7.4.0", "8.0.0"]))
        for target in (items, rng.choice(_JUNK)):
            r = vm.judge_fortios(p, target, rng.choice([None, FG, "FortiGate-7121F", 5]))
            assert r[0] in (A, U, C, R)
        # 文書の形が壊れていても、解析は FetchError か勧告を返す（ほかの例外を出さない）
        doc = csaf(*[rng.choice([{k: rng.choice(_JUNK) for k in ("cve", "title", "product_status", "scores")},
                                 vuln("FortiOS", [rng.choice(["FortiOS 7.4.1", *map(str, _JUNK)])], [])]) for _ in range(2)])
        try:
            adv = vf.parse_fortinet_csaf(doc)
        except vf.FetchError:
            continue
        assert ev("7.4.1", adv["affected"]) in (A, U, C, R)


# ================================================================ レビュー（J-2）の指摘の再現（作り物の ID。形は本物）


@pytest.mark.parametrize("model,kind", [
    ("FortiGate-6500F-DC", "6k7k"), ("FortiGate-7121F-2", "6k7k"), ("FortiGate-7060E-8", "6k7k"), ("fortigate-6501f", "6k7k"),
    ("FortiGate6500F", "6k7k"), ("FG-6500F", "6k7k"), ("FGT6500F", "6k7k"), ("FGT-7121F", "6k7k"), ("FG7060E", "6k7k"),
    ("FortiGate-7000", "6k7k"), ("FortiGate-6000F", "6k7k"),
    ("FortiGate-600F", "std"), ("FortiGate-60F-DC", "std"), ("FortiGate-70F", "std"), ("FortiGate-6500", "6k7k"),
    ("FortiGate-65001F", "6k7k"), ("FGT60F", None), ("FG-60F", None),  # 6xxx・7xxx で始まれば後ろは問わない
])
def test_6k7k_models_with_suffixes(model, kind):
    """H1: 6000 / 7000 系は、後ろに何が付いても（-DC・-2・-8 など）・短い表記でも 6K7K（FortiOS の行で判定しない）"""
    assert vm.fortios_model_kind(model) == kind
    if kind == "6k7k":
        assert vm.unknown_reason("fortinet", "7.0.6", model, vuln=True) == "fortios_6k7k"
        assert ev("7.0.6", ranges(*S_398), model) == R


IGNORED = ["fortios 7.2.4", "FORTIOS 7.2.4", "FortiOSxxx 7.2.4", "ＦｏｒｔｉＯＳ 7.2.4", "Forti\u00a0OS 7.2.4", "FortiOS\u00a07.2.4",
           "\ufeffFortiOS 7.2.4", " FortiOS 7.2.4", "FortiOS 7.2.4 ", "Forti\u200bOS 7.2.4", "FortiOS 7.２.4", "FortiOS 7.2.4\n"]


@pytest.mark.parametrize("text", IGNORED)
@pytest.mark.parametrize("key", ["known_affected", "known_not_affected"])
def test_fortios_like_strings_are_not_silently_ignored(text, key):
    """M1: FortiOS と読めない「fortios を含む」文字列は、読めない行（その脆弱性の判定を決められない側に倒す）"""
    aff, na = ["FortiOS >=7.2.0|<=7.2.3"], ["FortiOS-7.2.4"]
    (aff if key == "known_affected" else na).append(text)
    rows = ranges(vuln("FortiOS", aff, na, score=7.5))
    assert any(r.get("unreadable") for r in rows), text
    assert ev("7.2.4", rows) == R and ev("7.2.9", rows) == R  # 修正版以上でも非該当にしない
    assert ev("7.2.3", rows) == A


def test_fortios_like_strings_alone_make_a_fortios_vulnerability():
    rows = ranges({"cve": "CVE-2099-0001", "title": "Example - HIGH - FG-IR-99-001",
                   "product_status": {"known_not_affected": ["fortios-7.2.4"]}})
    assert ev("7.2.4", rows) == R


@pytest.mark.parametrize("aff,na,version,expected", [
    # M2 の再現 1: 修正版が 2 つ。最大（7.4.8）より前は非該当にしない
    (["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3", "FortiOS-7.4.8"], "7.4.6", C),
    (["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3", "FortiOS-7.4.8"], "7.4.8", U),
    (["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3", "FortiOS-7.4.8"], "7.4.2", A),
    # M2 の再現 2: 修正版の後に影響ありの範囲がある。修正版ちょうど・範囲の後とも非該当にしない
    (["FortiOS >=7.4.4|<=7.4.6"], ["FortiOS-7.4.3"], "7.4.7", C),
    (["FortiOS >=7.4.4|<=7.4.6"], ["FortiOS-7.4.3"], "7.4.3", C),
    (["FortiOS >=7.4.4|<=7.4.6"], ["FortiOS-7.4.3"], "7.4.5", R),  # 修正版以上で影響あり: 食い違い
    (["FortiOS 7.4.5"], ["FortiOS-7.4.3"], "7.4.6", C),
    (["FortiOS >=7.2.0|<=7.2.2"], ["FortiOS-7.2.2"], "7.2.3", C),  # 修正版が上限と同じ（上限より後でない）
    # ふつうの形は今までどおり
    (["FortiOS >=7.4.0|<=7.4.2"], ["FortiOS-7.4.3"], "7.4.3", U),
    (["FortiOS 7.6.0"], ["FortiOS-7.6.1"], "7.6.1", U),
])
def test_fix_must_be_the_last_one_and_after_all_affected_rows(aff, na, version, expected):
    assert ev(version, ranges(vuln("FortiOS", aff, na))) == expected


def test_affected_rows_with_a_note_are_read_in_known_affected_only():
    """L2・N2: 本物の FG-IR-23-001 の形。影響ありの欄の「読める形＋末尾の括弧の注記」は、その行に入る版を「候補」（理由 note）
    にする（注記が限定のことがあるため、該当にはしない）。ほかの系列は読める行で決める"""
    note = " (special note for fortios in additional note section)"
    rows = ranges(vuln("FortiOS", ["FortiOS >=7.2.0|<=7.2.3", "FortiOS 6.0 all versions" + note, "FortiOS 5.6 all versions" + note],
                       ["FortiOS-7.2.4"]))
    assert ev("6.0.10", rows) == C and ev("5.6.3", rows) == C and ev("7.2.1", rows) == A and ev("7.2.4", rows) == U
    assert vm.candidate_code("fortinet", "6.0.10", rows, FG)[0] == "note"
    assert vm.candidate_reason("fortinet", "6.0.10", rows, FG) == (
        "勧告に注記があります（special note for fortios in additional note section）。勧告のページで確かめてください")
    noted = [r for r in rows if r.get("note")]
    assert len(noted) == 2 and "special note" in noted[0]["raw"]
    # 影響なしの欄の注記つきは読めない行のまま（その系列だけ判定できない。ほかの系列は読める行で決める）
    rows = ranges(vuln("FortiOS", ["FortiOS >=7.2.0|<=7.2.3"], ["FortiOS-7.2.4", "FortiOS/ 6.4 all versions" + note]))
    assert ev("6.4.1", rows) == R and ev("7.2.4", rows) == U and ev("7.2.3", rows) == A
    # 注記の中身が読める形でも、括弧の外が読めなければ読めない
    rows = ranges(vuln("FortiOS", ["FortiOS 6.0 everything" + note], ["FortiOS-7.2.4"]))
    assert ev("6.0.1", rows) == R and ev("7.2.4", rows) == R  # 許可した骨格でない読めない行は全系列（N1）


@pytest.mark.parametrize("title,score,expected", [
    ("FortiOS - CRITICAL - FG-IR-99-001", 7.5, "critical"),  # 題の区分が高い: 題を採る（L1）
    ("FortiOS - HIGH - FG-IR-99-001", 9.6, "critical"),  # 点の区分が高い: 点を採る
    ("FortiOS - MEDIUM - FG-IR-99-001", 5.0, "medium"),
    ("FortiOS-6K7K - CRITICAL - FG-IR-99-001", 5.0, "medium"),  # 別製品の題の接頭辞は使わない
    ("FortiOS - Critical - FG-IR-99-001", 5.0, "medium"),  # 形の違う接頭辞は使わない
])
def test_severity_uses_title_prefix_and_score(title, score, expected):
    v = vuln("FortiOS", ["FortiOS 7.4.0"], ["FortiOS-7.4.1"], score=score)
    v["title"] = title
    adv = vf.parse_fortinet_csaf(csaf(v))
    assert adv["severity"] == expected and adv["cvss"] == score


@pytest.mark.parametrize("text", ["FG-IR-24-015\n", "FG-IR-２４-015", "FG-IR-24-01５", " FG-IR-24-015"])
def test_ids_and_versions_are_ascii_and_whole(text):
    assert not vf.valid_fortinet_id(text)
    assert vm.parse_version("fortinet", "7.４.3") is None and vm.parse_version("paloalto_panos", "10.2.３") is None


def test_provisional_document_is_marked():
    adv = vf.parse_fortinet_csaf(csaf(vuln("FortiOS", ["FortiOS 7.4.0"], ["FortiOS-7.4.1"]), status="interim"))
    assert any(r.get("provisional") for r in adv["affected"])
    assert ev("7.4.0", adv["affected"]) == A


PAGE = (b'<html><body><a href="/psirt/csaf/FG-IR-99-535?csaf_url=https://filestore.fortinet.com/fortiguard/psirt/'
        b'csaf_example-auth-bypass_fg-ir-99-535.json">CSAF</a></body></html>')


@pytest.mark.parametrize("body,ok", [
    (PAGE, True),
    (PAGE.replace(b"csaf_url=https://", b"csaf_url=https%3A%2F%2F").replace(b"psirt/csaf_e", b"psirt%2Fcsaf_e"), True),
    (PAGE + PAGE, True),  # 同じ URL が 2 回は 1 つに決まる
    (PAGE + PAGE.replace(b"example-auth", b"other-auth"), False),  # 違う URL が 2 つ: 決められない
    (PAGE.replace(b"filestore.fortinet.com", b"evil.example.test"), False),
    (PAGE.replace(b"fg-ir-99-535", b"fg-ir-99-536"), False),  # パスの ID が違う
    (PAGE.replace(b"https://", b"http://"), False),
    (b"<html>no link</html>", False),
    (b"x" * (vf.FORTINET_PAGE_MAX_BYTES + 1), False),
])
def test_csaf_url_from_page(body, ok):
    """M3: 題名から作った URL が 404 のとき、勧告のページの csaf_url= を検査してから使う（HTML は解析しない）"""
    got = vf.csaf_url_from_page(body, "FG-IR-99-535")
    assert (got == "https://filestore.fortinet.com/fortiguard/psirt/csaf_example-auth-bypass_fg-ir-99-535.json") is ok


# ================================================================ 2 回目のレビュー（N1・N2・L-a）


@pytest.mark.parametrize("aff,na,version", [
    (["FortiOS 7.4 and later"], ["FortiOS-7.6.1"], "7.6.2"),
    (["FortiOS >=7.4.0"], ["FortiOS/ 7.6 all versions"], "7.6.2"),
    (["FortiOS 7.4.0+"], ["FortiOS-7.6.2"], "7.6.3"),
    (["FortiOS <=7.4.3"], ["FortiOS-7.2.5"], "7.2.6"),
    (["FortiOS 7.4.3 and earlier"], ["FortiOS-7.2.5"], "7.2.6"),
    (["FortiOS 7.4.0 through 7.6.2"], ["FortiOS-7.6.3"], "7.6.3"),
    (["FortiOS 7.4 all versions and above"], ["FortiOS-7.6.3"], "7.6.3"),
    (["FortiOS >7.4.3"], ["FortiOS-7.6.3"], "7.6.3"),
    (["FortiOS 7.4.x"], ["FortiOS-7.6.3"], "7.6.3"),
])
def test_one_sided_or_worded_unreadable_rows_block_every_branch(aff, na, version):
    """N1: 片側だけ・語つき・形の違う読めない行は、ほかの系列にまたがりうるので全系列を判定できない（非該当にしない）"""
    rows = ranges(vuln("FortiOS", aff, na))
    assert [r.get("branch") for r in rows if r.get("unreadable")] == [None]
    assert ev(version, rows) == R


@pytest.mark.parametrize("key,text,scope", [
    ("known_not_affected", "FortiOS 7.4.3", "7.4"),  # 欄が違う（骨格は読める形）
    ("known_affected", "FortiOS-7.4.3", "7.4"),
    ("known_affected", "FortiOS/ 7.4 all versions", "7.4"),
    ("known_not_affected", "FortiOS 7.4 all versions", "7.4"),
    ("known_affected", "FortiOS >=7.4.5|<=7.4.2", "7.4"),  # 向きが逆でも、両端がそろって同じ系列
    ("known_not_affected", "FortiOS/ 7.4 all versions (note)", "7.4"),  # 影響なしの欄の注記つき
    ("fixed", "FortiOS-7.4.3", "7.4"),
    ("known_affected", "FortiOS >=7.2.0|<=7.4.2", None),  # 系列をまたぐ
    ("known_affected", "FortiOS >=7.4.0", None),
    ("known_affected", "FortiOS 7.4", None),
    ("known_affected", "FortiOS 7.4.0.1", None),
    ("known_affected", "FortiOS 7.4.0 to 7.4.2", None),
    ("known_affected", "fortios 7.4.3", None),
])
def test_branch_scope_only_for_allowed_skeletons(key, text, scope):
    assert vf.fortios_row(key, text, 0).get("branch") == scope


@pytest.mark.parametrize("aff,version,expected", [
    (["FortiOS 7.0 all versions (except 7.0.5)"], "7.0.5", C),
    (["FortiOS 7.0 all versions (except 7.0.5)"], "7.0.9", C),
    (["FortiOS >=7.0.0|<=7.0.5 (FortiGate-60F only)"], "7.0.3", C),
    (["FortiOS >=7.0.0|<=7.0.5 (FortiGate-60F only)", "FortiOS 7.0.2"], "7.0.2", A),  # 注記なしの行が含む: 該当
    (["FortiOS >=7.0.0|<=7.0.5 (FortiGate-60F only)"], "7.0.6", U),  # 修正版 7.0.6 ≧ 上限 7.0.5 の後: ほかの読める行で決まる
    (["FortiOS 7.2.3 (when SSL-VPN is enabled)"], "7.2.3", C),
])
def test_noted_affected_rows_are_candidates(aff, version, expected):
    """N2: 注記つきの影響ありの行に入る版は「候補」（note）。注記つきの行は非該当の根拠にも使わない"""
    rows = ranges(vuln("FortiOS", aff, ["FortiOS-7.0.6", "FortiOS-7.2.4"]))
    assert ev(version, rows) == expected
    assert ev(version, rows, "FortiWiFi-60E") == expected  # モデルの注記も機器のモデルでは判断しない


def test_noted_rows_never_clear_their_versions():
    rows = ranges(vuln("FortiOS", ["FortiOS 7.0 all versions (except 7.0.5)"], ["FortiOS/ 7.0 all versions"]))
    assert ev("7.0.5", rows) == C  # 注記つきの影響ありと影響なしが重なる: 非該当にしない


ONE_SIDED = ["FortiOS >={o}", "FortiOS <={o}", "FortiOS <{o}", "FortiOS >{o}", "FortiOS {o}+", "FortiOS {ob} and later",
             "FortiOS {o} and earlier", "FortiOS {o} and above", "FortiOS {o} or below", "FortiOS prior to {o}",
             "FortiOS {o} through {x}", "FortiOS >={x}|<={o}", "FortiOS {ob}.x", "FortiOS since {o}", "FortiOS {o} to {x}"]


@pytest.mark.parametrize("seed", range(40))
def test_cross_branch_unreadable_rows_never_move_to_unaffected(seed):
    """読めない行（機器と別の系列の数字・片側だけの範囲・語つき）を足しても、どの系列の該当・候補・判定できないも
    非該当に変わらない"""
    rng = random.Random(12000 + seed)
    for _ in range(20):
        vulns = [_rand_vuln(rng) for _ in range(rng.randint(1, 2))]
        base = ranges(*[vuln("FortiOS", a, n, cve=f"CVE-2099-{i:04d}") for i, (a, n) in enumerate(vulns)])
        ob = rng.choice(BRANCHES)
        xb = rng.choice(BRANCHES)
        text = rng.choice(ONE_SIDED).format(o=f"{ob}.{rng.randint(0, 9)}", ob=ob, x=f"{xb}.{rng.randint(0, 9)}")
        key = rng.choice(["known_affected", "known_not_affected", "fixed", "under_investigation"])
        i = rng.randrange(len(vulns))
        more = []
        for j, (a, n) in enumerate(vulns):
            other = {}
            if j == i:
                if key == "known_affected":
                    a = [*a, text]
                elif key == "known_not_affected":
                    n = [*n, text]
                else:
                    other = {key: [text]}
            more.append(vuln("FortiOS", a, n, cve=f"CVE-2099-{j:04d}", other_keys=other))
        added = ranges(*more)
        for v in _grid():
            before, after = ev(v, base), ev(v, added)
            if before != U:
                assert after != U, (v, before, after, text, key)
            assert after != U or before == U


@pytest.mark.parametrize("where", ["full_product_names", "relationships", "notes", "title", "branches"])
def test_notice_only_when_fortios_is_nowhere_in_the_document(where):
    """L-a: vulnerabilities が無くても、文書のどこか（正規化して）に FortiOS が出てくれば告知にしない（範囲を読み取れない）"""
    doc = csaf(drop_vulns=True)
    if where == "full_product_names":
        doc["product_tree"]["full_product_names"] = [{"name": "ＦｏｒｔｉＯＳ 7.4.1", "product_id": "x"}]
    elif where == "relationships":
        doc["product_tree"]["relationships"] = [{"category": "default_component_of", "full_product_name": {"name": "fortios"}}]
    elif where == "notes":
        doc["document"]["notes"] = [{"category": "summary", "text": "Affects FORTIOS and others"}]
    elif where == "title":
        doc["document"]["title"] = "Forti\u200bOS issue"
    else:
        doc["product_tree"]["branches"][0]["branches"] = [{"category": "product_name", "name": "FortiOSx"}]
    adv = vf.parse_fortinet_csaf(doc)
    assert not adv.get("notice") and adv["products"] == ["fortinet"]
    assert ev("7.4.1", adv["affected"]) == R
