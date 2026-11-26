"""ファームウェアのバージョンの正規化と、脆弱性の影響範囲との照合（純粋な関数。DB・通信は使わない）

目的: 機器台帳の OS バージョン（Device.os_version）を、機種ごとの書き方に沿って分解して、順序を比べられる形にする。
- 分解できないバージョン（想定外の書き方）は None（＝「判定できない」）。誤って該当・非該当にしない
- 影響範囲（ベンダーの勧告）は、同じリリース系列（10.2 など）の中だけで比べる。系列が勧告に載っていなければ該当にしない
  （勧告が「すべてのバージョン」と明記している場合を除く。defaultStatus が affected の勧告では「候補」にする）
- 比べられるのは同じ体系（scheme）どうしだけ。体系が違えば ValueError

体系（scheme）と書き方の例
  panos  : PAN-OS        10.2.14-h2 → (10, 2, 14, 2)   -h は hotfix。ホットフィックスなしは 0
  fortios: FortiOS       7.2.5 build1517 → (7, 2, 5)   build は比べない
  iosxe  : Cisco IOS XE  17.9.4a → (17, 9, 4, 1)       末尾の a・b…は再ビルド。"17.06.05" の 0 埋めも読む
  ios    : Cisco IOS     15.2(7)E7 → (15, 2, 7, "", "E", 7, "")
  nxos   : NX-OS         9.3(10) / 10.2(3)F / 7.0(3)I7(9)
  asa    : Cisco ASA     9.16(4) / 9.18(3)56
  junos  : Junos         21.4R3-S5.4
  eos    : Arista EOS    4.28.3M
上記以外の機種（AlliedWare Plus・Yamaha など）は対象外（体系なし）
"""
import re
from dataclasses import dataclass

# このアプリの platform → 体系。cisco_ios・cisco_xe は、バージョンの書き方で ios / iosxe を見分ける
PLATFORM_SCHEMES: dict[str, tuple[str, ...]] = {
    "paloalto_panos": ("panos",),
    "fortinet": ("fortios",),
    "cisco_ios": ("iosxe", "ios"),
    "cisco_xe": ("iosxe", "ios"),
    "cisco_nxos": ("nxos",),
    "cisco_asa": ("asa",),
    "juniper_junos": ("junos",),
    "arista_eos": ("eos",),
}

# endoflife.date などの「サポート終了日」の表で使う platform（体系 → platform）
EOL_PLATFORM = {"panos": "paloalto_panos", "fortios": "fortinet", "iosxe": "cisco_xe"}

# 脆弱性を、ベンダーの勧告の影響範囲で判定できる platform（confidence=confirmed）。PAN-OS（J-1）と FortiOS（J-2）
CONFIRMED_PLATFORMS = frozenset({"paloalto_panos", "fortinet"})
# 勧告の情報源 → その勧告で判定する platform
SOURCE_PLATFORM = {"paloalto": "paloalto_panos", "fortinet": "fortinet"}

MAX_VERSION_LENGTH = 128


@dataclass(frozen=True)
class Parsed:
    scheme: str
    key: tuple  # 同じ体系どうしで大小を比べられる
    branch: str  # リリース系列（例 "10.2"）。サポート終了日の照合・影響範囲の系列の照合に使う
    raw: str


def _i(s: str | None) -> int:
    return int(s) if s else 0


def _letter(s: str | None) -> int:
    """a → 1, b → 2 … なし → 0"""
    return ord(s.lower()) - 96 if s else 0


_PANOS = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\Z", re.I | re.A)
# FortiOS: "7.2.5 build1517"（台帳の読み取りの形）・"v7.2.5,build1517,230606 (GA.F)"（get system status の形）。
# build・日付・(GA.F) は比べない。"(Interim)"・"(Beta)" などの GA でない版は読まない（判定できない）
_FORTIOS = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[ ,]+build\s*(\d+)(?:,\d{6})?)?(?:\s*\(GA(?:\.[A-Z])?\))?\Z", re.I | re.A)
_IOSXE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([a-z])?\Z", re.I | re.A)
_IOS = re.compile(r"^(\d+)\.(\d+)\((\d+)([a-z]?)\)([A-Za-z]*)(\d*)([a-z]?)\Z", re.A)
_NXOS = re.compile(r"^(\d+)\.(\d+)\((\d+)([a-z]?)\)([A-Za-z]*)(\d*)(?:\((\d+)([a-z]?)\))?\Z", re.A)
_ASA = re.compile(r"^(\d+)\.(\d+)\((\d+)(?:\.(\d+))?\)(\d*)\Z", re.A)
_JUNOS = re.compile(r"^(\d+)\.(\d+)([RFXBIS])(\d+)(?:-S(\d+))?(?:\.(\d+))?\Z", re.A)
_EOS = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z]*)\Z", re.A)

_JUNOS_RELEASE = {"I": 0, "B": 1, "X": 2, "F": 3, "S": 4, "R": 5}  # 同じ系列での並び（目安。通常は R だけ）


def parse_scheme(scheme: str, text: str | None) -> Parsed | None:
    """体系を指定して分解する。分解できなければ None"""
    if not text:
        return None
    t = text.strip()
    if not t or len(t) > MAX_VERSION_LENGTH or re.search(r"[\x00-\x1f\x7f]", t):
        return None
    if scheme == "panos" and (m := _PANOS.match(t)):
        a, b, c, h = int(m[1]), int(m[2]), int(m[3]), _i(m[4])
        return Parsed("panos", (a, b, c, h), f"{a}.{b}", t)
    if scheme == "fortios" and (m := _FORTIOS.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("fortios", (a, b, c), f"{a}.{b}", t)
    if scheme == "iosxe" and (m := _IOSXE.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("iosxe", (a, b, c, _letter(m[4])), f"{a}.{b}", t)
    if scheme == "ios" and (m := _IOS.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("ios", (a, b, c, m[4].lower(), m[5].upper(), _i(m[6]), m[7].lower()), f"{a}.{b}", t)
    if scheme == "nxos" and (m := _NXOS.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("nxos", (a, b, c, m[4].lower(), m[5].upper(), _i(m[6]), _i(m[7]), m[8] or ""), f"{a}.{b}", t)
    if scheme == "asa" and (m := _ASA.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("asa", (a, b, c, _i(m[4]), _i(m[5])), f"{a}.{b}", t)
    if scheme == "junos" and (m := _JUNOS.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[4])
        return Parsed("junos", (a, b, _JUNOS_RELEASE[m[3]], c, _i(m[5]), _i(m[6])), f"{a}.{b}", t)
    if scheme == "eos" and (m := _EOS.match(t)):
        a, b, c = int(m[1]), int(m[2]), int(m[3])
        return Parsed("eos", (a, b, c, _i(m[4]), m[5].upper()), f"{a}.{b}", t)
    return None


def supported_platform(platform: str) -> bool:
    return platform in PLATFORM_SCHEMES


def parse_version(platform: str, text: str | None) -> Parsed | None:
    """機器の platform に応じて分解する。対象外の機種・分解できない書き方は None"""
    for scheme in PLATFORM_SCHEMES.get(platform, ()):
        p = parse_scheme(scheme, text)
        if p is not None:
            return p
    return None


def unknown_reason(platform: str, os_version: str | None, model: str | None = None, *, vuln: bool = False) -> str | None:
    """「判定できない」理由（判定できるなら None）。no_version / unsupported / unparseable / fortios_6k7k

    vuln=True（脆弱性の照合）のときだけ、モデルも見る: FortiGate 6000 / 7000 系は別系統の FortiOS（勧告では
    FortiOS-6K7K という別の製品）なので、FortiOS の勧告では判定しない（fortios_6k7k）。サポート終了日には使わない
    """
    if not supported_platform(platform):
        return "unsupported"
    if not (os_version or "").strip():
        return "no_version"
    if parse_version(platform, os_version) is None:
        return "unparseable"
    if vuln and platform == "fortinet" and fortios_model_kind(model) == "6k7k":
        return "fortios_6k7k"
    return None


def judgeable(platform: str, os_version: str | None, model: str | None) -> Parsed | None:
    """脆弱性の照合に使える分解済みの版（照合できない機器は None）。対象の platform・読める版・6K7K でない"""
    if platform not in CONFIRMED_PLATFORMS or unknown_reason(platform, os_version, model, vuln=True):
        return None
    return parse_version(platform, os_version)


def compare(a: Parsed, b: Parsed) -> int:
    if a.scheme != b.scheme:
        raise ValueError("体系の違うバージョンは比べられません")
    return (a.key > b.key) - (a.key < b.key)


def eol_platform(p: Parsed) -> str | None:
    """サポート終了日の表で使う platform（表に無い体系は None）"""
    return EOL_PLATFORM.get(p.scheme)


# ---------------------------------------------------------------- 影響範囲との照合
#
# 影響範囲（勧告の 1 行ずつ）は、取得のときに services/vuln_fetch.py の ranges_from_versions が次の形に直して保存する。
# どの形にも、元の値（version・lessThan・lessThanOrEqual・changes・status・versionType・defaultStatus・platforms・product）を
# "src" に残す（判定の理由をあとから追えるように）。"raw" は画面・記録用の短い説明。
#   {"status": "affected", "branch": "10.2", "ge": "10.2.0", "fixes": ["10.2.7-h40", …, "10.2.18-h14"]}
#        ge 以上で、修正点（changes の at と lessThan。昇順）の手前。判定は _span を参照
#   {"status": "affected", "branch": "10.2", "ge": "10.2.0", "open": true}
#        上限も修正点も無い行（＝その系列の ge 以上すべて。修正版が無い。lessThan が "*" や "10.2.*" も同じ）
#   {"status": "affected", "branch": "10.2", "ge": "10.2.0", "le": "10.2.4"}   lessThanOrEqual（ge 以上 le 以下）
#   {"status": "unaffected", "branch": "11.1", "ge": "11.1.0", "open": true}   その系列の ge 以上は影響なし
#   {"status": "affected" | "unaffected", "all": true, "branch": null | "11.1"}
#        すべての版（"PAN-OS 11.1" のような系列つきの製品なら、その系列すべて）
#   {"unreadable": true, "branch": "10.2" | null}   読み取れなかった行（branch が無ければ全系列に影響しうる）
#   {"status": …, "none": true, "branch": "9.1"}   古い形の "9.1 None"（この列に当てはまる版が無い。判定に使わない）
#   {"kind": "default", "default": "affected" | "unknown"}  製品の defaultStatus（記載のない系列の扱い）
#   "platforms": ["Panorama"]   Panorama だけの行は、機器のモデルで判定する
#   "platforms": ["PA-3200", …] Panorama だけではない行は、機種を自動では決めず「候補」（Panorama と判別できた機器には、
#                               すべての要素がファイアウォールの機種名と言い切れるときだけ当てない）
#   "platforms_bad": true       platforms の形が違った（文字列・中身が文字列でない など）。どの機器にも「候補」
#   "entry": 0                  勧告の affected[] の何番目の製品行か（defaultStatus は同じ製品行の系列だけで判断する）
# 方針: はっきり認識できた形だけで該当・非該当を決め、それ以外は必ず「判定できない」か「候補」に落とす。
#       非該当を返す枝には、その根拠をコメントで書く（_gate の skip・_span の out・_judge の最後）
# 旧い形（"lt"・"after_all"・status なし）も読む: lt は修正点の 1 つ、after_all は open、status なしは affected

PANORAMA_MODEL = re.compile(r"^(?:PAN-)?M-?\d{3}\b")  # 管理アプライアンス（M-100・M-200・M-300・M-500・M-600・M-700）
# ファイアウォール: PA-440・PA-VM・PA-VM-300・VM-50・VM-Series・PAN-PA-440（前に PAN- が付く書き方）など
FIREWALL_MODEL = re.compile(r"^(?:PAN-)?(?:PA-?VM|(?:PA|VM)[- ]?(?:\d|SERIES))")

CANDIDATE_REASONS = {
    "panorama": "Panorama だけに影響する勧告です。機器の種類（Panorama かファイアウォールか）を判別できませんでした",
    "default_affected": "勧告は、記載のない系列も影響ありとしています（この機器の系列は勧告の表に載っていません）",
    "platforms": "特定の機種だけに影響する勧告です（対象: {platforms}）。機種を確かめてください",
    # FortiOS（Fortinet の CSAF）
    "not_listed": "勧告のデータにこの系列が載っていません。勧告のページで確かめてください",
    "newer_branch": "勧告より新しい系列です。勧告のデータに載っていません（勧告のページで確かめてください）",
    "not_decided": "勧告のデータで、この版の扱いがはっきりしません（この系列の影響ありの範囲の外ですが、"
                   "この版を影響なしとする記載がありません）。勧告のページで確かめてください",
    "note": "勧告に注記があります（{note}）。勧告のページで確かめてください",
    "model_unknown": "機器のモデルを読み取れず、FortiGate 6000 / 7000 系（別系統の FortiOS）かどうかを判別できません",
}


def device_kind(model: str | None) -> str | None:
    """PAN-OS 機器の種類: "panorama" / "firewall" / None（モデルが空・判別できない）"""
    m = (model or "").strip().upper() if isinstance(model, str) else ""
    if not m:
        return None
    if "PANORAMA" in m or PANORAMA_MODEL.match(m):
        return "panorama"
    if FIREWALL_MODEL.match(m):
        return "firewall"
    return None


# platforms の要素の認識。どれも要素の全体で確かめる（前後の空白・大文字小文字は無視）
_PLAT_PANORAMA_EXACT = re.compile(r"^panorama$", re.I)  # 「Panorama だけ」の根拠にしてよい形
_PLAT_PANORAMA = re.compile(r"^panorama(?:\s+(?:m-series|virtual|vm|\(virtual\)|\(m-series\)))?$", re.I)  # Panorama と読める
# ファイアウォールの機種名と言い切れる形（PA-440・PA-3200 Series・PA-VM・PA-VM-300・VM-50 など）
_PLAT_FIREWALL = re.compile(r"^(?:PAN-)?(?:PA-?\d+[A-Z]*|PA-?VM(?:-\d+)?|VM-?\d+)(?:\s+Series)?$", re.I)


def _plats(item: dict) -> list[str]:
    plats = item.get("platforms")
    return [str(x) for x in plats] if isinstance(plats, list) else []


def _gate(item: dict, model: str | None) -> str | None:
    """platforms による絞り込み

    None="この機器に当てはまる" / "skip"=当てはまらない / "unknown"=Panorama だけの行で機器の種類を判別できない /
    "platforms"=機種を自動では決めない（候補）
    "skip"（＝この行を根拠に非該当になりうる）を返すのは、次のどちらかをはっきり認識できたときだけ:
      - platforms のすべての要素が、全体で「Panorama」と一致し、機器がファイアウォールと判別できた
      - 機器が Panorama と判別でき、platforms のすべての要素が、全体でファイアウォールの機種名
        （PA-数字…・PA-VM・VM-数字…。後ろの " Series" は可）と一致する
    """
    if item.get("platforms_bad"):
        return "platforms"  # 形の違う platforms は、platforms なしとは扱わない
    plats = item.get("platforms")
    if plats is None or plats == []:
        return None
    if not isinstance(plats, list) or not all(isinstance(x, str) and x.strip() for x in plats):
        return "platforms"
    names = [x.strip() for x in plats]
    kind = device_kind(model)
    if all(_PLAT_PANORAMA_EXACT.match(x) for x in names):
        return "skip" if kind == "firewall" else "unknown" if kind is None else None
    if kind == "panorama":
        if any(_PLAT_PANORAMA.match(x) for x in names):
            return None
        return "skip" if all(_PLAT_FIREWALL.match(x) for x in names) else "platforms"
    return "platforms"  # PA-3200 などの機種の系列・決められない表記。機器のモデルとの対応は判別しない（README の限界）


_BRANCH_TEXT = re.compile(r"^\d+\.\d+\Z", re.A)


def _span(p: Parsed, item: dict) -> str:
    """行の範囲に版 p が入るか: "in" / "out_fix" / "out_lt" / "out_start" / "out_le" / "out_branch" / "bad"（読み取れない）

    PAN-OS の版は x.y.z（保守版）または x.y.z-hN（ホットフィックス）。行の範囲（ge 以上）の中で、
      1. 同じ保守版 x.y.z に修正点 x.y.z-hM があれば、N ≧ M は外れ（修正済み）、N ＜ M は入る
      2. 同じ保守版に修正点が無ければ、修正点の最大より前なら入る、最大以上なら外れ
    lessThan は修正点の 1 つとして扱う（lessThan が修正点の最小のこともあるため、lessThan では打ち切らない）
    外れの種類（根拠）: out_fix=changes の修正点（at）以上（「ここから影響なし」という行の明記）/
    out_lt=changes に無い lessThan だけを根拠にした外れ（「この版より前が影響あり」と言うだけ）/ out_start=行の始まりより前 /
    out_le=lessThanOrEqual より後 / out_branch=別の系列の行。根拠の無い形は "bad"。
    out_lt・out_start・out_le は行の外というだけなので、既定（defaultStatus）が affected・unknown の製品行では既定に従う
    """
    branch = item.get("branch")
    if branch is not None and not (isinstance(branch, str) and _BRANCH_TEXT.match(branch)):
        return "bad"
    if item.get("all") is True:
        if branch is None:
            return "in"
        return "in" if branch == p.branch else "out_branch"  # 根拠: 別の系列についての「すべて」の行
    if branch is None:
        return "bad"  # 系列の無い範囲の行は、どの系列のものか決められない
    if branch != p.branch:
        return "out_branch"  # 根拠: 行は別のリリース系列のもの（その系列の版のことは書いていない）
    lo = parse_scheme(p.scheme, item.get("ge")) if isinstance(item.get("ge"), str) else None
    if lo is None or lo.branch != p.branch:
        return "bad"
    if compare(p, lo) < 0:
        return "out_start"  # 根拠: 行の始まり（version）より前の版
    if item.get("open") is True or item.get("after_all") is True:
        return "in"
    if item.get("le") is not None:
        hi = parse_scheme(p.scheme, item["le"]) if isinstance(item["le"], str) else None
        if hi is None or hi.branch != p.branch:
            return "bad"
        if p.scheme == "panos" and hi.key[3] == 0 and p.key[:3] == hi.key[:3] and p.key[3] > 0:
            return "bad"  # le が x.y.z（h なし）で、版が同じ x.y.z のホットフィックス: 含むか決められない
        return "in" if compare(p, hi) <= 0 else "out_le"  # 根拠: lessThanOrEqual より後の版
    texts = item.get("fixes") or []
    if not isinstance(texts, list):
        return "bad"
    texts = [*texts, item["lt"]] if item.get("lt") is not None else list(texts)
    lt_only = item.get("lt_only") or []  # changes に無い lessThan（旧い形の "lt" も同じ扱い）
    if not isinstance(lt_only, list):
        return "bad"
    lt_only = [*lt_only, item["lt"]] if item.get("lt") is not None else lt_only
    if not texts:
        return "bad"  # 上限も修正点も「上限なし」の印も無い行は、読み違いを避けて判定しない
    fixes = [parse_scheme(p.scheme, t) if isinstance(t, str) else None for t in texts]
    if any(f is None or f.branch != p.branch or compare(f, lo) <= 0 for f in fixes):
        return "bad"
    top = max(fixes, key=lambda f: f.key)
    lt_keys = {f.key for t in lt_only if isinstance(t, str) and (f := parse_scheme(p.scheme, t)) is not None}
    by_changes = [f for f in fixes if f.key not in lt_keys]  # changes の at（既定より優先してよい修正点）

    def out() -> str:
        """外れの根拠: changes の at で言えれば out_fix、lessThan だけなら out_lt"""
        if by_changes and compare(p, max(by_changes, key=lambda f: f.key)) >= 0:
            return "out_fix"  # 根拠: changes の最大の修正点以上
        if p.scheme == "panos" and any(f.key[:3] == p.key[:3] and p.key[3] >= f.key[3] for f in by_changes):
            return "out_fix"  # 根拠: 同じ保守版の changes の修正点以上
        return "out_lt"

    if compare(p, top) >= 0:
        return out()  # 最大の修正点（以上は修正済み）
    if p.scheme != "panos":
        return "in" if len({f.key for f in fixes}) == 1 else "bad"  # ホットフィックスの考え方は PAN-OS だけ
    same = [f.key[3] for f in fixes if f.key[:3] == p.key[:3]]
    if same:
        return out() if p.key[3] >= min(same) else "in"  # 同じ保守版の修正点（x.y.z-hM 以上は修正済み）
    return "in"


def judge_detail(p: Parsed, affected: list[dict] | None, model: str | None = None) -> tuple[str, str | None]:
    """分解済みの版の判定と、その理由: (affected / candidate / unreadable / unaffected, 理由の符号 or None)

    優先: 影響ありの行（または既定の affected）と、影響なしの行が同じ版に重なる → unreadable("conflict")
          影響ありの行に入る → affected / Panorama だけの行で機器の種類が分からない → candidate("panorama")
          機種を自動では決めない platforms の行 → candidate("platforms")
          読み取れない行がこの系列にある（系列の無い読めない行は全系列）・"x.y None" の影響なしだけで対の行が無い・
          既定が unknown → unreadable
          製品行の defaultStatus が affected で、機器の系列がその製品行に載っていない → candidate("default_affected")
          影響なしの行に入る → unaffected / それ以外 → unaffected（下の「非該当の根拠」）
    例外は出さない（読めない入力は unreadable）
    """
    return judge_explain(p, affected, model)[:2]


def judge_explain(p: Parsed, affected: list[dict] | None, model: str | None = None) -> tuple[str, str | None, list[str]]:
    """judge_detail に、「特定の機種」の候補の対象の機種（platforms の値）を足したもの"""
    try:
        return _judge(p, affected, model)
    except Exception:  # noqa: BLE001 - 想定外の形でも落ちずに「判定できない」
        return "unreadable", None, []


class _Group:
    """1 つの製品行（affected[] の 1 件）の、機器の系列についての状況"""

    def __init__(self) -> None:
        self.decided = False  # 読める行がこの版を決めた（含む・修正点以上・"x.y All"・影響ありの "x.y None"）
        self.none_unaffected = False  # 影響なしの "x.y None" がある
        self.all_affected = False  # "x.y All"（または " All"）の影響ありの行がある
        self.other_usable = False  # それ以外の、判定に使える行がこの系列にある


def _judge(p: Parsed, affected, model) -> tuple[str, str | None, list[str]]:
    if not isinstance(affected, list):
        return "unreadable", None, []
    hit = cand = unread = clear = False
    cand_plats: list[str] = []  # 「特定の機種」の候補の対象（理由の文に出す）
    groups: dict = {}
    defaults: list[tuple] = []  # (製品行, defaultStatus, gate, platforms)
    for it in affected:
        if not isinstance(it, dict):
            unread = True
            continue
        if "kind" in it:
            if it.get("kind") != "default":
                unread = True
                continue
            defaults.append((it.get("entry"), it.get("default"), _gate(it, model), _plats(it)))
            continue
        g = groups.setdefault(it.get("entry"), _Group())
        branch = it.get("branch")
        if branch is not None and not isinstance(branch, str):
            unread = True
            continue
        mine = branch in (None, p.branch)  # この版の系列についての行か（系列の無い行は全系列）
        gate = _gate(it, model)
        status = it.get("status", "affected")
        if it.get("none") is True:
            if branch is None or status not in ("affected", "unaffected"):
                unread = True
            elif branch == p.branch and gate != "skip":
                if status == "unaffected":
                    g.none_unaffected = True  # 「影響なしの版が無い」: 確定は "x.y All" の影響ありと組のときだけ（下）
                else:
                    g.decided = True
                    clear |= gate is None  # 根拠: 影響ありの "x.y None"＝この系列に影響ありの版は無い（表の明記）
            continue
        if it.get("unreadable"):
            unread |= mine
            continue
        r = _span(p, it)
        if r == "bad" or status not in ("affected", "unaffected"):
            unread |= mine
            continue
        if mine:
            if it.get("all") is True and status == "affected":
                g.all_affected = True
            else:
                g.other_usable = True
        if r in ("in", "out_fix"):
            g.decided = True
        if r != "in":
            continue
        if status == "unaffected":
            clear |= gate is None  # 根拠: 影響なしの行（この機器に当てはまる行）がこの版を含む
        elif gate is None:
            hit = True
        elif gate == "unknown":
            cand = True
        elif gate == "platforms":
            cand_plats += [x for x in _plats(it) if x not in cand_plats]
    for g in groups.values():
        if g.none_unaffected and (not g.all_affected or g.other_usable):
            unread = True  # 影響なしの "x.y None" が、"x.y All" の影響ありだけと組になっていない: 確定しない
    def_cand = def_unknown = False
    def_plats: list[str] = []
    for entry, ds, gate, plats in defaults:
        if gate == "skip":
            continue  # 根拠: その製品行の platforms がこの機器に当てはまらない（_gate の skip の条件）
        g = groups.get(entry)
        if g is not None and g.decided:
            continue  # 根拠: 同じ製品行の読める行が、この版を決めた（含む・修正点以上・"x.y All"・"x.y None"）
        if ds == "affected":
            def_cand = True
            if gate == "platforms":
                def_plats += [x for x in plats if x not in def_plats]
        else:
            def_unknown = True
    if (hit or cand or cand_plats or def_cand) and clear:
        return "unreadable", "conflict", []
    if hit:
        return "affected", None, []
    if cand:
        return "candidate", "panorama", []
    if cand_plats:
        return "candidate", "platforms", cand_plats
    if unread or def_unknown:
        return "unreadable", "default_unknown" if def_unknown and not unread else None, []
    if def_cand:
        return ("candidate", "platforms", def_plats) if def_plats else ("candidate", "default_affected", [])
    if clear:
        return "unaffected", None, []  # 根拠: 影響なしの行がこの版を含む（"x.y All" の影響なし・version だけの影響なし など）
    # 根拠（ここまで来た場合）: この系列に読めない行は無く、既定（defaultStatus）が affected・unknown の製品行は、
    # 読める行がこの版を決めたか（修正点以上など）、機器に当てはまらない。そのうえで、この版を含む影響ありの行が無い。つまり
    #   - 行の範囲の外で、_span の根拠つきの外れ（修正点以上・始まりより前・lessThanOrEqual より後・別の系列）で決まった
    #     （始まりより前・lessThanOrEqual より後は、既定が unaffected・無しの製品行のときだけ）
    #   - 系列がどの行にも無く、その製品行の defaultStatus が unaffected・無し（記載のない系列は影響なし）
    #   - または、行が platforms でこの機器に当てはまらない（skip）
    return "unaffected", None, []


def judge_parsed(p: Parsed, affected: list[dict], model: str | None = None, source: str = "paloalto") -> str:
    """分解済みのバージョンの判定: affected / candidate / unreadable / unaffected"""
    return judge_source(source, p, affected, model)[0]


def judge_source(source: str, p: Parsed, affected, model: str | None = None) -> tuple[str, str | None, list[str]]:
    """勧告の情報源ごとの判定（paloalto: CVE 5.0 の範囲 / fortinet: CSAF の FortiOS の行）。知らない情報源は判定できない"""
    if source == "paloalto" and p.scheme == "panos":
        return judge_explain(p, affected, model)
    if source == "fortinet" and p.scheme == "fortios":
        return judge_fortios(p, affected, model)
    return "unreadable", None, []


def evaluate(platform: str, os_version: str | None, affected: list[dict], model: str | None = None,
             source: str | None = None) -> str:
    """影響範囲に対する機器の判定: affected / candidate / unaffected / unreadable（範囲を読めない）/ unknown（版が読めない）"""
    p = parse_version(platform, os_version)
    if p is None:
        return "unknown"
    return judge_source(source or _source_of(platform), p, affected, model)[0]


def _source_of(platform: str) -> str:
    return next((s for s, plat in SOURCE_PLATFORM.items() if plat == platform), "")


def candidate_code(platform: str, os_version: str | None, affected: list[dict], model: str | None = None,
                   source: str | None = None) -> tuple[str | None, list[str]]:
    """「候補」の理由の符号と、特定の機種の候補の対象（候補でなければ (None, [])）"""
    p = parse_version(platform, os_version)
    if p is None:
        return None, []
    result, code, plats = judge_source(source or _source_of(platform), p, affected, model)
    return (code, plats) if result == "candidate" else (None, [])


def candidate_reason(platform: str, os_version: str | None, affected: list[dict], model: str | None = None,
                     source: str | None = None) -> str | None:
    """「候補」の理由の文（候補でなければ None）"""
    code, plats = candidate_code(platform, os_version, affected, model, source)
    if code not in CANDIDATE_REASONS:
        return None
    text = ", ".join(plats)[:200]
    return CANDIDATE_REASONS[code].format(platforms=text, note=text)


# ---------------------------------------------------------------- FortiOS（Fortinet の CSAF）との照合
#
# 影響範囲は、取得のときに services/vuln_fetch.py の parse_fortinet_csaf が、CSAF の vulnerabilities[].product_status の
# FortiOS の文字列（本物の形は 2026-11 に確認。vuln_fetch.py の「Fortinet」の節）を次の形に直して保存する。
# どれも "fmt": "fortios"。"v" は vulnerabilities[] の何番目か（CVE × 製品ごとの 1 件。判定は v ごと）、"raw" は元の文字列
#   {"kind": "vuln", "v": 0, "cve": "CVE-…"}
#        FortiOS の脆弱性の 1 件（行が 0 件でも、ここで数える）
#   {"status": "affected", "branch": "7.4", "ge": "7.4.0", "le": "7.4.2"}
#        known_affected の "FortiOS >=7.4.0|<=7.4.2"（範囲。両端を含む）
#   {"status": "affected", "branch": "7.6", "eq": "7.6.0"}      known_affected の "FortiOS 7.6.0"（単独の版）
#   {"status": "affected", "branch": "7.0", "all": true}        known_affected の "FortiOS 7.0 all versions"（修正版なし）
#   {"status": "unaffected", "branch": "7.4", "fix": "7.4.3"}   known_not_affected の "FortiOS-7.4.3"（修正版。以上は影響なし）
#   {"status": "unaffected", "branch": "8.0", "all": true}      known_not_affected の "FortiOS/ 8.0 all versions"（影響なし）
#   {"upcoming": "7.2.14", "branch": "7.2"}                     known_not_affected の "FortiOS-upcoming  7.2.14"（未公開）
#   {"unreadable": true, "v": 0 | null}   読めない行（v が null なら勧告の全体。どの系列にも当たりうる）
# 方針（PAN-OS と同じ）: はっきり認識できた形だけで該当・非該当を決め、それ以外は必ず「判定できない」か「候補」に落とす。
#   非該当を返すのは 2 か所だけ（_fortios_group の「非該当の根拠」）。勧告に載っていない系列は非該当にしない（候補）:
#   本物の FG-IR-26-193 で、勧告のページの表にある系列（7.0・6.4）が CSAF に無いことを確かめたため

# FortiGate 6000 / 7000 系（FortiOS-6K7K。勧告では別の製品）。FortiGate-6500F・FortiGate-7121F のほか、後ろに何が付いても
# （FortiGate-6500F-DC・FortiGate-7121F-2・FortiGate-7060E-8 など）6K7K とする。短い表記（FG-6500F・FGT6500F・FG6500F）も同じ。
# 台帳の読み取り（inventory.parse_fortinet）は get system status の「Version:」の先頭の語（FortiGate-60F の形）を入れる。
# モデル名の全体の形は実機で未確認（README の限界）
FORTIOS_6K7K_MODEL = re.compile(r"^(?:FortiGate|FGT|FG)-?[67]\d{3}", re.I | re.A)
# ふつうの FortiOS の機器と言えるモデル（FortiGate-60F・FortiGate-VM64-KVM・FortiWiFi-60E・FortiGateRugged-60F など）
FORTIOS_STD_MODEL = re.compile(r"^Forti(?:Gate|WiFi)(?:Rugged)?-[0-9A-Za-z][0-9A-Za-z\-]{0,40}\Z", re.I | re.A)


def fortios_model_kind(model: str | None) -> str | None:
    """FortiGate のモデルの種類: "6k7k"（FortiOS-6K7K）/ "std"（ふつうの FortiOS）/ None（空・判別できない）"""
    m = model.strip() if isinstance(model, str) else ""
    if not m:
        return None
    if FORTIOS_6K7K_MODEL.match(m):
        return "6k7k"
    return "std" if FORTIOS_STD_MODEL.match(m) else None


def _fos(text) -> Parsed | None:
    return parse_scheme("fortios", text) if isinstance(text, str) and re.fullmatch(r"\d+\.\d+\.\d+", text, re.A) else None


class _FosGroup:
    """1 つの脆弱性（v）の、機器の系列についての状況"""

    def __init__(self) -> None:
        self.hit = False  # 影響ありの行（範囲・単独の版・all versions）がこの版を含む
        self.clear_all = False  # 影響なしの "FortiOS/ A.B all versions"（この系列）
        self.fixes: list[Parsed] = []  # この系列の修正版（FortiOS-X）
        self.fix_le = False  # この版以下の修正版がある（影響ありの行と重なれば食い違い）
        self.tops: list[Parsed] = []  # この系列の影響ありの行の上限（範囲の終わり・単独の版）
        self.affected_rows = False  # この系列に影響ありの行がある
        self.listed = False  # この系列の行（影響あり・影響なし・修正版・未公開の修正版）がある
        self.unread = False  # この系列（または系列を決められない）読めない行がある
        self.notes: list[str] = []  # この版を含む、注記つきの影響ありの行の注記（「候補」にする）


def _fortios_group(p: Parsed, items: list[dict], newest: tuple | None = None) -> tuple[str, str | None]:
    """1 つの脆弱性の判定: (affected / candidate / unreadable / unaffected, 理由の符号)

    newest は勧告に載っている系列の最大（機器の系列がそれより新しく、行が無ければ newer_branch の候補）
    """
    g = _FosGroup()
    for it in items:
        if it.get("kind") == "vuln":
            continue
        if it.get("unreadable"):
            # 読めない行: 系列を読み取れた行（"FortiOS 6.0 …" の形）はその系列だけ、それ以外はどの系列にも当たりうる
            ub = it.get("branch")
            if isinstance(ub, str) and _BRANCH_TEXT.match(ub) and ub != p.branch:
                continue  # 根拠なしに非該当にはしない: 別の系列の版のことだけを書いた読めない行（その系列だけ判定できない）
            g.unread = True
            continue
        branch = it.get("branch")
        if not (isinstance(branch, str) and _BRANCH_TEXT.match(branch)):
            g.unread = True
            continue
        if branch != p.branch:
            continue  # 別の系列の行（その系列の版のことだけを書いている。この版の判定には使わない）
        g.listed = True
        if "upcoming" in it:
            x = _fos(it.get("upcoming"))
            if x is None or x.branch != branch:
                g.unread = True
            elif compare(p, x) >= 0:
                g.unread = True  # 修正版が未公開なのに、その版以上: 勧告のデータでは決められない
            continue
        status = it.get("status")
        if status == "affected":
            g.affected_rows = True
            note = it.get("note")
            if note is not None and not (isinstance(note, str) and note):
                g.unread = True
                continue
            if it.get("all") is True and not any(k in it for k in ("ge", "le", "eq", "fix")):
                _hit(g, note)
            elif "eq" in it and not any(k in it for k in ("ge", "le", "fix", "all")):
                x = _fos(it.get("eq"))
                if x is None or x.branch != branch:
                    g.unread = True
                else:
                    g.tops.append(x)
                    if compare(p, x) == 0:
                        _hit(g, note)
            elif "ge" in it and "le" in it and not any(k in it for k in ("eq", "fix", "all")):
                lo, hi = _fos(it.get("ge")), _fos(it.get("le"))
                if lo is None or hi is None or lo.branch != branch or hi.branch != branch or compare(lo, hi) > 0:
                    g.unread = True
                else:
                    g.tops.append(hi)
                    if compare(lo, p) <= 0 <= compare(hi, p):
                        _hit(g, note)
            else:
                g.unread = True
        elif status == "unaffected":
            if it.get("all") is True and not any(k in it for k in ("ge", "le", "eq", "fix")):
                g.clear_all = True
            elif "fix" in it and not any(k in it for k in ("ge", "le", "eq", "all")):
                x = _fos(it.get("fix"))
                if x is None or x.branch != branch:
                    g.unread = True
                else:
                    g.fixes.append(x)
                    g.fix_le |= compare(p, x) >= 0
            else:
                g.unread = True
        else:
            g.unread = True
    if g.hit and (g.clear_all or g.fix_le):
        return "unreadable", "conflict"  # 影響ありの行と影響なしの行（修正版以上）が同じ版に重なる: データの食い違い
    if g.hit:
        return "affected", None
    if g.notes:
        # 注記つきの影響ありの行がこの版を含む: 候補（注記の文を理由に出す）。影響なしの行と重なっても非該当にしない
        return "candidate", "note:" + "／".join(dict.fromkeys(g.notes))[:200]
    if g.unread:
        return "unreadable", None
    if g.clear_all and g.affected_rows:
        return "unreadable", "conflict"  # 系列は影響なしと言いながら、同じ系列に影響ありの行がある
    if g.clear_all:
        # 非該当の根拠 1: known_not_affected が「FortiOS/ A.B all versions」でこの系列の全体を影響なしとしている
        # （勧告のページの表の「Not affected / Not Applicable」。FG-IR-23-097・26-195 で突き合わせ済み）。
        # この系列に読めない行・影響ありの行は無い
        return "unaffected", None
    top_fix = max(g.fixes, key=lambda f: f.key) if g.fixes else None
    if top_fix is not None and compare(p, top_fix) >= 0 and all(compare(top_fix, t) > 0 for t in g.tops):
        # 非該当の根拠 2: この版は、この系列の修正版（known_not_affected の「FortiOS-X」＝表の「Upgrade to X or above」）の
        # 最大以上で、その最大の修正版は、この系列の影響ありの行（範囲の終わり・単独の版）のどれよりも後。
        # この系列に all versions の影響ありの行・読めない行は無く、この版はどの影響ありの行にも入らない
        # （修正版が複数ある・修正版の後にまた影響ありの範囲がある、の形では、最大でない修正版を根拠にしない）
        return "unaffected", None
    if not g.listed:
        if newest is not None and tuple(int(x) for x in p.branch.split(".")) > newest:
            return "candidate", "newer_branch"  # 勧告に載っているどの系列よりも新しい系列（判定は候補のまま）
        return "candidate", "not_listed"  # この系列の行が無い（載っていない系列は非該当にしない。FG-IR-26-193 の実例）
    return "candidate", "not_decided"  # 系列の行はあるが、どの行もこの版を決めない（範囲の外で、修正版の記載が無い など）


def _hit(g: _FosGroup, note) -> None:
    """影響ありの行がこの版を含む。注記つきの行（"FortiOS 7.0 all versions (except 7.0.5)" など）は、注記が限定の
    ことがあるので「該当」にせず「候補」（理由 note）にする"""
    if note:
        g.notes.append(note)
    else:
        g.hit = True


_FOS_RANK = {"affected": 3, "candidate": 2, "unreadable": 1, "unaffected": 0}


def judge_fortios(p: Parsed, affected, model: str | None = None) -> tuple[str, str | None, list[str]]:
    """FortiOS の勧告の判定: (affected / candidate / unreadable / unaffected, 理由の符号, [])。例外は出さない

    脆弱性（v）ごとに判定し、強いほうを採る（該当 ＞ 候補 ＞ 判定できない ＞ 非該当）。勧告の全体の読めない行があれば、
    非該当にはしない（判定できない）。機器のモデルが 6000 / 7000 系なら判定できない、モデルを判別できなければ
    「該当」は候補、「非該当」は判定できないにする（別系統の FortiOS-6K7K の可能性を残すため）
    """
    try:
        return _judge_fortios(p, affected, model)
    except Exception:  # noqa: BLE001 - 想定外の形でも落ちずに「判定できない」
        return "unreadable", None, []


def _judge_fortios(p: Parsed, affected, model) -> tuple[str, str | None, list[str]]:
    if p.scheme != "fortios" or not isinstance(affected, list):
        return "unreadable", None, []
    kind = fortios_model_kind(model)
    if kind == "6k7k":
        return "unreadable", "6k7k", []
    groups: dict[int, list[dict]] = {}
    whole_unread = False
    for it in affected:
        if not isinstance(it, dict) or it.get("fmt") != "fortios":
            whole_unread = True
            continue
        v = it.get("v")
        if v is None and it.get("unreadable"):
            whole_unread = True
            continue
        if not isinstance(v, int) or isinstance(v, bool):
            whole_unread = True
            continue
        groups.setdefault(v, []).append(it)
    branches = [tuple(int(x) for x in b.split(".")) for items in groups.values() for it in items
                if isinstance(b := it.get("branch"), str) and _BRANCH_TEXT.match(b) and not it.get("unreadable")]
    newest = max(branches) if branches else None
    results = [_fortios_group(p, items, newest) for items in groups.values()]
    if whole_unread:
        results.append(("unreadable", None))
    if not results:
        # 非該当の根拠（勧告の全体）: 改訂で FortiOS の行が無くなった勧告（取得のときに読めた文書で、
        # どの脆弱性も FortiOS 以外の製品のもの）。影響範囲が空のまま保存してある
        return "unaffected", None, []
    result, code = max(results, key=lambda r: _FOS_RANK[r[0]])
    extra: list[str] = []
    if code and code.startswith("note:"):
        code, extra = "note", [code[5:]]  # 注記の文（理由の文に入れる）
    if kind is None:
        if result == "affected":
            return "candidate", "model_unknown", []
        if result == "unaffected":
            return "unreadable", "model_unknown", []
    return result, code, extra
