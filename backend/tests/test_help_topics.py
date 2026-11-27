"""アプリ内のヘルプ（frontend/src/help/）を、画面の定義・README・ロールの定義と静的に突き合わせる

ヘルプの中身は TypeScript のデータなので、ファイルを文字として読んで確かめる。
画面を足したのにヘルプの項目が無い、画面の権限を変えたのにヘルプの「使えるロール」が古い、
README の見出しを変えたのにヘルプの案内が古い、を検出する。
"""
import re
from pathlib import Path

import pytest

from app.core.permissions import ROLE_PERMISSIONS, Perm, Role

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "frontend" / "src"
HELP = SRC / "help"

# backend だけをマウントしたコンテナで pytest を実行した場合は frontend・README が無いので飛ばす
pytestmark = pytest.mark.skipif(not HELP.is_dir() or not (ROOT / "README.md").is_file(), reason="frontend/src/help が見つからない")

GROUPS = ["ダッシュボード", "機器", "コンフィグ", "監視", "管理", "共通"]
ROLES = {"管理者", "オペレーター以上", "すべてのロール"}

TOPIC_HEAD = re.compile(
    r'^    id: "(?P<id>[^"]+)",\n'
    r'    title: "(?P<title>[^"]+)",\n'
    r'    group: "(?P<group>[^"]+)",\n'
    r'(?:    path: "(?P<path>[^"]+)",\n)?'
    r'(?:    perm: PERM\.(?P<perm>\w+),\n)?'
    r'(?:    roles: "(?P<roles>[^"]+)",\n)?'
    r'(?:    feature: "(?P<feature>[^"]+)",\n)?',
    re.M,
)


def topics() -> list[dict]:
    """content/*.ts の項目の見出しの部分（id・title・group・path・perm・roles・feature）と本文のブロック"""
    found = []
    for f in sorted((HELP / "content").glob("*.ts")):
        text = f.read_text(encoding="utf-8")
        heads = list(TOPIC_HEAD.finditer(text))
        # 書式の崩れで取りこぼしていないこと（項目の先頭は 4 字下げの id:）
        assert len(heads) == len(re.findall(r'^    id: "', text, re.M)), f.name
        for i, m in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            found.append({**m.groupdict(), "body": text[m.end():end], "file": f.name})
    return found


def perm_values() -> dict[str, str]:
    """frontend の PERM（名前 → 値）。auth.tsx の定義"""
    block = re.search(r"export const PERM = \{(.*?)\} as const;", (SRC / "auth.tsx").read_text(encoding="utf-8"), re.S)
    assert block
    return dict(re.findall(r'(\w+): "([a-z]+:[a-z]+)"', block.group(1)))


def routes() -> dict[str, tuple[str, str]]:
    """App.tsx の Route（パス → (権限の名前, 画面の部品名)）。/terminal/:deviceId のようなパラメータ付きは親と同じ項目なので除く"""
    text = (SRC / "App.tsx").read_text(encoding="utf-8")
    found = re.findall(
        r'<Route\s+path="(/[^"]*)"\s+element=\{<RequirePerm perm=\{PERM\.(\w+)\}><(\w+) />', text)
    return {p: (perm, page) for p, perm, page in found if ":" not in p}


def menu() -> list[dict]:
    """App.tsx のメニュー（NAV_TOP・NAV_GROUPS）の項目: path・label・perm・feature・group。

    1 項目の `{…}` を取り出してから、キーごとに読む（キーの順・改行に左右されない）。
    `path: "` の数と拾えた件数が合わなければ失敗する（拾えない書き方の項目を黙って飛ばさない）
    """
    text = (SRC / "App.tsx").read_text(encoding="utf-8")
    block = text[text.index("const NAV_TOP"):text.index("const isOnPath")]
    groups = [(m.start(), m.group(1)) for m in re.finditer(r'\bid: "\w+",\s*label: "([^"]+)"', block)]
    raw = list(re.finditer(r"\{[^{}]*\bpath: \"[^\"]+\"[^{}]*\}", block))
    assert len(raw) == block.count('path: "'), "メニューの項目を読み取れない書き方がある（test_help_topics.py の menu() を直す）"
    items = []
    for m in raw:
        body = m.group(0)
        group = "ダッシュボード"
        for pos, label in groups:
            if pos < m.start():
                group = label
        field = {k: re.search(rf'\b{k}: "([^"]*)"', body) for k in ("path", "label", "icon", "feature")}
        perm = re.search(r"\bperm: PERM\.(\w+)", body)
        assert field["path"] and field["label"] and perm, f"メニューの項目に path・label・perm が揃っていない: {body}"
        known = {"path", "label", "icon", "perm", "feature"}
        assert set(re.findall(r"(\w+):", body)) <= known, f"メニューの項目に未知のキーがある: {body}"
        items.append({"path": field["path"].group(1), "label": field["label"].group(1), "perm": perm.group(1),
                      "feature": field["feature"].group(1) if field["feature"] else None, "group": group})
    return items


def help_link_topics() -> dict[str, set[str]]:
    """各 Page の `<HelpLink topic="…" />` の topic（ファイル名 → topic の集合）"""
    out = {}
    for f in sorted((SRC / "pages").glob("*.tsx")):
        found = set(re.findall(r'<HelpLink topic="([^"]+)"', f.read_text(encoding="utf-8")))
        if found:
            out[f.stem] = found
    return out


def role_for(perm_value: str) -> str:
    """その権限を持つ最も下のロールに対応する、ヘルプの表記（backend の ROLE_PERMISSIONS から）"""
    perm = Perm(perm_value)
    if perm in ROLE_PERMISSIONS[Role.VIEWER]:
        return "すべてのロール"
    if perm in ROLE_PERMISSIONS[Role.OPERATOR]:
        return "オペレーター以上"
    return "管理者"


def readme_headings() -> set[str]:
    out, fenced = set(), False
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("## "):
            out.add(line[3:].strip())
    return out


def test_topics_are_parsed_and_well_formed():
    ts = topics()
    assert len(ts) >= 20
    ids = [t["id"] for t in ts]
    assert len(ids) == len(set(ids)), "項目の id が重複している"
    for t in ts:
        assert t["group"] in GROUPS, t["id"]
        # 画面の項目の id は、パスの先頭の語（左ペインの「ヘルプ」とヘルプの「?」が、この規則で項目を引く）
        if t["path"]:
            assert t["id"] == t["path"].lstrip("/"), t["id"]
            assert t["perm"], f"{t['id']}: 画面の項目には perm が要る"
        else:
            assert t["group"] == "共通", f"{t['id']}: 画面に対応しない項目は「共通」に置く"
        assert t["roles"] in ROLES, f"{t['id']}: roles が要る"
    # どの大項目にも 1 つ以上の項目がある（並びは topics.ts の HELP_TOPICS で決まる）
    assert {t["group"] for t in ts} == set(GROUPS)


def test_every_topic_path_is_a_route():
    r = routes()
    for t in topics():
        if t["path"]:
            assert t["path"] in r, f"{t['id']}: {t['path']} が App.tsx の Route に無い"


def test_every_menu_item_has_a_topic():
    """メニューに画面を足したら、ヘルプの項目も足す（漏れの検出）。表記・大項目・権限・機能の条件も合わせる"""
    by_path = {t["path"]: t for t in topics() if t["path"]}
    items = menu()
    assert len(items) >= 20
    for m in items:
        t = by_path.get(m["path"])
        assert t, f"メニューの {m['path']}（{m['label']}）のヘルプの項目が無い（frontend/src/help/content/ に足す）"
        assert t["title"] == m["label"], f"{m['path']}: ヘルプの title がメニューの表記と違う"
        assert t["group"] == m["group"], f"{m['path']}: ヘルプの大項目がメニューと違う"
        assert t["perm"] == m["perm"], f"{m['path']}: ヘルプの perm がメニューと違う"
        assert t["feature"] == m["feature"], f"{m['path']}: ヘルプの feature がメニューと違う"


def test_perm_and_roles_match_routes_and_backend():
    r = routes()
    values = perm_values()
    for t in topics():
        if t["perm"]:
            assert t["perm"] in values, f"{t['id']}: PERM.{t['perm']} は auth.tsx に無い"
            assert r[t["path"]][0] == t["perm"], f"{t['id']}: perm が App.tsx の Route と違う"
            assert t["roles"] == role_for(values[t["perm"]]), (
                f"{t['id']}: 使えるロールが backend の ROLE_PERMISSIONS と違う（正しくは {role_for(values[t['perm']])}）")


def test_readme_headings_exist():
    headings = readme_headings()
    for t in topics():
        for h in re.findall(r'heading: "([^"]+)"', t["body"]):
            assert h in headings, f"{t['id']}: README に「## {h}」が無い"


def test_readme_guide_is_for_admin_topics_only():
    for t in topics():
        if "readme:" in t["body"]:
            assert t["roles"] == "管理者", f"{t['id']}: README の案内は管理者向けの項目だけに付ける"


def test_topics_are_short_enough_for_one_screen():
    for t in topics():
        steps = len(re.findall(r"^        title: ", t["body"], re.M))
        tips = re.search(r"    tips: \[\n(.*?)\n    \],", t["body"], re.S)
        assert tips, t["id"]
        n_tips = len(re.findall(r'^      "', tips.group(1), re.M))
        assert 2 <= steps <= 5, f"{t['id']}: steps は 2〜5 個（いま {steps}）"
        assert 2 <= n_tips <= 6, f"{t['id']}: tips は 2〜6 個（いま {n_tips}）"


def test_help_files_do_not_render_raw_html():
    files = [SRC / "pages" / "HelpPage.tsx", SRC / "components" / "HelpLink.tsx", *HELP.rglob("*.ts")]
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert "dangerouslySetInnerHTML" not in text, f.name
        assert "innerHTML" not in text, f.name


def test_every_screen_has_a_help_link_to_its_topic():
    """各 Page の見出しに「?」（HelpLink）があり、その topic は実在する項目の id（メニューの各画面は、自分の項目を指す）"""
    ids = {t["id"] for t in topics()}
    links = help_link_topics()
    for page, found in links.items():
        assert found <= ids, f"{page}.tsx の HelpLink の topic が実在しない: {found - ids}"
    r = routes()
    for m in menu():
        _perm, page = r[m["path"]]
        assert m["path"].lstrip("/") in links.get(page, set()), f"{page}.tsx の見出しに HelpLink topic=\"{m['path'].lstrip('/')}\" が無い"
    page_topics = set().union(*links.values())
    assert page_topics == {t["id"] for t in topics() if t["path"]}, "HelpLink の topic の集合と、画面の項目の id の集合が違う"
