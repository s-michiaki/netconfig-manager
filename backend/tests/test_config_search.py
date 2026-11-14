"""コンフィグの横断検索"""
import time
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.services import config_search
from app.services import config_service as cs


def login(c, u, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


def test_search_across_devices():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        uid = uuid.uuid4().hex[:6]
        g = c.post("/api/device-groups/", json={"name": f"srch-g-{uid}"}, headers=admin).json()
        ids = {}
        for n, grp in (("a", g["id"]), ("b", g["id"]), ("c", None), ("new", g["id"])):
            ids[n] = c.post("/api/devices/", json=dict(name=f"srch-{n}-{uid}", hostname="10.9.0.1", platform="cisco_ios",
                                                       username="u", password="p", group_id=grp), headers=admin).json()["id"]
        mark = f"VLAN{uid}"
        cs.save_config(ids["a"], f"hostname a\ninterface Gi0/1\n description {mark} uplink {mark}\n switchport\n!\n", "test")
        cs.save_config(ids["b"], "hostname b\nntp server 10.0.0.1\n" + "".join(f"name {mark.lower()}-{i}\n" for i in range(60)), "test")
        cs.save_config(ids["c"], f"hostname c\nsnmp-server location {mark}\n", "test")

        def search(**kw):
            return c.post("/api/configs/search", json=kw, headers=admin)

        # 文字列（大文字小文字を区別しない）・前後の行
        d = search(query=mark, context=1).json()
        hits = {x["name"]: x for x in d["devices"]}
        assert set(hits) == {f"srch-a-{uid}", f"srch-b-{uid}", f"srch-c-{uid}"} and d["matched"] == 3
        a = hits[f"srch-a-{uid}"]
        assert a["count"] == 1 and a["lines"][0]["line"] == 3 and len(a["commit"]) == 40 and a["group"] == g["name"]
        assert a["lines"][0]["before"] == ["interface Gi0/1"] and a["lines"][0]["after"] == [" switchport"]
        line = a["lines"][0]
        assert [line["text"][s:e] for s, e in line["ranges"]] == [mark, mark]
        b = hits[f"srch-b-{uid}"]
        assert b["count"] == 60 and len(b["lines"]) == d["max_lines_per_device"] == 50
        assert d["total_lines"] == 62
        assert f"srch-new-{uid}" in [x["name"] for x in d["not_collected"]]
        # 大文字小文字を区別すると b は外れ、「一致しなかった機器」に入る
        d = search(query=mark, case_sensitive=True).json()
        assert f"srch-b-{uid}" not in [x["name"] for x in d["devices"]]
        assert f"srch-b-{uid}" in [x["name"] for x in d["unmatched"]]
        assert d["devices"][0]["lines"][0]["before"] == []
        # グループで絞る
        d = search(query=mark, group_id=g["id"]).json()
        assert {x["name"] for x in d["devices"]} == {f"srch-a-{uid}", f"srch-b-{uid}"}
        assert {x["name"] for x in search(query=mark, group_id="none").json()["devices"]} == {f"srch-c-{uid}"}
        # 正規表現。文字列モードでは記号をそのまま探す
        d = search(query=rf"^snmp-server location {mark}$", mode="regex").json()
        assert [x["name"] for x in d["devices"]] == [f"srch-c-{uid}"]
        assert search(query=rf"^snmp-server location {mark}$").json()["matched"] == 0
        assert search(query="10.0.0.1", group_id=g["id"]).json()["matched"] == 1
        # 入力の誤り
        assert search(query="(", mode="regex").status_code == 422
        assert search(query="   ").status_code == 422
        assert search(query="x", mode="glob").status_code == 422
        # 閲覧者も検索できる。未ログインは不可
        name = f"srchv-{uid}"
        c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"}, headers=admin)
        assert c.post("/api/configs/search", json={"query": mark}, headers=login(c, name, "password-1234")).status_code == 200
        assert c.post("/api/configs/search", json={"query": mark}).status_code == 401


def test_search_device_limits():
    # 重い正規表現は時間で打ち切る
    rx = config_search.build_pattern(r"^(?:a|aa)+c", "regex", True)
    t0 = time.monotonic()
    try:
        config_search.search_device(rx, "a" * 40, 0, time.monotonic() + 0.3)
        raise AssertionError("打ち切られなかった")
    except TimeoutError:
        pass
    assert time.monotonic() - t0 < 3
    # 長い行は切り詰め、範囲も切り詰めた中に収める
    rx = config_search.build_pattern("key", "contains", False)
    long = "key " + "x" * 1000 + " key"
    count, lines = config_search.search_device(rx, long, 0, time.monotonic() + 5)
    assert count == 1 and len(lines[0]["text"]) == config_search.MAX_LINE_LENGTH + 1 and lines[0]["ranges"] == [[0, 3]]
    # 空文字に一致する正規表現（^）は行として数える
    count, lines = config_search.search_device(config_search.build_pattern("^", "regex", True), "a\nb\n", 0, time.monotonic() + 5)
    assert count == 2 and lines[0]["ranges"] == []
