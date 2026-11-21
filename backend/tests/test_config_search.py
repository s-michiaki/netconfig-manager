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


def test_search_platform_filter_and_csv_export():
    import csv
    import io

    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        uid = uuid.uuid4().hex[:6]
        ids = {}
        for n, platform in (("ios", "cisco_ios"), ("fgt", "fortinet"), ("ios2", "cisco_ios")):
            ids[n] = c.post("/api/devices/", json=dict(name=f"exp-{n}-{uid}", hostname=f"10.8.0.{len(ids) + 1}",
                                                       platform=platform, username="u", password="p"),
                            headers=admin).json()["id"]
        mark = f"EXP{uid}"
        # 画面の表示上限（50 行）を超える一致・数式に見える行・長い行
        cs.save_config(ids["ios"], "hostname ios\n" + "".join(f" description {mark}-{i}\n" for i in range(70))
                       + f"={mark}+1\n" + f"{mark} " + "x" * 1000 + "\n", "test")
        cs.save_config(ids["fgt"], f"config system global\n    set hostname {mark}\nend\n", "test")
        cs.save_config(ids["ios2"], "hostname ios2\n", "test")

        def search(**kw):
            return c.post("/api/configs/search", json=kw, headers=admin)

        # 機種で絞る
        d = search(query=mark, platform="fortinet").json()
        assert [x["name"] for x in d["devices"]] == [f"exp-fgt-{uid}"]
        assert all(x["platform"] == "fortinet" for x in d["devices"] + d["unmatched"] + d["not_collected"])
        d = search(query=mark, platform="cisco_ios").json()
        assert [x["name"] for x in d["devices"]] == [f"exp-ios-{uid}"] and f"exp-ios2-{uid}" in [x["name"] for x in d["unmatched"]]

        def export(**kw):
            return c.post("/api/configs/search/export", json=kw, headers=admin)

        r = export(query=mark, context=3)
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        assert 'filename="config_search_' in r.headers["content-disposition"]
        assert r.text.startswith("﻿")
        rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
        assert rows[0] == ["機器名", "ホスト / IP", "機種", "グループ", "世代", "行番号", "一致した行"]
        body = [x for x in rows[1:] if x[0].endswith(uid)]
        ios = [x for x in body if x[0] == f"exp-ios-{uid}"]
        # 50 行を超えても一致した行はすべて出す（前後の行は含めない）
        assert len(ios) == 72 and len(body) == 73
        assert ios[0][1:6] == ["10.8.0.1", cs.PLATFORMS["cisco_ios"].label, "", ios[0][4], "2"] and len(ios[0][4]) == 7
        assert ios[0][6] == f" description {mark}-0" and ios[69][5] == "71"
        assert ios[70][6] == f"'={mark}+1"  # 数式として実行されないよう ' を付ける
        assert len(ios[71][6]) == config_search.MAX_LINE_LENGTH + 1  # 長い行は検索と同じく切る
        fgt = [x for x in body if x[0] == f"exp-fgt-{uid}"]
        assert fgt == [[f"exp-fgt-{uid}", "10.8.0.2", cs.PLATFORMS["fortinet"].label, "", fgt[0][4], "2", f"    set hostname {mark}"]]
        assert [x[0] for x in body] == sorted(x[0] for x in body)  # 機器名順
        assert r.headers["x-search-rows"] == str(len(rows) - 1) and r.headers["x-search-timed-out"] == "0"
        assert r.headers["x-search-total-lines"] == str(len(rows) - 1)
        # 機種で絞った CSV
        r = export(query=mark, platform="fortinet")
        assert [x[0] for x in csv.reader(io.StringIO(r.text.lstrip("﻿")))][1:] == [f"exp-fgt-{uid}"]

        # 監査ログには件数と条件だけを残し、検索語は残さない
        log = c.get("/api/audit/logs", params={"action": "config.search_export"}, headers=admin).json()["items"][0]
        assert '"rows": 1' in log["detail"] and '"platform": "fortinet"' in log["detail"] and mark not in log["detail"]
        # 入力の誤り・権限
        assert export(query="(", mode="regex").status_code == 422
        assert export(query=" ").status_code == 422
        assert c.post("/api/configs/search/export", json={"query": mark}).status_code == 401
        name = f"expv-{uid}"
        c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"}, headers=admin)
        assert c.post("/api/configs/search/export", json={"query": mark},
                      headers=login(c, name, "password-1234")).status_code == 200


def test_search_total_line_limit():
    """CSV 用の合計の上限（max_total_lines）で返す行を打ち切り、件数は全部数える"""
    import uuid as _uuid

    ids = [str(_uuid.uuid4()) for _ in range(2)]
    for i in ids:
        cs.save_config(i, "".join(f"line {n}\n" for n in range(30)), "test")
    targets = [config_search.Target(i, f"t{n}", "h", "cisco_ios", None) for n, i in enumerate(ids)]
    res = config_search.search(targets, "line", max_lines=100, max_total_lines=45)
    assert [len(h.lines) for h in res.hits] == [30, 15] and res.total_lines == 60
    # 既定（画面）は機器ごとに 50 行まで
    res = config_search.search(targets, "line")
    assert [len(h.lines) for h in res.hits] == [30, 30]


def test_search_history():
    """過去の世代も含める検索: 消えた行・いまもある行と、最初・最後に見つかった世代"""
    import datetime as dt

    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        uid = uuid.uuid4().hex[:6]
        did = c.post("/api/devices/", json=dict(name=f"srchh-{uid}", hostname="10.9.1.1", platform="cisco_ios",
                                                username="u", password="p"), headers=admin).json()["id"]
        ip_old, ip_new = f"10.{int(uid[:2], 16)}.1.1", f"10.{int(uid[:2], 16)}.2.2"
        cs.save_config(did, f"hostname h\nntp server {ip_old}\n", "test")
        cs.save_config(did, f"hostname h\nntp server {ip_old}\nntp server {ip_new}\n", "test")
        cs.save_config(did, f"hostname h\nntp server {ip_new}\n", "test")  # 古いほうを消した
        cs.save_config(did, f"hostname h2\nntp server {ip_new}\n", "test")
        history = cs.get_config_history(did)
        oldest, second = history[-1]["full_hash"], history[-2]["full_hash"]

        def search(**kw):
            return c.post("/api/configs/search", json={"query": "ntp server", "scope": "history", **kw}, headers=admin)

        d = search().json()
        dev = next(x for x in d["devices"] if x["id"] == did)
        assert d["scope"] == "history" and d["commits_searched"] >= 4 and dev["count"] == 2
        new, old = dev["lines"]  # いまもある行が先
        assert new["text"] == f"ntp server {ip_new}" and new["current"] is True and new["first_seen"]["full_hash"] == second
        assert old["text"] == f"ntp server {ip_old}" and old["current"] is False
        assert old["first_seen"]["full_hash"] == oldest and old["last_seen"]["full_hash"] == second
        assert [old["text"][s:e] for s, e in old["ranges"]] == ["ntp server"]
        # 最新だけの検索では消えた行は出ない
        d = c.post("/api/configs/search", json={"query": ip_old}, headers=admin).json()
        assert did not in [x["id"] for x in d["devices"]] and did in [x["id"] for x in d["unmatched"]]
        assert did in [x["id"] for x in search(query=ip_old).json()["devices"]]
        # 期間で絞る（未来の期間なら世代が無く「一致しなかった」）
        future = (dt.date.today() + dt.timedelta(days=3)).isoformat()
        d = search(since=future).json()
        assert did in [x["id"] for x in d["unmatched"]]
        assert did in [x["id"] for x in search(until=dt.date.today().isoformat()).json()["devices"]]
        assert search(since=future, until=dt.date.today().isoformat()).status_code == 422
        assert search(scope="all").status_code == 422
        # 世代の上限で打ち切ったら partial に入る
        import pytest

        mp = pytest.MonkeyPatch()
        mp.setattr(config_search, "MAX_HISTORY_COMMITS", 2)
        d = search().json()
        mp.undo()
        assert did in [x["id"] for x in d["partial"]]
        # CSV（過去の世代を含める場合は最初・最後の世代の列）
        r = c.post("/api/configs/search/export", json={"query": ip_old, "scope": "history"}, headers=admin)
        assert r.status_code == 200
        text = r.content.decode("utf-8-sig")
        assert "最初に見つかった世代" in text.splitlines()[0]
        row = next(x for x in text.splitlines() if x.startswith(f"srchh-{uid},"))
        assert ",いいえ," in row and oldest[:7] in row and second[:7] in row
        c.delete(f"/api/devices/{did}", headers=admin)


def test_search_concurrency_limit(monkeypatch):
    """#16: 検索（CSV 出力も）はユーザーごと・全体で同時に実行できる数に上限があり、超えたら待たせずに 429"""
    from app.api import configs
    from app.core.config import settings

    monkeypatch.setattr(settings, "SEARCH_MAX_PER_USER", 2)
    monkeypatch.setattr(settings, "SEARCH_MAX_CONCURRENT", 3)
    monkeypatch.setattr(configs, "_running", configs.Counter())
    body = {"query": "hostname", "scope": "history"}
    with TestClient(app) as c:
        h = login(c, "admin", "initial-pass-123")
        me = c.get("/api/auth/me", headers=h).json()["id"]
        configs._running[me] = 2  # 自分の検索が 2 件実行中
        for path in ("/api/configs/search", "/api/configs/search/export"):
            r = c.post(path, json=body, headers=h)
            assert r.status_code == 429 and "前の検索" in r.json()["detail"], r.text
        configs._running[me] = 1
        configs._running["other-user"] = 2  # 全体で 3 件実行中
        r = c.post("/api/configs/search", json=body, headers=h)
        assert r.status_code == 429 and "ほかの検索" in r.json()["detail"]
        del configs._running["other-user"]
        assert c.post("/api/configs/search", json=body, headers=h).status_code == 200
        assert configs._running == {me: 1}  # 終わった検索の分は戻る（エラーでも戻る）
        assert c.post("/api/configs/search", json={"query": "("  , "mode": "regex"}, headers=h).status_code == 422
        assert configs._running == {me: 1}
