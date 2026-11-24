"""変更（世代）の確認（確認済み・想定外）のテスト"""
import asyncio
import json
import sqlite3
from datetime import timedelta
from unittest import mock

import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.device import ConfigSnapshot
from app.services import config_service as cs

GROUP: list[str] = [""]


@pytest.fixture(scope="module")
def client():
    with (
        mock.patch("app.api.devices.collect_device_config"),
        mock.patch("app.api.devices.collect_all_devices"),
        TestClient(app) as c,
    ):
        yield c


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _snap(device_id, commit, days_ago, added=1, removed=0, triggered_by="schedule"):
    return ConfigSnapshot(device_id=device_id, commit_hash=commit, collected_at=utcnow() - timedelta(days=days_ago),
                          lines_added=added, lines_removed=removed, triggered_by=triggered_by)


@pytest.fixture(scope="module")
def env(client):
    admin = _login(client, "admin", "initial-pass-123")
    for name, role in [("rev-op", "operator"), ("rev-op2", "operator"), ("rev-view", "viewer")]:
        r = client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        assert r.status_code == 201, r.text
    group = client.post("/api/device-groups/", json={"name": "rev-grp", "color": "#4f8ef7"}, headers=admin).json()

    def dev(name, group_id=None):
        r = client.post("/api/devices/", json=dict(name=name, hostname="10.7.0.1", platform="cisco_ios", username="u", password="p",
                                                   group_id=group_id), headers=admin)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    group2 = client.post("/api/device-groups/", json={"name": "rev-grp2", "color": "#c084fc"}, headers=admin).json()
    a, b = dev("rev-sw1", group["id"]), dev("rev-sw2", group["id"])  # 他のテストの機器と混ざらないよう、同じグループで絞り込む
    a1 = cs.save_config(a, "hostname rev-sw1\n", "manual").commit_hash
    a2 = cs.save_config(a, "hostname rev-sw1\nvlan 99\n", "manual").commit_hash
    a3 = cs.save_config(a, "hostname rev-sw1\nvlan 99\nvlan 100\n", "manual").commit_hash
    b1 = cs.save_config(b, "hostname rev-sw2\n", "manual").commit_hash
    b2 = cs.save_config(b, "hostname rev-sw2\nntp server 10.0.0.1\n", "manual").commit_hash

    c, d = dev("rev-sw3", group2["id"]), dev("rev-sw4", group2["id"])
    c1 = cs.save_config(c, "hostname rev-sw3\n", "manual").commit_hash
    c2 = cs.save_config(c, "hostname rev-sw3\nvlan 7\n", "manual").commit_hash
    d1 = cs.save_config(d, "hostname rev-sw4\n", "manual").commit_hash
    d2 = cs.save_config(d, "hostname rev-sw4\nvlan 8\n", "manual").commit_hash

    async def snaps():
        async with AsyncSessionLocal() as db:
            # 収集が記録する世代の行。各機器の最初の世代（a1・b1）は確認の対象外。a2 は 10 日前、a3 は 1 日前、b2 は 100 日前
            db.add_all([_snap(a, a1, 40, 3, 0, "manual"), _snap(a, a2, 10, 1, 0), _snap(a, a3, 1, 1, 0), _snap(a, a3, 1, 1, 0),
                        _snap(b, b1, 120, 1, 0, "manual"), _snap(b, b2, 100, 1, 0),
                        # rev-sw3 は最初の世代（c1）の行もある。rev-sw4 は最初の世代の行が無い（d2 だけ）。d2 も確認の対象
                        _snap(c, c1, 50, 1, 0, "manual"), _snap(c, c2, 5, 1, 0), _snap(d, d2, 3, 1, 0)])
            await db.commit()
    asyncio.run(snaps())
    GROUP[0] = group["id"]
    yield {
        "admin": admin,
        "op": _login(client, "rev-op", "password-1234"),
        "op2": _login(client, "rev-op2", "password-1234"),
        "viewer": _login(client, "rev-view", "password-1234"),
        "a": a, "b": b, "a1": a1, "a2": a2, "a3": a3, "b1": b1, "b2": b2, "group": group["id"],
        "group2": group2["id"], "c": c, "d": d, "c1": c1, "c2": c2, "d1": d1, "d2": d2,
    }
    for did in (a, b, c, d):
        client.delete(f"/api/devices/{did}", headers=admin)
    for g in (group, group2):
        client.delete(f"/api/device-groups/{g['id']}", headers=admin)


def _db_rows(did):
    con = sqlite3.connect(f"{TMP}/t.db")
    try:
        return con.execute("select commit_hash, status, note, reviewed_by from config_reviews where device_id=?", (did,)).fetchall()
    finally:
        con.close()


def _list(client, h, **params):
    params.setdefault("group_id", GROUP[0])  # 他のテストの収集結果が混ざらないよう、このテストの機器のグループで絞る
    r = client.get("/api/configs/reviews", params=params, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _hashes(res):
    return [x["commit_hash"] for x in res["items"]]


def test_permissions_are_exposed(client, env):
    assert "config:review" in client.get("/api/auth/me", headers=env["op"]).json()["permissions"]
    assert "config:review" in client.get("/api/auth/me", headers=env["admin"]).json()["permissions"]
    assert "config:review" not in client.get("/api/auth/me", headers=env["viewer"]).json()["permissions"]


def test_set_overwrite_delete_and_permissions(client, env):
    did, url = env["a"], f"/api/configs/{env['a']}/reviews/{env['a2'][:8]}"
    # 閲覧者・未ログインは付けられない・戻せない
    assert client.put(url, json={"status": "confirmed"}, headers=env["viewer"]).status_code == 403
    assert client.delete(url, headers=env["viewer"]).status_code == 403
    assert client.put(url, json={"status": "confirmed"}).status_code == 401
    # 短縮ハッシュで付けても、完全な 40 桁で保存する。メモは前後の空白を除く
    r = client.put(url, json={"status": "confirmed", "note": "  CHG-1 の作業  "}, headers=env["op"])
    assert r.status_code == 200, r.text
    assert r.json()["commit_hash"] == env["a2"] and r.json()["status"] == "confirmed"
    assert r.json()["note"] == "CHG-1 の作業" and r.json()["reviewed_by"] == "rev-op" and r.json()["reviewed_at"].endswith("+00:00")
    assert _db_rows(did) == [(env["a2"], "confirmed", "CHG-1 の作業", "rev-op")]
    # 別のオペレーターが付け直せる（1 件のまま。確認者は上書きされる）
    r = client.put(url, json={"status": "unexpected", "note": ""}, headers=env["op2"])
    assert r.status_code == 200 and r.json()["status"] == "unexpected" and r.json()["note"] is None
    assert _db_rows(did) == [(env["a2"], "unexpected", None, "rev-op2")]
    # 管理者も付け直せる。未確認に戻す
    assert client.put(url, json={"status": "confirmed"}, headers=env["admin"]).status_code == 200
    assert client.delete(url, headers=env["op"]).status_code == 204
    assert _db_rows(did) == []
    assert client.delete(url, headers=env["op"]).status_code == 404  # 既に未確認


def test_input_and_target_checks(client, env):
    did, h = env["a"], env["op"]
    url = f"/api/configs/{did}/reviews/{env['a2']}"
    assert client.put(url, json={"status": "bad"}, headers=h).status_code == 422
    assert client.put(url, json={}, headers=h).status_code == 422
    assert client.put(url, json={"status": "confirmed", "note": "あ" * 501}, headers=h).status_code == 422
    assert client.put(url, json={"status": "confirmed", "note": "あ" * 500}, headers=h).status_code == 200
    client.delete(url, headers=h)
    # 最初の世代は対象外
    r = client.put(f"/api/configs/{did}/reviews/{env['a1']}", json={"status": "confirmed"}, headers=h)
    assert r.status_code == 422 and "最初の世代" in r.json()["detail"]
    # 存在しない世代・他の機器の世代・形式の誤り・存在しない機器
    assert client.put(f"/api/configs/{did}/reviews/{'0' * 40}", json={"status": "confirmed"}, headers=h).status_code == 404
    assert client.put(f"/api/configs/{did}/reviews/{env['b2']}", json={"status": "confirmed"}, headers=h).status_code == 404
    assert client.put(f"/api/configs/{did}/reviews/zzzzzzzz", json={"status": "confirmed"}, headers=h).status_code == 422
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.put(f"/api/configs/{missing}/reviews/{env['a2']}", json={"status": "confirmed"}, headers=h).status_code == 404
    assert _db_rows(did) == []


def test_history_has_review_and_first_flag(client, env):
    did = env["a"]
    client.put(f"/api/configs/{did}/reviews/{env['a3']}", json={"status": "unexpected", "note": "予定外の VLAN"}, headers=env["op"])
    for role in ("viewer", "op", "admin"):
        h = {c["full_hash"]: c for c in client.get(f"/api/configs/{did}/history", headers=env[role]).json()}
        assert h[env["a3"]]["review"]["status"] == "unexpected" and h[env["a3"]]["review"]["note"] == "予定外の VLAN"
        assert h[env["a3"]]["review"]["reviewed_by"] == "rev-op"
        assert h[env["a2"]]["review"] is None
        assert h[env["a1"]]["is_first"] is True and h[env["a2"]]["is_first"] is False
    client.delete(f"/api/configs/{did}/reviews/{env['a3']}", headers=env["op"])


def test_list_filters_and_first_generation_excluded(client, env):
    # 既定は未確認・直近の日数（CHANGE_REVIEW_DAYS）。最初の世代（a1・b1）は出ない。a3 は重複していても 1 件
    res = _list(client, env["viewer"])
    assert settings.CHANGE_REVIEW_DAYS == 30 and res["days"] == 30
    assert _hashes(res) == [env["a3"], env["a2"]] and res["total"] == 2  # 新しい順
    item = res["items"][0]
    assert item["device_name"] == "rev-sw1" and item["group_name"] == "rev-grp" and item["hash"] == env["a3"][:8]
    assert item["added"] == 1 and item["removed"] == 0 and item["triggered_by"] == "schedule"
    assert item["collected_at"].endswith("+00:00") and item["review"] is None and item["comment"] is None
    assert res["counts"] == {"unreviewed": 2, "unexpected": 0, "confirmed": 0}
    # 期間: 7 日なら a3 だけ、0 ならすべて（b2 も）
    assert _hashes(_list(client, env["viewer"], days=7)) == [env["a3"]]
    assert _hashes(_list(client, env["viewer"], days=0)) == [env["a3"], env["a2"], env["b2"]]
    assert _list(client, env["viewer"], days=90)["total"] == 2
    # 機器グループ
    assert _hashes(_list(client, env["viewer"], days=0, group_id=env["group2"])) == [env["d2"], env["c2"]]  # 別のグループの機器は除かれる
    assert env["c2"] not in _hashes(_list(client, env["viewer"], days=0)) and env["b2"] in _hashes(_list(client, env["viewer"], days=0))
    assert _list(client, env["viewer"], days=0, group_id="no-such-group")["items"] == []
    # コメントも付く
    client.put(f"/api/configs/{env['a']}/comments/{env['a3']}", json={"body": "VLAN 100 追加"}, headers=env["op"])
    assert _list(client, env["viewer"])["items"][0]["comment"] == "VLAN 100 追加"
    # 状態での絞り込み
    client.put(f"/api/configs/{env['a']}/reviews/{env['a3']}", json={"status": "confirmed"}, headers=env["op"])
    client.put(f"/api/configs/{env['b']}/reviews/{env['b2']}", json={"status": "unexpected", "note": "想定外"}, headers=env["op"])
    assert _hashes(_list(client, env["viewer"], days=0)) == [env["a2"]]
    assert _hashes(_list(client, env["viewer"], days=0, state="confirmed")) == [env["a3"]]
    assert _hashes(_list(client, env["viewer"], days=0, state="unexpected")) == [env["b2"]]
    allres = _list(client, env["viewer"], days=0, state="all")
    assert _hashes(allres) == [env["a3"], env["a2"], env["b2"]]
    assert allres["counts"] == {"unreviewed": 1, "unexpected": 1, "confirmed": 1}
    assert allres["items"][2]["review"]["note"] == "想定外" and allres["items"][2]["review"]["reviewed_by"] == "rev-op"
    assert client.get("/api/configs/reviews", params={"state": "bad"}, headers=env["viewer"]).status_code == 422
    assert client.get("/api/configs/reviews", params={"days": -1}, headers=env["viewer"]).status_code == 422
    assert client.get("/api/configs/reviews").status_code == 401
    for h in ("a3", "b2"):
        client.delete(f"/api/configs/{env['a' if h == 'a3' else 'b']}/reviews/{env[h]}", headers=env["op"])
    client.delete(f"/api/configs/{env['a']}/comments/{env['a3']}", headers=env["op"])


def test_list_is_limited_to_500(client, env):
    async def many():
        async with AsyncSessionLocal() as db:
            db.add_all([_snap(env["b"], f"{i:040x}", 0.5) for i in range(1, 502)])
            await db.commit()
    asyncio.run(many())
    res = _list(client, env["viewer"], days=0)
    assert len(res["items"]) == 500 and res["total"] == 504 and res["limit"] == 500

    async def clean():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import delete
            await db.execute(delete(ConfigSnapshot).where(ConfigSnapshot.commit_hash.like("000000000000000000000000000000000000%")))
            await db.commit()
    asyncio.run(clean())
    assert _list(client, env["viewer"], days=0)["total"] == 3


def test_bulk(client, env):
    items = [{"device_id": env["a"], "commit_hash": env["a2"][:8]}, {"device_id": env["a"], "commit_hash": env["a2"]},
             {"device_id": env["a"], "commit_hash": env["a3"]}, {"device_id": env["b"], "commit_hash": env["b2"]},
             {"device_id": env["a"], "commit_hash": env["a1"]},  # 最初の世代
             {"device_id": env["a"], "commit_hash": "f" * 40},  # 世代が無い
             {"device_id": "00000000-0000-0000-0000-000000000000", "commit_hash": env["a2"]}]  # 機器が無い
    url = "/api/configs/reviews/bulk"
    assert client.post(url, json={"items": items, "status": "confirmed"}, headers=env["viewer"]).status_code == 403
    r = client.post(url, json={"items": items, "status": "confirmed", "note": "月次の作業"}, headers=env["op"])
    assert r.status_code == 200, r.text
    assert r.json()["updated"] == 3  # 同じ世代の重複は 1 件
    assert [s["reason"] for s in r.json()["skipped"]] == ["最初の世代は対象外です", "世代が見つかりません", "機器が見つかりません"]
    assert sorted(_db_rows(env["a"])) == sorted([(env["a2"], "confirmed", "月次の作業", "rev-op"),
                                                  (env["a3"], "confirmed", "月次の作業", "rev-op")])
    assert _list(client, env["viewer"], days=0)["total"] == 0
    # 付け直し（想定外へ）
    r = client.post(url, json={"items": items[:1], "status": "unexpected"}, headers=env["op2"])
    assert r.json()["updated"] == 1 and (env["a2"], "unexpected", None, "rev-op2") in _db_rows(env["a"])
    # 件数・形式の検査
    assert client.post(url, json={"items": [], "status": "confirmed"}, headers=env["op"]).status_code == 422
    too_many = [{"device_id": env["a"], "commit_hash": env["a2"]}] * 201
    assert client.post(url, json={"items": too_many, "status": "confirmed"}, headers=env["op"]).status_code == 422
    assert client.post(url, json={"items": [{"device_id": env["a"], "commit_hash": "zz"}], "status": "confirmed"},
                       headers=env["op"]).status_code == 422
    assert client.post(url, json={"items": items[:1], "status": "x"}, headers=env["op"]).status_code == 422
    for did, h in ((env["a"], env["a2"]), (env["a"], env["a3"]), (env["b"], env["b2"])):
        client.delete(f"/api/configs/{did}/reviews/{h}", headers=env["op"])


def test_audit_log(client, env):
    did = env["b"]
    url = f"/api/configs/{did}/reviews/{env['b2']}"
    client.put(url, json={"status": "unexpected", "note": "未承認の NTP"}, headers=env["op"])
    client.put(url, json={"status": "confirmed", "note": "申請を確認"}, headers=env["op2"])
    client.delete(url, headers=env["op"])
    client.post("/api/configs/reviews/bulk", json={"items": [{"device_id": did, "commit_hash": env["b2"]}], "status": "confirmed"},
                headers=env["op"])
    logs = client.get("/api/audit/logs", params={"action": "config.", "q": "rev-sw2"}, headers=env["admin"]).json()["items"]
    # まとめて付けた記録の対象名は件数（機器ごとの記録ではない）。内訳は detail に残る
    bulk = client.get("/api/audit/logs", params={"action": "config.review_bulk"}, headers=env["admin"]).json()["items"]
    detail = json.loads(bulk[0]["detail"])
    assert bulk[0]["target_name"] == "1 件" and detail["count"] == 1
    assert detail["items"] == [{"device": "rev-sw2", "commit": env["b2"][:8]}]
    by = [(x["action"], json.loads(x["detail"])) for x in logs if x["target_name"] == "rev-sw2"]
    assert by[0][0] == "config.review_delete" and by[0][1]["before"]["status"] == "confirmed"
    assert by[1][0] == "config.review" and by[1][1]["status"] == "confirmed"
    assert by[1][1]["before"] == {"status": "unexpected", "note": "未承認の NTP", "reviewed_by": "rev-op"}  # 前の状態が残る
    assert by[2][0] == "config.review" and by[2][1]["before"] is None and by[2][1]["note"] == "未承認の NTP"
    labels = client.get("/api/audit/actions", headers=env["admin"]).json()
    assert labels["config.review"] == "コンフィグ変更の確認" and "config.review_delete" in labels and "config.review_bulk" in labels
    client.delete(url, headers=env["op"])


def test_dashboard(client, env):
    base = client.get("/api/dashboard", headers=env["viewer"]).json()["reviews"]  # 他のテストの機器の分を含むので、差で確かめる
    assert base["days"] == 30 and base["unreviewed"] >= 2  # このテストの a2・a3 は未確認
    client.put(f"/api/configs/{env['a']}/reviews/{env['a3']}", json={"status": "unexpected"}, headers=env["op"])
    client.put(f"/api/configs/{env['a']}/reviews/{env['a2']}", json={"status": "confirmed"}, headers=env["op"])
    for role in ("viewer", "op", "admin"):
        d = client.get("/api/dashboard", headers=env[role]).json()
        # 直近 30 日の未確認が 2 件減る（a2・a3 は確認済み・想定外）。想定外は期間なしで数える（a3 の 1 件）。b2 は 100 日前で期間外
        assert d["reviews"] == {"days": 30, "unreviewed": base["unreviewed"] - 2, "unexpected": base["unexpected"] + 1}
    client.delete(f"/api/configs/{env['a']}/reviews/{env['a2']}", headers=env["op"])
    assert client.get("/api/dashboard", headers=env["viewer"]).json()["reviews"]["unreviewed"] == base["unreviewed"] - 1

    async def recent():
        async with AsyncSessionLocal() as db:
            # 直近の変更（新しい 10 件）に出るよう、a1・a2・a3 の行を今の時刻で足す（重複した行は一覧では 1 件にまとまる）
            db.add_all([_snap(env["a"], h, 0) for h in (env["a1"], env["a2"], env["a3"])])
            await db.commit()
    asyncio.run(recent())
    rows = client.get("/api/dashboard", headers=env["viewer"]).json()["changes"]["recent"]
    mine = {x["full_commit"]: x for x in rows if x["device_id"] == env["a"]}
    assert mine[env["a3"]]["review"]["status"] == "unexpected" and mine[env["a3"]]["first"] is False
    assert mine[env["a2"]]["review"] is None
    assert mine[env["a1"]]["first"] is True and mine[env["a1"]]["review"] is None
    for h in (env["a3"],):
        client.delete(f"/api/configs/{env['a']}/reviews/{h}", headers=env["op"])


def test_device_delete_removes_reviews(client, env):
    admin = env["admin"]
    r = client.post("/api/devices/", json=dict(name="rev-del", hostname="10.7.0.9", platform="cisco_ios", username="u", password="p"),
                    headers=admin)
    did = r.json()["id"]
    cs.save_config(did, "hostname rev-del\n", "manual")
    c2 = cs.save_config(did, "hostname rev-del\nvlan 5\n", "manual").commit_hash
    assert client.put(f"/api/configs/{did}/reviews/{c2}", json={"status": "unexpected"}, headers=env["op"]).status_code == 200
    assert len(_db_rows(did)) == 1
    assert client.delete(f"/api/devices/{did}", headers=admin).status_code == 204
    assert _db_rows(did) == []


def test_second_generation_without_first_snapshot_is_listed(client, env):
    """初回の snapshot が無い機器（rev-sw4）の 2 世代目は、一覧・件数・ダッシュボードの数に含まれる（最初の世代は Git で判定する）"""
    res = _list(client, env["viewer"], days=0, group_id=env["group2"])
    assert _hashes(res) == [env["d2"], env["c2"]] and res["counts"]["unreviewed"] == 2
    base = client.get("/api/dashboard", headers=env["viewer"]).json()["reviews"]["unreviewed"]
    assert client.put(f"/api/configs/{env['d']}/reviews/{env['d2']}", json={"status": "confirmed"}, headers=env["op"]).status_code == 200
    assert client.get("/api/dashboard", headers=env["viewer"]).json()["reviews"]["unreviewed"] == base - 1
    assert _hashes(_list(client, env["viewer"], days=0, group_id=env["group2"])) == [env["c2"]]
    # 最初の世代は snapshot の有無に関わらず対象外
    assert client.put(f"/api/configs/{env['d']}/reviews/{env['d1']}", json={"status": "confirmed"}, headers=env["op"]).status_code == 422
    client.delete(f"/api/configs/{env['d']}/reviews/{env['d2']}", headers=env["op"])


def test_unexpected_count_matches_dashboard_and_list(client, env):
    for did, h in ((env["a"], env["a3"]), (env["c"], env["c2"]), (env["d"], env["d2"])):
        assert client.put(f"/api/configs/{did}/reviews/{h}", json={"status": "unexpected"}, headers=env["op"]).status_code == 200
    # group_id="" は絞り込みなし（全機器）。ダッシュボードの「想定外」と同じ数になる
    everything = _list(client, env["viewer"], days=0, state="unexpected", group_id="")
    assert everything["total"] <= everything["limit"]
    assert client.get("/api/dashboard", headers=env["viewer"]).json()["reviews"]["unexpected"] == everything["total"]
    assert {env["a3"], env["c2"], env["d2"]} <= set(_hashes(everything))
    for did, h in ((env["a"], env["a3"]), (env["c"], env["c2"]), (env["d"], env["d2"])):
        client.delete(f"/api/configs/{did}/reviews/{h}", headers=env["op"])


def test_bulk_with_existing_rows_and_conflicts(client, env):
    url = "/api/configs/reviews/bulk"
    items = [{"device_id": env["a"], "commit_hash": env["a2"]}, {"device_id": env["a"], "commit_hash": env["a3"]}]
    # 既に付いている行は付け直す（500 にならない）
    client.put(f"/api/configs/{env['a']}/reviews/{env['a2']}", json={"status": "confirmed", "note": "先に付けた"}, headers=env["op2"])
    r = client.post(url, json={"items": items, "status": "unexpected"}, headers=env["op"])
    assert r.status_code == 200 and r.json()["updated"] == 2
    assert sorted((x[0], x[1]) for x in _db_rows(env["a"])) == sorted([(env["a2"], "unexpected"), (env["a3"], "unexpected")])
    # 読んだあとに別の人が同じ世代へ先に付けた状態（既存の行が見えなかった）を作ると、409 を返す（500 にしない）
    for did, h in ((env["a"], env["a2"]), (env["a"], env["a3"])):
        client.delete(f"/api/configs/{did}/reviews/{h}", headers=env["op"])
    client.put(f"/api/configs/{env['a']}/reviews/{env['a2']}", json={"status": "confirmed"}, headers=env["op2"])

    async def blind(*_args, **_kwargs):
        return {}
    with mock.patch("app.api.config_reviews._existing_map", blind):
        r = client.post(url, json={"items": items, "status": "unexpected"}, headers=env["op"])
    assert r.status_code == 409 and "画面を開き直して" in r.json()["detail"]
    with mock.patch("app.api.config_reviews._existing", mock.AsyncMock(return_value=None)):
        r = client.put(f"/api/configs/{env['a']}/reviews/{env['a2']}", json={"status": "unexpected"}, headers=env["op"])
    assert r.status_code == 409
    # 失敗しても元の行は変わらない
    assert _db_rows(env["a"]) == [(env["a2"], "confirmed", None, "rev-op2")]
    client.delete(f"/api/configs/{env['a']}/reviews/{env['a2']}", headers=env["op"])


def test_first_commit_hash_is_cached(client, env):
    from app.services import config_service

    assert config_service.first_commit_hash(env["a"]) == env["a1"]
    assert config_service.peek_first_commit(env["a"]) == env["a1"]
    assert config_service.first_commit_hash("00000000-0000-0000-0000-000000000000") is None  # リポジトリが無ければ覚えない
    assert config_service.peek_first_commit("00000000-0000-0000-0000-000000000000") is None
