"""構成図（トポロジー）API のテスト"""
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from conftest import TMP


def login(client, username, password):
    r = client.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        for name, role in [("topo-op", "operator"), ("topo-view", "viewer")]:
            assert c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role},
                          headers=admin).status_code == 201
        devs = []
        for i in range(4):
            d = c.post("/api/devices/", json=dict(name=f"topo-{uuid.uuid4().hex[:6]}", hostname=f"10.8.0.{i + 1}",
                                                  platform="cisco_ios", username="u", password="p"), headers=admin)
            devs.append(d.json()["id"])
        yield {
            "c": c, "admin": admin, "op": login(c, "topo-op", "password-1234"),
            "view": login(c, "topo-view", "password-1234"), "devs": devs,
        }


def sample(devs):
    return {
        "nodes": [
            {"id": "n1", "type": "device", "x": 0, "y": 0, "device_id": devs[0], "icon": "l3switch"},
            {"id": "n2", "type": "device", "x": 200, "y": 0, "device_id": devs[1]},
            {"id": "c1", "type": "cloud", "x": 100, "y": -150, "w": 140, "h": 70, "label": "Internet"},
            {"id": "u1", "type": "unmanaged", "x": 400, "y": 0, "label": "ISPルーター", "note": "203.0.113.1", "icon": "router"},
            {"id": "t1", "type": "text", "x": 0, "y": 200, "label": "本社 2F", "font_size": "l", "color": "#e4e6f0"},
            {"id": "g1", "type": "group", "x": -40, "y": -40, "w": 400, "h": 200, "label": "DMZ", "color": "#4f8ef7"},
        ],
        "edges": [
            {"id": "e1", "source": "n1", "target": "n2", "source_port": "Gi1/0/1", "target_port": "Gi0/1",
             "label": "Po1", "line_style": "solid"},
            {"id": "e2", "source": "c1", "target": "n1", "line_style": "dashed"},
            {"id": "e3", "source": "n2", "target": "u1", "source_port": "Gi0/2", "target_port": "LAN1"},
        ],
        "viewport": {"x": 10, "y": 20, "zoom": 1.2},
    }


def test_crud_and_roles(ctx):
    c, admin, op, view, devs = ctx["c"], ctx["admin"], ctx["op"], ctx["view"], ctx["devs"]
    # viewer は閲覧のみ
    assert c.post("/api/topology/maps", json={"name": "v"}, headers=view).status_code == 403
    r = c.post("/api/topology/maps", json={"name": "本社ネットワーク", "description": "1F〜4F"}, headers=op)
    assert r.status_code == 201, r.text
    m = r.json()
    assert m["version"] == 1 and m["data"]["nodes"] == [] and m["updated_by"] == "topo-op"
    assert c.post("/api/topology/maps", json={"name": "本社ネットワーク"}, headers=op).status_code == 409

    url = f"/api/topology/maps/{m['id']}"
    r = c.put(url, json={"version": 1, "data": sample(devs)}, headers=op)
    assert r.status_code == 200, r.text
    m2 = r.json()
    assert m2["version"] == 2
    assert len(m2["data"]["nodes"]) == 6 and len(m2["data"]["edges"]) == 3
    u = next(n for n in m2["data"]["nodes"] if n["id"] == "u1")
    assert u["type"] == "unmanaged" and u["note"] == "203.0.113.1" and u["icon"] == "router"
    assert m2["data"]["edges"][0]["source_port"] == "Gi1/0/1"
    assert m2["data"]["viewport"]["zoom"] == 1.2
    assert m2["data"]["nodes"][0]["icon"] == "l3switch" and m2["data"]["nodes"][1]["icon"] is None
    assert set(m2["devices"]) == {devs[0], devs[1]}
    assert m2["devices"][devs[0]]["status"] == "never"

    # 古い version での保存は 409（他の人の変更を上書きしない）
    r = c.put(url, json={"version": 1, "data": {"nodes": [], "edges": []}}, headers=admin)
    assert r.status_code == 409 and "topo-op" in r.json()["detail"]
    # 名前だけ変更（data は変わらない）
    r = c.put(url, json={"version": 2, "name": "本社"}, headers=admin)
    assert r.json()["name"] == "本社" and len(r.json()["data"]["nodes"]) == 6

    # viewer は読めるが書けない
    assert c.get(url, headers=view).status_code == 200
    assert c.put(url, json={"version": 3, "name": "x"}, headers=view).status_code == 403
    lst = c.get("/api/topology/maps", headers=view).json()
    s = next(x for x in lst if x["id"] == m["id"])
    assert s["node_count"] == 6 and s["device_count"] == 2  # 非管理機器は登録機器数に含めない

    # 複製
    r = c.post("/api/topology/maps", json={"name": "本社（コピー）", "copy_from": m["id"]}, headers=op)
    assert r.status_code == 201 and len(r.json()["data"]["nodes"]) == 6

    # 削除
    assert c.delete(url, headers=view).status_code == 403
    assert c.delete(url, headers=op).status_code == 204
    assert c.get(url, headers=admin).status_code == 404


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d["nodes"].append(dict(d["nodes"][0])), "ノードIDが重複"),
    (lambda d: d["nodes"].append({"id": "n9", "type": "device", "x": 0, "y": 0, "device_id": d["nodes"][0]["device_id"]}),
     "同じ機器"),
    (lambda d: d["nodes"].append({"id": "n9", "type": "device", "x": 0, "y": 0}), "device_id"),
    (lambda d: d["edges"].append({"id": "e9", "source": "n1", "target": "zz"}), "存在しないノード"),
    (lambda d: d["edges"].append({"id": "e9", "source": "n1", "target": "n1"}), "同じノード"),
    (lambda d: d["nodes"][2].update(color="red; background:url(x)"), None),
    (lambda d: d["nodes"][0].update(id="<script>"), None),
    (lambda d: d["nodes"][3].update(note="x" * 201), None),
    (lambda d: d["nodes"][3].update(icon="toaster"), None),
])
def test_validation(ctx, mutate, msg):
    c, op, devs = ctx["c"], ctx["op"], ctx["devs"]
    m = c.post("/api/topology/maps", json={"name": f"v-{uuid.uuid4().hex[:6]}"}, headers=op).json()
    data = sample(devs)
    mutate(data)
    r = c.put(f"/api/topology/maps/{m['id']}", json={"version": 1, "data": data}, headers=op)
    assert r.status_code == 422, r.text
    if msg:
        assert msg in r.text


def test_device_status_and_deleted_device(ctx):
    c, admin, op, devs = ctx["c"], ctx["admin"], ctx["op"], ctx["devs"]
    m = c.post("/api/topology/maps", json={"name": f"s-{uuid.uuid4().hex[:6]}"}, headers=op).json()
    data = {
        "nodes": [{"id": f"n{i}", "type": "device", "x": i * 100, "y": 0, "device_id": d} for i, d in enumerate(devs)],
        "edges": [{"id": "e1", "source": "n2", "target": "n3"}, {"id": "e2", "source": "n0", "target": "n1"}],
    }
    url = f"/api/topology/maps/{m['id']}"
    assert c.put(url, json={"version": 1, "data": data}, headers=op).status_code == 200

    db = sqlite3.connect(f"{TMP}/t.db")
    ins = "insert into collect_logs (id, device_id, status, message, started_at, finished_at) values (?,?,?,?,?,?)"
    # devs[0]: 成功（変更なし）。古い世代はあるが、最後の収集より前
    db.execute("insert into config_snapshots (id, device_id, commit_hash, collected_at, lines_added, lines_removed, "
               "triggered_by) values (?,?,?,?,?,?,?)",
               (str(uuid.uuid4()), devs[0], "a" * 40, "2026-10-29 08:00:05.000000", 1, 0, "manual"))
    db.execute(ins, (str(uuid.uuid4()), devs[0], "success", None, "2026-10-30 09:00:00.000000", "2026-10-30 09:00:10.000000"))
    # devs[1]: 最後の収集で新しい世代 → 変更あり
    db.execute(ins, (str(uuid.uuid4()), devs[1], "failed", "x", "2026-10-29 09:00:00.000000", None))
    db.execute(ins, (str(uuid.uuid4()), devs[1], "success", None, "2026-10-30 09:00:00.000000", "2026-10-30 09:00:10.000000"))
    db.execute("insert into config_snapshots (id, device_id, commit_hash, collected_at, lines_added, lines_removed, "
               "triggered_by) values (?,?,?,?,?,?,?)",
               (str(uuid.uuid4()), devs[1], "b" * 40, "2026-10-30 09:00:10.000000", 3, 1, "schedule"))
    # devs[2]: 最後の収集が失敗
    db.execute(ins, (str(uuid.uuid4()), devs[2], "success", None, "2026-10-29 09:00:00.000000", "2026-10-29 09:00:10.000000"))
    db.execute(ins, (str(uuid.uuid4()), devs[2], "failed", "タイムアウトまたは接続不可", "2026-10-30 09:00:00.000000",
                     "2026-10-30 09:00:30.000000"))
    db.commit()

    st = c.get(f"{url}/status", headers=ctx["view"]).json()
    assert st[devs[0]]["status"] == "ok"
    assert st[devs[1]]["status"] == "changed"
    assert st[devs[2]]["status"] == "failed" and "タイムアウト" in st[devs[2]]["last_message"]
    assert st[devs[3]]["status"] == "never"
    assert c.post("/api/topology/device-status", json=[devs[2]], headers=ctx["view"]).json()[devs[2]]["status"] == "failed"

    # 機器を削除すると、構成図からノードとその接続線が消える
    assert c.delete(f"/api/devices/{devs[3]}", headers=admin).status_code == 204
    got = c.get(url, headers=admin).json()
    assert [n["id"] for n in got["data"]["nodes"]] == ["n0", "n1", "n2"]
    assert [e["id"] for e in got["data"]["edges"]] == ["e2"]
    # 削除済み機器を含む古い画面から保存しても落とされる
    r = c.put(url, json={"version": got["version"], "data": data}, headers=op)
    assert r.status_code == 200 and len(r.json()["data"]["nodes"]) == 3
