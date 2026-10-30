"""機器のグループのテスト"""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        c.post("/api/users/", json={"username": "grp-op", "password": "password-1234", "role": "operator"}, headers=admin)
        yield {"c": c, "admin": admin, "op": login(c, "grp-op", "password-1234")}


def dev(c, h, **kw):
    body = dict(name=f"g-{uuid.uuid4().hex[:6]}", hostname="10.5.0.1", platform="cisco_ios", username="u", password="p")
    body.update(kw)
    r = c.post("/api/devices/", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_group_crud_and_membership(ctx):
    c, admin, op = ctx["c"], ctx["admin"], ctx["op"]
    # 作成は管理者のみ（機器の編集と同じ権限）、閲覧はオペレーターも可
    assert c.post("/api/device-groups/", json={"name": "x"}, headers=op).status_code == 403
    tokyo = c.post("/api/device-groups/", json={"name": f"東京-{uuid.uuid4().hex[:4]}", "color": "#4f8ef7",
                                                 "description": "本社"}, headers=admin).json()
    osaka = c.post("/api/device-groups/", json={"name": f"大阪-{uuid.uuid4().hex[:4]}"}, headers=admin).json()
    assert c.post("/api/device-groups/", json={"name": tokyo["name"]}, headers=admin).status_code == 409
    assert c.post("/api/device-groups/", json={"name": "y", "color": "red"}, headers=admin).status_code == 422

    d1 = dev(c, admin, group_id=tokyo["id"])
    assert d1["group_id"] == tokyo["id"] and d1["group_name"] == tokyo["name"]
    d2 = dev(c, admin)
    assert d2["group_id"] is None and d2["group_name"] is None
    assert c.post("/api/devices/", json=dict(name="g-bad", hostname="h", platform="cisco_ios", username="u",
                                             password="p", group_id=str(uuid.uuid4())), headers=admin).status_code == 422

    # 編集で所属を変える（1台は1グループのみ）。他の項目だけの更新では所属は変わらない
    r = c.put(f"/api/devices/{d1['id']}", json={"group_id": osaka["id"]}, headers=admin).json()
    assert r["group_id"] == osaka["id"]
    r = c.put(f"/api/devices/{d1['id']}", json={"description": "x"}, headers=admin).json()
    assert r["group_id"] == osaka["id"]
    r = c.put(f"/api/devices/{d1['id']}", json={"group_id": None}, headers=admin).json()
    assert r["group_id"] is None

    # まとめて移動
    r = c.post("/api/device-groups/assign", json={"device_ids": [d1["id"], d2["id"]], "group_id": tokyo["id"]},
               headers=admin)
    assert r.status_code == 200 and r.json()["updated"] == 2
    assert c.post("/api/device-groups/assign", json={"device_ids": [d1["id"]], "group_id": tokyo["id"]},
                  headers=op).status_code == 403
    assert c.post("/api/device-groups/assign", json={"device_ids": [str(uuid.uuid4())], "group_id": None},
                  headers=admin).status_code == 404
    groups = {g["id"]: g for g in c.get("/api/device-groups/", headers=op).json()}
    assert groups[tokyo["id"]]["device_count"] == 2 and groups[osaka["id"]]["device_count"] == 0
    assert groups[tokyo["id"]]["description"] == "本社"

    # 名前変更は一覧の表示名に反映される
    new_name = f"東京本社-{uuid.uuid4().hex[:4]}"
    r = c.put(f"/api/device-groups/{tokyo['id']}", json={"name": new_name, "color": "#34d399"}, headers=admin)
    assert r.status_code == 200 and r.json()["device_count"] == 2
    names = {d["id"]: d["group_name"] for d in c.get("/api/devices/", headers=op).json()}
    assert names[d1["id"]] == new_name

    # グループを削除すると、所属機器は未分類に戻る（機器は消えない）
    assert c.delete(f"/api/device-groups/{tokyo['id']}", headers=admin).status_code == 204
    after = {d["id"]: d for d in c.get("/api/devices/", headers=op).json()}
    assert after[d1["id"]]["group_id"] is None and after[d2["id"]]["group_id"] is None

    # 監査ログ
    acts = c.get("/api/audit/logs", params={"action": "device_group."}, headers=admin).json()["items"]
    assert {"device_group.create", "device_group.update", "device_group.delete"} <= {a["action"] for a in acts}
    deleted = next(a for a in acts if a["action"] == "device_group.delete")
    assert '"moved_to_ungrouped": 2' in deleted["detail"]
