"""Ping監視のテスト"""
import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import ping as ping_api
from app.main import app
from app.services import ping as ping_service


def login(c, u, p):
    return c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]


def hdr(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        for u, role in [("png-op", "operator"), ("png-view", "viewer")]:
            c.post("/api/users/", json={"username": u, "password": "password-1234", "role": role}, headers=hdr(admin))
        yield {"c": c, "admin": admin, "op": login(c, "png-op", "password-1234"),
               "view": login(c, "png-view", "password-1234")}


def test_valid_address():
    for ok in ["10.0.0.1", "2001:db8::1", "router1", "core-sw.example.local", "a.b.c."]:
        assert ping_service.valid_address(ok), ok
    for ng in ["", "10.0.0.1;rm", "-bad", "a..b", "x" * 254, "host name", "1.2.3.4/24"]:
        assert not ping_service.valid_address(ng), ng


def test_target_crud_and_permissions(ctx):
    c, admin, op, view = ctx["c"], hdr(ctx["admin"]), hdr(ctx["op"]), hdr(ctx["view"])
    grp = c.post("/api/device-groups/", json={"name": f"PING-{uuid.uuid4().hex[:4]}"}, headers=admin).json()
    dev = c.post("/api/devices/", json=dict(name=f"p-{uuid.uuid4().hex[:6]}", hostname="192.0.2.10",
                                            platform="cisco_ios", username="u", password="p", group_id=grp["id"]),
                 headers=admin).json()

    # 閲覧者は一覧のみ、追加はオペレーター以上
    body = {"name": "GW", "address": "192.0.2.1", "group_id": grp["id"], "description": "既定ゲートウェイ"}
    assert c.post("/api/ping/targets", json=body, headers=view).status_code == 403
    t = c.post("/api/ping/targets", json=body, headers=op)
    assert t.status_code == 201, t.text
    t = t.json()
    assert t["key"] == f"t:{t['id']}" and t["kind"] == "custom" and t["created_by"] == "png-op"
    assert c.post("/api/ping/targets", json={"name": "x", "address": "1.1.1.1;ls"}, headers=op).status_code == 422
    assert c.post("/api/ping/targets", json={"name": "x", "address": "1.1.1.1", "group_id": "nope"},
                  headers=op).status_code == 422

    lst = c.get("/api/ping/targets", headers=view).json()
    keys = {x["key"]: x for x in lst["targets"]}
    assert keys[f"d:{dev['id']}"]["address"] == "192.0.2.10" and keys[f"d:{dev['id']}"]["group_id"] == grp["id"]
    assert keys[t["key"]]["address"] == "192.0.2.1"
    assert any(g["id"] == grp["id"] for g in lst["groups"]) and lst["max_targets"] >= 1

    r = c.put(f"/api/ping/targets/{t['id']}", json={"name": "GW2", "address": "gw.example.local"}, headers=op)
    assert r.status_code == 200 and r.json()["address"] == "gw.example.local" and r.json()["group_id"] is None
    assert c.put(f"/api/ping/targets/{t['id']}", json={"name": "a", "address": "1.1.1.1"}, headers=view).status_code == 403

    # グループを消すと追加IPは未分類に戻る
    c.put(f"/api/ping/targets/{t['id']}", json={"name": "GW2", "address": "192.0.2.1", "group_id": grp["id"]}, headers=op)
    assert c.delete(f"/api/device-groups/{grp['id']}", headers=admin).status_code == 204
    keys = {x["key"]: x for x in c.get("/api/ping/targets", headers=view).json()["targets"]}
    assert keys[t["key"]]["group_id"] is None

    # 操作履歴に残る
    logs = c.get("/api/audit/logs", params={"action": "ping.target_create"}, headers=admin).json()["items"]
    assert any(x["target_id"] == t["id"] for x in logs)

    assert c.delete(f"/api/ping/targets/{t['id']}", headers=view).status_code == 403
    assert c.delete(f"/api/ping/targets/{t['id']}", headers=op).status_code == 204
    assert c.delete(f"/api/ping/targets/{t['id']}", headers=op).status_code == 404


def test_ws_requires_auth(ctx):
    c = ctx["c"]
    with c.websocket_connect("/api/ping/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": "bad"}))
        with pytest.raises(Exception):
            ws.receive_text()


def test_ws_streams_results(ctx, monkeypatch):
    """登録した対象のキーだけを受け付け、間隔ごとに結果を返す（PING 自体は差し替え）"""
    c, op = ctx["c"], hdr(ctx["op"])
    up = c.post("/api/ping/targets", json={"name": "up", "address": "192.0.2.50"}, headers=op).json()
    down = c.post("/api/ping/targets", json={"name": "down", "address": "192.0.2.51"}, headers=op).json()
    bad = c.post("/api/ping/targets", json={"name": "bad", "address": "no-such-host.invalid"}, headers=op).json()

    seen: list[dict] = []

    async def fake_ping_many(addresses, timeout=None):
        seen.append(dict(addresses))
        return {k: (1.5 if ip == "192.0.2.50" else None) for k, ip in addresses.items()}

    async def fake_resolve(address):
        if address.endswith(".invalid"):
            raise ValueError("名前解決できません")
        return address

    monkeypatch.setattr(ping_api, "ping_many", fake_ping_many)
    monkeypatch.setattr(ping_api, "resolve", fake_resolve)

    with c.websocket_connect("/api/ping/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": ctx["view"]}))
        ws.send_text(json.dumps({"type": "start", "interval": 1,
                                 "keys": [up["key"], down["key"], bad["key"], "t:not-exist", "x:evil"]}))
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "targets"
        items = {x["key"]: x for x in msg["items"]}
        assert set(items) == {up["key"], down["key"], bad["key"]}
        assert items[bad["key"]]["ip"] is None and "名前解決" in items[bad["key"]]["error"]
        tick = json.loads(ws.receive_text())
        assert tick == {"type": "tick", "seq": 1, "results": {up["key"]: 1.5, down["key"]: None}}
        assert json.loads(ws.receive_text())["seq"] == 2
        ws.send_text(json.dumps({"type": "stop"}))
    # 送ったのはサーバー側で引いたアドレスだけ
    assert all(set(s.values()) <= {"192.0.2.50", "192.0.2.51"} for s in seen)


def test_ws_reports_unavailable(ctx, monkeypatch):
    c, op = ctx["c"], hdr(ctx["op"])
    t = c.post("/api/ping/targets", json={"name": "u", "address": "192.0.2.60"}, headers=op).json()

    async def unavailable(addresses, timeout=None):
        raise ping_service.PingUnavailable("NET_RAW が必要です")

    monkeypatch.setattr(ping_api, "ping_many", unavailable)
    with c.websocket_connect("/api/ping/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": ctx["view"]}))
        ws.send_text(json.dumps({"type": "start", "keys": [t["key"]]}))
        assert json.loads(ws.receive_text())["type"] == "targets"
        err = json.loads(ws.receive_text())
        assert err["type"] == "error" and "NET_RAW" in err["message"]


def test_real_ping_localhost():
    """実際に 127.0.0.1 へ PING する（ICMP を送れない環境ではスキップ）"""
    try:
        r = asyncio.run(ping_service.ping_many({"lo": "127.0.0.1"}, timeout=1))
    except ping_service.PingUnavailable:
        pytest.skip("この環境では ICMP を送れない")
    assert r["lo"] is not None and r["lo"] >= 0
