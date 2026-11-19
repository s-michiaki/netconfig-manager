"""Ping監視の常時監視: 登録・状態・履歴・応答なしと復旧の通知"""
import uuid

import fakeredis
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.api import ping as ping_api
from app.core.config import settings
from app.main import app
from app.services import notify
from app.services import ping_monitor as svc


def login(c, u, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


@pytest.fixture
def env(monkeypatch):
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(worker, "_redis", lambda: r)
    monkeypatch.setattr(ping_api, "_redis_client", lambda: r)
    sent = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: sent.append((kind, url, payload)))
    answers: dict[str, float | None] = {}

    async def fake_ping_many(addresses, timeout=None):
        return {k: answers.get(k) for k in addresses}

    async def fake_resolve(address):
        if address == "no-such-host.invalid":
            raise ValueError("名前解決できません")
        return address

    monkeypatch.setattr(svc, "ping_many", fake_ping_many)
    monkeypatch.setattr(svc, "resolve", fake_resolve)
    monkeypatch.setattr(settings, "PING_ALERT_AFTER", 3)
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        t = uuid.uuid4().hex[:6]
        hook = f"https://discord.com/api/webhooks/970/{t}"
        c.post("/api/users/", json={"username": f"pm-{t}", "password": "password-1234", "role": "viewer"}, headers=admin)
        vh = login(c, f"pm-{t}", "password-1234")
        assert c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": False,
                                                   "on_system": False, "on_inventory": False, "on_ping": True},
                     headers=vh).status_code == 200
        dev = c.post("/api/devices/", json=dict(name=f"pm-sw-{t}", hostname="10.66.0.1", platform="cisco_ios",
                                                username="u", password="p"), headers=admin).json()
        tgt = c.post("/api/ping/targets", json={"name": f"pm-gw-{t}", "address": "10.66.0.254"}, headers=admin).json()
        yield {"c": c, "admin": admin, "viewer": vh, "dev": dev, "tgt": tgt, "answers": answers, "sent": sent,
               "hook": hook, "r": r, "t": t}
        for m in c.get("/api/ping/monitors", headers=admin).json()["items"]:
            c.put(f"/api/ping/monitors/{m['key']}", json={"monitored": False}, headers=admin)
        c.delete(f"/api/devices/{dev['id']}", headers=admin)
        c.delete(f"/api/ping/targets/{tgt['id']}", headers=admin)
        uid = next(u["id"] for u in c.get("/api/users/", headers=admin).json() if u["username"] == f"pm-{t}")
        c.delete(f"/api/users/{uid}", headers=admin)


def mine(env):
    return [p for _, u, p in env["sent"] if u == env["hook"]]


def test_monitor_down_and_recovery(env):
    c, admin, ans = env["c"], env["admin"], env["answers"]
    dk, tk = f"d:{env['dev']['id']}", env["tgt"]["key"]
    # 閲覧者は登録できない。存在しないキーは 404
    assert c.put(f"/api/ping/monitors/{dk}", json={"monitored": True}, headers=env["viewer"]).status_code == 403
    assert c.put("/api/ping/monitors/d:nope", json={"monitored": True}, headers=admin).status_code == 404
    for k in (dk, tk):
        assert c.put(f"/api/ping/monitors/{k}", json={"monitored": True}, headers=admin).status_code == 204
    items = {m["key"]: m for m in c.get("/api/ping/monitors", headers=env["viewer"]).json()["items"]}
    assert items[dk]["status"] == "unknown" and items[tk]["name"] == f"pm-gw-{env['t']}"

    ans[dk], ans[tk] = 1.5, 2.0
    assert worker.ping_monitor.apply().get()["checked"] >= 2
    items = {m["key"]: m for m in c.get("/api/ping/monitors", headers=admin).json()["items"]}
    assert items[dk]["status"] == "up" and items[dk]["last_rtt"] == 1.5 and items[dk]["sent_24h"] == 1

    # 2 回までは「応答なし」にしない。3 回目で通知（2 件を 1 通にまとめる）
    ans[dk] = ans[tk] = None
    worker.ping_monitor.apply().get()
    worker.ping_monitor.apply().get()
    assert mine(env) == []
    items = {m["key"]: m for m in c.get("/api/ping/monitors", headers=admin).json()["items"]}
    assert items[dk]["status"] == "up" and items[dk]["fails"] == 2
    worker.ping_monitor.apply().get()
    (p,) = mine(env)
    emb = p["embeds"][0]
    assert emb["title"] == "Ping監視: 2 件が応答なし" and f"pm-sw-{env['t']}" in emb["description"]
    items = {m["key"]: m for m in c.get("/api/ping/monitors", headers=admin).json()["items"]}
    assert items[dk]["status"] == "down" and items[dk]["since"]
    # 続けて応答が無くても、繰り返し通知しない
    worker.ping_monitor.apply().get()
    assert len(mine(env)) == 1
    # 復旧（1 台だけ）
    ans[dk] = 3.0
    worker.ping_monitor.apply().get()
    emb = mine(env)[-1]["embeds"][0]
    assert emb["title"] == f"Ping監視: 復旧 pm-sw-{env['t']}"
    acts = c.get("/api/activity/logs", params={"device_id": env["dev"]["id"]}, headers=admin).json()["items"]
    events = [a["event"] for a in acts]
    assert "ping.down" in events and "ping.up" in events

    # 履歴: 回数と応答なし
    h = c.get(f"/api/ping/monitors/{dk}/history", params={"hours": 1}, headers=env["viewer"]).json()
    assert h["sent"] == 6 and h["lost"] == 4 and any(b["avg"] for b in h["buckets"])
    assert c.get(f"/api/ping/monitors/{dk}/history", headers=admin).json()["hours"] == 24
    # 外すと履歴も消え、監視しない
    assert c.put(f"/api/ping/monitors/{dk}", json={"monitored": False}, headers=admin).status_code == 204
    assert c.get(f"/api/ping/monitors/{dk}/history", headers=admin).status_code == 404
    assert dk not in [m["key"] for m in c.get("/api/ping/monitors", headers=admin).json()["items"]]
    # 監査ログ
    logs = c.get("/api/audit/logs", params={"action": "ping.monitor_on"}, headers=admin).json()["items"]
    assert any(x["target_id"] == tk for x in logs)


def test_monitor_removed_target_and_unresolvable(env):
    c, admin = env["c"], env["admin"]
    tgt = c.post("/api/ping/targets", json={"name": f"pm-bad-{env['t']}", "address": "no-such-host.invalid"},
                 headers=admin).json()
    assert c.put(f"/api/ping/monitors/{tgt['key']}", json={"monitored": True}, headers=admin).status_code == 204
    for _ in range(3):
        worker.ping_monitor.apply().get()
    items = {m["key"]: m for m in c.get("/api/ping/monitors", headers=admin).json()["items"]}
    assert items[tgt["key"]]["status"] == "down"  # 名前解決できなければ応答なし
    # 追加 IP を消すと、常時監視からも消える
    assert c.delete(f"/api/ping/targets/{tgt['id']}", headers=admin).status_code == 204
    assert tgt["key"] not in [m["key"] for m in c.get("/api/ping/monitors", headers=admin).json()["items"]]
    # 機器を消した場合は、次の実行で worker が監視の登録を消す
    dk = f"d:{env['dev']['id']}"
    c.put(f"/api/ping/monitors/{dk}", json={"monitored": True}, headers=admin)
    c.delete(f"/api/devices/{env['dev']['id']}", headers=admin)
    worker.ping_monitor.apply().get()
    assert dk not in [m["key"] for m in c.get("/api/ping/monitors", headers=admin).json()["items"]]
    assert env["r"].hget(svc.STATE_KEY, dk) is None
