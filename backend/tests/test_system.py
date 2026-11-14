"""システムの状態の確認と、異常の通知（ウォッチドッグ）"""
import asyncio
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.device import CollectLog
from app.services import login_limit, notify, system

SLACK = "https://hooks.slack.com/services/T000/B000/systemtest"


def token(c, user, pw):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": user, "password": pw}).json()["access_token"]}


@pytest.fixture
def ctx(monkeypatch):
    monkeypatch.setattr(system, "ping_workers", lambda timeout=1.5: ["celery@test"])
    real_disk = system.check_disk
    # テストを動かす環境のディスクの空きに左右されないようにする
    monkeypatch.setattr(system, "check_disk", lambda: system.Component("disk", "ディスクの空き", "ok", "ok"))
    sent = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: sent.append((kind, url, payload)) and None)
    with TestClient(app) as c:
        admin = token(c, "admin", "initial-pass-123")
        yield {"c": c, "admin": admin, "sent": sent, "real_disk": real_disk}


def beat(now=None):
    asyncio.run(login_limit.client().set(system.HEARTBEAT_KEY, (now or utcnow()).isoformat()))


def tick(wd, now=None):
    async def run():
        async with AsyncSessionLocal() as db:
            return await wd.tick(db, now)
    return asyncio.run(run())


def by_key(c, admin):
    r = c.get("/api/system/status", headers=admin)
    assert r.status_code == 200
    return r.json(), {x["key"]: x for x in r.json()["components"]}


def test_status_and_permission(ctx):
    c, admin = ctx["c"], ctx["admin"]
    name = f"sysv-{uuid.uuid4().hex[:6]}"
    c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"}, headers=admin)
    assert c.get("/api/system/status", headers=token(c, name, "password-1234")).status_code == 403
    # スケジューラーからの定期実行がまだ届いていない
    data, comp = by_key(c, admin)
    assert comp["db"]["status"] == comp["redis"]["status"] == comp["worker"]["status"] == "ok"
    assert comp["beat"]["status"] == "error" and data["overall"] == "error"
    assert comp["cert"]["status"] == "unknown"
    disk = ctx["real_disk"]()
    assert disk.status in ("ok", "warn", "error") and disk.detail["volumes"][0]["total_gb"] > 0
    beat()
    data, comp = by_key(c, admin)
    assert comp["beat"]["status"] == "ok"
    beat(utcnow() - timedelta(minutes=10))  # 定期実行が 10 分前で止まっている
    assert by_key(c, admin)[1]["beat"]["status"] == "error"


def test_worker_down_and_redis_down(ctx, monkeypatch):
    c, admin = ctx["c"], ctx["admin"]
    beat()
    monkeypatch.setattr(system, "ping_workers", lambda timeout=1.5: [])
    comp = by_key(c, admin)[1]
    assert comp["worker"]["status"] == "error" and comp["beat"]["status"] == "unknown"

    def broken(timeout=1.5):  # 依存パッケージの不具合で Celery が Redis に接続できない（kombu 5.7.0 で実際に起きた）
        raise ModuleNotFoundError("No module named 'packaging'")
    monkeypatch.setattr(system, "ping_workers", broken)
    w = by_key(c, admin)[1]["worker"]
    assert w["status"] == "error" and "packaging" in w["summary"]

    class Down:
        async def ping(self):
            raise RedisConnectionError("down")
        get = hgetall = hset = ttl = ping

        def pipeline(self, **kw):
            raise RedisConnectionError("down")
    monkeypatch.setattr(login_limit, "_client", Down())
    comp = by_key(c, admin)[1]
    assert comp["redis"]["status"] == "error" and comp["worker"]["status"] == "unknown"


def test_stale_devices(ctx, monkeypatch):
    c, admin = ctx["c"], ctx["admin"]
    monkeypatch.setattr(settings, "SYSTEM_STALE_DAYS", 7)
    names = [f"stale-{uuid.uuid4().hex[:6]}" for _ in range(2)]
    ids = [c.post("/api/devices/", json=dict(name=n, hostname="10.7.0.1", platform="cisco_ios", username="u", password="p"),
                  headers=admin).json()["id"] for n in names]

    async def add_log(device_id, days_ago):
        async with AsyncSessionLocal() as db:
            at = utcnow() - timedelta(days=days_ago)
            db.add(CollectLog(device_id=device_id, status="success", started_at=at, finished_at=at))
            await db.commit()
    asyncio.run(add_log(ids[0], 10))  # 10 日前に成功したきり
    asyncio.run(add_log(ids[1], 1))
    col = by_key(c, admin)[1]["collect"]
    stale = [d["name"] for d in col["detail"]["devices"]]
    assert col["status"] == "warn" and names[0] in stale and names[1] not in stale
    # 無効にした機器は対象外
    c.put(f"/api/devices/{ids[0]}", json={"is_active": False}, headers=admin)
    assert names[0] not in [d["name"] for d in by_key(c, admin)[1]["collect"]["detail"]["devices"]]
    monkeypatch.setattr(settings, "SYSTEM_STALE_DAYS", 0)
    assert by_key(c, admin)[1]["collect"]["status"] == "ok"


def test_watchdog_alerts_once_and_recovers(ctx, monkeypatch):
    c, admin, sent = ctx["c"], ctx["admin"], ctx["sent"]
    monkeypatch.setattr(settings, "SYSTEM_STALE_DAYS", 0)
    monkeypatch.setattr(settings, "SYSTEM_ALERT_AFTER_MIN", 10)
    # 通知先: 対象の機器グループを絞っていても、システムの異常は届く
    r = c.put("/api/notifications/me", json={"mode": "custom", "slack_webhook": SLACK, "all_devices": False,
                                             "include_ungrouped": True, "on_change": False, "on_system": True}, headers=admin)
    assert r.status_code == 200, r.text
    beat()
    wd, t0 = system.Watchdog(), utcnow()
    assert tick(wd, t0) == [] and not sent
    monkeypatch.setattr(system, "ping_workers", lambda timeout=1.5: [])  # worker が止まった
    assert tick(wd, t0 + timedelta(minutes=1)) == []  # 一時的な停止（再起動中など）では通知しない
    assert tick(wd, t0 + timedelta(minutes=9)) == [] and not sent
    assert tick(wd, t0 + timedelta(minutes=11)) == [("worker", "alert")]
    assert len(sent) == 1 and "worker" in sent[0][2]["text"] and "システムの異常" in sent[0][2]["text"]
    assert tick(wd, t0 + timedelta(minutes=12)) == [] and len(sent) == 1  # 同じ異常は繰り返し通知しない
    # API を再起動しても（状態は Redis にある）、同じ通知を繰り返さない
    wd2 = system.Watchdog()
    tick(wd2, t0 + timedelta(minutes=13))
    assert tick(wd2, t0 + timedelta(minutes=30)) == [] and len(sent) == 1
    monkeypatch.setattr(system, "ping_workers", lambda timeout=1.5: ["celery@test"])
    beat(t0 + timedelta(minutes=31))
    assert tick(wd2, t0 + timedelta(minutes=31)) == [("worker", "recovered")]
    assert len(sent) == 2 and "復旧" in sent[1][2]["text"]
    acts = c.get("/api/activity/logs", params={"category": "system", "limit": 20}, headers=admin).json()
    events = [x["event"] for x in (acts["items"] if isinstance(acts, dict) else acts)]
    assert "system.alert" in events and "system.recovered" in events
    # on_system を外した設定には送らない
    c.put("/api/notifications/me", json={"mode": "custom", "slack_webhook": SLACK, "on_change": True, "on_system": False},
          headers=admin)
    monkeypatch.setattr(system, "ping_workers", lambda timeout=1.5: [])
    wd3 = system.Watchdog()
    tick(wd3, t0 + timedelta(minutes=40))
    assert tick(wd3, t0 + timedelta(minutes=55)) == [("worker", "alert")] and len(sent) == 2
    c.put("/api/notifications/me", json={"mode": "off", "slack_webhook": ""}, headers=admin)  # ほかのテストに残さない


def test_watchdog_stale_devices_and_cert(ctx, monkeypatch):
    c, admin, sent = ctx["c"], ctx["admin"], ctx["sent"]
    monkeypatch.setattr(settings, "SYSTEM_STALE_DAYS", 7)
    c.put("/api/notifications/me", json={"mode": "custom", "slack_webhook": SLACK, "on_change": False, "on_system": True},
          headers=admin)
    beat()
    name = f"old-{uuid.uuid4().hex[:6]}"
    c.post("/api/devices/", json=dict(name=name, hostname="10.7.0.2", platform="cisco_ios", username="u", password="p"),
           headers=admin)
    wd, now = system.Watchdog(), utcnow()
    tick(wd, now)
    sent.clear()
    # 登録から 8 日たっても一度も収集できていない機器 → すぐに通知（猶予なし）。翌日以降は増えたときだけ
    assert ("collect", "alert") in tick(wd, now + timedelta(days=8))
    # （ほかのテストが登録した機器も対象になるため、機器名は一覧の上限に入らないことがある）
    assert len(sent) == 1 and "収集できていません" in sent[0][2]["text"] and "機器:" in sent[0][2]["text"]
    beat(now + timedelta(days=9))
    assert ("collect", "alert") not in tick(wd, now + timedelta(days=9))
    # 証明書: 期限が近づいたら1回、さらに近づいたらもう1回
    monkeypatch.setattr(settings, "SYSTEM_CERT_ENDPOINT", "frontend:443")
    base = now + timedelta(days=9)
    monkeypatch.setattr(system, "fetch_cert_expiry", lambda h, p: base + timedelta(days=20))
    beat(base)
    assert ("cert", "alert") in tick(wd, base)
    assert ("cert", "alert") not in tick(wd, base)
    monkeypatch.setattr(system, "fetch_cert_expiry", lambda h, p: base + timedelta(days=5))
    assert ("cert", "alert") in tick(wd, base)
    monkeypatch.setattr(system, "fetch_cert_expiry", lambda h, p: base + timedelta(days=300))
    assert ("cert", "recovered") in tick(wd, base)
    c.put("/api/notifications/me", json={"mode": "off", "slack_webhook": ""}, headers=admin)  # ほかのテストに残さない
