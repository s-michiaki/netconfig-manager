"""ダッシュボードの要約"""
import asyncio
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient

from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.device import CollectLog, ConfigSnapshot


def login(c, u, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


def test_dashboard_summary():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        uid = uuid.uuid4().hex[:6]
        ids = {}
        for n in ("ok", "ng", "new", "off"):
            ids[n] = c.post("/api/devices/", json=dict(name=f"dash-{n}-{uid}", hostname="10.8.0.1", platform="cisco_ios",
                                                       username="u", password="p"), headers=admin).json()["id"]
        c.put(f"/api/devices/{ids['off']}", json={"is_active": False}, headers=admin)
        g = c.post("/api/device-groups/", json={"name": f"dash-g-{uid}"}, headers=admin).json()
        c.post("/api/schedules/", json={"name": f"dash-s-{uid}", "cron_expression": "0 1 * * *", "target": f"group:{g['id']}"},
               headers=admin)
        before = c.get("/api/dashboard", headers=admin).json()

        async def seed():
            now = utcnow()
            async with AsyncSessionLocal() as db:
                # ok: 失敗のあと成功（最新が成功）。ng: 成功のあと失敗（最新が失敗）。off（無効）は失敗でも数えない
                db.add_all([
                    CollectLog(device_id=ids["ok"], status="failed", message="old", started_at=now - timedelta(hours=3)),
                    CollectLog(device_id=ids["ok"], status="success", started_at=now - timedelta(hours=1),
                               finished_at=now - timedelta(hours=1)),
                    CollectLog(device_id=ids["ng"], status="success", started_at=now - timedelta(hours=5)),
                    CollectLog(device_id=ids["ng"], status="failed", message="認証に失敗しました", started_at=now - timedelta(hours=2),
                               finished_at=now - timedelta(hours=2)),
                    CollectLog(device_id=ids["off"], status="failed", message="x", started_at=now),
                    ConfigSnapshot(device_id=ids["ok"], commit_hash="a" * 40, collected_at=now - timedelta(hours=1),
                                   lines_added=4, lines_removed=1, triggered_by="schedule"),
                    ConfigSnapshot(device_id=ids["ok"], commit_hash="b" * 40, collected_at=now - timedelta(days=3),
                                   lines_added=9, lines_removed=0, triggered_by="manual"),
                ])
                await db.commit()
        asyncio.run(seed())
        d = c.get("/api/dashboard", headers=admin).json()
        dv, b = d["devices"], before["devices"]
        assert dv["total"] - b["total"] == 0 and dv["inactive"] >= 1
        assert dv["failing"] - b["failing"] == 1 and dv["never"] - b["never"] == -2  # ok・ng が「未収集」でなくなった
        failing = {x["name"]: x for x in d["failing"]}
        assert failing[f"dash-ng-{uid}"]["message"] == "認証に失敗しました"
        assert f"dash-ok-{uid}" not in failing and f"dash-off-{uid}" not in failing
        assert f"dash-new-{uid}" in [x["name"] for x in d["never"]]
        ch = d["changes"]
        assert ch["last_24h"] - before["changes"]["last_24h"] == 1 and ch["last_7d"] - before["changes"]["last_7d"] == 2
        # ほかのテストが作った新しい世代が先頭に来ることがあるので、機器名で探す
        mine = [x for x in ch["recent"] if x["device_name"] == f"dash-ok-{uid}"]
        assert mine[0] == {**mine[0], "added": 4, "removed": 1, "commit": "aaaaaaaa", "triggered_by": "schedule"}
        assert [x["at"] for x in ch["recent"]] == sorted((x["at"] for x in ch["recent"]), reverse=True)
        s = [x for x in d["schedules"]["upcoming"] if x["name"] == f"dash-s-{uid}"] or d["schedules"]["upcoming"]
        assert d["schedules"]["active"] >= 1 and s[0]["next_run"] and "kind" in s[0]
        assert set(d["compliance"]["by_severity"]) == {"high", "medium", "low"}
        # 閲覧者も見られる
        name = f"dashv-{uid}"
        c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"}, headers=admin)
        assert c.get("/api/dashboard", headers=login(c, name, "password-1234")).status_code == 200
        assert c.get("/api/dashboard").status_code == 401
