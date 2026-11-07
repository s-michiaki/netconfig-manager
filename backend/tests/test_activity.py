"""アクティビティログのテスト（収集の結果・違反の発生と解消・通知の結果・保持期間）"""
import asyncio
import json
import uuid
from datetime import timedelta
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.services import notify
from app.services.activity import make_activity
from app.services.audit import purge_old


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        name = f"act-view-{uuid.uuid4().hex[:4]}"
        c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"}, headers=admin)
        yield {"c": c, "admin": admin, "view": login(c, name, "password-1234")}


@pytest.fixture
def r():
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr), \
            mock.patch.object(worker.send_change_notification, "delay"):
        yield fr


def logs(c, h, **params):
    res = c.get("/api/activity/logs", params=params, headers=h)
    assert res.status_code == 200, res.text
    return res.json()["items"]


def device(c, admin, port, password="pw"):
    return c.post("/api/devices/", json=dict(name=f"A-SW-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=port,
                                             platform="cisco_ios", username="admin", password=password),
                  headers=admin).json()


def test_collect_results_are_recorded(ctx, r):
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]
    port, _, _ = fake_sshd.start()
    d = device(c, admin, port)
    # 初回 → 変更なし → 変更あり（同じ ref でまとまる）
    res = worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "ref-1")).get()
    assert res["success"]
    worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "ref-2")).get()
    with mock.patch.object(fake_sshd, "CONFIG", fake_sshd.CONFIG + "\r\nlogging host 192.0.2.9"):
        worker.collect_device_config.apply(args=(d["id"], "schedule", "スケジュール「夜間」", "ref-3")).get()

    items = logs(c, view, device_id=d["id"])  # 閲覧者も見られる
    by_ref = {x["ref"]: x for x in items}
    assert by_ref["ref-1"]["event"] == "collect.first" and by_ref["ref-1"]["actor"] == "admin"
    assert by_ref["ref-2"]["event"] == "collect.unchanged" and by_ref["ref-2"]["level"] == "info"
    changed = by_ref["ref-3"]
    assert changed["event"] == "collect.changed" and "+1 / -0" in changed["message"]
    assert changed["actor"] == "スケジュール「夜間」" and json.loads(changed["detail"])["commit"]
    assert changed["device_name"] == d["name"]
    assert [x["event"] for x in logs(c, view, ref="ref-3")] == ["collect.changed"]

    # 変更なしを記録しない設定
    with mock.patch.object(worker.settings, "ACTIVITY_LOG_UNCHANGED", False), \
            mock.patch.object(fake_sshd, "CONFIG", fake_sshd.CONFIG + "\r\nlogging host 192.0.2.9"):
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "ref-4")).get()
    assert logs(c, view, ref="ref-4") == []

    # 実行中ならスキップを記録
    lock = r.lock(f"netconfig:collect:{d['id']}", timeout=60)
    lock.acquire()
    worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "ref-5")).get()
    lock.release()
    assert logs(c, view, ref="ref-5")[0]["event"] == "collect.skipped"

    # 失敗（認証失敗はリトライしないのでエラー）
    d2 = device(c, admin, port, password="wrong")
    worker.collect_device_config.apply(args=(d2["id"], "manual", "admin", "ref-6")).get()
    failed = logs(c, view, ref="ref-6")[0]
    assert failed["event"] == "collect.failed" and failed["level"] == "error" and "認証失敗" in failed["message"]
    assert any(x["id"] == failed["id"] for x in logs(c, view, level="warning+"))
    assert all(x["level"] == "error" for x in logs(c, view, level="error"))


def test_collect_run_audit_links_to_activity(ctx):
    c, admin = ctx["c"], ctx["admin"]
    port, _, _ = fake_sshd.start()
    d = device(c, admin, port)
    with mock.patch("app.api.devices.collect_device_config") as one:
        one.delay.return_value.id = "task-xyz"
        assert c.post(f"/api/devices/{d['id']}/collect", headers=admin).status_code == 200
        # 実行したユーザー名をきっかけとして渡している
        assert one.delay.call_args.args == (d["id"], "manual", "admin")
    a = c.get("/api/audit/logs", params={"action": "collect.run", "q": d["name"]}, headers=admin).json()["items"][0]
    assert json.loads(a["detail"])["task_id"] == "task-xyz"


def test_compliance_transitions(ctx):
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]
    port, _, _ = fake_sshd.start()
    d = device(c, admin, port)
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr):
        assert worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()["success"]
    rule = c.post("/api/compliance/rules", json={
        "name": f"act-rule-{uuid.uuid4().hex[:4]}", "severity": "high", "match_type": "contains",
        "expect": "present", "pattern": "service password-encryption", "scope": "config", "platforms": ["cisco_ios"],
    }, headers=admin)
    assert rule.status_code in (200, 201), rule.text
    rule = rule.json()
    v = list(logs(c, view, device_id=d["id"], category="compliance"))
    assert v and v[0]["event"] == "compliance.violation" and rule["name"] in v[0]["message"]
    assert v[0]["actor"] == "admin" and "高" in v[0]["message"]
    # ルールを変えて違反が解消
    c.put(f"/api/compliance/rules/{rule['id']}", json={**{k: rule[k] for k in (
        "name", "severity", "match_type", "expect", "scope", "platforms")}, "pattern": "hostname R1"}, headers=admin)
    v = logs(c, view, device_id=d["id"], category="compliance")
    assert v[0]["event"] == "compliance.resolved"
    # 変化が無ければ記録しない
    n = len(v)
    c.post("/api/compliance/run", headers=admin)
    assert len(logs(c, view, device_id=d["id"], category="compliance")) == n
    c.delete(f"/api/compliance/rules/{rule['id']}", headers=admin)


def test_notify_results_are_recorded(ctx, monkeypatch):
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]
    hook = f"https://discord.com/api/webhooks/77/act-{uuid.uuid4().hex[:6]}"
    c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook}, headers=view)
    port, _, _ = fake_sshd.start()
    d = device(c, admin, port)
    monkeypatch.setattr(notify, "send_webhook", lambda k, url, p: None if url != hook else "HTTP 500")

    async def run():
        async with AsyncSessionLocal() as db:
            return await notify.notify_change(db, d["id"], "b" * 40, 1, 0, "manual", ref="ref-ntf")
    asyncio.run(run())
    items = logs(c, view, ref="ref-ntf")
    failed = next(x for x in items if x["event"] == "notify.failed")
    assert failed["level"] == "error" and "HTTP 500" in failed["message"] and hook not in json.dumps(items)
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=view)


def test_purge_and_events(ctx):
    c, view = ctx["c"], ctx["view"]

    async def run():
        async with AsyncSessionLocal() as db:
            old = make_activity("collect.unchanged", "古い記録", ref="ref-old")
            old.at = utcnow() - timedelta(days=400)
            db.add(old)
            await db.commit()
            return await purge_old(db)
    result = asyncio.run(run())
    assert result["activity_logs"] >= 1
    assert logs(c, view, ref="ref-old") == []
    assert logs(c, view, event="system.purge")[0]["level"] == "info"
    ev = c.get("/api/activity/events", headers=view).json()
    assert ev["events"]["collect.changed"] == "収集（変更あり）" and ev["categories"]["compliance"] == "コンプライアンス"
    assert c.get("/api/activity/logs").status_code == 401


def test_csv_export(ctx):
    import csv
    import io
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]

    async def add():
        async with AsyncSessionLocal() as db:
            db.add(make_activity("collect.failed", "=HYPERLINK(\"x\") 失敗", ref="ref-csv", device_name="CSV-SW"))
            await db.commit()
    asyncio.run(add())
    r = c.get("/api/activity/logs/export", params={"ref": "ref-csv"}, headers=view)  # 閲覧者も出力できる
    assert r.status_code == 200, r.text
    assert 'filename="activity_logs_' in r.headers["content-disposition"] and r.content.startswith("﻿".encode())
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][1] == "重要度" and len(rows) == 2
    assert rows[1][1] == "エラー" and rows[1][2] == "収集" and rows[1][4] == "collect.failed"
    assert rows[1][5] == "CSV-SW" and rows[1][6].startswith("'=HYPERLINK")
    a = c.get("/api/audit/logs", params={"action": "activity.export"}, headers=admin).json()["items"][0]
    assert json.loads(a["detail"])["rows"] == 1
    assert c.get("/api/activity/logs/export").status_code == 401
