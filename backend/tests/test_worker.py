import asyncio
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

import fake_sshd
import fakeredis
import git
import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.main import app


@pytest.fixture
def r():
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr): yield fr

def _client_device(port):
    c = TestClient(app); c.__enter__()
    tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    d = c.post("/api/devices/", json=dict(name=f"w-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=port, platform="cisco_ios", username="admin", password="pw"), headers=h).json()
    return c, d["id"]

def test_collect_task(r):
    port, _, _ = fake_sshd.start()
    c, did = _client_device(port)
    res = worker.collect_device_config.apply(args=(did, "schedule")).get()
    assert res["success"] and res["commit_hash"], res
    db = sqlite3.connect(f"{TMP}/t.db")
    assert db.execute("select triggered_by from config_snapshots where device_id=?", (did,)).fetchone()[0] == "schedule"
    assert db.execute("select status from collect_logs where device_id=?", (did,)).fetchone()[0] == "success"
    # ロック取得中は二重実行しない
    lock = r.lock(f"netconfig:collect:{did}", timeout=60); lock.acquire()
    assert worker.collect_device_config.apply(args=(did,)).get()["skipped"]
    lock.release()
    # 2回目の実行（別イベントループ）でもDBアクセスできる
    assert worker.collect_device_config.apply(args=(did,)).get()["success"]
    # 同じ機器への別の SSH 処理（FW ヒット数の取得など）が終わらなければ、収集は待ったうえで再試行に回す
    ssh = r.lock(f"netconfig:ssh:{did}", timeout=60); ssh.acquire()
    with mock.patch.object(worker, "SSH_LOCK_WAIT", 0.3), \
            mock.patch.object(worker.collect_device_config, "max_retries", 0):
        res = worker.collect_device_config.apply(args=(did,)).get()
    assert not res["success"] and "SSH" in res["error"]
    # FW ヒット数の取得は、収集中（SSH ロック中）なら取らずに次回へ
    assert worker.collect_fw_hits_device.apply(args=(did,)).get() == {"skipped": True}
    ssh.release()
    c.__exit__(None, None, None)


def test_snmp_poll_runs_one_at_a_time(r):
    with mock.patch.object(worker.settings, "MONITORING_ENABLED", True):
        lock = r.lock("netconfig:snmp-poll", timeout=60); lock.acquire()
        assert worker.poll_snmp.apply().get() == {"skipped": True}
        lock.release()
        assert "skipped" not in worker.poll_snmp.apply().get()

def test_dispatch(r):
    asyncio.run(_add_schedule("17 3 * * *"))  # 他のテストと重ならない時刻
    now = datetime(2026, 10, 28, 3, 17, 30, tzinfo=ZoneInfo("Asia/Tokyo"))
    with mock.patch.object(worker, "collect_all_devices") as all_:
        assert len(worker.dispatch_schedules_at(now)["dispatched"]) == 1
        assert worker.dispatch_schedules_at(now)["dispatched"] == []  # 同じ時刻は二重投入しない
        all_.delay.assert_called_once()
        args = all_.delay.call_args.args
        assert args[0] == "schedule" and args[1] == "スケジュール「s」" and args[2]  # きっかけと、記録をまとめる ID
    # スケジュールの実行はアクティビティログに残る
    db = sqlite3.connect(f"{TMP}/t.db")
    row = db.execute("select message, actor, ref from activity_logs where event='schedule.run' order by at desc").fetchone()
    assert "スケジュール「s」" in row[0] and row[1] == "スケジュール「s」" and row[2] == args[2]

async def _add_schedule(expr):
    from app.models import Schedule
    async with worker._sessionmaker()() as db:
        db.add(Schedule(name="s", cron_expression=expr, target="all")); await db.commit()

def test_legacy_migration():
    from app.core.config import settings
    did = str(uuid.uuid4())
    db = sqlite3.connect(f"{TMP}/t.db")
    db.execute("insert into devices(id,name,hostname,platform,port,username,password,enable_secret,is_active,created_at,updated_at) values(?,?,?,?,?,?,?,?,1,'2025-01-01','2025-01-01')",
               (did, "legacy-sw", "1.2.3.4", "cisco_ios", 22, "u", "plainpw", "plainen")); db.commit()
    legacy = os.path.join(settings.GIT_REPO_PATH, "legacy-sw"); os.makedirs(legacy)
    repo = git.Repo.init(legacy)
    Path(f"{legacy}/running-config.txt").write_text("x\n")
    repo.index.add(["running-config.txt"]); repo.index.commit("old")
    with TestClient(app):  # 起動時の移行処理を実行させる
        pass
    pw, en = db.execute("select password, enable_secret from devices where id=?", (did,)).fetchone()
    assert pw.startswith("enc:") and en.startswith("enc:")
    from app.core.crypto import decrypt
    assert decrypt(pw) == "plainpw"
    assert os.path.isdir(os.path.join(settings.GIT_REPO_PATH, did, ".git")) and not os.path.exists(legacy)

def test_compliance_schedule(r):
    """種類「コンプライアンスチェック」のスケジュールは収集せずに再検査する"""
    from app.services import config_service as cs
    c = TestClient(app); c.__enter__()
    tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    d = c.post("/api/devices/", json=dict(name=f"cs-{uuid.uuid4().hex[:6]}", hostname="10.7.0.1", platform="cisco_ios",
                                          username="u", password="p"), headers=h).json()
    cs.save_config(d["id"], "hostname X\nip http server\n", "test")
    rule = c.post("/api/compliance/rules", json={"name": f"cs-rule-{uuid.uuid4().hex[:4]}", "match_type": "contains",
                                                 "expect": "absent", "pattern": "ip http server",
                                                 "platforms": ["cisco_ios"]}, headers=h).json()
    # 種類の指定（不正な値は 422）と一覧への表示
    assert c.post("/api/schedules/", json={"name": "x", "cron_expression": "0 1 * * *", "kind": "bad"},
                  headers=h).status_code == 422
    sch = c.post("/api/schedules/", json={"name": "夜間検査", "cron_expression": "23 4 * * *", "target": d["id"],
                                          "kind": "compliance"}, headers=h)
    assert sch.status_code == 201, sch.text
    assert sch.json()["kind"] == "compliance"
    assert c.post("/api/schedules/", json={"name": "y", "cron_expression": "0 1 * * *"}, headers=h).json()["kind"] == "collect"

    # 収集し直さずにコンフィグを差し替えておく → スケジュールの再検査で違反が解消する
    cs.save_config(d["id"], "hostname X\n", "test")
    now = datetime(2026, 10, 28, 4, 23, 10, tzinfo=ZoneInfo("Asia/Tokyo"))
    with mock.patch.object(worker, "collect_device_config") as one, \
            mock.patch.object(worker, "collect_all_devices") as all_, \
            mock.patch.object(worker.run_compliance_checks, "delay",
                              side_effect=lambda *a: worker.run_compliance_checks.apply(args=a).get()) as chk:
        dispatched = worker.dispatch_schedules_at(now)["dispatched"]
        assert sch.json()["id"] in dispatched
        one.delay.assert_not_called()
        all_.delay.assert_not_called()
        assert chk.call_args.args[0] == "スケジュール「夜間検査」" and chk.call_args.args[2] == d["id"]
    res = c.get("/api/compliance/results", params={"device_id": d["id"], "rule_id": rule["id"]}, headers=h).json()
    assert [x["status"] for x in res] == ["pass"]
    db = sqlite3.connect(f"{TMP}/t.db")
    ref = chk.call_args.args[1]
    events = [e for (e,) in db.execute("select event from activity_logs where ref=? order by at", (ref,))]
    assert events[0] == "schedule.run" and "compliance.resolved" in events and "compliance.run" in events
    msg = db.execute("select message from activity_logs where ref=? and event='compliance.run'", (ref,)).fetchone()[0]
    assert "1 台" in msg and "解消 1 件" in msg
    c.delete(f"/api/compliance/rules/{rule['id']}", headers=h)
    c.__exit__(None, None, None)
