import asyncio, os, sqlite3, uuid
from datetime import datetime
from unittest import mock
from zoneinfo import ZoneInfo
import fakeredis, git, pytest
from conftest import TMP
import fake_sshd
from fastapi.testclient import TestClient
from app.main import app
from app import worker

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
    c.__exit__(None, None, None)

def test_dispatch(r):
    asyncio.run(_add_schedule("17 3 * * *"))  # 他のテストと重ならない時刻
    now = datetime(2026, 10, 28, 3, 17, 30, tzinfo=ZoneInfo("Asia/Tokyo"))
    with mock.patch.object(worker, "collect_all_devices") as all_:
        assert len(worker.dispatch_schedules_at(now)["dispatched"]) == 1
        assert worker.dispatch_schedules_at(now)["dispatched"] == []  # 同じ時刻は二重投入しない
        all_.delay.assert_called_once_with("schedule")

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
    repo = git.Repo.init(legacy); open(f"{legacy}/running-config.txt", "w").write("x\n")
    repo.index.add(["running-config.txt"]); repo.index.commit("old")
    with TestClient(app):  # 起動時の移行処理を実行させる
        pass
    pw, en = db.execute("select password, enable_secret from devices where id=?", (did,)).fetchone()
    assert pw.startswith("enc:") and en.startswith("enc:")
    from app.core.crypto import decrypt; assert decrypt(pw) == "plainpw"
    assert os.path.isdir(os.path.join(settings.GIT_REPO_PATH, did, ".git")) and not os.path.exists(legacy)
