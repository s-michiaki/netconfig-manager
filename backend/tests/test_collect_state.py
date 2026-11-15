"""収集の進み具合（待ち・収集中・再試行待ち）をデバイス管理で見られるようにする"""
import time
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
import redis
from fastapi.testclient import TestClient

from app import worker
from app.main import app
from app.services import collect_state, login_limit


def login(c, u="admin", p="initial-pass-123"):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


@pytest.fixture
def shared_redis(monkeypatch):
    """worker（同期）と API（非同期）が同じ Redis を見るようにする。

    テストでは API 側の Redis が偽物に差し替えられているので、worker 側も同じ偽のサーバーにつなぐ
    """
    server = fakeredis.FakeServer()
    monkeypatch.setattr(login_limit, "_client", fakeredis.FakeAsyncRedis(server=server))
    sync = fakeredis.FakeRedis(server=server)
    monkeypatch.setattr(worker, "_redis", lambda: sync)
    return sync


def test_state_helpers():
    r = fakeredis.FakeRedis()
    collect_state.mark(r, "d1", "queued", "manual", only_if_idle=True)
    v = collect_state.parse(r.get(collect_state.key("d1")))
    assert v["state"] == "queued" and v["triggered_by"] == "manual" and abs(v["since"] - time.time()) < 5
    assert 0 < r.ttl(collect_state.key("d1")) <= collect_state.TTL["queued"]  # 期限つき（worker が落ちても残り続けない）
    # 収集中の機器にもう一度依頼しても「待ち」に戻さない
    collect_state.mark(r, "d1", "running", "manual")
    collect_state.mark(r, "d1", "queued", "schedule", only_if_idle=True)
    assert collect_state.parse(r.get(collect_state.key("d1")))["state"] == "running"
    collect_state.clear(r, "d1")
    assert r.get(collect_state.key("d1")) is None
    assert collect_state.parse(b"broken") is None and collect_state.parse(b'{"state":"x"}') is None
    # Redis が使えなくても例外にしない（表示用の情報なので収集を止めない）
    broken = mock.Mock()
    broken.set.side_effect = redis.ConnectionError()
    broken.delete.side_effect = redis.ConnectionError()
    collect_state.mark(broken, "d1", "running")
    collect_state.clear(broken, "d1")


def test_collect_status_api_and_worker(shared_redis):
    port, _state, _ = fake_sshd.start()
    with TestClient(app) as c:
        admin = login(c)
        name = f"cst-{uuid.uuid4().hex[:6]}"
        d = c.post("/api/devices/", json=dict(name=name, hostname="127.0.0.1", port=port, platform="cisco_ios",
                                              username="admin", password="pw"), headers=admin).json()
        did = d["id"]
        try:
            def status():
                return c.get("/api/devices/collect-status", headers=admin).json()

            s = status()
            assert s["available"] is True and did not in s["active"] and did not in s["last"]
            # 依頼した時点で「待ち」になる（worker はまだ動いていない）
            with mock.patch.object(worker.collect_device_config, "delay") as delay:
                delay.return_value.id = "t-1"
                assert c.post(f"/api/devices/{did}/collect", headers=admin).status_code == 200
            a = status()["active"][did]
            assert a["state"] == "queued" and a["triggered_by"] == "manual" and a["seconds"] < 5
            # worker が動いている間は「収集中」。終わると消えて、最後の結果が成功になる
            seen = []
            orig = worker.collect_config_sync

            def spy(device, triggered_by):
                seen.append(collect_state.parse(shared_redis.get(collect_state.key(did)))["state"])
                return orig(device, triggered_by)

            with mock.patch.object(worker, "collect_config_sync", side_effect=spy):
                assert worker.collect_device_config.apply(args=(did, "manual", "admin", "cst-1")).get()["success"]
            assert seen == ["running"]
            s = status()
            assert did not in s["active"] and s["last"][did]["status"] == "success" and s["last"][did]["message"] is None
            # 失敗（認証エラー。やり直さない）→ 状態は消え、最後の結果が失敗とその理由になる
            assert c.put(f"/api/devices/{did}", json={"password": "wrong"}, headers=admin).status_code == 200
            r = worker.collect_device_config.apply(args=(did, "manual", "admin", "cst-2")).get()
            assert r["success"] is False
            s = status()
            assert did not in s["active"] and s["last"][did]["status"] == "failed" and s["last"][did]["message"]
            # 閲覧者も見られる。未ログインは不可
            c.post("/api/users/", json={"username": f"{name}-v", "password": "password-1234", "role": "viewer"}, headers=admin)
            assert c.get("/api/devices/collect-status", headers=login(c, f"{name}-v", "password-1234")).status_code == 200
            assert c.get("/api/devices/collect-status").status_code == 401
        finally:
            c.delete(f"/api/devices/{did}", headers=admin)


def test_retry_shows_waiting_state(shared_redis):
    # 一時的な失敗でやり直すときは「再試行待ち」を残す
    with TestClient(app) as c:
        admin = login(c)
        d = c.post("/api/devices/", json=dict(name=f"cst-r-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=1,
                                              platform="cisco_ios", username="admin", password="pw"), headers=admin).json()
        did = d["id"]
        try:
            fail = worker.CollectResult(False, error="接続がタイムアウトしました", retryable=True)
            with mock.patch.object(worker, "collect_config_sync", return_value=fail), \
                    mock.patch.object(worker.collect_device_config, "retry", side_effect=RuntimeError("retry")):
                try:
                    worker.collect_device_config.apply(args=(did, "manual", "admin", "cst-3"), throw=True).get()
                except RuntimeError:
                    pass
            a = c.get("/api/devices/collect-status", headers=admin).json()["active"][did]
            assert a["state"] == "retry"
        finally:
            c.delete(f"/api/devices/{did}", headers=admin)
