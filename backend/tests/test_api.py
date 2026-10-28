from unittest import mock
import pytest
from fastapi.testclient import TestClient
from conftest import TMP

from app.main import app
from app.services import config_service as cs

@pytest.fixture(scope="module")
def client():
    with mock.patch("app.api.devices.collect_device_config") as one, mock.patch("app.api.devices.collect_all_devices") as all_:
        one.delay.return_value.id = "t1"; all_.delay.return_value.id = "t2"
        with TestClient(app) as c:
            yield c

@pytest.fixture(scope="module")
def auth(client):
    r = client.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

def test_requires_auth(client):
    for path in ["/api/devices/", "/api/schedules/", "/api/configs/x/history", "/api/tasks/x"]:
        assert client.get(path).status_code == 401
    assert client.post("/api/auth/token", data={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.get("/api/devices/", headers={"Authorization": "Bearer abc"}).status_code == 401

def test_device_crud_and_encryption(client, auth):
    body = dict(name="sw1", hostname="10.0.0.1", platform="cisco_ios", username="u", password="p@ss", enable_secret="")
    r = client.post("/api/devices/", json=body, headers=auth); assert r.status_code == 201, r.text
    d = r.json(); assert "password" not in d and d["has_enable_secret"] is False
    assert client.post("/api/devices/", json=body, headers=auth).status_code == 409
    assert client.post("/api/devices/", json={**body, "name": "x", "platform": "bad"}, headers=auth).status_code == 422
    assert client.post("/api/devices/", json={**body, "name": "y", "hostname": "a b; rm"}, headers=auth).status_code == 422
    # 部分更新: パスワード不要
    r = client.put(f"/api/devices/{d['id']}", json={"description": "core", "enable_secret": "en"}, headers=auth)
    assert r.status_code == 200 and r.json()["has_enable_secret"]
    # DBには暗号化されて保存されている
    import sqlite3
    raw = sqlite3.connect(f"{TMP}/t.db").execute("select password, enable_secret from devices").fetchone()
    assert raw[0].startswith("enc:") and raw[1].startswith("enc:")
    r = client.put(f"/api/devices/{d['id']}", json={"clear_enable_secret": True}, headers=auth)
    assert r.json()["has_enable_secret"] is False
    assert client.post(f"/api/devices/{d['id']}/collect", headers=auth).json()["task_id"] == "t1"
    assert client.post("/api/devices/collect/all", headers=auth).json()["task_id"] == "t2"
    pytest.device_id = d["id"]

def test_configs_and_injection(client, auth):
    did = pytest.device_id
    assert client.get(f"/api/configs/{did}/history", headers=auth).json() == []
    c1 = cs.save_config(did, "hostname a\n!\n!\n", "manual"); assert (c1.added, c1.removed) == (3, 0)
    c2 = cs.save_config(did, "hostname b\n!\n", "schedule"); assert (c2.added, c2.removed) == (1, 2)
    assert cs.save_config(did, "hostname b\n!\n", "schedule").commit_hash is None
    h = client.get(f"/api/configs/{did}/history", headers=auth).json()
    assert len(h) == 2 and h[0]["date"].endswith("+00:00")
    r = client.get(f"/api/configs/{did}/diff", params={"from_hash": c1.commit_hash, "to_hash": c2.commit_hash}, headers=auth)
    assert "+hostname b" in r.json()["diff"]
    r = client.get(f"/api/configs/{did}/diff", params={"from_hash": f"--output={TMP}/pwn", "to_hash": c2.commit_hash}, headers=auth)
    assert r.status_code == 422
    import os; assert not os.path.exists(f"{TMP}/pwn")
    assert client.get(f"/api/configs/{did}/content/{c1.commit_hash}", headers=auth).text == "hostname a\n!\n!\n"
    assert client.get(f"/api/configs/{did}/content/{'0'*40}", headers=auth).status_code == 404
    assert client.get("/api/configs/..%2F..%2Fetc/history", headers=auth).status_code == 404

def test_normalize():
    raw = "Building configuration...\r\n\r\nCurrent configuration : 1234 bytes\r\n! Last configuration change at 10:00\r\nhostname r1  \r\nntp clock-period 1234\r\nend"
    assert cs.normalize_config(raw, "cisco_ios") == "hostname r1\nend\n"

def test_schedules(client, auth):
    assert client.post("/api/schedules/", json={"name": "n", "cron_expression": "bad"}, headers=auth).status_code == 422
    assert client.post("/api/schedules/", json={"name": "n", "cron_expression": "0 9 * * *", "target": "nope"}, headers=auth).status_code == 422
    r = client.post("/api/schedules/", json={"name": "n", "cron_expression": "0  9 * * *", "target": pytest.device_id}, headers=auth)
    assert r.status_code == 201 and r.json()["next_run"] and r.json()["cron_expression"] == "0 9 * * *"
    assert client.patch(f"/api/schedules/{r.json()['id']}/toggle", headers=auth).json()["next_run"] is None

def test_is_due():
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from app.worker import is_due
    tz = ZoneInfo("Asia/Tokyo")
    assert is_due("0 9 * * *", datetime(2026,10,28,9,0,0,tzinfo=tz))
    assert is_due("0 9 * * *", datetime(2026,10,28,9,1,20,tzinfo=tz))
    assert not is_due("0 9 * * *", datetime(2026,10,28,9,2,0,tzinfo=tz))
    assert not is_due("0 9 * * *", datetime(2026,10,28,8,59,59,tzinfo=tz))

def test_change_password(client, auth):
    assert client.post("/api/auth/change-password", json={"current_password": "x", "new_password": "newpassword1"}, headers=auth).status_code == 400
    assert client.get("/api/auth/me", headers=auth).json()["username"] == "admin"

def test_ws_auth(client, auth):
    from starlette.websockets import WebSocketDisconnect
    with client.websocket_connect(f"/api/terminal/ws/{pytest.device_id}") as ws:
        ws.send_text('{"type":"auth","token":"bad"}')
        with pytest.raises(WebSocketDisconnect) as e: ws.receive_text()
        assert e.value.code == 4401
    # 正しいトークン + SSH接続失敗（存在しないホスト）→ エラーメッセージ
    token = auth["Authorization"].split()[1]
    with mock.patch("app.api.terminal.TerminalSession.connect", side_effect=TimeoutError("timed out")):
        with client.websocket_connect(f"/api/terminal/ws/{pytest.device_id}") as ws:
            ws.send_text(f'{{"type":"auth","token":"{token}"}}')
            assert "タイムアウト" in ws.receive_text()
