"""監査ログ（操作履歴・ターミナルの記録）のテスト"""
import asyncio
import json
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import fake_sshd
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.audit import AuditLog, TerminalSession
from app.services.audit import purge_old


def login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        assert c.post("/api/users/", json={"username": "aud-op", "password": "password-1234", "role": "operator"},
                      headers=admin).status_code == 201
        yield {"c": c, "admin": admin, "op": login(c, "aud-op", "password-1234")}


def logs(c, h, **params):
    r = c.get("/api/audit/logs", params=params, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def test_only_admin_can_read(ctx):
    c = ctx["c"]
    assert c.get("/api/audit/logs", headers=ctx["op"]).status_code == 403
    assert c.get("/api/audit/terminal-sessions", headers=ctx["op"]).status_code == 403
    assert "device.update" in c.get("/api/audit/actions", headers=ctx["admin"]).json()


def test_login_and_failed_login(ctx):
    c, admin = ctx["c"], ctx["admin"]
    assert c.post("/api/auth/token", data={"username": "aud-op", "password": "wrong-pass-0"}).status_code == 401
    assert c.post("/api/auth/token", data={"username": "nobody-x", "password": "wrong-pass-0"}).status_code == 401
    failed = logs(c, admin, action="auth.login_failed")["items"]
    reasons = {(x["username"], json.loads(x["detail"])["reason"]) for x in failed}
    assert ("aud-op", "パスワード誤り") in reasons and ("nobody-x", "ユーザーが存在しない") in reasons
    assert all(not x["success"] for x in failed)
    ok = logs(c, admin, action="auth.login", username="aud-op")["items"]
    assert ok and ok[0]["ip"]


def test_device_changes_without_secrets(ctx):
    c, admin = ctx["c"], ctx["admin"]
    name = f"aud-{uuid.uuid4().hex[:6]}"
    d = c.post("/api/devices/", json=dict(name=name, hostname="10.7.0.1", platform="cisco_ios",
                                          username="u", password="Secret-PW-123"), headers=admin).json()
    c.put(f"/api/devices/{d['id']}", json={"password": "New-Secret-456", "description": "コア"}, headers=admin)
    c.delete(f"/api/devices/{d['id']}", headers=admin)
    items = logs(c, admin, action="device.", q=name)["items"]
    assert [x["action"] for x in items] == ["device.delete", "device.update", "device.create"]
    assert all(x["username"] == "admin" and x["target_name"] == name for x in items)
    upd = json.loads(items[1]["detail"])
    assert upd["password"] == "（変更）" and upd["description"] == "コア"
    blob = json.dumps(items, ensure_ascii=False)
    assert "Secret-PW-123" not in blob and "New-Secret-456" not in blob
    # 失敗した操作（ロールバック）は残らない
    c.post("/api/devices/", json=dict(name="dup-aud", hostname="10.7.0.2", platform="cisco_ios", username="u",
                                      password="p"), headers=admin)
    c.post("/api/devices/", json=dict(name="dup-aud", hostname="10.7.0.3", platform="cisco_ios", username="u",
                                      password="p"), headers=admin)
    assert logs(c, admin, action="device.create", q="dup-aud")["total"] == 1


def test_paging_and_filters(ctx):
    c, admin = ctx["c"], ctx["admin"]
    page = logs(c, admin, limit=2, offset=0)
    assert len(page["items"]) == 2 and page["total"] >= 2
    assert logs(c, admin, failed_only=True)["total"] >= 2
    future = (utcnow() + timedelta(days=1)).isoformat()
    assert logs(c, admin, since=future)["total"] == 0


def test_terminal_session_is_recorded(ctx):
    c, admin = ctx["c"], ctx["admin"]
    port, _, _ = fake_sshd.start()
    d = c.post("/api/devices/", json=dict(name=f"tr-{port}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                          username="admin", password="pw"), headers=admin).json()
    token = admin["Authorization"].split()[1]
    with c.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token, "cols": 100, "rows": 30}))
        assert "R1#" in ws.receive_text()
        ws.send_text(json.dumps({"type": "input", "data": "show running-config\r"}))
        buf = ""
        deadline = time.time() + 10
        while "description" not in buf and time.time() < deadline:
            buf += ws.receive_text()
        ws.send_text(json.dumps({"type": "resize", "cols": 140, "rows": 40}))
        time.sleep(0.3)
    # 切断後の記録の保存を待つ
    for _ in range(50):
        s = c.get("/api/audit/terminal-sessions", params={"device": f"tr-{port}"}, headers=admin).json()
        if s["items"] and s["items"][0]["ended_at"]:
            break
        time.sleep(0.1)
    item = s["items"][0]
    assert item["username"] == "admin" and item["device_host"] == "127.0.0.1"
    assert item["end_reason"] == "利用者が切断" and item["has_recording"] and item["bytes_out"] > 0
    rec = c.get(f"/api/audit/terminal-sessions/{item['id']}/recording", headers=admin)
    assert rec.status_code == 200
    lines = rec.text.splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2 and header["width"] == 100 and header["height"] == 30
    events = [json.loads(x) for x in lines[1:]]
    out = "".join(e[2] for e in events if e[1] == "o")
    assert "hostname R1" in out and "日本語の説明" in out
    assert any(e[1] == "r" and e[2] == "140x40" for e in events)
    assert all(e[1] != "i" for e in events)  # キー入力は記録しない
    acts = [x["action"] for x in logs(c, admin, q=f"tr-{port}")["items"]]
    assert "terminal.open" in acts and "terminal.close" in acts
    assert logs(c, admin, action="audit.view_recording")["total"] >= 1
    # 他人（オペレーター）は記録を読めない
    assert c.get(f"/api/audit/terminal-sessions/{item['id']}/recording", headers=ctx["op"]).status_code == 403


def test_terminal_connect_failure_is_logged(ctx):
    c, admin = ctx["c"], ctx["admin"]
    d = c.post("/api/devices/", json=dict(name=f"tf-{uuid.uuid4().hex[:4]}", hostname="127.0.0.1", port=1,
                                          platform="cisco_ios", username="u", password="p"), headers=admin).json()
    token = admin["Authorization"].split()[1]
    with c.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        assert "失敗" in ws.receive_text()
    items = logs(c, admin, action="terminal.open", q=d["name"])["items"]
    assert items and not items[0]["success"] and "error" in json.loads(items[0]["detail"])


def test_recording_limit(ctx, monkeypatch):
    from app.services.audit import TerminalRecorder
    monkeypatch.setattr(settings, "TERMINAL_LOG_MAX_BYTES", 2000)
    r = TerminalRecorder(str(uuid.uuid4()), utcnow(), 80, 24, "t")
    for _ in range(100):
        r.output("x" * 100)
    r.close()
    assert r.truncated and r.bytes <= 2000
    assert "記録の上限" in Path(r.path).read_text(encoding="utf-8")


def test_purge_old(ctx):
    async def run():
        old = utcnow() - timedelta(days=400)
        sid = str(uuid.uuid4())
        f = Path(settings.TERMINAL_LOG_PATH) / "old" / f"{sid}.cast"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("{}\n")
        async with AsyncSessionLocal() as db:
            db.add(AuditLog(id=str(uuid.uuid4()), at=old, action="auth.login", success=True))
            db.add(TerminalSession(id=sid, started_at=old, log_file=f"old/{sid}.cast", bytes_out=0, truncated=False,
                                   cols=80, rows=24))
            await db.commit()
            result = await purge_old(db)
        return result, f.exists()

    result, exists = asyncio.run(run())
    assert result["audit_logs"] >= 1 and result["terminal_sessions"] >= 1 and not exists


def test_terminal_closed_by_device(ctx):
    c, admin = ctx["c"], ctx["admin"]
    port, _, _ = fake_sshd.start()
    d = c.post("/api/devices/", json=dict(name=f"te-{port}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                          username="admin", password="pw"), headers=admin).json()
    token = admin["Authorization"].split()[1]
    with c.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        assert "R1#" in ws.receive_text()
        ws.send_text(json.dumps({"type": "input", "data": "exit\r"}))
        buf = ""
        deadline = time.time() + 10
        while "セッションが終了" not in buf and time.time() < deadline:
            buf += ws.receive_text()
    for _ in range(50):
        s = c.get("/api/audit/terminal-sessions", params={"device": f"te-{port}"}, headers=admin).json()["items"]
        if s and s[0]["ended_at"]:
            break
        time.sleep(0.1)
    assert s[0]["end_reason"] == "機器側で終了"
