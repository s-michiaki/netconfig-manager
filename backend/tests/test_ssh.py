import json, uuid
import fake_sshd
from app.core.config import settings
from app.services import config_service as cs

def dev(port, pw="pw"):
    return cs.DeviceConnectionInfo(id=str(uuid.uuid4()), name="r1", hostname="127.0.0.1", platform="cisco_ios", port=port, username="admin", password=pw, enable_secret=None)

def test_collect_and_hostkey_tofu():
    port, _, sock = fake_sshd.start()
    d = dev(port)
    r = cs.collect_config_sync(d); assert r.success and r.commit_hash, r
    content = cs.get_config_content(d.id, r.commit_hash)
    assert content == "hostname R1\ninterface Gi0/1\n description 日本語の説明\nend\n", repr(content)
    assert f"[127.0.0.1]:{port}" in open(settings.SSH_KNOWN_HOSTS).read()
    assert cs.collect_config_sync(d).commit_hash is None  # タイムスタンプ行が変わっても差分なし
    assert cs.collect_config_sync(dev(port, "bad")).error == "認証失敗"
    sock.close()
    # 同じポートで別の鍵を持つサーバー → ホスト鍵不一致で拒否
    port2, _, s2 = fake_sshd.start()
    lines = open(settings.SSH_KNOWN_HOSTS).read().replace(f"[127.0.0.1]:{port} ", f"[127.0.0.1]:{port2} ")
    open(settings.SSH_KNOWN_HOSTS, "w").write(lines)  # 別鍵を登録済みにする
    r = cs.collect_config_sync(dev(port2)); assert not r.success and "一致しません" in r.error, r

def test_strict_policy(monkeypatch):
    monkeypatch.setattr(settings, "SSH_HOST_KEY_POLICY", "strict")
    port, _, _ = fake_sshd.start()
    r = cs.collect_config_sync(dev(port)); assert not r.success and "未登録" in r.error, r

def test_terminal_end_to_end():
    from fastapi.testclient import TestClient
    from app.main import app
    port, state, _ = fake_sshd.start()
    with TestClient(app) as c:
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        did = c.post("/api/devices/", json=dict(name=f"r-{port}", hostname="127.0.0.1", port=port, platform="cisco_ios", username="admin", password="pw"), headers=h).json()["id"]
        with c.websocket_connect(f"/api/terminal/ws/{did}") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": tok, "cols": 100, "rows": 30}))
            assert "R1#" in ws.receive_text()
            ws.send_text('{"type":"input","data":"{\\"json\\": 1}\\r"}')  # JSONっぽい入力も機器に届く
            out = ""
            while "R1#" not in out[3:]: out += ws.receive_text()
            assert '{"json": 1}' in out
            ws.send_text(json.dumps({"type": "resize", "cols": 150, "rows": 50}))
            ws.send_text(json.dumps({"type": "input", "data": "utf8\r"}))
            out = ""
            while out.count("R1#") < 1: out += ws.receive_text()
            assert "�" not in out and out.count("あいうえお") == 2000
            assert state["server"].size == (150, 50)
            ws.send_text(json.dumps({"type": "input", "data": "exit\r"}))
            out = ""
            while "セッションが終了" not in out: out += ws.receive_text()
