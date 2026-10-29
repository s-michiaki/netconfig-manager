"""機器の SSH 鍵認証と PAN-OS 対応のテスト"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import fake_jump
import fake_sshd
from app.main import app
from app.services import config_service as cs
from test_jump import ed25519_openssh, jinfo, rsa_pem


def dev(port, platform="cisco_ios", password="pw", private_key=None, key_passphrase=None, jump=None):
    return cs.DeviceConnectionInfo(
        id=str(uuid.uuid4()), name="d", hostname="127.0.0.1", platform=platform, port=port,
        username="admin", password=password, enable_secret=None, jump=jump,
        private_key=private_key, key_passphrase=key_passphrase,
    )


# ---------------------------------------------------------------- PAN-OS
def test_panos_password_collect():
    port, state, _ = fake_sshd.start(mode="panos")
    d = dev(port, platform="paloalto_panos")
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash, r
    content = cs.get_config_content(d.id, r.commit_hash)
    assert content.startswith("set deviceconfig system hostname PA-VM\n"), content
    assert "[edit]" not in content and "Entering configuration mode" not in content
    assert 'set address web01 description "日本語の説明"' in content
    # set 形式に切り替えてから設定モードで show し、設定モードを抜けている
    cmds = state["commands"]
    assert cmds.index("set cli config-output-format set") < cmds.index("configure") < cmds.index("show")
    assert "exit" in cmds[cmds.index("show"):]
    assert state["auth_method"] == "keyboard-interactive"
    # 2回目は変更なし
    assert cs.collect_config_sync(d).commit_hash is None


def test_panos_key_only():
    pkey, text = ed25519_openssh()
    port, state, _ = fake_sshd.start(mode="panos", password=None, pubkey=pkey)
    r = cs.collect_config_sync(dev(port, platform="paloalto_panos", password=None, private_key=text))
    assert r.success, r
    assert state["auth_method"] == "publickey"


# ---------------------------------------------------------------- 鍵認証（直接接続）
@pytest.mark.parametrize("keytype", ["rsa", "ed25519"])
def test_key_only_with_passphrase(keytype):
    pkey, text = rsa_pem("pp-1") if keytype == "rsa" else ed25519_openssh("pp-1")
    port, state, _ = fake_sshd.start(password=None, pubkey=pkey)
    r = cs.collect_config_sync(dev(port, password=None, private_key=text, key_passphrase="pp-1"))
    assert r.success, r
    assert state["auth_method"] == "publickey"


def test_key_rejected_falls_back_to_password():
    _, other = rsa_pem()
    port, state, _ = fake_sshd.start(password="pw")
    r = cs.collect_config_sync(dev(port, password="pw", private_key=other))
    assert r.success, r
    assert state["auth_method"] == "password"


def test_key_errors():
    pkey, _ = ed25519_openssh()
    _, wrong = ed25519_openssh()
    port, _, _ = fake_sshd.start(password=None, pubkey=pkey)
    assert cs.collect_config_sync(dev(port, password=None, private_key=wrong)).error == "認証失敗"
    _, enc = ed25519_openssh("secret")
    r = cs.collect_config_sync(dev(port, password=None, private_key=enc))
    assert not r.success and not r.retryable and r.error.startswith("機器の秘密鍵: ") and "パスフレーズ" in r.error


def test_key_auth_via_jump():
    pkey, text = ed25519_openssh()
    dev_port, state, _ = fake_sshd.start(password=None, pubkey=pkey)
    jport, cfg = fake_jump.start(password="jpass")
    r = cs.collect_config_sync(dev(dev_port, password=None, private_key=text, jump=jinfo(jport, password="jpass")))
    assert r.success, r
    assert state["auth_method"] == "publickey" and cfg["forwarded"]


# ---------------------------------------------------------------- API / ターミナル
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_device_api_key_auth(client, admin):
    pkey, text = ed25519_openssh("pp-2")
    base = dict(name=f"k-{uuid.uuid4().hex[:6]}", hostname="10.1.1.1", platform="paloalto_panos", username="admin")
    assert client.post("/api/devices/", json=base, headers=admin).status_code == 422          # 認証情報なし
    r = client.post("/api/devices/", json={**base, "private_key": text}, headers=admin)
    assert r.status_code == 422 and "パスフレーズ" in r.json()["detail"]
    r = client.post("/api/devices/", json={**base, "private_key": text, "key_passphrase": "pp-2"}, headers=admin)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["platform"] == "paloalto_panos" and d["has_private_key"] and not d["has_password"]
    assert d["key_info"].startswith("ssh-ed25519 SHA256:")
    assert "private_key" not in d and "key_passphrase" not in d and "password" not in d
    url = f"/api/devices/{d['id']}"
    assert client.put(url, json={"clear_private_key": True}, headers=admin).status_code == 422  # 両方なしは不可
    r = client.put(url, json={"password": "pw2"}, headers=admin)
    assert r.json()["has_password"] and r.json()["has_private_key"]
    r = client.put(url, json={"clear_private_key": True}, headers=admin)
    assert r.json()["has_password"] and not r.json()["has_private_key"] and r.json()["key_info"] is None
    r = client.put(url, json={"private_key": text, "key_passphrase": "pp-2", "clear_password": True}, headers=admin)
    assert not r.json()["has_password"] and r.json()["has_private_key"]


def test_terminal_with_key_only_device(client, admin):
    pkey, text = ed25519_openssh()
    port, state, _ = fake_sshd.start(password=None, pubkey=pkey)
    d = client.post("/api/devices/", json=dict(
        name=f"kt-{port}", hostname="127.0.0.1", port=port, platform="cisco_ios", username="admin", private_key=text,
    ), headers=admin).json()
    token = admin["Authorization"].split()[1]
    with client.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        assert "R1#" in ws.receive_text()
    assert state["auth_method"] == "publickey"
