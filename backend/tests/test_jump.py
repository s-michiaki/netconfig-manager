"""踏み台サーバ経由の接続テスト"""
import io
import json
import socket
import uuid
from unittest import mock

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

import fake_jump
import fake_sshd
from app.core.ssh_jump import JumpHostInfo, PrivateKeyError, load_private_key
from app.core.ssh_jump import test_jump_host as run_jump_test
from app.main import app
from app.services import config_service as cs


# ---------------------------------------------------------------- 鍵の生成ヘルパー
def rsa_pem(passphrase=None):
    key = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    key.write_private_key(buf, password=passphrase)
    return key, buf.getvalue()


def ed25519_openssh(passphrase=None):
    k = ed25519.Ed25519PrivateKey.generate()
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    )
    text = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc).decode()
    return load_private_key(text, passphrase), text


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def device_via(jump: JumpHostInfo | None, port: int, password="pw"):
    return cs.DeviceConnectionInfo(
        id=str(uuid.uuid4()), name="r1", hostname="127.0.0.1", platform="cisco_ios", port=port,
        username="admin", password=password, enable_secret=None, jump=jump,
    )


def jinfo(port, **kw):
    base = dict(name="jump1", hostname="127.0.0.1", port=port, username="jumpuser",
                password=None, private_key=None, key_passphrase=None)
    base.update(kw)
    return JumpHostInfo(**base)


# ---------------------------------------------------------------- 秘密鍵の読み込み
def test_load_private_key_formats():
    _, pem = rsa_pem()
    assert load_private_key(pem).get_name() == "ssh-rsa"
    _, op = ed25519_openssh()
    assert load_private_key(op.replace("\n", "\r\n")).get_name() == "ssh-ed25519"  # Windows 改行も可
    _, enc = ed25519_openssh("secret-pass")
    assert load_private_key(enc, "secret-pass").get_name() == "ssh-ed25519"
    with pytest.raises(PrivateKeyError, match="パスフレーズで保護"):
        load_private_key(enc)
    with pytest.raises(PrivateKeyError, match="パスフレーズが違います"):
        load_private_key(enc, "wrong")
    with pytest.raises(PrivateKeyError, match="PuTTY"):
        load_private_key("PuTTY-User-Key-File-3: ssh-rsa\n...")
    with pytest.raises(PrivateKeyError, match="認識できません"):
        load_private_key("hello")


# ---------------------------------------------------------------- 収集
def test_collect_via_jump_password():
    dev_port, _, _ = fake_sshd.start()
    jport, cfg = fake_jump.start(password="jpass")
    r = cs.collect_config_sync(device_via(jinfo(jport, password="jpass"), dev_port))
    assert r.success and r.commit_hash, r
    assert cfg["forwarded"] == [("127.0.0.1", dev_port)]  # 実際に踏み台経由で接続している


@pytest.mark.parametrize("keytype", ["rsa", "ed25519"])
def test_collect_via_jump_private_key_with_passphrase(keytype):
    pkey, text = rsa_pem("pp-123") if keytype == "rsa" else ed25519_openssh("pp-123")
    dev_port, _, _ = fake_sshd.start()
    jport, cfg = fake_jump.start(pubkey=pkey)
    r = cs.collect_config_sync(device_via(jinfo(jport, private_key=text, key_passphrase="pp-123"), dev_port))
    assert r.success, r
    assert cfg["forwarded"]


def test_collect_via_jump_key_and_password_fallback():
    """鍵が受け入れられなくてもパスワードで認証できる（両方設定時）"""
    _, other_key = rsa_pem()
    dev_port, _, _ = fake_sshd.start()
    jport, _ = fake_jump.start(password="jpass")
    r = cs.collect_config_sync(device_via(jinfo(jport, password="jpass", private_key=other_key), dev_port))
    assert r.success, r


def test_jump_errors():
    dev_port, _, _ = fake_sshd.start()
    jport, _ = fake_jump.start(password="jpass")
    r = cs.collect_config_sync(device_via(jinfo(jport, password="bad"), dev_port))
    assert not r.success and not r.retryable and r.error == "踏み台サーバ「jump1」: 認証に失敗しました", r
    # 踏み台から機器に届かない
    r = cs.collect_config_sync(device_via(jinfo(jport, password="jpass"), closed_port()))
    assert not r.success and r.retryable and "踏み台から機器に接続できませんでした" in r.error, r
    # 踏み台でポートフォワーディングが禁止されている
    jport2, _ = fake_jump.start(password="jpass", allow_forward=False)
    r = cs.collect_config_sync(device_via(jinfo(jport2, password="jpass"), dev_port))
    assert not r.success and not r.retryable and "AllowTcpForwarding" in r.error, r
    # 踏み台自体に接続できない
    r = cs.collect_config_sync(device_via(jinfo(closed_port(), password="jpass"), dev_port))
    assert not r.success and r.retryable and r.error.startswith("踏み台サーバ「jump1」: 接続できませんでした"), r
    # 機器側の認証失敗は踏み台のエラーと区別される
    r = cs.collect_config_sync(device_via(jinfo(jport, password="jpass"), dev_port, password="bad"))
    assert r.error == "認証失敗（機器）", r


def test_jump_test_function():
    dev_port, _, _ = fake_sshd.start()
    jport, _ = fake_jump.start(password="jpass")
    assert "接続・認証できました" in run_jump_test(jinfo(jport, password="jpass"))
    assert "到達できました" in run_jump_test(jinfo(jport, password="jpass"), "127.0.0.1", dev_port)


# ---------------------------------------------------------------- API / ターミナル
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _login_as(client, admin, role):
    name = f"{role}-{uuid.uuid4().hex[:6]}"
    client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
    r = client.post("/api/auth/token", data={"username": name, "password": "password-1234"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_jump_host_api(client, admin):
    pkey, text = ed25519_openssh("pp-123")
    base = {"name": f"jh-{uuid.uuid4().hex[:6]}", "hostname": "127.0.0.1", "port": 2200, "username": "u"}
    assert client.post("/api/jump-hosts/", json=base, headers=admin).status_code == 422  # 認証情報なし
    r = client.post("/api/jump-hosts/", json={**base, "private_key": text}, headers=admin)
    assert r.status_code == 422 and "パスフレーズ" in r.json()["detail"]
    r = client.post("/api/jump-hosts/", json={**base, "private_key": "junk"}, headers=admin)
    assert r.status_code == 422
    r = client.post("/api/jump-hosts/", json={**base, "private_key": text, "key_passphrase": "pp-123"}, headers=admin)
    assert r.status_code == 201, r.text
    jh = r.json()
    assert jh["has_private_key"] and not jh["has_password"] and jh["key_info"].startswith("ssh-ed25519 SHA256:")
    assert "private_key" not in jh and "key_passphrase" not in jh
    assert client.post("/api/jump-hosts/", json={**base, "password": "x"}, headers=admin).status_code == 409

    # デバイスに割り当て
    dev = client.post("/api/devices/", json=dict(
        name=f"d-{uuid.uuid4().hex[:6]}", hostname="10.0.0.9", platform="cisco_ios", username="u", password="p",
        jump_host_id=jh["id"]), headers=admin).json()
    assert dev["jump_host_id"] == jh["id"] and dev["jump_host_name"] == jh["name"]
    assert client.post("/api/devices/", json=dict(
        name="bad-jump", hostname="h", platform="cisco_ios", username="u", password="p",
        jump_host_id="nope"), headers=admin).status_code == 422
    listed = {j["id"]: j for j in client.get("/api/jump-hosts/", headers=admin).json()}
    assert listed[jh["id"]]["device_count"] == 1

    # 使用中は削除できない → 直接接続に戻すと削除できる
    assert client.delete(f"/api/jump-hosts/{jh['id']}", headers=admin).status_code == 409
    r = client.put(f"/api/devices/{dev['id']}", json={"jump_host_id": None}, headers=admin)
    assert r.json()["jump_host_id"] is None

    # 更新: 両方の認証情報を消すことはできない / パスワード追加後なら鍵を消せる
    url = f"/api/jump-hosts/{jh['id']}"
    assert client.put(url, json={"clear_private_key": True}, headers=admin).status_code == 422
    r = client.put(url, json={"password": "newpw", "clear_private_key": True}, headers=admin)
    assert r.status_code == 200 and r.json()["has_password"] and not r.json()["has_private_key"]
    assert client.delete(url, headers=admin).status_code == 204


def test_jump_host_permissions(client, admin):
    viewer = _login_as(client, admin, "viewer")
    operator = _login_as(client, admin, "operator")
    body = {"name": "perm-jh", "hostname": "h", "username": "u", "password": "p"}
    assert client.get("/api/jump-hosts/", headers=viewer).status_code == 200
    for h in (viewer, operator):
        assert client.post("/api/jump-hosts/", json=body, headers=h).status_code == 403
    jh = client.post("/api/jump-hosts/", json=body, headers=admin).json()
    assert client.post(f"/api/jump-hosts/{jh['id']}/test", json={}, headers=operator).status_code == 403
    client.delete(f"/api/jump-hosts/{jh['id']}", headers=admin)


def test_jump_test_endpoint_and_terminal(client, admin):
    dev_port, _, _ = fake_sshd.start()
    jport, cfg = fake_jump.start(password="jpass")
    jh = client.post("/api/jump-hosts/", json={
        "name": f"term-jh-{jport}", "hostname": "127.0.0.1", "port": jport, "username": "jumpuser", "password": "jpass",
    }, headers=admin).json()
    r = client.post(f"/api/jump-hosts/{jh['id']}/test", json={"dest_host": "127.0.0.1", "dest_port": dev_port},
                    headers=admin).json()
    assert r["ok"], r
    bad = client.post(f"/api/jump-hosts/{jh['id']}/test", json={"dest_host": "127.0.0.1", "dest_port": closed_port()},
                      headers=admin).json()
    assert not bad["ok"] and "踏み台から機器" in bad["message"]

    dev = client.post("/api/devices/", json=dict(
        name=f"term-{dev_port}", hostname="127.0.0.1", port=dev_port, platform="cisco_ios", username="admin",
        password="pw", jump_host_id=jh["id"]), headers=admin).json()
    token = admin["Authorization"].split()[1]
    with client.websocket_connect(f"/api/terminal/ws/{dev['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        assert "R1#" in ws.receive_text()
        ws.send_text(json.dumps({"type": "input", "data": "show running-config\r"}))
        out = ""
        while "end" not in out:
            out += ws.receive_text()
        assert "日本語の説明" in out
    assert ("127.0.0.1", dev_port) in cfg["forwarded"]

    # 踏み台の認証失敗はターミナルにも分かる形で表示される
    client.put(f"/api/jump-hosts/{jh['id']}", json={"password": "wrong"}, headers=admin)
    with mock.patch("app.api.terminal.logger"):
        with client.websocket_connect(f"/api/terminal/ws/{dev['id']}") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": token}))
            assert "踏み台サーバ「" in ws.receive_text()
