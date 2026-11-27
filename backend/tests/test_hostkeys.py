"""SSH ホスト鍵の記録（#35）

- 踏み台経由の機器は、踏み台ごとに分けて記録する（別の踏み台の先にある同じアドレスの機器と互いに比べない）
- 以前の版の記録（踏み台の区別なし）しか無い機器は、一致すれば引き継ぐ（strict でも「未登録」にしない）。
  一致しなければ今までどおり拒否し、踏み台ごとの記録も作らない
- TOFU で新しく登録したら、アクティビティ（ssh.hostkey_added）と監査ログに指紋つきで残す
"""
import json
import sqlite3
import uuid
from pathlib import Path
from unittest import mock

import fake_jump
import fake_sshd
import fakeredis
import paramiko
import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.core import ssh_hostkeys
from app.core.config import settings
from app.core.ssh_jump import JumpHostInfo
from app.main import app
from app.services import config_service as cs


def _jump(port, jid):
    return JumpHostInfo(name=f"jump-{jid[:4]}", hostname="127.0.0.1", port=port, username="jumpuser", password="jpass",
                        private_key=None, key_passphrase=None, id=jid)


def _dev(port, jump=None):
    return cs.DeviceConnectionInfo(id=str(uuid.uuid4()), name="r1", hostname="127.0.0.1", platform="cisco_ios", port=port,
                                   username="admin", password="pw", enable_secret=None, jump=jump)


def _known() -> str:
    p = Path(settings.SSH_KNOWN_HOSTS)
    return p.read_text() if p.is_file() else ""


def _add_line(name: str, key: paramiko.PKey) -> None:
    p = Path(settings.SSH_KNOWN_HOSTS)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(f"{name} {key.get_name()} {key.get_base64()}\n")


@pytest.fixture(autouse=True)
def _clear_events():
    ssh_hostkeys.take_events()
    yield
    ssh_hostkeys.take_events()


def test_jump_devices_are_recorded_per_jump():
    """拠点ごとの踏み台の先に同じアドレス・ポートの機器があっても、互いの鍵と比べて失敗しない"""
    key = paramiko.RSAKey.generate(2048)
    port, _, _ = fake_sshd.start(key=key)
    jport, _ = fake_jump.start(password="jpass")
    j1, j2 = str(uuid.uuid4()), str(uuid.uuid4())
    name = f"[127.0.0.1]:{port}"
    # 踏み台 1 の先の同じアドレスには、別の鍵の機器がある（記録済み）
    _add_line(ssh_hostkeys.scoped_name(j1, name), paramiko.RSAKey.generate(2048))
    r = cs.collect_config_sync(_dev(port, _jump(jport, j2)))  # 踏み台 2 の先の機器は、踏み台 1 の記録と比べない
    assert r.success, r
    assert f"jump-{j2}/{name} ssh-rsa {key.get_base64()}" in _known()
    assert f"\n{name} " not in "\n" + _known()  # 踏み台の区別なしの名前では記録しない
    assert {e["target"] for e in ssh_hostkeys.take_events()} == {"jump", "device"}  # 初回は TOFU で登録
    r = cs.collect_config_sync(_dev(port, _jump(jport, j2)))  # 2 回目は記録と一致（新規登録ではない）
    assert r.success and ssh_hostkeys.take_events() == [], r
    # 踏み台 1 の記録（別の鍵）とは一致しないので拒否する（中間者対策は今までどおり）
    r = cs.collect_config_sync(_dev(port, _jump(jport, j1)))
    assert not r.success and "一致しません" in r.error and not r.retryable, r


def test_legacy_record_is_inherited_when_it_matches(monkeypatch):
    """以前の版の記録（踏み台の区別なし）と一致すれば、踏み台ごとの名前でも記録して接続する（strict でも失敗しない）"""
    key = paramiko.RSAKey.generate(2048)
    port, _, _ = fake_sshd.start(key=key)
    jport, _ = fake_jump.start(password="jpass")
    jid = str(uuid.uuid4())
    name = f"[127.0.0.1]:{port}"
    _add_line(name, key)  # 以前の版で記録したもの
    r = cs.collect_config_sync(_dev(port, _jump(jport, jid)))  # 踏み台自身は未登録（tofu で登録される）
    assert r.success, r
    assert f"jump-{jid}/{name} ssh-rsa {key.get_base64()}" in _known()
    events = ssh_hostkeys.take_events()
    assert [e["target"] for e in events] == ["jump"]  # 機器の鍵は「新規登録」ではない（引き継ぎ）
    monkeypatch.setattr(settings, "SSH_HOST_KEY_POLICY", "strict")
    jid2 = str(uuid.uuid4())
    # strict でも、以前の記録と一致する機器は「未登録」にならない（踏み台 2 は同じ踏み台サーバーの別登録）
    r = cs.collect_config_sync(_dev(port, _jump(jport, jid2)))
    assert r.success, r
    assert f"jump-{jid2}/{name} " in _known()


def test_legacy_record_mismatch_is_rejected_and_not_inherited():
    key = paramiko.RSAKey.generate(2048)
    port, _, _ = fake_sshd.start(key=key)
    jport, _ = fake_jump.start(password="jpass")
    jid = str(uuid.uuid4())
    name = f"[127.0.0.1]:{port}"
    _add_line(name, paramiko.RSAKey.generate(2048))  # 以前の記録は別の鍵
    r = cs.collect_config_sync(_dev(port, _jump(jport, jid)))
    assert not r.success and "一致しません" in r.error, r
    assert f"jump-{jid}/{name}" not in _known()  # 照合できなかった鍵は引き継がない
    assert not [e for e in ssh_hostkeys.take_events() if e["target"] == "device"]


def test_direct_devices_keep_the_old_names():
    """踏み台を使わない機器は、今までどおり [host]:port で記録する"""
    port, _, _ = fake_sshd.start()
    assert cs.collect_config_sync(_dev(port)).success
    assert f"[127.0.0.1]:{port} ssh-rsa" in _known() and f"/[127.0.0.1]:{port}" not in _known()


# ---------------------------------------------------------------- TOFU の記録


@pytest.fixture
def client():
    with TestClient(app) as c:
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        yield c, {"Authorization": f"Bearer {tok}"}


def _db():
    con = sqlite3.connect(f"{TMP}/t.db")
    con.row_factory = sqlite3.Row
    return con


def test_tofu_is_recorded_in_activity_and_audit(client):
    c, h = client
    key = paramiko.RSAKey.generate(2048)
    port, _, _ = fake_sshd.start(key=key)
    jport, _ = fake_jump.start(password="jpass")
    jh = c.post("/api/jump-hosts/", json={"name": f"tofu-jh-{jport}", "hostname": "127.0.0.1", "port": jport,
                                          "username": "jumpuser", "password": "jpass"}, headers=h).json()
    d = c.post("/api/devices/", json=dict(name=f"tofu-{port}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                          username="admin", password="pw", jump_host_id=jh["id"]), headers=h).json()
    try:
        with mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
            assert worker.collect_device_config.apply(args=(d["id"], "manual", "operator1")).get()["success"]
        fp = ssh_hostkeys.fingerprint(key)
        acts = _db().execute("select device_id, message, detail, actor from activity_logs where event='ssh.hostkey_added'"
                             " and (device_id=? or detail like ?)", (d["id"], f"%{jport}%")).fetchall()
        dev_act = [a for a in acts if a["device_id"] == d["id"]]
        assert len(dev_act) == 1 and fp in dev_act[0]["message"] and dev_act[0]["actor"] == "operator1"
        det = json.loads(dev_act[0]["detail"])
        assert det["fingerprint"] == fp and det["recorded_as"] == f"jump-{jh['id']}/[127.0.0.1]:{port}"
        assert det["via"] == jh["name"] and "pw" not in dev_act[0]["detail"]
        assert any(a["device_id"] is None and "踏み台サーバ" in a["message"] for a in acts)  # 踏み台自身の鍵も
        audit = _db().execute("select username, target_type, target_id, detail from audit_logs"
                              " where action='ssh.hostkey_added' and target_id in (?, ?)", (d["id"], jh["id"])).fetchall()
        assert {(a["target_type"], a["target_id"]) for a in audit} == {("device", d["id"]), ("jump_host", jh["id"])}
        dev_audit = next(a for a in audit if a["target_type"] == "device")
        assert dev_audit["username"] == "operator1" and json.loads(dev_audit["detail"])["fingerprint"] == fp
        # 2 回目は登録済みなので記録しない
        with mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
            assert worker.collect_device_config.apply(args=(d["id"],)).get()["success"]
        assert _db().execute("select count(*) from activity_logs where event='ssh.hostkey_added' and device_id=?",
                             (d["id"],)).fetchone()[0] == 1
        assert "ssh.hostkey_added" in c.get("/api/audit/actions", headers=h).json()
    finally:
        c.delete(f"/api/devices/{d['id']}", headers=h)
        c.delete(f"/api/jump-hosts/{jh['id']}", headers=h)


def test_jump_test_endpoint_records_tofu_with_user(client):
    c, h = client
    jport, _ = fake_jump.start(password="jpass")
    jh = c.post("/api/jump-hosts/", json={"name": f"tofu-test-{jport}", "hostname": "127.0.0.1", "port": jport,
                                          "username": "jumpuser", "password": "jpass"}, headers=h).json()
    try:
        assert c.post(f"/api/jump-hosts/{jh['id']}/test", json={}, headers=h).json()["ok"]
        rows = _db().execute("select username, ip, detail from audit_logs where action='ssh.hostkey_added' and target_id=?",
                             (jh["id"],)).fetchall()
        assert len(rows) == 1 and rows[0]["username"] == "admin" and "SHA256:" in rows[0]["detail"]
        assert c.post(f"/api/jump-hosts/{jh['id']}/test", json={}, headers=h).json()["ok"]  # 2 回目は登録済み
        assert _db().execute("select count(*) from audit_logs where action='ssh.hostkey_added' and target_id=?",
                             (jh["id"],)).fetchone()[0] == 1
    finally:
        c.delete(f"/api/jump-hosts/{jh['id']}", headers=h)


def test_pending_events_are_bounded():
    for i in range(ssh_hostkeys.MAX_PENDING_EVENTS + 10):
        ssh_hostkeys._push_event({"host": str(i)})
    assert len(ssh_hostkeys.take_events(lambda e: e["host"] == "5")) == 1
    assert len(ssh_hostkeys.take_events()) == ssh_hostkeys.MAX_PENDING_EVENTS - 1


def test_terminal_records_tofu_with_user(client):
    c, h = client
    port, _, _ = fake_sshd.start()
    d = c.post("/api/devices/", json=dict(name=f"tofu-term-{port}", hostname="127.0.0.1", port=port,
                                          platform="cisco_ios", username="admin", password="pw"), headers=h).json()
    try:
        with c.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": h["Authorization"].split()[1]}))
            assert "R1#" in ws.receive_text()
        rows = _db().execute("select username, target_type, detail from audit_logs where action='ssh.hostkey_added'"
                             " and target_id=?", (d["id"],)).fetchall()
        assert len(rows) == 1 and rows[0]["username"] == "admin" and rows[0]["target_type"] == "device"
        assert json.loads(rows[0]["detail"])["recorded_as"] == f"[127.0.0.1]:{port}"
        act = _db().execute("select actor from activity_logs where event='ssh.hostkey_added' and device_id=?",
                            (d["id"],)).fetchall()
        assert [a["actor"] for a in act] == ["admin"]
    finally:
        c.delete(f"/api/devices/{d['id']}", headers=h)
