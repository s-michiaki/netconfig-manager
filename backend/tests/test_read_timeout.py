"""応答の遅い機器（PAN-OS など）向けの応答待ち時間のテスト"""
import time
import uuid

import fake_sshd
from app.services import config_service as cs
from test_device_auth import admin, client, dev  # noqa: F401 - fixture を再利用


def test_slow_panos_prompt_succeeds_with_default():
    # Netmiko 既定ではログイン後のプロンプト待ちが 20 秒固定のため失敗していたケース
    port, state, _ = fake_sshd.start(mode="panos", login_delay=23)
    r = cs.collect_config_sync(dev(port, platform="paloalto_panos"))
    assert r.success and r.commit_hash, r


def test_short_device_timeout_reports_clear_error():
    port, _, _ = fake_sshd.start(mode="panos", login_delay=14)
    d = dev(port, platform="paloalto_panos")
    d.read_timeout = 10
    t0 = time.time()
    r = cs.collect_config_sync(d)
    assert not r.success and r.retryable
    assert "応答待ち時間" in r.error and "10秒" in r.error, r.error
    assert time.time() - t0 < 30


def test_device_read_timeout_api(client, admin):  # noqa: F811
    assert client.get("/api/devices/defaults", headers=admin).json() == {"read_timeout": 120}
    base = dict(name=f"rt-{uuid.uuid4().hex[:6]}", hostname="10.1.1.2", platform="paloalto_panos",
                username="admin", password="pw")
    for bad in (5, 601):
        assert client.post("/api/devices/", json={**base, "read_timeout": bad}, headers=admin).status_code == 422
    d = client.post("/api/devices/", json={**base, "read_timeout": 180}, headers=admin).json()
    assert d["read_timeout"] == 180
    url = f"/api/devices/{d['id']}"
    assert client.put(url, json={"description": "x"}, headers=admin).json()["read_timeout"] == 180  # 未指定は変更なし
    assert client.put(url, json={"read_timeout": None}, headers=admin).json()["read_timeout"] is None  # 既定に戻す
