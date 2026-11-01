"""対応プラットフォームのテスト（FortiGate・AlliedWare Plus は疑似機器で収集まで確認）"""
import uuid

import pytest
from fastapi.testclient import TestClient
from netmiko.ssh_dispatcher import CLASS_MAPPER

import fake_sshd
from app.main import app
from app.services import config_service as cs


def dev(port, platform, enable_secret=None):
    return cs.DeviceConnectionInfo(
        id=str(uuid.uuid4()), name="d", hostname="127.0.0.1", platform=platform, port=port,
        username="admin", password="pw", enable_secret=enable_secret,
    )


def test_every_platform_has_netmiko_driver_and_command():
    for key, spec in cs.PLATFORMS.items():
        assert spec.device_type in CLASS_MAPPER, key
        assert spec.commands or spec.config_mode_commands, key
        assert spec.label and spec.vendor, key
        assert spec.icon in ("switch", "l3switch", "router", "firewall", "wireless", "server"), key
        for p in spec.ignore_patterns:
            __import__("re").compile(p)


# ---------------------------------------------------------------- FortiGate
def test_fortinet_collect_and_restore_output_mode():
    port, state, _ = fake_sshd.start(mode="fortinet")
    d = dev(port, "fortinet")
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash, r
    content = cs.get_config_content(d.id, r.commit_hash)
    assert content.startswith("#config-version=FGT60F-7.2.5"), content
    assert "#conf_file_ver" not in content
    assert 'set description "日本語の説明"' in content
    # 管理者パスワードのハッシュ（変わらない値）は残し、可逆暗号の値・秘密鍵は伏せる
    assert "set password ENC SH2stablehashvalue=" in content
    assert "set psksecret ENC <暗号化された値（取得のたびに変わるため省略）>" in content
    assert 'set private-key "<秘密鍵（取得のたびに変わるため省略）>"' in content
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in content
    # ページング無効化のため output を standard にし、終了時に more へ戻している
    cmds = state["commands"]
    assert cmds.index("set output standard") < cmds.index("show") < cmds.index("set output more")
    assert state["output"] == "more"
    # 取得のたびに変わる値を伏せているので、2回目は変更なし
    assert cs.collect_config_sync(d).commit_hash is None


def test_fortinet_already_standard_does_not_touch_console():
    port, state, _ = fake_sshd.start(mode="fortinet")
    state["output"] = "standard"
    r = cs.collect_config_sync(dev(port, "fortinet"))
    assert r.success, r
    assert "set output standard" not in state["commands"] and "set output more" not in state["commands"]


# ---------------------------------------------------------------- AlliedWare Plus
def test_awplus_auto_enable_without_password():
    port, state, _ = fake_sshd.start(mode="awplus")
    d = dev(port, "allied_telesis_awplus")
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash, r
    content = cs.get_config_content(d.id, r.commit_hash)
    assert "hostname awplus" in content and " description 日本語の説明" in content
    assert "awplus#" not in content and "show running-config" not in content
    cmds = state["commands"]
    assert cmds.index("terminal length 0") < cmds.index("enable") < cmds.index("show running-config")
    assert cs.collect_config_sync(d).commit_hash is None


def test_awplus_enable_with_password():
    port, state, _ = fake_sshd.start(mode="awplus", enable_password="en-secret")
    assert cs.collect_config_sync(dev(port, "allied_telesis_awplus", enable_secret="en-secret")).success
    # パスワードが違えば失敗する（リトライしても解決しない種類ではないが、失敗として返る）
    r = cs.collect_config_sync(dev(port, "allied_telesis_awplus", enable_secret="wrong"))
    assert not r.success


# ---------------------------------------------------------------- コンフィグ取得コマンドの流れ（汎用の疑似機器）
# Netmiko のドライバーが「# プロンプトの機器」として素直に動くものについて、取得コマンドを送って保存できるかを確かめる
# （プロンプトの形式・ログイン手順が特殊なもの: Huawei・JunOS・MikroTik などはこの疑似機器では確認できない）
GENERIC_OK = [
    "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr", "cisco_asa", "cisco_s300", "cisco_wlc", "cisco_viptela",
    "yamaha", "hp_procurve", "aruba_osswitch", "aruba_aoscx", "aruba_os", "dell_os10", "dell_os9", "dell_os6",
    "extreme_exos", "extreme_vsp", "extreme_ers", "extreme_slx", "extreme_nos", "extreme_netiron", "ruckus_fastiron",
    "vyos", "ubiquiti_edgerouter", "ubiquiti_edgeswitch", "nokia_sros", "checkpoint_gaia", "hillstone_stoneos",
    "alcatel_aos", "a10", "netscaler", "mellanox_mlnxos", "ruijie_os", "zte_zxros", "tplink_jetstream",
    "netgear_prosafe", "broadcom_icos", "dlink_ds", "zyxel_os", "ipinfusion_ocnos", "centec_os", "eltex",
]


@pytest.mark.parametrize("platform", GENERIC_OK)
def test_generic_flow(platform):
    spec = cs.PLATFORMS[platform]
    port, state, _ = fake_sshd.start(mode="generic", config_commands=tuple(spec.commands))
    d = dev(port, platform)
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash, (platform, r, state.get("commands"))
    assert "hostname sw1" in cs.get_config_content(d.id, r.commit_hash)
    assert all(c in state["commands"] for c in spec.commands)


def test_normalize_ignore_patterns():
    xr = "Mon Nov  2 08:00:00.123 JST\nBuilding configuration...\n!! IOS XR Configuration 7.3.2\n!! Last configuration change at Mon Nov  2 07:00:00 2026 by admin\nhostname R1\n"
    assert cs.normalize_config(xr, "cisco_xr") == "!! IOS XR Configuration 7.3.2\nhostname R1\n"
    mt = "# 2026-11-02 08:00:00 by RouterOS 7.16\n# software id = ABCD-1234\n/system identity\nset name=r1\n"
    assert cs.normalize_config(mt, "mikrotik_routeros") == "# software id = ABCD-1234\n/system identity\nset name=r1\n"
    ya = "# RTX1210 Rev.14.01.38 (Fri Jul  3 11:14:19 2020)\n# Reporting Date: Nov 2 08:00:00 2026\nip route default gateway pp 1\n"
    assert "Reporting Date" not in cs.normalize_config(ya, "yamaha")
    es = "!Current Configuration:\n!\n!System Description \"EdgeSwitch\"\n!System Up Time          0 days 1 hrs 2 mins\n!Current SNTP Synchronized Time: Nov 02 08:00:00 2026\nhostname \"sw\"\n"
    assert cs.normalize_config(es, "ubiquiti_edgeswitch") == "!\n!System Description \"EdgeSwitch\"\nhostname \"sw\"\n"


# ---------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        yield c, {"Authorization": f"Bearer {tok}"}


def test_platforms_api_and_validation(client):
    c, h = client
    items = c.get("/api/devices/platforms", headers=h).json()
    ids = [x["id"] for x in items]
    assert ids == list(cs.PLATFORMS) and "fortinet" in ids and "allied_telesis_awplus" in ids
    forti = next(x for x in items if x["id"] == "fortinet")
    assert forti["icon"] == "firewall" and forti["note"] and forti["vendor"] == "Fortinet"
    body = dict(name=f"p-{uuid.uuid4().hex[:6]}", hostname="10.7.7.7", username="u", password="p")
    r = c.post("/api/devices/", json={**body, "platform": "fortinet"}, headers=h)
    assert r.status_code == 201 and r.json()["platform"] == "fortinet"
    assert c.post("/api/devices/", json={**body, "name": "x-bad", "platform": "no_such_os"}, headers=h).status_code == 422
    assert c.put(f"/api/devices/{r.json()['id']}", json={"platform": "bogus"}, headers=h).status_code == 422
    assert c.put(f"/api/devices/{r.json()['id']}", json={"platform": "allied_telesis_awplus"}, headers=h).status_code == 200
