"""機器台帳の自動取得（show version などの読み取りと、収集への組み込み）"""
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from fastapi.testclient import TestClient
from test_device_auth import dev

from app import worker
from app.core.config import settings
from app.main import app
from app.services import config_service as cs
from app.services import inventory

IOS_XE = """Cisco IOS XE Software, Version 17.06.05
Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.6.5, RELEASE SOFTWARE (fc2)

Core-SW01 uptime is 1 year, 2 weeks
cisco C9300-24T (X86) processor with 1331809K/6147K bytes of memory.
Processor board ID FCW2245L0AB

Model Number                       : C9300-24T
System Serial Number               : FCW2245L0AB
"""
ISR = """Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.5(3)S5, RELEASE SOFTWARE (fc2)
rt1 uptime is 3 days
cisco ISR4331/K9 (1RU) processor with 1795999K/6147K bytes of memory.
Processor board ID FDO21520ABC
"""
NXOS = """Cisco Nexus Operating System (NX-OS) Software
Software
  BIOS: version 07.69
  NXOS: version 9.3(10)
Hardware
  cisco Nexus9000 C93180YC-EX chassis
  Intel(R) Xeon(R) CPU  with 24633476 kB of memory.
  Processor Board ID FDO21120V5D

  Device name: N9K-1
"""
ASA = """Cisco Adaptive Security Appliance Software Version 9.16(4)
SSP Operating System Version 2.10(1.217)

fw1 up 10 days 3 hours

Hardware:   ASA5506, 4096 MB RAM, CPU Atom C2000 series 1250 MHz, 1 CPU (4 cores)
Serial Number: JAD2012ABCD
"""
JUNOS = ["""Hostname: ex-1
Model: ex2300-24t
Junos: 21.4R3-S5.4
JUNOS OS Kernel 64-bit  [20230831.de6b1a4_builder_stable_12_214]
""", """Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                JW0218160123      EX2300-24T
Pseudo CB 0
"""]
ARISTA = """Arista DCS-7050TX-64-R
Hardware version: 01.11
Serial number: JPE14080457
Hardware MAC address: 001c.7300.0001

Software image version: 4.28.3M
Architecture: i686
"""
YAMAHA = """RTX1210 BootROM Ver. 1.04
RTX1210 FlashROM Table Ver. 1.00
RTX1210 Rev.14.01.38 (Thu Jul  9 14:30:00 2020)
  main:  RTX1210 ver=00 serial=S4H012345 MAC-Address=00:a0:de:00:00:01 MAC-Address=00:a0:de:00:00:02
CPU:   3%(5sec)   2%(1min)   2%(5min)    Memory: 30% used
"""


def crlf(s: str) -> str:
    return s.replace("\n", "\r\n")


@pytest.mark.parametrize("platform, outputs, expected", [
    ("cisco_ios", [fake_sshd.CISCO_VERSION], ("WS-C2960X-24TS-L", "FOC1234X5YZ", "15.2(7)E7", "R1")),
    ("cisco_xe", [IOS_XE], ("C9300-24T", "FCW2245L0AB", "17.06.05", "Core-SW01")),
    ("cisco_ios", [ISR], ("ISR4331/K9", "FDO21520ABC", "15.5(3)S5", "rt1")),
    ("cisco_nxos", [NXOS], ("Nexus9000 C93180YC-EX", "FDO21120V5D", "9.3(10)", "N9K-1")),
    ("cisco_asa", [ASA], ("ASA5506", "JAD2012ABCD", "9.16(4)", "fw1")),
    ("juniper_junos", JUNOS, ("ex2300-24t", "JW0218160123", "21.4R3-S5.4", "ex-1")),
    ("arista_eos", [ARISTA], ("DCS-7050TX-64-R", "JPE14080457", "4.28.3M", None)),
    ("fortinet", [fake_sshd.FORTI_STATUS], ("FortiGate-60F", "FGT60FTK20012345", "7.2.5 build1517", "FGT60F")),
    ("paloalto_panos", [fake_sshd.PANOS_SYSTEM_INFO], ("PA-220", "012801000001", "10.1.9-h1", "PA-VM")),
    ("allied_telesis_awplus", [fake_sshd.AWPLUS_SYSTEM], ("x230-10GP", "A05050G144100001", "5.5.2-0.1", "awplus")),
    ("yamaha", [YAMAHA], ("RTX1210", "S4H012345", "Rev.14.01.38", None)),
])
def test_parse(platform, outputs, expected):
    it = iter(crlf(o) for o in outputs)
    sent = []
    facts = inventory.gather(platform, lambda cmd: sent.append(cmd) or next(it))
    assert sent == inventory.SPECS[platform][0]
    assert (facts["model"], facts["serial_number"], facts["os_version"], facts["reported_hostname"]) == expected


def test_parse_unreadable_and_unsupported():
    # 読み取れない出力（コマンドが通らない機器など）は None。対応していない機種はコマンドを送らない
    assert inventory.gather("cisco_ios", lambda cmd: "% Invalid input detected at '^' marker.") is None
    assert inventory.gather("mikrotik_routeros", lambda cmd: pytest.fail("送ってはいけない")) is None
    # 一部だけ読めた場合は読めた項目だけ。長すぎる値は捨てる
    facts = inventory.gather("paloalto_panos", lambda cmd: "model: PA-220\r\nserial: " + "9" * 200)
    assert facts == {"model": "PA-220", "serial_number": None, "os_version": None, "reported_hostname": None}
    # 変化の判定: 以前の値がある項目だけ。今回読めなかった項目は「変化」にしない
    old = {"model": "PA-220", "serial_number": "A", "os_version": "10.1.9", "reported_hostname": None}
    new = {"model": "PA-220", "serial_number": None, "os_version": "10.1.11", "reported_hostname": "fw"}
    assert inventory.changes(old, new) == [("os_version", "10.1.9", "10.1.11")]


@pytest.mark.parametrize("mode, platform, model", [
    ("cisco", "cisco_ios", "WS-C2960X-24TS-L"), ("panos", "paloalto_panos", "PA-220"),
    ("fortinet", "fortinet", "FortiGate-60F"), ("awplus", "allied_telesis_awplus", "x230-10GP"),
])
def test_collect_reads_inventory(mode, platform, model):
    port, state, _ = fake_sshd.start(mode=mode)
    r = cs.collect_config_sync(dev(port, platform=platform))
    assert r.success and r.commit_hash, r
    assert r.inventory["model"] == model and r.inventory["serial_number"] and r.inventory["os_version"], r.inventory
    # コンフィグの取得が終わってから実行する
    cmds = state["commands"]
    assert cmds.index(inventory.SPECS[platform][0][0]) > cmds.index(cs.PLATFORMS[platform].commands[-1] if mode != "panos" else "show")


def test_inventory_failure_does_not_fail_collect(monkeypatch):
    # 台帳用のコマンドでページャーが出て止まっても、コンフィグは保存する
    port, state, _ = fake_sshd.start()
    state["inventory_pager"] = True
    r = cs.collect_config_sync(dev(port))
    assert r.success and r.commit_hash and r.inventory is None, r
    # 無効にするとコマンドを送らない
    port, state, _ = fake_sshd.start()
    monkeypatch.setattr(settings, "INVENTORY_ENABLED", False)
    r = cs.collect_config_sync(dev(port))
    assert r.success and r.inventory is None and "show version" not in state["commands"]


def test_worker_saves_inventory_and_records_change():
    port, state, _ = fake_sshd.start()
    with TestClient(app) as c, mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        name = f"inv-{uuid.uuid4().hex[:6]}"
        d = c.post("/api/devices/", json=dict(name=name, hostname="127.0.0.1", port=port, platform="cisco_ios",
                                              username="admin", password="pw"), headers=h).json()
        assert d["model"] is None and d["inventory_at"] is None
        assert worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "inv-1")).get()["success"]
        got = c.get(f"/api/devices/{d['id']}", headers=h).json()
        assert (got["model"], got["serial_number"], got["os_version"], got["reported_hostname"]) == \
            ("WS-C2960X-24TS-L", "FOC1234X5YZ", "15.2(7)E7", "R1") and got["inventory_at"]

        def events():
            return c.get("/api/activity/logs", params={"device_id": d["id"], "event": "inventory.changed"}, headers=h).json()["items"]
        assert events() == []  # 初めての取得は「変化」ではない
        # バージョンアップ → 情報として記録
        state["inventory"] = fake_sshd.CISCO_VERSION.replace("15.2(7)E7", "15.2(7)E9")
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "inv-2")).get()
        ev = events()
        assert len(ev) == 1 and ev[0]["level"] == "info" and "OS バージョン: 15.2(7)E7 → 15.2(7)E9" in ev[0]["message"]
        # 機器の交換（シリアル番号が変わる）→ 警告
        state["inventory"] = state["inventory"].replace("FOC1234X5YZ", "FOC9999X9ZZ")
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "inv-3")).get()
        ev = events()
        assert len(ev) == 2 and ev[0]["level"] == "warning" and "シリアル番号" in ev[0]["message"]
        # 読み取れなくなっても、前回の値は消さない
        state["inventory"] = "% Invalid input"
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", "inv-4")).get()
        assert c.get(f"/api/devices/{d['id']}", headers=h).json()["serial_number"] == "FOC9999X9ZZ" and len(events()) == 2
        # 台帳の CSV（認証情報は含めない）。閲覧者も出力でき、監査ログに残る
        c.post("/api/users/", json={"username": f"{name}-v", "password": "password-1234", "role": "viewer"}, headers=h)
        vt = c.post("/api/auth/token", data={"username": f"{name}-v", "password": "password-1234"}).json()["access_token"]
        r = c.get("/api/devices/export", headers={"Authorization": f"Bearer {vt}"})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        row = next(x for x in r.text.splitlines() if x.startswith(name + ","))
        assert "WS-C2960X-24TS-L,FOC9999X9ZZ,15.2(7)E9,R1" in row and "pw" not in row.split(",")
        assert c.get("/api/audit/logs", params={"action": "device.export"}, headers=h).json()["total"] >= 1
        # 対応している機種は画面で分かる
        plats = {p["id"]: p for p in c.get("/api/devices/platforms", headers=h).json()}
        assert plats["cisco_ios"]["inventory"] and not plats["mikrotik_routeros"]["inventory"]


def test_inventory_change_is_notified(monkeypatch):
    """機器情報が変わったら、「機器情報の変化」を選んだ通知先へ送る（初めての取得・変化なしでは送らない）"""
    from app.services import notify

    sent = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: sent.append((kind, url, payload)))
    monkeypatch.setattr(worker.send_inventory_notification, "delay",
                        lambda *a, **kw: worker.send_inventory_notification.apply(args=a, kwargs=kw).get())
    port, state, _ = fake_sshd.start()
    t = uuid.uuid4().hex[:6]
    hook = f"https://discord.com/api/webhooks/960/{t}"
    with TestClient(app) as c, mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        c.post("/api/users/", json={"username": f"invn-{t}", "password": "password-1234", "role": "viewer"}, headers=h)
        vt = c.post("/api/auth/token", data={"username": f"invn-{t}", "password": "password-1234"}).json()["access_token"]
        vh = {"Authorization": f"Bearer {vt}"}
        r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": False,
                                                 "on_system": False, "on_inventory": True}, headers=vh)
        assert r.status_code == 200 and r.json()["on_inventory"] is True
        d = c.post("/api/devices/", json=dict(name=f"invn-{t}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                              username="admin", password="pw"), headers=h).json()

        def mine():
            return [p for _, u, p in sent if u == hook]

        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()
        assert mine() == []  # 初めての取得・変化なし
        state["inventory"] = fake_sshd.CISCO_VERSION.replace("15.2(7)E7", "15.2(7)E9")
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()
        (p,) = mine()
        emb = p["embeds"][0]
        assert emb["title"] == f"機器情報の変化: invn-{t}"
        assert {"name": "OS バージョン", "value": "15.2(7)E7 → 15.2(7)E9", "inline": True} in emb["fields"]
        # 機器の交換（シリアル番号）は件名と説明で目立たせる
        state["inventory"] = state["inventory"].replace("FOC1234X5YZ", "FOC9999X9ZZ")
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()
        emb = mine()[-1]["embeds"][0]
        assert emb["title"].startswith("機器の交換？") and "登録内容" in emb["description"]
        # 「機器情報の変化」を外すと送らない
        assert c.put("/api/notifications/me", json={"mode": "custom", "on_change": True, "on_system": False,
                                                    "on_inventory": False}, headers=vh).status_code == 200
        state["inventory"] = state["inventory"].replace("15.2(7)E9", "15.2(7)E10")
        worker.collect_device_config.apply(args=(d["id"], "manual", "admin", None)).get()
        assert len(mine()) == 2
        sent_log = c.get("/api/activity/logs", params={"device_id": d["id"], "event": "notify.sent"}, headers=h).json()
        assert any("機器情報の変化を通知しました" in i["message"] for i in sent_log["items"])
        c.delete(f"/api/devices/{d['id']}", headers=h)
        uid_ = next(u["id"] for u in c.get("/api/users/", headers=h).json() if u["username"] == f"invn-{t}")
        assert c.delete(f"/api/users/{uid_}", headers=h).status_code == 204
