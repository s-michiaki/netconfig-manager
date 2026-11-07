"""モニタリング（試験導入）のテスト: 無効時の挙動・SNMP の取得（snmpsim）・FW ヒット数の解析と保存"""
import asyncio
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

import fakeredis
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.monitoring import IfSample, MonInterface
from app.services import fw_hits, monitoring


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        hs = {}
        for role in ("operator", "viewer"):
            name = f"mon-{role}-{uuid.uuid4().hex[:4]}"
            c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
            hs[role] = login(c, name, "password-1234")
        yield {"c": c, "admin": admin, "op": hs["operator"], "view": hs["viewer"]}


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "MONITORING_ENABLED", True)


def device(c, h, **kw):
    body = dict(name=f"mon-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", platform="cisco_ios", username="u", password="p")
    body.update(kw)
    r = c.post("/api/devices/", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_disabled_by_default(ctx):
    c, admin = ctx["c"], ctx["admin"]
    assert settings.MONITORING_ENABLED is False
    assert c.get("/api/health").json()["features"] == {"monitoring": False}
    r = c.get("/api/monitoring/snmp", headers=admin)
    assert r.status_code == 404 and "MONITORING_ENABLED" in r.json()["detail"]
    assert worker.poll_snmp.apply().get() == {"disabled": True}
    assert worker.collect_fw_hits_all.apply().get() == {"disabled": True}


def test_snmp_settings(ctx, enabled):
    c, admin, op, view = ctx["c"], ctx["admin"], ctx["op"], ctx["view"]
    assert c.get("/api/health").json()["features"]["monitoring"] is True
    d = device(c, admin)
    url = f"/api/monitoring/snmp/{d['id']}"
    assert c.put(url, json={"version": "2c", "community": "public"}, headers=op).status_code == 403
    # 入力チェック
    assert c.put(url, json={"version": "2c"}, headers=admin).status_code == 422
    assert c.put(url, json={"version": "3"}, headers=admin).status_code == 422
    assert c.put(url, json={"version": "3", "v3_user": "u", "v3_auth_proto": "SHA", "v3_auth_key": "short"},
                 headers=admin).status_code == 422
    assert c.put(url, json={"version": "3", "v3_user": "u", "v3_priv_proto": "AES", "v3_priv_key": "privpass1"},
                 headers=admin).status_code == 422
    r = c.put(url, json={"version": "3", "v3_user": "mon", "v3_auth_proto": "SHA256", "v3_auth_key": "authpass1",
                         "v3_priv_proto": "AES", "v3_priv_key": "privpass1"}, headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["has_auth_key"] and r.json()["has_priv_key"] and "authpass1" not in r.text
    # 秘密の値は省略すると変えない
    r = c.put(url, json={"version": "3", "v3_user": "mon", "v3_auth_proto": "SHA256", "v3_priv_proto": "AES",
                         "port": 1161}, headers=admin)
    assert r.status_code == 200 and r.json()["has_priv_key"] and r.json()["port"] == 1161
    rows = {x["device_id"]: x for x in c.get("/api/monitoring/snmp", headers=view).json()}
    assert rows[d["id"]]["configured"] and rows[d["id"]]["version"] == "3"
    log = c.get("/api/audit/logs", params={"action": "monitor.snmp_update"}, headers=admin).json()["items"][0]
    assert "authpass1" not in log["detail"]
    assert c.delete(url, headers=admin).status_code == 204
    assert c.delete(url, headers=admin).status_code == 404


# ---------------------------------------------------------------- SNMP（snmpsim で機器の代わりをさせる）

SNMPREC = """1.3.6.1.2.1.1.1.0|4|Test switch
1.3.6.1.2.1.1.5.0|4|SW-TEST
1.3.6.1.2.1.2.2.1.8.1|2|1
1.3.6.1.2.1.2.2.1.8.2|2|2
1.3.6.1.2.1.31.1.1.1.1.1|4|Gi1/0/1
1.3.6.1.2.1.31.1.1.1.1.2|4|Gi1/0/2
1.3.6.1.2.1.31.1.1.1.6.1|70:numeric|rate=125000,initial=1000
1.3.6.1.2.1.31.1.1.1.6.2|70|0
1.3.6.1.2.1.31.1.1.1.10.1|70:numeric|rate=12500,initial=1000
1.3.6.1.2.1.31.1.1.1.10.2|70|0
1.3.6.1.2.1.31.1.1.1.15.1|66|1000
1.3.6.1.2.1.31.1.1.1.15.2|66|1000
1.3.6.1.2.1.31.1.1.1.18.1|4|uplink to core
1.3.6.1.2.1.31.1.1.1.18.2|4|
"""


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def snmp_agent():
    exe = shutil.which("snmpsim-command-responder") or str(Path(sys.executable).with_name("snmpsim-command-responder"))
    if not Path(exe).exists():
        pytest.skip("snmpsim がインストールされていません（requirements-dev.txt）")
    work = tempfile.mkdtemp(prefix="snmpsim-")
    os.chmod(work, 0o755)
    Path(work, "data").mkdir()
    Path(work, "data", "public.snmprec").write_text(SNMPREC)
    os.chmod(Path(work, "data"), 0o755)
    port = _free_udp_port()
    args = [exe, f"--data-dir={work}/data", f"--agent-udpv4-endpoint=127.0.0.1:{port}", f"--cache-dir={work}/cache"]
    if hasattr(os, "geteuid") and os.geteuid() == 0:  # root では権限を落とす必要がある
        args += ["--process-user=nobody", "--process-group=nogroup"]
        os.makedirs(f"{work}/cache", exist_ok=True)
        os.chmod(f"{work}/cache", 0o777)
    log = open(f"{work}/sim.log", "w")  # noqa: SIM115 - PIPE だとログでバッファが詰まり応答が止まるためファイルへ
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    target = monitoring.SnmpTarget("x", "x", "127.0.0.1", port, "2c", community="public")
    for _ in range(50):
        try:
            asyncio.run(monitoring.snmp_get_info(target))
            break
        except Exception:  # noqa: BLE001 - 起動待ち
            if proc.poll() is not None:
                pytest.skip(f"snmpsim を起動できません: {Path(work, 'sim.log').read_text()[-300:]}")
            time.sleep(0.2)
    yield port
    proc.terminate()
    proc.wait(5)
    log.close()
    shutil.rmtree(work, ignore_errors=True)


def test_snmp_poll(ctx, enabled, snmp_agent):
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]
    d = device(c, admin)
    assert c.put(f"/api/monitoring/snmp/{d['id']}", json={"version": "2c", "community": "public", "port": snmp_agent},
                 headers=admin).status_code == 200
    info = c.post(f"/api/monitoring/snmp/{d['id']}/test", headers=admin)
    assert info.status_code == 200 and info.json()["sys_name"] == "SW-TEST"

    async def poll():
        async with AsyncSessionLocal() as db:
            return await monitoring.poll_all(db)
    first = asyncio.run(poll())
    assert first["ok"] >= 1 and first["samples"] == 0  # 1回目はカウンタを覚えるだけ
    time.sleep(1.5)
    with mock.patch.object(monitoring, "MIN_SAMPLE_SEC", 1):
        second = asyncio.run(poll())
    assert second["samples"] >= 1
    ifs = {i["name"]: i for i in c.get("/api/monitoring/interfaces", params={"device_id": d["id"]}, headers=view).json()}
    up, down = ifs["Gi1/0/1"], ifs["Gi1/0/2"]
    assert up["oper_up"] and up["alias"] == "uplink to core" and up["speed_mbps"] == 1000
    assert up["in_bps"] > 0 and up["in_util"] is not None and up["in_bps"] > up["out_bps"]
    assert not down["oper_up"] and down["in_bps"] == 0
    series = c.get(f"/api/monitoring/interfaces/{up['id']}/samples", params={"hours": 1}, headers=view).json()
    assert len(series["points"]) == 1 and series["points"][0]["in_bps"] == up["in_bps"]
    # 停止中のインタフェースは記録しない（MONITOR_UP_ONLY）
    assert c.get(f"/api/monitoring/interfaces/{down['id']}/samples", headers=view).json()["points"] == []
    assert any(x["id"] == up["id"] for x in c.get("/api/monitoring/interfaces/top", headers=view).json())

    # 応答しない機器は失敗として残し、他の機器の取得は続ける
    d2 = device(c, admin, hostname="127.0.0.1")
    c.put(f"/api/monitoring/snmp/{d2['id']}", json={"version": "2c", "community": "wrong", "port": snmp_agent},
          headers=admin)
    with mock.patch.object(settings, "SNMP_TIMEOUT", 0.5), mock.patch.object(settings, "SNMP_RETRIES", 0):
        third = asyncio.run(poll())
    assert third["failed"] == 1 and third["ok"] >= 1
    # 前回から短すぎる取得（MIN_SAMPLE_SEC 未満）では記録せず、値も変えない
    assert third["samples"] == 0
    again = {i["name"]: i for i in c.get("/api/monitoring/interfaces", params={"device_id": d["id"]}, headers=view).json()}
    assert again["Gi1/0/1"]["in_bps"] == up["in_bps"]
    rows = {x["device_id"]: x for x in c.get("/api/monitoring/snmp", headers=view).json()}
    assert rows[d2["id"]]["last_error"] and rows[d["id"]]["last_error"] is None
    assert c.post(f"/api/monitoring/snmp/{d2['id']}/test", headers=admin).status_code == 422

    # 機器を削除するとモニタリングのデータも消える
    c.delete(f"/api/devices/{d2['id']}", headers=admin)
    assert d2["id"] not in {x["device_id"] for x in c.get("/api/monitoring/snmp", headers=view).json()}


def test_rate_and_downsample(ctx, enabled):
    c, admin, view = ctx["c"], ctx["admin"], ctx["view"]
    assert monitoring._rate(1000, 2000, 8) == 1000.0
    assert monitoring._rate(2000, 1000, 8) is None  # カウンタが戻った
    assert monitoring._rate(None, 1000, 8) is None
    d = device(c, admin)

    async def setup():
        async with AsyncSessionLocal() as db:
            i = MonInterface(device_id=d["id"], if_index=1, name="ge-0/0/0", speed_mbps=100, oper_up=True,
                             in_bps=50e6, out_bps=1e6, last_at=utcnow())
            db.add(i)
            await db.flush()
            now = utcnow()
            for k in range(2000):  # 5分ごと約7日分
                db.add(IfSample(interface_id=i.id, at=now - timedelta(minutes=5 * k), in_bps=float(k % 10) * 1e6,
                                out_bps=1e6))
            old = IfSample(interface_id=i.id, at=now - timedelta(days=settings.MONITOR_RETENTION_DAYS + 1),
                           in_bps=1.0, out_bps=1.0)
            db.add(old)
            await db.commit()
            return i.id
    iid = asyncio.run(setup())
    s = c.get(f"/api/monitoring/interfaces/{iid}/samples", params={"hours": 24 * 7}, headers=view).json()
    assert 0 < len(s["points"]) <= 600 and s["bucket_seconds"] > settings.MONITOR_INTERVAL_SEC
    assert s["points"][0]["in_max"] >= s["points"][0]["in_bps"]
    assert s["interface"]["in_util"] == 50.0

    async def purge():
        async with AsyncSessionLocal() as db:
            n = await monitoring.purge_samples(db)
            await db.commit()
            return n
    assert asyncio.run(purge()) >= 1


# ---------------------------------------------------------------- FW ルールのヒット数

PANOS = """
Rule Name                     Hit Count            Last Hit Timestamp             Last Reset Timestamp           First Hit Timestamp            Rule Creation Timestamp        Rule Modify Timestamp
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
allow-dns                     12345                Fri Nov  7 10:00:01 2026       -                              Mon Jan  6 09:00:00 2025       Mon Jan  6 08:00:00 2025       Mon Jan  6 08:00:00 2025
web access to dmz             0                    -                              -                              -                              Mon Jan  6 08:00:00 2025       Mon Jan  6 08:00:00 2025
a-very-long-rule-name-that-overflows-the-column 77     Fri Nov  7 09:00:00 2026       -                              Fri Nov  7 08:00:00 2026       -                              -
intrazone-default             982                  Thu Nov  6 21:10:00 2026       -                              Mon Jan  6 09:00:00 2025       -                              -

admin@PA-VM>
"""

FORTI_SHOW = """config firewall policy
    edit 3
        set name "LAN-to-WAN"
        set srcintf "port2"
    next
    edit 1
        set name "DMZ-web"
    next
    edit 7
        set srcintf "port3"
    next
end
"""

FORTI_IPROPE = """policy index=3 uuid_idx=14 action=accept
flag (8050108): redir nat master use_src pol_stats
pkts/bytes=268530/178372466
asic_pkts/asic_bytes=0/0
first hit:2026-10-01 10:00:00 last hit:2026-11-07 15:00:00
hit count:1234
policy index=1 uuid_idx=15 action=accept
pkts/bytes=10/2000
first hit:2026-11-01 08:00:00 last hit:2026-11-02 08:00:00
hit count:5
policy index=1 uuid_idx=15 action=accept
pkts/bytes=5/1000
hit count:2
"""


def test_parsers():
    rules = fw_hits.parse_panos(PANOS)
    assert [r.name for r in rules] == ["allow-dns", "web access to dmz", "a-very-long-rule-name-that-overflows-the-column",
                                      "intrazone-default"]
    assert [r.hit_count for r in rules] == [12345, 0, 77, 982]
    assert rules[0].last_hit_at.isoformat() == "2026-11-07T10:00:01" and rules[1].last_hit_at is None
    assert rules[0].first_hit_at.year == 2025 and rules[2].last_hit_at.hour == 9
    assert fw_hits.parse_panos("Error: something") == []

    pol = fw_hits.parse_forti_policies(FORTI_SHOW)
    assert pol == [("3", "LAN-to-WAN"), ("1", "DMZ-web"), ("7", "")]
    st = fw_hits.parse_forti_iprope(FORTI_IPROPE)
    assert st["3"]["hit_count"] == 1234 and st["3"]["bytes"] == 178372466
    assert st["1"]["hit_count"] == 7 and st["1"]["packets"] == 15  # 複数エントリは合算
    assert st["3"]["last_hit_at"].isoformat() == "2026-11-07T15:00:00"

    dev = mock.Mock(platform="fortinet")
    with mock.patch.object(fw_hits, "run_commands", return_value=[FORTI_SHOW, FORTI_IPROPE]):
        res = fw_hits.collect_fw_hits(dev)
    assert res.error is None and [r.name for r in res.rules] == ["LAN-to-WAN", "DMZ-web", "ポリシー 7"]
    assert res.rules[2].hit_count == 0 and "diagnose firewall iprope" in res.raw
    # iprope の統計を読めないとき（権限不足・VDOM の Command fail など）は、全ポリシーを 0 にせず失敗にする
    for bad in ["Command fail. Return code -61", "", "Unknown action 0"]:
        with mock.patch.object(fw_hits, "run_commands", return_value=[FORTI_SHOW, bad]):
            res = fw_hits.collect_fw_hits(dev)
        assert res.error and "iprope" in res.error and res.rules == [] and "LAN-to-WAN" in res.raw
    assert fw_hits.collect_fw_hits(mock.Mock(platform="cisco_ios")).error
    with mock.patch.object(fw_hits, "run_commands", side_effect=ValueError("接続できません")):
        assert fw_hits.collect_fw_hits(mock.Mock(platform="paloalto_panos", jump=None, read_timeout=None)).error


def test_fw_hits_flow(ctx, enabled):
    c, admin, op, view = ctx["c"], ctx["admin"], ctx["op"], ctx["view"]
    fw = device(c, admin, platform="paloalto_panos")
    ios = device(c, admin)
    listed = {x["device_id"]: x for x in c.get("/api/monitoring/fw", headers=view).json()}
    assert fw["id"] in listed and ios["id"] not in listed and listed[fw["id"]]["collected_at"] is None

    with mock.patch.object(worker.collect_fw_hits_device, "delay") as dly:
        dly.return_value.id = "task-fw"
        assert c.post(f"/api/monitoring/fw/{fw['id']}/collect", headers=view).status_code == 403
        assert c.post(f"/api/monitoring/fw/{ios['id']}/collect", headers=op).status_code == 404
        assert c.post(f"/api/monitoring/fw/{fw['id']}/collect", headers=op).json() == {"task_id": "task-fw"}

    fr = fakeredis.FakeRedis()
    out1 = PANOS
    out2 = PANOS.replace("12345 ", "12400 ").replace("982 ", "1000")
    with mock.patch.object(worker, "_redis", return_value=fr):
        with mock.patch.object(fw_hits, "run_commands", return_value=[out1]):
            assert worker.collect_fw_hits_device.apply(args=(fw["id"], "admin")).get()["rules"] == 4
        with mock.patch.object(fw_hits, "run_commands", return_value=[out2]):
            worker.collect_fw_hits_device.apply(args=(fw["id"], "admin")).get()
    rules = c.get(f"/api/monitoring/fw/{fw['id']}/rules", headers=view).json()
    by = {r["name"]: r for r in rules}
    assert by["allow-dns"]["hit_count"] == 12400 and by["allow-dns"]["delta"] == 55
    assert by["web access to dmz"]["unused"] and not by["allow-dns"]["unused"]
    st = {x["device_id"]: x for x in c.get("/api/monitoring/fw", headers=view).json()}[fw["id"]]
    assert st["success"] and st["rule_count"] == 4 and st["unused_count"] == 1 and st["has_raw"]
    assert c.get(f"/api/monitoring/fw/{fw['id']}/raw", headers=op).status_code == 403
    assert "allow-dns" in c.get(f"/api/monitoring/fw/{fw['id']}/raw", headers=admin).text

    # 失敗したときは前回のルールを残し、アクティビティに記録する
    with mock.patch.object(worker, "_redis", return_value=fr), \
            mock.patch.object(fw_hits, "run_commands", side_effect=ValueError("未対応の応答")):
        assert worker.collect_fw_hits_device.apply(args=(fw["id"], "admin", "ref-fw")).get()["error"]
    st = {x["device_id"]: x for x in c.get("/api/monitoring/fw", headers=view).json()}[fw["id"]]
    assert st["success"] is False and st["rule_count"] == 4 and "未対応の応答" in st["error"]
    assert len(c.get(f"/api/monitoring/fw/{fw['id']}/rules", headers=view).json()) == 4
    acts = c.get("/api/activity/logs", params={"ref": "ref-fw"}, headers=view).json()["items"]
    assert acts[0]["event"] == "monitor.fw_failed" and acts[0]["level"] == "warning"

    # 定期取得は対応機種の有効な機器だけを投入する
    with mock.patch.object(worker.collect_fw_hits_device, "delay") as dly:
        n = worker.collect_fw_hits_all.apply().get()["devices"]
        ids = {call.args[0] for call in dly.call_args_list}
    assert fw["id"] in ids and ios["id"] not in ids and n == len(ids)
