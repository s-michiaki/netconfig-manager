"""コンプライアンスチェックのテスト"""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import config_service as cs
from app.services.compliance import RuleSpec, evaluate, parse_sections

IOS = """\
hostname R1
service password-encryption
enable secret 9 $9$abc
ip http server
!
interface GigabitEthernet0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/2
 shutdown
!
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
!
line vty 0 4
 transport input ssh telnet
line vty 5 15
 transport input ssh
!
ntp server 10.0.0.100
end
"""


# ---------------------------------------------------------------- 評価エンジン
def test_parse_sections():
    secs = parse_sections(IOS.splitlines())
    heads = [h for _, h, _ in secs]
    assert "interface GigabitEthernet0/1" in heads and "line vty 5 15" in heads
    body = dict((h, b) for _, h, b in secs)["interface GigabitEthernet0/1"]
    assert [line.strip() for _, line in body] == ["description uplink", "ip address 10.0.0.1 255.255.255.0"]


@pytest.mark.parametrize("spec,status,detail", [
    (RuleSpec("contains", "present", "service password-encryption"), "pass", None),
    (RuleSpec("regex", "present", r"^ip ssh version 2"), "fail", "一致する行がありません"),
    (RuleSpec("regex", "absent", r"^ip http server"), "fail", "4行目: ip http server"),
    (RuleSpec("regex", "absent", r"^enable password "), "pass", None),
    # 物理インターフェースごとに description が必要 → Gi0/2 が違反（Vlan10 は対象外）
    (RuleSpec("regex", "present", r"^\s+description ", "section", r"^interface GigabitEthernet"), "fail",
     "10行目: interface GigabitEthernet0/2（一致する行がありません）"),
    # VTY で telnet を許可しない → 0 4 だけ違反
    (RuleSpec("regex", "absent", r"transport input .*telnet", "section", r"^line vty"), "fail",
     "16行目: line vty 0 4 → transport input ssh telnet"),
    (RuleSpec("contains", "present", "description", "section", r"^interface NoSuch"), "pass", None),
    (RuleSpec("regex", "present", r"([unclosed"), "error", "正規表現"),
])
def test_evaluate(spec, status, detail):
    ev = evaluate(spec, IOS)
    assert ev.status == status, ev
    if detail:
        assert any(detail in d for d in ev.details), ev.details
    if status == "fail" and spec.scope == "section":
        assert len(ev.details) == 1


def test_detail_limit():
    text = "\n".join(f"bad {i}" for i in range(50))
    ev = evaluate(RuleSpec("contains", "absent", "bad"), text)
    assert ev.status == "fail" and len(ev.details) == 21 and ev.details[-1] == "ほか 30 行"


# ---------------------------------------------------------------- API
def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        for u, role in [("cmp-op", "operator"), ("cmp-view", "viewer")]:
            c.post("/api/users/", json={"username": u, "password": "password-1234", "role": role}, headers=admin)
        devs = {}
        for name, plat, cfg in [
            ("cmp-r1", "cisco_ios", IOS),
            ("cmp-r2", "cisco_ios", IOS.replace("ip http server\n", "").replace(" shutdown\n", " description spare\n")),
            ("cmp-fw", "paloalto_panos", "set deviceconfig system hostname PA\n"),
            ("cmp-new", "cisco_ios", None),  # 未収集
        ]:
            d = c.post("/api/devices/", json=dict(name=f"{name}-{uuid.uuid4().hex[:4]}", hostname="10.6.0.1",
                                                  platform=plat, username="u", password="p"), headers=admin).json()
            if cfg:
                cs.save_config(d["id"], cfg, "test")
            devs[name] = d
        yield {"c": c, "admin": admin, "op": login(c, "cmp-op", "password-1234"),
               "view": login(c, "cmp-view", "password-1234"), "devs": devs}


def test_rule_crud_and_results(ctx):
    c, op, view, devs = ctx["c"], ctx["op"], ctx["view"], ctx["devs"]
    rule = {"name": "HTTP サーバー無効", "platforms": ["cisco_ios"], "match_type": "regex", "expect": "absent",
            "pattern": r"^ip http server", "severity": "high"}
    assert c.post("/api/compliance/rules", json=rule, headers=view).status_code == 403
    r = c.post("/api/compliance/rules", json=rule, headers=op)
    assert r.status_code == 201, r.text
    out = r.json()
    # 作成と同時に全機器を検査: r1 違反 / r2 合格 / fw 対象外 / 未収集は結果なし
    # （他のテストで作った機器も検査されるため、件数は「以上」で確認する）
    assert out["fail_count"] >= 1 and out["pass_count"] >= 1
    res = c.get("/api/compliance/results", params={"rule_id": out["id"]}, headers=view).json()
    by = {x["device_id"]: x for x in res}
    assert by[devs["cmp-r1"]["id"]]["status"] == "fail" and by[devs["cmp-r2"]["id"]]["status"] == "pass"
    assert devs["cmp-fw"]["id"] not in by and devs["cmp-new"]["id"] not in by
    assert by[devs["cmp-r1"]["id"]]["details"] == ["4行目: ip http server"]
    assert by[devs["cmp-r1"]["id"]]["commit_hash"]
    assert c.post("/api/compliance/rules", json=rule, headers=op).status_code == 409  # 同名

    # 無効にすると結果が消える
    r = c.put(f"/api/compliance/rules/{out['id']}", json={**rule, "enabled": False}, headers=op).json()
    assert r["fail_count"] == 0 and r["pass_count"] == 0
    c.put(f"/api/compliance/rules/{out['id']}", json=rule, headers=op)

    # 不正な正規表現・セクション指定漏れ
    assert c.post("/api/compliance/rules", json={**rule, "name": "x", "pattern": "([bad"}, headers=op).status_code == 422
    assert c.post("/api/compliance/rules", json={**rule, "name": "y", "scope": "section"}, headers=op).status_code == 422

    # 収集し直して違反が解消されたら、その機器だけ再検査される
    from app.worker import _check_compliance, _run_async
    cs.save_config(devs["cmp-r1"]["id"], IOS.replace("ip http server\n", ""), "test")
    _run_async(_check_compliance(devs["cmp-r1"]["id"]))
    res = c.get("/api/compliance/results", params={"device_id": devs["cmp-r1"]["id"]}, headers=view).json()
    assert [x["status"] for x in res if x["rule_id"] == out["id"]] == ["pass"]

    # 削除
    assert c.delete(f"/api/compliance/rules/{out['id']}", headers=op).status_code == 204
    assert c.get("/api/compliance/results", params={"rule_id": out["id"]}, headers=view).json() == []


def test_section_rule_summary_and_topology(ctx):
    c, op, admin, devs = ctx["c"], ctx["op"], ctx["admin"], ctx["devs"]
    rule = {"name": f"IF説明-{uuid.uuid4().hex[:4]}", "match_type": "regex", "expect": "present",
            "pattern": r"^\s+description ", "scope": "section", "section_pattern": r"^interface GigabitEthernet",
            "severity": "low", "platforms": []}
    out = c.post("/api/compliance/rules", json=rule, headers=op).json()
    # PAN-OS（字下げなしの set 形式）は対象のセクションが無いので合格
    res = {x["device_id"]: x for x in c.get("/api/compliance/results", params={"rule_id": out["id"]},
                                             headers=op).json()}
    assert res[devs["cmp-r1"]["id"]]["status"] == "fail"
    assert res[devs["cmp-r2"]["id"]]["status"] == "pass"
    assert res[devs["cmp-fw"]["id"]]["status"] == "pass"

    s = c.get("/api/compliance/summary", headers=ctx["view"]).json()
    row = next(x for x in s["devices"] if x["device_id"] == devs["cmp-r1"]["id"])
    assert row["checked"] and row["fail_count"] >= 1 and row["worst_severity"] in ("low", "high")
    assert next(x for x in s["devices"] if x["device_id"] == devs["cmp-new"]["id"])["checked"] is False
    assert s["fail_by_severity"]["low"] >= 1

    # 構成図の機器の状態に違反数が載る
    st = c.post("/api/topology/device-status", json=[devs["cmp-r1"]["id"]], headers=ctx["view"]).json()
    assert st[devs["cmp-r1"]["id"]]["violations"] >= 1

    # 再検査（全機器）と監査ログ
    r = c.post("/api/compliance/run", headers=op)
    assert r.status_code == 200 and r.json()["checked"] >= 3
    acts = [x["action"] for x in c.get("/api/audit/logs", params={"action": "compliance."}, headers=admin).json()["items"]]
    assert "compliance.run" in acts and "compliance.rule_create" in acts

    # 機器を削除すると結果も消える
    assert c.delete(f"/api/devices/{devs['cmp-new']['id']}", headers=admin).status_code == 204


def test_rule_test_and_templates(ctx):
    c, view, devs = ctx["c"], ctx["view"], ctx["devs"]
    t = c.get("/api/compliance/templates", headers=view).json()
    assert len(t) >= 8 and all({"name", "pattern", "severity"} <= set(x) for x in t)
    rule = {"name": "t", "match_type": "contains", "expect": "present", "pattern": "ntp server", "platforms": ["cisco_ios"]}
    r = c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-r1"]["id"]}, headers=view).json()
    assert r == {**r, "applicable": True, "has_config": True, "status": "pass"}
    r = c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-fw"]["id"]}, headers=view).json()
    assert r["applicable"] is False
    # テンプレートはそのままルールとして登録できる
    for x in t:
        body = {k: v for k, v in x.items() if k != "description"}
        assert c.post("/api/compliance/rules/test", json={"rule": body, "device_id": devs["cmp-r2"]["id"]},
                      headers=view).status_code == 200, x["name"]
