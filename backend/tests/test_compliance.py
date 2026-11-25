"""コンプライアンスチェックのテスト"""
import uuid

import pytest
import regex_cases
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
    body = {h: b for _, h, b in secs}["interface GigabitEthernet0/1"]
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
    c, op, view, devs = ctx["c"], ctx["op"], ctx["view"], ctx["devs"]
    t = c.get("/api/compliance/templates", headers=view).json()
    assert len(t) >= 8 and all({"name", "pattern", "severity"} <= set(x) for x in t)
    rule = {"name": "t", "match_type": "contains", "expect": "present", "pattern": "ntp server", "platforms": ["cisco_ios"]}
    # 試すのはルールを作る人（オペレーター以上）だけ
    assert c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-r1"]["id"]},
                  headers=view).status_code == 403
    r = c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-r1"]["id"]}, headers=op).json()
    assert r == {**r, "applicable": True, "has_config": True, "status": "pass"}
    r = c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-fw"]["id"]}, headers=op).json()
    assert r["applicable"] is False
    # テンプレートはそのままルールとして登録できる
    for x in t:
        body = {k: v for k, v in x.items() if k != "description"}
        assert c.post("/api/compliance/rules/test", json={"rule": body, "device_id": devs["cmp-r2"]["id"]},
                      headers=op).status_code == 200, x["name"]


# ---------------------------------------------------------------- 正規表現の照合時間（ReDoS 対策）
EVIL = r"^(?:a|aa)+c"  # 「a」が続く行で照合が指数関数的に長くなる
EVIL_CONFIG = "hostname r1\n" + "a" * 40 + "\n"


@pytest.mark.parametrize("spec, ignore", [
    (RuleSpec("regex", "absent", EVIL), None),
    (RuleSpec("contains", "present", "x", "section", section_pattern=EVIL), None),
    (RuleSpec("contains", "absent", "a"), [EVIL]),  # 例外の正規表現
])
def test_regex_timeout(monkeypatch, spec, ignore):
    import time

    from app.core.config import settings
    from app.services.compliance import compile_pattern
    monkeypatch.setattr(settings, "COMPLIANCE_REGEX_TIMEOUT", 0.3)
    t0 = time.monotonic()
    ev = evaluate(spec, EVIL_CONFIG, [compile_pattern(p) for p in ignore] if ignore else None)
    assert time.monotonic() - t0 < 2
    assert ev.status == "error" and "0.3 秒" in ev.details[0]


def test_regex_timeout_does_not_block_api(ctx, monkeypatch):
    """照合が終わらないパターンを試しても、ほかのリクエストは止まらず、結果はエラーになる"""
    import threading
    import time

    from app.core.config import settings
    monkeypatch.setattr(settings, "COMPLIANCE_REGEX_TIMEOUT", 1.5)
    c, op, admin = ctx["c"], ctx["op"], ctx["admin"]
    dev = c.post("/api/devices/", json=dict(name=f"cmp-evil-{uuid.uuid4().hex[:4]}", hostname="10.6.0.9",
                                            platform="cisco_ios", username="u", password="p"), headers=admin).json()
    cs.save_config(dev["id"], EVIL_CONFIG, "test")
    rule = {"name": "evil", "match_type": "regex", "expect": "absent", "pattern": EVIL}
    out = {}

    def run():
        try:
            out["r"] = c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": dev["id"]},
                              headers=op).json()
        except Exception as e:  # noqa: BLE001
            out["e"] = repr(e)

    th = threading.Thread(target=run)
    th.start()
    time.sleep(0.3)
    t0 = time.monotonic()
    assert c.get("/api/health").status_code == 200
    assert time.monotonic() - t0 < 1.0  # 照合中でも応答する（GIL を手放している）
    th.join(10)
    assert "r" in out, out
    assert out["r"]["status"] == "error", out


# ---------------------------------------------------------------- 重い正規表現（読み込みの重さを別のプロセスで測る）
# 重いものはテストのプロセスでは compile せず、子プロセスの中で止まることだけを確かめる
HEAVY = regex_cases.HEAVY
NORMAL = regex_cases.NORMAL


@pytest.mark.parametrize("pattern", HEAVY)
def test_heavy_pattern_evaluate_error(pattern):
    """DB に入っている重いルール・見出しは「エラー」にする（検査全体は止めない）"""
    for spec in (RuleSpec("regex", "absent", pattern),
                 RuleSpec("contains", "present", "x", "section", section_pattern=pattern)):
        ev = evaluate(spec, IOS)
        assert ev.status == "error" and "重すぎます" in ev.details[0], ev


def test_templates_and_normal_patterns_pass():
    """テンプレートの正規表現と、IP アドレス・MAC アドレスなどを含む普通のルールは通る（以前の文字列の検査の誤検出）"""
    from app.services.compliance import TEMPLATES, validate_spec
    specs = [RuleSpec(t["match_type"], t["expect"], t["pattern"], t.get("scope", "config"), t.get("section_pattern"))
             for t in TEMPLATES]
    specs += [RuleSpec("regex", "absent", p) for p in NORMAL]
    specs += [RuleSpec("regex", "present", r"^\s+description ", "section", p) for p in NORMAL]
    assert len(TEMPLATES) >= 15
    for spec in specs:
        validate_spec(spec)


def test_heavy_pattern_rejected_by_api(ctx):
    """ルール・セクションの見出し・ルールの試し・例外の正規表現で、重いパターンは 422（日本語の理由）。500 にしない"""
    import time
    c, op, devs = ctx["c"], ctx["op"], ctx["devs"]
    r1 = devs["cmp-r1"]["id"]
    base = {"name": f"heavy-{uuid.uuid4().hex[:4]}", "match_type": "regex", "expect": "absent", "pattern": "^x"}
    ok = c.post("/api/compliance/rules", json=base, headers=op)
    assert ok.status_code == 201, ok.text
    try:
        for p in HEAVY:
            t0 = time.monotonic()
            for r in (
                c.post("/api/compliance/rules", json={**base, "name": "heavy-x", "pattern": p}, headers=op),
                c.post("/api/compliance/rules", json={**base, "name": "heavy-y", "scope": "section",
                                                      "section_pattern": p}, headers=op),
                c.put(f"/api/compliance/rules/{ok.json()['id']}", json={**base, "pattern": p}, headers=op),
                c.post("/api/compliance/rules/test", json={"rule": {**base, "pattern": p}, "device_id": r1}, headers=op),
                c.post("/api/compliance/exceptions", json={"rule_id": ok.json()["id"], "device_id": r1,
                                                           "ignore_pattern": p, "reason": "x"}, headers=op),
            ):
                assert r.status_code == 422, r.text
                assert "重すぎます" in r.json()["detail"], r.text
            assert time.monotonic() - t0 < 5, p
        # 括弧の入れ子が深すぎる（compile が RecursionError）ものも 422。速い経路（{ なし）と遅い経路（{ あり）の両方
        for p in ("(" * 400 + "a" + ")" * 400, "(" * 400 + "a{2}" + ")" * 400):
            r = c.post("/api/compliance/rules", json={**base, "name": "deep", "pattern": p}, headers=op)
            assert r.status_code == 422 and "入れ子が深すぎます" in r.json()["detail"], r.text
        # 普通のパターンは通る
        for p in NORMAL:
            r = c.post("/api/compliance/rules/test", json={"rule": {**base, "pattern": p}, "device_id": r1}, headers=op)
            assert r.status_code == 200 and r.json()["status"] in ("pass", "fail"), r.text
            r = c.post("/api/compliance/exceptions", json={"rule_id": ok.json()["id"], "device_id": r1,
                                                           "ignore_pattern": p, "reason": "x"}, headers=op)
            assert r.status_code == 201, r.text
            assert c.delete(f"/api/compliance/exceptions/{r.json()['id']}", headers=op).status_code == 204
        r = c.post("/api/compliance/rules", json={**base, "name": base["name"] + "-s", "scope": "section",
                                                  "pattern": NORMAL[0], "section_pattern": NORMAL[3]}, headers=op)
        assert r.status_code == 201, r.text
        c.delete(f"/api/compliance/rules/{r.json()['id']}", headers=op)
    finally:
        c.delete(f"/api/compliance/rules/{ok.json()['id']}", headers=op)


def test_heavy_rule_in_db_does_not_stop_checks(ctx, caplog):
    """API を通さずに DB に入った重いルール・除外があっても、worker の検査は止まらない。ルールはエラー、除外は使わない"""
    import asyncio
    import logging

    from app.core.database import AsyncSessionLocal
    from app.models.compliance import ComplianceException, ComplianceRule
    from app.worker import _check_compliance, _run_async
    c, op, view, devs = ctx["c"], ctx["op"], ctx["view"], ctx["devs"]
    r1 = devs["cmp-r1"]["id"]
    tag = uuid.uuid4().hex[:4]
    # r1 には ntp server の行があるので違反になる
    good = c.post("/api/compliance/rules", json={"name": f"good-{tag}", "match_type": "regex", "expect": "absent",
                                                 "pattern": NORMAL[0], "platforms": ["cisco_ios"]}, headers=op).json()

    async def insert():
        async with AsyncSessionLocal() as db:
            heavy = ComplianceRule(name=f"heavy-db-{tag}", match_type="regex", expect="absent", pattern=HEAVY[0],
                                   platforms='["cisco_ios"]')
            db.add(heavy)
            await db.flush()
            db.add(ComplianceException(rule_id=good["id"], device_id=r1, ignore_pattern=HEAVY[1], reason="x"))
            await db.commit()
            return heavy.id
    heavy_id = asyncio.run(insert())
    try:
        with caplog.at_level(logging.WARNING, logger="app.services.compliance"):
            _run_async(_check_compliance(r1))
        res = {x["rule_id"]: x for x in c.get("/api/compliance/results", params={"device_id": r1}, headers=view).json()}
        assert res[heavy_id]["status"] == "error" and "重すぎます" in res[heavy_id]["details"][0]
        # 読み込めない除外は使わない（除外にならず違反のまま）。飛ばしたことはログに残す
        assert res[good["id"]]["status"] == "fail"
        assert any("読み込めない除外" in r.getMessage() and HEAVY[1][:80] in r.getMessage() for r in caplog.records)
    finally:
        c.delete(f"/api/compliance/rules/{heavy_id}", headers=op)
        c.delete(f"/api/compliance/rules/{good['id']}", headers=op)


def test_regex_validation_does_not_block_api(ctx, monkeypatch):
    """ルール・例外の正規表現の検証（compile）はスレッドで行い、その間もほかのリクエストに応答する"""
    import threading
    import time

    import app.api.compliance as api
    c, op, devs = ctx["c"], ctx["op"], ctx["devs"]
    orig_spec, orig_ignore = api.validate_spec, api.validate_ignore_pattern

    def slow(orig):
        def f(*a):
            time.sleep(1.5)  # compile に時間がかかる場合の代わり
            return orig(*a)
        return f
    monkeypatch.setattr(api, "validate_spec", slow(orig_spec))
    monkeypatch.setattr(api, "validate_ignore_pattern", slow(orig_ignore))
    rule = {"name": "slow", "match_type": "regex", "expect": "absent", "pattern": r"^(?!x)"}
    calls = [
        lambda: c.post("/api/compliance/rules/test", json={"rule": rule, "device_id": devs["cmp-r1"]["id"]}, headers=op),
        lambda: c.post("/api/compliance/exceptions", json={"rule_id": "nope", "device_id": devs["cmp-r1"]["id"],
                                                           "ignore_pattern": "x", "reason": "x"}, headers=op),
    ]
    for call in calls:
        out = {}
        th = threading.Thread(target=lambda out=out, call=call: out.setdefault("r", call()))
        th.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        assert c.get("/api/health").status_code == 200
        assert time.monotonic() - t0 < 1.0  # 検証の途中でも応答する
        th.join(10)
        assert "r" in out and out["r"].status_code in (200, 404), out


# ---------------------------------------------------------------- 例外
def test_evaluate_with_exceptions():
    from app.services.compliance import ExceptionSpec, evaluate_with_exceptions
    sec = RuleSpec("regex", "present", r"^\s+description ", "section", r"^interface GigabitEthernet")
    # 予備ポート（Gi0/2）のセクションを外すと除外扱い
    ev = evaluate_with_exceptions(sec, IOS, [ExceptionSpec("予備ポート", r"GigabitEthernet0/2$")])
    assert ev.status == "exempt" and ev.details[0] == "例外: 予備ポート"
    assert ev.details[1] == "除外: 10行目: interface GigabitEthernet0/2"
    # 一致しない箇所を指定しても違反のまま
    assert evaluate_with_exceptions(sec, IOS, [ExceptionSpec("x", r"Gi9/9")]).status == "fail"
    # コンフィグ全体で「あってはいけない」: 違反行の一部だけ外す
    absent = RuleSpec("regex", "absent", r"^(ip http server|ntp server)")
    ev = evaluate_with_exceptions(absent, IOS, [ExceptionSpec("NTP は許可", r"^ntp ")])
    assert ev.status == "fail" and ev.details == ["4行目: ip http server"] and ev.ignored == ["21行目: ntp server 10.0.0.100"]
    # 機器単位: 違反は除外、合格はそのまま合格
    ev = evaluate_with_exceptions(absent, IOS, [ExceptionSpec("移行中")])
    assert ev.status == "exempt" and ev.details[0] == "例外（機器単位）: 移行中" and "4行目: ip http server" in ev.details
    assert evaluate_with_exceptions(RuleSpec("contains", "absent", "nothing"), IOS, [ExceptionSpec("x")]).status == "pass"
    # 「必要」なルールでは箇所の指定は使わない
    present = RuleSpec("regex", "present", r"^ip ssh version 2")
    assert evaluate_with_exceptions(present, IOS, [ExceptionSpec("x", r".*")]).status == "fail"


def test_exception_api(ctx):
    c, op, view, admin, devs = ctx["c"], ctx["op"], ctx["view"], ctx["admin"], ctx["devs"]
    rule = c.post("/api/compliance/rules", json={
        "name": f"IF説明-例外-{uuid.uuid4().hex[:4]}", "match_type": "regex", "expect": "present",
        "pattern": r"^\s+description ", "scope": "section", "section_pattern": r"^interface GigabitEthernet",
        "severity": "medium", "platforms": ["cisco_ios"]}, headers=op).json()
    r1 = devs["cmp-r1"]["id"]

    def status_of(device_id):
        res = c.get("/api/compliance/results", params={"rule_id": rule["id"], "device_id": device_id}, headers=view).json()
        return res[0]["status"] if res else None

    cleanup = c.post("/api/compliance/rules", json={
        "name": f"HTTP-例外-{uuid.uuid4().hex[:4]}", "match_type": "regex", "expect": "present",
        "pattern": "^ip ssh version 2", "platforms": ["cisco_ios"]}, headers=op).json()
    # IOS の Gi0/2 は shutdown で description なし → 違反（r1 は前のテストで差し替え済みでも Gi0/2 は同じ）
    assert status_of(r1) == "fail"
    body = {"rule_id": rule["id"], "device_id": r1, "ignore_pattern": r"GigabitEthernet0/2$", "reason": "予備ポート"}
    assert c.post("/api/compliance/exceptions", json=body, headers=view).status_code == 403
    # 入力チェック: 全機器 × 箇所なし / 不正な正規表現 / 過去の期限 / 「必要」ルールで箇所指定
    assert c.post("/api/compliance/exceptions", json={**body, "device_id": None, "ignore_pattern": None},
                  headers=op).status_code == 422
    assert c.post("/api/compliance/exceptions", json={**body, "ignore_pattern": "([x"}, headers=op).status_code == 422
    assert c.post("/api/compliance/exceptions", json={**body, "expires_at": "2020-01-01T00:00:00Z"},
                  headers=op).status_code == 422
    assert c.post("/api/compliance/exceptions", json={**body, "rule_id": cleanup["id"]}, headers=op).status_code == 422

    e = c.post("/api/compliance/exceptions", json={**body, "expires_at": "2099-01-01T00:00:00+09:00"}, headers=op)
    assert e.status_code == 201, e.text
    e = e.json()
    assert e["device_name"] == devs["cmp-r1"]["name"] and e["created_by"] == "cmp-op" and not e["expired"]
    assert e["expires_at"].startswith("2098-12-31T15:00")
    # 登録と同時に再検査されて除外になる。違反の件数・サマリーにも反映
    assert status_of(r1) == "exempt"
    rules = {x["id"]: x for x in c.get("/api/compliance/rules", headers=view).json()}
    assert rules[rule["id"]]["exempt_count"] >= 1 and rules[rule["id"]]["exception_count"] == 1
    s = next(x for x in c.get("/api/compliance/summary", headers=view).json()["devices"] if x["device_id"] == r1)
    assert s["exempt_count"] >= 1
    assert c.get("/api/compliance/results", params={"rule_id": rule["id"], "status": "exempt"},
                 headers=view).json()[0]["details"][0] == "例外: 予備ポート"
    acts = c.get("/api/activity/logs", params={"device_id": r1, "category": "compliance"}, headers=view).json()["items"]
    assert acts[0]["event"] == "compliance.exempted"
    listed = c.get("/api/compliance/exceptions", params={"device_id": r1}, headers=view).json()
    assert [x["id"] for x in listed] == [e["id"]]

    # 期限切れの例外は使わない
    import asyncio
    from datetime import timedelta

    from app.core.database import AsyncSessionLocal
    from app.core.timeutil import utcnow
    from app.models.compliance import ComplianceException

    async def expire():
        async with AsyncSessionLocal() as db:
            x = await db.get(ComplianceException, e["id"])
            x.expires_at = utcnow() - timedelta(minutes=1)
            await db.commit()
    asyncio.run(expire())
    assert c.get("/api/compliance/exceptions", headers=view).json()[0]["expired"] is True
    # 定期処理が期限切れを見つけて再検査する（1回だけ）
    from app.services.compliance import recheck_expired_exceptions

    async def recheck():
        async with AsyncSessionLocal() as db:
            return await recheck_expired_exceptions(db)
    assert asyncio.run(recheck()) == 1
    assert status_of(r1) == "fail"
    assert asyncio.run(recheck()) == 0
    acts = c.get("/api/activity/logs", params={"device_id": r1, "category": "compliance"}, headers=view).json()["items"]
    assert {"compliance.exception_expired", "compliance.violation"} <= {x["event"] for x in acts[:2]}
    assert "予備ポート" in next(x for x in acts if x["event"] == "compliance.exception_expired")["message"]

    # 全機器 × 箇所の例外 → 削除すると違反に戻る。監査ログに残る
    e2 = c.post("/api/compliance/exceptions", json={**body, "device_id": None}, headers=op).json()
    assert status_of(r1) == "exempt" and e2["device_name"] is None
    assert c.delete(f"/api/compliance/exceptions/{e2['id']}", headers=view).status_code == 403
    assert c.delete(f"/api/compliance/exceptions/{e2['id']}", headers=op).status_code == 204
    assert status_of(r1) == "fail"
    acts = [x["action"] for x in c.get("/api/audit/logs", params={"action": "compliance."},
                                       headers=admin).json()["items"]]
    assert "compliance.exception_create" in acts and "compliance.exception_delete" in acts

    # 機器単位の例外 → ルールを削除すると例外も消える
    c.post("/api/compliance/exceptions", json={**body, "ignore_pattern": None, "reason": "更改予定"}, headers=op)
    assert status_of(r1) == "exempt"
    c.delete(f"/api/compliance/rules/{rule['id']}", headers=op)
    c.delete(f"/api/compliance/rules/{cleanup['id']}", headers=op)
    assert [x for x in c.get("/api/compliance/exceptions", headers=view).json() if x["rule_id"] == rule["id"]] == []


def test_probe_unavailable(ctx, monkeypatch):
    """重さを確かめられない（子プロセスを起動できない）ときは、API は 503、検査はその回だけ「エラー」。覚えないので次は通る"""
    from app.core import safe_regex as sr
    from app.services.compliance import ExceptionSpec, evaluate_with_exceptions
    c, op, devs = ctx["c"], ctx["op"], ctx["devs"]
    tag = uuid.uuid4().hex
    pattern = rf"^ntp server \d{{1,3}}(?:{tag})?"

    def broken(*a, **kw):
        raise OSError("起動できない")
    monkeypatch.setattr(sr.subprocess, "run", broken)
    rule = {"name": f"unavail-{tag[:6]}", "match_type": "regex", "expect": "absent", "pattern": pattern}
    r = c.post("/api/compliance/rules", json=rule, headers=op)
    assert r.status_code == 503 and "確かめられませんでした" in r.json()["detail"], r.text
    r = c.post("/api/compliance/exceptions", json={"rule_id": "nope", "device_id": devs["cmp-r1"]["id"],
                                                   "ignore_pattern": pattern, "reason": "x"}, headers=op)
    assert r.status_code == 503, r.text
    ev = evaluate(RuleSpec("regex", "absent", pattern), IOS)
    assert ev.status == "error" and "次の検査でもう一度" in ev.details[0]
    # 確かめられない除外を飛ばすと違反に変わって偽の通知になるので、その回はエラーにする
    ev = evaluate_with_exceptions(RuleSpec("regex", "absent", "^ntp server"), IOS, [ExceptionSpec("x", pattern)])
    assert ev.status == "error"
    monkeypatch.undo()
    assert evaluate(RuleSpec("regex", "absent", pattern), IOS).status == "fail"
