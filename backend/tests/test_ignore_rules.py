"""収集時に無視する行（画面で設定する正規表現）のテスト"""
import json
import sqlite3
import time
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
import regex
import regex_cases
from celery.exceptions import Retry
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.main import app
from app.services import config_service as cs
from app.services import ignore_rules as ir

EVIL = r"^(?:a|aa)+c"  # 「a」が続く行で照合が指数関数的に長くなる
EVIL_LINE = "a" * 40


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def env(client):
    admin = _login(client, "admin", "initial-pass-123")
    for name, role in [("ign-op", "operator"), ("ign-view", "viewer")]:
        assert client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role},
                           headers=admin).status_code == 201
    return {"admin": admin, "op": _login(client, "ign-op", "password-1234"),
            "viewer": _login(client, "ign-view", "password-1234")}


def _device(client, env, platform="cisco_ios", port=22, name=None):
    r = client.post("/api/devices/", json=dict(name=name or f"ign-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=port,
                                               platform=platform, username="admin", password="pw"), headers=env["admin"])
    assert r.status_code == 201, r.text
    return r.json()


def _rule(client, env, pattern, **kw):
    # 同じ DB にほかのテストの cisco_ios の機器が残っていると、保存時の確認（409）に当たることがあるので了承して送る。
    # 確認そのものは test_confirm_broad で確かめる
    body = {"scope": "platform", "platform": "cisco_ios", "pattern": pattern, "confirm_broad": True, **kw}
    r = client.post("/api/ignore-rules/", json=body, headers=env["admin"])
    assert r.status_code == 201, r.text
    return r.json()


def _clear(client, env):
    for r in client.get("/api/ignore-rules/", headers=env["admin"]).json():
        client.delete(f"/api/ignore-rules/{r['id']}", headers=env["admin"])


# ---------------------------------------------------------------- normalize_config
def test_normalize_extra_ignore():
    text = "hostname r1\r\nntp clock-period 1\nuptime is 5 days\ninterface Gi0/1\n counter 100\n"
    base = cs.normalize_config(text, "cisco_ios")
    assert "uptime" in base and "counter" in base  # 引数なしなら今までどおり（組み込みの除外だけ）
    out = cs.normalize_config(text, "cisco_ios", extra_ignore=[r"^uptime ", r"counter \d+$"])
    assert out == "hostname r1\ninterface Gi0/1\n"
    # 空のリスト・None は何もしない
    assert cs.normalize_config(text, "cisco_ios", []) == base == cs.normalize_config(text, "cisco_ios", None)


def test_normalize_timeout_skips_rule(monkeypatch):
    monkeypatch.setattr(settings, "IGNORE_RULE_TIMEOUT", 0.3)
    monkeypatch.setattr(settings, "IGNORE_TOTAL_TIMEOUT", 5)
    text = "hostname r1\n" + EVIL_LINE + "\nclock 12:00\n"
    skipped: list[str] = []
    t0 = time.monotonic()
    out = cs.normalize_config(text, "generic", [EVIL, r"^clock "], skipped)
    assert time.monotonic() - t0 < 3
    # 時間切れのルールは飛ばし（理由付きで積む）、あとのルールは適用される
    assert [(x.pattern, x.reason) for x in skipped] == [(EVIL, "timeout")]
    assert out == "hostname r1\n" + EVIL_LINE + "\n"


def test_normalize_total_timeout(monkeypatch):
    """ルールが多くても、全ルール合計の上限を超えて時間をかけない"""
    monkeypatch.setattr(settings, "IGNORE_RULE_TIMEOUT", 0.3)
    monkeypatch.setattr(settings, "IGNORE_TOTAL_TIMEOUT", 0.5)
    skipped: list[str] = []
    t0 = time.monotonic()
    cs.normalize_config("x\n" + EVIL_LINE + "\n", "generic", [EVIL] * 10 + [r"^x$"], skipped)
    assert time.monotonic() - t0 < 2.5
    assert len(skipped) == 11  # 合計の上限を使い切ったあとのルールは、最後の無害なものも飛ばす


# ---------------------------------------------------------------- 重い正規表現（コンパイル前の検査）
HEAVY = regex_cases.HEAVY
NORMAL = [r"^ntp clock-period \d+$", r"^! Last configuration change at .*$", r"\{1000\}", r"[{1000}]x", r"[]{1000}]x",
          r"[^]{999}]", r"\p{L}x", r"a{101}", r"x{1,200}", r"(a{100}){100}"] + [
          p for p in regex_cases.NORMAL if not regex.search(p, "")]  # 空の行に一致するものは無視する行では使えない


def test_heavy_patterns():
    """読み込みが重い正規表現は、別のプロセスで測って弾く（このプロセスでは compile しない）。普通のものは通る"""
    for p in HEAVY:
        t0 = time.monotonic()
        with pytest.raises(ir.PatternTooHeavy):
            ir.validate_pattern(p)
        assert time.monotonic() - t0 < 3, p  # 子プロセスのメモリ・時間の上限で止まる
    for p in NORMAL:
        ir.validate_pattern(p)  # 回数指定の繰り返しの数値が大きくても、軽いものは通る


def test_drop_lines_unavailable(monkeypatch):
    """重さを確かめられないルールは「重すぎる」と分けて積み（再試行）、API は 503"""
    from app.core import safe_regex as sr

    def broken(*a, **kw):
        raise OSError("起動できない")
    monkeypatch.setattr(sr.subprocess, "run", broken)
    p = rf"^x{{2}}(?:{uuid.uuid4().hex})?"
    skipped: list = []
    assert ir.drop_lines(["xx", "y"], [p], skipped) == ["xx", "y"]
    assert [x.reason for x in skipped] == [ir.SKIP_UNAVAILABLE]
    assert "確かめられませんでした（再試行します）" in ir.skipped_message(skipped)
    with TestClient(app) as c:
        admin = _login(c, "admin", "initial-pass-123")
        r = c.post("/api/ignore-rules/", json={"scope": "platform", "platform": "cisco_ios", "pattern": p}, headers=admin)
        assert r.status_code == 503, r.text


def test_drop_lines_reasons(monkeypatch):
    """飛ばした理由（時間切れ／不正／読み込みが重すぎる）を分けて積む。DB から読んだものもコンパイル前に確かめる"""
    monkeypatch.setattr(settings, "IGNORE_RULE_TIMEOUT", 0.3)
    skipped: list = []
    t0 = time.monotonic()
    out = ir.drop_lines(["x", EVIL_LINE, "y"], [HEAVY[0], "(", EVIL, "^y$"], skipped)
    assert time.monotonic() - t0 < 3
    assert [x.reason for x in skipped] == ["too_heavy", "invalid", "timeout"] and out == ["x", EVIL_LINE]
    msg = ir.skipped_message(skipped)
    assert "時間切れになりました（ルール: " + EVIL in msg and "読み込みが重すぎます" in msg and "保存していません" in msg


def test_validate_empty_timeout(monkeypatch):
    """空文字への照合すら時間切れになるものは 422（ValueError）"""
    def slow(self, rx, text):
        raise ir.RegexTimeout()
    monkeypatch.setattr(ir.Deadline, "search", slow)
    with pytest.raises(ValueError, match="時間がかかりすぎる"):
        ir.validate_pattern("^x")


# ---------------------------------------------------------------- API
def test_permissions(client, env):
    d = _device(client, env)
    body = {"scope": "platform", "platform": "cisco_ios", "pattern": "^foo"}
    calls = [("get", "/api/ignore-rules/", None), ("post", "/api/ignore-rules/", body),
             ("put", "/api/ignore-rules/x", body), ("delete", "/api/ignore-rules/x", None),
             ("post", "/api/ignore-rules/preview", {**body, "scope": "device", "device_id": d["id"], "platform": None})]
    for who, code in (("viewer", 403), ("op", 403)):
        for m, url, js in calls:
            assert client.request(m, url, json=js, headers=env[who]).status_code == code, (who, m, url)
    assert client.get("/api/ignore-rules/").status_code == 401
    assert client.get("/api/ignore-rules/", headers=env["admin"]).status_code == 200
    # ユーザー画面の権限は管理者のみ
    perms = client.get("/api/auth/me", headers=env["admin"]).json()["permissions"]
    assert "config:ignore" in perms
    assert "config:ignore" not in client.get("/api/auth/me", headers=env["op"]).json()["permissions"]
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_crud_and_validation(client, env):
    _clear(client, env)
    d = _device(client, env, name="ign-crud")
    r = _rule(client, env, r"^ntp clock-period", description="時刻の同期で変わる行")
    assert r["scope"] == "platform" and r["platform_label"] and r["enabled"] and r["created_by"] == "admin"
    rd = client.post("/api/ignore-rules/", json={"scope": "device", "device_id": d["id"], "platform": "cisco_ios",
                                                 "pattern": "counter", "enabled": False}, headers=env["admin"]).json()
    assert rd["device_name"] == "ign-crud" and rd["platform"] is None  # 機器のルールは機種を持たない
    assert len(client.get("/api/ignore-rules/", headers=env["admin"]).json()) == 2
    u = client.put(f"/api/ignore-rules/{r['id']}", json={"scope": "platform", "platform": "cisco_ios", "pattern": "^x",
                                                         "enabled": False}, headers=env["admin"])
    assert u.status_code == 200 and u.json()["pattern"] == "^x" and not u.json()["enabled"]
    assert client.put("/api/ignore-rules/none", json={"scope": "platform", "platform": "cisco_ios", "pattern": "x"},
                      headers=env["admin"]).status_code == 404
    # 検証: 不正な正規表現・空文字・空の行に一致するもの・長すぎるもの・対象の指定漏れ・存在しない機種や機器
    bad = [{"pattern": "("}, {"pattern": ""}, {"pattern": "a*"}, {"pattern": "^$"}, {"pattern": "(?:)"},
           {"pattern": "x" * 501}, {"pattern": "x", "platform": None}, {"pattern": "x", "platform": "nope"},
           {"pattern": "x", "scope": "device", "device_id": None}, {"pattern": "x", "scope": "device", "device_id": "zzz"},
           {"pattern": "x", "description": "d" * 201}]
    for b in bad:
        res = client.post("/api/ignore-rules/", json={"scope": "platform", "platform": "cisco_ios", **b}, headers=env["admin"])
        assert res.status_code == 422, (b, res.text)
    # 重い正規表現は、このプロセスで compile せずに 422（理由は日本語）
    for p in HEAVY:
        t0 = time.monotonic()
        res = client.post("/api/ignore-rules/", json={"scope": "platform", "platform": "cisco_ios", "pattern": p},
                          headers=env["admin"])
        assert res.status_code == 422 and "重すぎます" in res.json()["detail"], res.text
        assert time.monotonic() - t0 < 3
        res = client.post("/api/ignore-rules/preview", json={"scope": "platform", "platform": "cisco_ios", "pattern": p},
                          headers=env["admin"])
        assert res.status_code == 422
    for p in NORMAL:
        res = client.post("/api/ignore-rules/", json={"scope": "device", "device_id": d["id"], "pattern": p},
                          headers=env["admin"])
        assert res.status_code == 201, res.text
        client.delete(f"/api/ignore-rules/{res.json()['id']}", headers=env["admin"])
    assert client.delete(f"/api/ignore-rules/{r['id']}", headers=env["admin"]).status_code == 204
    assert client.delete(f"/api/ignore-rules/{r['id']}", headers=env["admin"]).status_code == 404
    # 機器を消すと、その機器のルールも消える
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])
    assert client.get("/api/ignore-rules/", headers=env["admin"]).json() == []


def test_audit_has_no_matched_lines(client, env):
    _clear(client, env)
    r = _rule(client, env, r"^ SECRET-LINE")
    client.put(f"/api/ignore-rules/{r['id']}", json={"scope": "platform", "platform": "cisco_ios", "pattern": r"^ SECRET-LINE2"},
               headers=env["admin"])
    client.delete(f"/api/ignore-rules/{r['id']}", headers=env["admin"])
    logs = client.get("/api/audit/logs", params={"action": "ignore_rule."}, headers=env["admin"]).json()["items"]
    assert [x["action"] for x in logs][:3] == ["ignore_rule.delete", "ignore_rule.update", "ignore_rule.create"]
    upd = json.loads(logs[1]["detail"])
    assert upd["pattern"] == "^ SECRET-LINE2" and upd["before"]["pattern"] == "^ SECRET-LINE"
    # 変更前の対象も残す
    assert upd["before"]["scope"] == "platform" and upd["before"]["platform"] == "cisco_ios"
    assert "device_id" in upd["before"]
    labels = client.get("/api/audit/actions", headers=env["admin"]).json()
    assert labels["ignore_rule.create"] and labels["ignore_rule.update"] and labels["ignore_rule.delete"]


# ---------------------------------------------------------------- プレビュー
def test_preview(client, env):
    _clear(client, env)
    a, b = _device(client, env, name="ign-pv1"), _device(client, env, name="ign-pv2")
    other = _device(client, env, platform="fortinet", name="ign-pv-forti")
    empty = _device(client, env, name="ign-pv3")  # 未収集
    cs.save_config(a["id"], "hostname a\nntp clock-period 1\n" + "".join(f"counter {i}\n" for i in range(8)), "t")
    cs.save_config(b["id"], "hostname b\nvlan 1\nvlan 2\nvlan 3\n", "t")
    cs.save_config(other["id"], "counter 1\n", "t")
    url = "/api/ignore-rules/preview"
    r = client.post(url, json={"scope": "platform", "platform": "cisco_ios", "pattern": r"^counter \d+"}, headers=env["admin"])
    assert r.status_code == 200, r.text
    res = r.json()
    items = {i["device_name"]: i for i in res["devices"]}
    assert "ign-pv-forti" not in items  # 同じ機種の機器だけ
    assert items["ign-pv1"]["matched_lines"] == 8 and items["ign-pv1"]["total_lines"] == 10
    assert len(items["ign-pv1"]["examples"]) == 5  # 例は 5 行まで
    assert items["ign-pv2"]["matched_lines"] == 0 and items["ign-pv2"]["examples"] == []
    assert items["ign-pv3"]["has_config"] is False
    assert res["matched_total"] == 8 and res["warning"] and "ign-pv1" in res["warning"]  # 8/10 ≥ 50%
    # 一致が少なければ警告なし。保存はしない
    res = client.post(url, json={"scope": "device", "device_id": b["id"], "pattern": "vlan 2"}, headers=env["admin"]).json()
    assert [i["device_name"] for i in res["devices"]] == ["ign-pv2"] and res["warning"] is None
    assert client.get("/api/ignore-rules/", headers=env["admin"]).json() == []
    # 1 行は 200 文字まで
    cs.save_config(b["id"], "hostname b\nlong " + "x" * 400 + "\n", "t")
    res = client.post(url, json={"scope": "device", "device_id": b["id"], "pattern": "^long"}, headers=env["admin"]).json()
    assert len(res["devices"][0]["examples"][0]) == 200
    # 検証は保存と同じ（422）
    for body in ({"scope": "platform", "platform": "cisco_ios", "pattern": "a*"},
                 {"scope": "platform", "platform": "cisco_ios", "pattern": "("},
                 {"scope": "device", "device_id": "zzz", "pattern": "x"}):
        assert client.post(url, json=body, headers=env["admin"]).status_code == 422
    for d in (a, b, other, empty):
        client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_preview_max_devices(client, env):
    """機種の対象は 50 台まで（同じ機種の機器が 51 台以上あっても）"""
    made = [_device(client, env, platform="yamaha", name=f"ign-max-{i:02d}") for i in range(ir.PREVIEW_MAX_DEVICES + 1)]
    res = client.post("/api/ignore-rules/preview", json={"scope": "platform", "platform": "yamaha", "pattern": "^x"},
                      headers=env["admin"])
    assert res.status_code == 200
    assert len(res.json()["devices"]) == ir.PREVIEW_MAX_DEVICES == 50
    for d in made:
        client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_confirm_broad(client, env):
    """保存時も全行の 50% 以上に一致する機器があれば 409。confirm_broad を付けて送り直すと保存できる"""
    _clear(client, env)
    d = _device(client, env, platform="vyos", name="ign-broad")
    cs.save_config(d["id"], "set a\nset b\nset c\nkeep\n", "t")
    # 機器のルールで確かめる（機種のルールだと、ほかのテストが残した同じ機種の機器にも当たるため）
    body = {"scope": "device", "device_id": d["id"], "pattern": "^set "}
    r = client.post("/api/ignore-rules/", json=body, headers=env["admin"])
    assert r.status_code == 409, r.text
    det = r.json()["detail"]
    assert det["code"] == "ignore_rule_broad" and "ign-broad で全行の 75% が消えます" in det["message"]
    assert det["devices"][0]["device_name"] == "ign-broad" and det["devices"][0]["percent"] == 75
    assert client.get("/api/ignore-rules/", headers=env["admin"]).json() == []  # 保存していない
    # 無効のまま保存するときは確認しない。有効にするとき（PUT）は確認する
    off = client.post("/api/ignore-rules/", json={**body, "enabled": False}, headers=env["admin"])
    assert off.status_code == 201
    assert client.put(f"/api/ignore-rules/{off.json()['id']}", json=body, headers=env["admin"]).status_code == 409
    ok = client.put(f"/api/ignore-rules/{off.json()['id']}", json={**body, "confirm_broad": True}, headers=env["admin"])
    assert ok.status_code == 200 and ok.json()["enabled"]
    # 新規も送り直しで保存できる。狭いものは確認なし
    assert client.post("/api/ignore-rules/", json={**body, "confirm_broad": True}, headers=env["admin"]).status_code == 201
    assert client.post("/api/ignore-rules/", json={**body, "pattern": "^set a$"}, headers=env["admin"]).status_code == 201
    _clear(client, env)
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_preview_timeout(client, env, monkeypatch):
    monkeypatch.setattr(settings, "IGNORE_RULE_TIMEOUT", 0.3)
    d = _device(client, env, name="ign-pv-evil")
    cs.save_config(d["id"], "hostname x\n" + EVIL_LINE + "\n", "t")
    t0 = time.monotonic()
    res = client.post("/api/ignore-rules/preview", json={"scope": "device", "device_id": d["id"], "pattern": EVIL},
                      headers=env["admin"]).json()
    assert time.monotonic() - t0 < 3
    assert res["timeout"] is True and res["devices"][0]["timeout"] is True
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


# ---------------------------------------------------------------- 収集（worker）
@pytest.fixture
def redis_():
    fr = fakeredis.FakeRedis()
    # 変更の通知は別タスク（Redis が要る）なので投入しない
    with mock.patch.object(worker, "_redis", return_value=fr), mock.patch.object(worker.send_change_notification, "delay"):
        yield fr


def _activity(event, did):
    con = sqlite3.connect(f"{TMP}/t.db")
    try:
        return con.execute("select level, message, detail from activity_logs where event=? and device_id=?",
                           (event, did)).fetchall()
    finally:
        con.close()


def test_worker_applies_rules(client, env, redis_):
    _clear(client, env)
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    other = _device(client, env, port=port)
    did = d["id"]
    first = worker.collect_device_config.apply(args=(did,)).get()
    assert first["success"] and "description" in cs.get_config_content(did, first["commit_hash"])
    # 機種のルール＋この機器だけのルール（別の機器には効かない）。無効なルールは使わない
    _rule(client, env, r"^ description ")
    client.post("/api/ignore-rules/", json={"scope": "device", "device_id": did, "pattern": r"^interface "},
                headers=env["admin"])
    _rule(client, env, r"^hostname ", enabled=False)
    res = worker.collect_device_config.apply(args=(did,)).get()
    assert res["success"] and res["commit_hash"] and res["commit_hash"] != first["commit_hash"]
    assert cs.get_config_content(did, res["commit_hash"]) == "hostname R1\nend\n"
    # 追加後の最初の収集で「消える変更」が 1 回だけ記録される。過去の世代は変わらない
    assert "description" in cs.get_config_content(did, first["commit_hash"])
    assert worker.collect_device_config.apply(args=(did,)).get()["commit_hash"] is None
    # 別の機器には機種のルールだけが効く
    o = worker.collect_device_config.apply(args=(other["id"],)).get()
    assert cs.get_config_content(other["id"], o["commit_hash"]) == "hostname R1\ninterface Gi0/1\nend\n"
    _clear(client, env)
    for x in (d, other):
        client.delete(f"/api/devices/{x['id']}", headers=env["admin"])


def _snapshots(did):
    con = sqlite3.connect(f"{TMP}/t.db")
    try:
        return con.execute("select count(*) from config_snapshots where device_id=?", (did,)).fetchone()[0]
    finally:
        con.close()


def _collect_logs(did):
    con = sqlite3.connect(f"{TMP}/t.db")
    try:
        return con.execute("select status, message from collect_logs where device_id=? order by started_at",
                           (did,)).fetchall()
    finally:
        con.close()


def test_worker_timeout_does_not_save(client, env, redis_, monkeypatch):
    """時間切れのルールがあれば、その回は保存しない（消える回と消えない回が混ざると偽の変更になる）。再試行できる失敗"""
    _clear(client, env)
    monkeypatch.setattr(settings, "IGNORE_RULE_TIMEOUT", 0.3)
    monkeypatch.setattr(fake_sshd, "CONFIG", "hostname R1\r\n" + EVIL_LINE + "\r\ninterface Gi0/1\r\n description x\r\nend")
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    assert worker.collect_device_config.apply(args=(d["id"],)).get()["success"]
    assert _snapshots(d["id"]) == 1
    _rule(client, env, EVIL)
    _rule(client, env, r"^ description ")
    t0 = time.monotonic()
    with mock.patch.object(worker.collect_device_config, "max_retries", 0), \
            mock.patch.object(worker, "queue_failure_notification") as notice, \
            mock.patch.object(worker, "_wants", new=_yes):
        res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert time.monotonic() - t0 < 8
    assert res["success"] is False and "無視する行の照合が時間切れになりました（ルール: " + EVIL in res["error"]
    assert _snapshots(d["id"]) == 1  # 世代は増えない
    status_, msg = _collect_logs(d["id"])[-1]
    assert status_ == "failed" and "時間切れ" in msg
    assert notice.called  # 最終的な失敗は失敗の通知に乗る
    rows = _activity("ignore.timeout", d["id"])
    assert len(rows) == 1 and rows[0][0] == "warning"
    det = json.loads(rows[0][2])
    assert det["pattern"] == EVIL and det["reason"] == "timeout"
    assert EVIL_LINE not in rows[0][1] + rows[0][2].replace(EVIL, "")  # 機器の出力（行の中身）は記録しない
    assert _activity("collect.failed", d["id"])
    _clear(client, env)
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_worker_probe_unavailable_does_not_save(client, env, redis_, monkeypatch):
    """収集の時に重さを確かめられない（子プロセスを起動できない）ルールがあれば、その回は保存せず再試行できる失敗にする。
    アクティビティは「重すぎる」「不正」（ignore.skipped）と分けて ignore.unavailable に残す"""
    from app.core import safe_regex as sr
    _clear(client, env)
    monkeypatch.setattr(fake_sshd, "CONFIG", "hostname R1\r\ninterface Gi0/1\r\n description x\r\nend")
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    assert worker.collect_device_config.apply(args=(d["id"],)).get()["success"]
    pattern = rf"^ description x{{1,2}}(?:{uuid.uuid4().hex})?"
    _rule(client, env, pattern)
    sr.clear_caches()  # 登録時に覚えた判定を消し、収集の時に確かめ直させる

    def broken(*a, **kw):
        raise OSError("起動できない")
    monkeypatch.setattr(sr.subprocess, "run", broken)
    with mock.patch.object(worker.collect_device_config, "max_retries", 0), \
            mock.patch.object(worker, "queue_failure_notification"), mock.patch.object(worker, "_wants", new=_yes):
        res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert res["success"] is False and "確かめられませんでした（再試行します）" in res["error"]
    assert _snapshots(d["id"]) == 1
    rows = _activity("ignore.unavailable", d["id"])
    assert len(rows) == 1 and json.loads(rows[0][2])["reason"] == "unavailable"
    assert _activity("ignore.skipped", d["id"]) == []
    _clear(client, env)
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


async def _yes(event):
    return True


def test_worker_retryable_failures(client, env, redis_):
    """時間切れ・読み込み失敗は再試行できる失敗（retryable）として扱う"""
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    with mock.patch.object(worker, "_get_ignore_patterns", side_effect=RuntimeError("db down")), \
            mock.patch.object(worker.collect_device_config, "retry", side_effect=Retry("retry")) as retry:
        assert worker.collect_device_config.apply(args=(d["id"],)).state == "RETRY"
    assert retry.called and retry.call_args.kwargs["kwargs"] == {"lock_waits": 0, "failures": 1}
    assert _activity("collect.failed", d["id"])[0][0] == "warning"  # 再試行する失敗は警告
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_worker_load_failure_does_not_save(client, env, redis_):
    """ルールの読み込みに失敗したら、無視しないまま保存しない（接続もしない）"""
    _clear(client, env)
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    with mock.patch.object(worker, "_get_ignore_patterns", side_effect=RuntimeError("db down")), \
            mock.patch.object(worker.collect_device_config, "max_retries", 0), \
            mock.patch.object(worker, "collect_config_sync") as collect:
        res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert res["success"] is False and "無視する行の設定を読み込めなかった" in res["error"]
    assert not collect.called and _snapshots(d["id"]) == 0
    assert _collect_logs(d["id"])[-1][0] == "failed"
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_worker_uses_new_platform_rules(client, env, redis_):
    """機器の機種を変えた後は、新しい機種のルールが効く（古い機種のルールは効かない）"""
    _clear(client, env)
    d = _device(client, env, name="ign-plat")
    _rule(client, env, r"^old-rule")
    _rule(client, env, r"^new-rule", platform="cisco_xe")
    seen: list = []

    def fake(device, triggered_by, extra_ignore=None):
        seen.append((device.platform, extra_ignore))
        return cs.CollectResult(success=True)

    with mock.patch.object(worker, "collect_config_sync", side_effect=fake):
        worker.collect_device_config.apply(args=(d["id"],)).get()
        assert client.put(f"/api/devices/{d['id']}", json={"platform": "cisco_xe"}, headers=env["admin"]).status_code == 200
        worker.collect_device_config.apply(args=(d["id"],)).get()
    assert seen == [("cisco_ios", [r"^old-rule"]), ("cisco_xe", [r"^new-rule"])]
    _clear(client, env)
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_worker_broad_warning(client, env, redis_):
    """追加のルールで全行の 50% 以上が消えたら、保存は続けたうえでアクティビティに警告（ignore.broad）"""
    _clear(client, env)
    port, _, _ = fake_sshd.start()
    d = _device(client, env, port=port)
    # まだ世代が無いので保存時の確認（409）は出ない。hostname / interface / description の 3 行を消す（4 行中）
    client.post("/api/ignore-rules/", json={"scope": "device", "device_id": d["id"], "pattern": r"^(hostname|interface| description)"},
                headers=env["admin"])
    res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert res["success"] and cs.get_config_content(d["id"], res["commit_hash"]) == "end\n"
    rows = _activity("ignore.broad", d["id"])
    assert len(rows) == 1 and rows[0][0] == "warning" and "75%" in rows[0][1]
    assert json.loads(rows[0][2]) == {"dropped": 3, "lines": 4}
    _clear(client, env)
    client.delete(f"/api/devices/{d['id']}", headers=env["admin"])


def test_collect_signature_unchanged():
    """引数なしの呼び出しは今までどおり（既存の呼び出し元・テストが壊れない）"""
    import inspect
    assert list(inspect.signature(cs.collect_config_sync).parameters)[:2] == ["device", "triggered_by"]
    assert list(inspect.signature(cs.normalize_config).parameters)[:2] == ["text", "platform"]


@pytest.mark.parametrize("reason,retry", [("invalid", False), ("too_heavy", False), ("timeout", True), ("unavailable", True)])
def test_collect_retries_only_when_the_skip_may_pass_next_time(monkeypatch, reason, retry):
    """使えなかったルールがあれば保存しない。再試行するのは、やり直して直りうるもの（時間切れ・確かめられない）だけ。
    正規表現そのものが不正・重すぎるものは、何度やっても同じなので再試行しない（すぐに失敗にして通知する）"""
    def fake_normalize(raw, platform, extra, skipped, stats):
        skipped.append(ir.Skipped("^x(", reason))
        return raw

    monkeypatch.setattr(cs, "fetch_config", lambda d: ("hostname R1\n", None, None))
    monkeypatch.setattr(cs, "normalize_config", fake_normalize)
    d = cs.DeviceConnectionInfo(id=str(uuid.uuid4()), name="r1", hostname="192.0.2.1", platform="cisco_ios", port=22,
                                username="u", password="p", enable_secret=None)
    res = cs.collect_config_sync(d, extra_ignore=["^x("])
    assert res.success is False and res.retryable is retry and res.ignore_skipped

    # 理由が混ざっているときは、直りうるものが 1 つでもあれば再試行する
    def mixed(raw, platform, extra, skipped, stats):
        skipped.extend([ir.Skipped("^a(", "invalid"), ir.Skipped("^b", "timeout")])
        return raw
    monkeypatch.setattr(cs, "normalize_config", mixed)
    assert cs.collect_config_sync(d, extra_ignore=["^a(", "^b"]).retryable is True
