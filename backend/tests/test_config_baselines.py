"""基準の世代（ベースライン）とずれの検出のテスト"""
import sqlite3
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.main import app
from app.services import baseline as baseline_svc
from app.services import config_service as cs
from app.services import notify


def uid():
    return uuid.uuid4().hex[:6]


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def client():
    with (
        mock.patch("app.api.devices.collect_device_config"),
        mock.patch("app.api.devices.collect_all_devices"),
        TestClient(app) as c,
    ):
        yield c


@pytest.fixture(scope="module")
def env(client):
    admin = _login(client, "admin", "initial-pass-123")
    t = uid()
    for name, role in [(f"bl-op-{t}", "operator"), (f"bl-view-{t}", "viewer")]:
        r = client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        assert r.status_code == 201, r.text
    group = client.post("/api/device-groups/", json={"name": f"bl-grp-{t}", "color": "#4f8ef7"}, headers=admin).json()

    def dev(name):
        r = client.post("/api/devices/", json=dict(name=name, hostname="10.8.0.1", platform="cisco_ios", username="u",
                                                   password="p", group_id=group["id"]), headers=admin)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    a, b, c = dev(f"bl-sw1-{t}"), dev(f"bl-sw2-{t}"), dev(f"bl-sw3-{t}")
    a1 = cs.save_config(a, "hostname a\n", "manual").commit_hash
    a2 = cs.save_config(a, "hostname a\nvlan 99\n", "manual").commit_hash
    a3 = cs.save_config(a, "hostname a\nvlan 100\nntp server 10.0.0.1\n", "manual").commit_hash
    b1 = cs.save_config(b, "hostname b\n", "manual").commit_hash
    yield {"admin": admin, "op": _login(client, f"bl-op-{t}", "password-1234"),
           "viewer": _login(client, f"bl-view-{t}", "password-1234"),
           "a": a, "b": b, "c": c, "a1": a1, "a2": a2, "a3": a3, "b1": b1, "group": group["id"]}
    for did in (a, b, c):
        client.delete(f"/api/devices/{did}", headers=admin)
    client.delete(f"/api/device-groups/{group['id']}", headers=admin)


def test_compute_drift(env):
    # 基準 a2（vlan 99）→ 最新 a3（vlan 100 と ntp）: +2 / -1
    d = baseline_svc.compute_drift(env["a"], env["a2"])
    assert (d.added, d.removed, d.latest_hash) == (2, 1, env["a3"])
    # 基準が最新そのものならずれは 0
    d = baseline_svc.compute_drift(env["a"], env["a3"])
    assert (d.added, d.removed, d.latest_hash) == (0, 0, env["a3"])
    # 基準の世代を読めなければ None
    assert baseline_svc.compute_drift(env["a"], "0" * 40) is None
    assert baseline_svc.compute_drift(str(uuid.uuid4()), env["a3"]) is None


def test_set_and_clear_and_permissions(client, env):
    a, op, viewer, admin = env["a"], env["op"], env["viewer"], env["admin"]
    url = f"/api/configs/{a}/baseline"
    assert client.get(url, headers=viewer).json() is None
    # 閲覧者は指定・解除できない
    assert client.put(url, json={"commit_hash": env["a2"]}, headers=viewer).status_code == 403
    assert client.delete(url, headers=viewer).status_code == 403
    # 基準が無いときの解除は 404
    assert client.delete(url, headers=op).status_code == 404
    # 存在しない世代・他の機器の世代・形式が違うものは通らない
    assert client.put(url, json={"commit_hash": "0" * 40}, headers=op).status_code == 404
    assert client.put(url, json={"commit_hash": env["b1"]}, headers=op).status_code == 404
    assert client.put(url, json={"commit_hash": "zz"}, headers=op).status_code == 422
    assert client.put(url, json={"commit_hash": env["a2"], "note": "x" * 201}, headers=op).status_code == 422
    assert client.put("/api/configs/nope/baseline", json={"commit_hash": env["a2"]}, headers=op).status_code == 404
    # 短縮ハッシュで指定でき、完全なハッシュで保存される。直後にずれが計算される
    r = client.put(url, json={"commit_hash": env["a2"][:8], "note": " 承認済み "}, headers=op)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["commit_hash"] == env["a2"] and body["note"] == "承認済み" and body["set_by"].startswith("bl-op-")
    assert (body["drift_added"], body["drift_removed"], body["latest_hash"]) == (2, 1, env["a3"])
    assert client.get(url, headers=viewer).json()["commit_hash"] == env["a2"]
    # 世代一覧に baseline_hash が付く
    hist = client.get(f"/api/configs/{a}/history", headers=viewer).json()
    assert {h["baseline_hash"] for h in hist} == {env["a2"]}
    # 付け替え（最初の世代も指定できる）。最新そのものならずれは 0
    r = client.put(url, json={"commit_hash": env["a3"]}, headers=admin)
    assert r.status_code == 200 and (r.json()["drift_added"], r.json()["drift_removed"]) == (0, 0)
    assert client.put(url, json={"commit_hash": env["a1"]}, headers=op).json()["drift_added"] == 2
    # 監査ログ（付け替えのときは前の基準を残す）
    logs = client.get("/api/audit/logs", params={"action": "config.baseline_set"}, headers=admin).json()["items"]
    mine = [x for x in logs if x["target_id"] == a]
    assert len(mine) == 3 and "before" in mine[0]["detail"]
    # 解除
    assert client.delete(url, headers=op).status_code == 204
    assert client.get(url, headers=op).json() is None
    assert client.get(f"/api/configs/{a}/history", headers=op).json()[0]["baseline_hash"] is None
    assert any(x["target_id"] == a for x in client.get(
        "/api/audit/logs", params={"action": "config.baseline_clear"}, headers=admin).json()["items"])


def _list(client, h, **params):
    params.setdefault("group_id", _GROUP[0])
    r = client.get("/api/configs/baselines", params=params, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


_GROUP: list[str] = [""]


def test_list_states_and_dashboard(client, env):
    _GROUP[0] = env["group"]
    a, b, op, viewer = env["a"], env["b"], env["op"], env["viewer"]
    client.put(f"/api/configs/{a}/baseline", json={"commit_hash": env["a2"]}, headers=op)  # ずれあり
    client.put(f"/api/configs/{b}/baseline", json={"commit_hash": env["b1"]}, headers=op)  # b は 1 世代だけ → ずれなし
    res = _list(client, viewer, state="all")
    assert res["counts"] == {"drift": 1, "ok": 1, "unknown": 0, "none": 1} and res["total"] == 3
    assert _list(client, viewer)["items"][0]["device_id"] == a  # 既定は drift
    drift = _list(client, viewer, state="drift")["items"]
    assert [i["device_id"] for i in drift] == [a]
    base = drift[0]["baseline"]
    assert base["hash"] == env["a2"][:8] and base["latest"] == env["a3"][:8]
    assert (base["drift_added"], base["drift_removed"]) == (2, 1) and base["set_by"].startswith("bl-op-")
    assert [i["device_id"] for i in _list(client, viewer, state="ok")["items"]] == [b]
    none = _list(client, viewer, state="none")["items"]
    assert [i["device_id"] for i in none] == [env["c"]] and none[0]["baseline"] is None
    assert _list(client, viewer, state="drift", group_id="no-such-group")["total"] == 0
    # ダッシュボード（閲覧者も見える）
    dash = client.get("/api/dashboard/", headers=viewer).json()
    assert dash["baselines"]["total"] >= 2 and dash["baselines"]["drift"] >= 1
    # 機器を削除すると基準も消える
    d = client.post("/api/devices/", json=dict(name=f"bl-del-{uid()}", hostname="10.8.0.2", platform="cisco_ios",
                                               username="u", password="p"), headers=env["admin"]).json()
    h1 = cs.save_config(d["id"], "hostname d\n", "manual").commit_hash
    assert client.put(f"/api/configs/{d['id']}/baseline", json={"commit_hash": h1}, headers=op).status_code == 200
    before = client.get("/api/dashboard/", headers=viewer).json()["baselines"]["total"]
    assert client.delete(f"/api/devices/{d['id']}", headers=env["admin"]).status_code == 204
    assert client.get("/api/dashboard/", headers=viewer).json()["baselines"]["total"] == before - 1


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: calls.append((kind, url, payload)))
    monkeypatch.setattr(worker.send_change_notification, "delay", lambda *a, **kw: None)  # 変更通知は対象外（Redis が無い）
    monkeypatch.setattr(worker.send_drift_notification, "delay",
                        lambda *a, **kw: worker.send_drift_notification.apply(args=a, kwargs=kw).get())
    return calls


def _collect_env(client, env, sent, enable_drift: bool):
    """通知ユーザー・fake の機器を作る。(did, collect, mine, events, hdrs, cleanup) を返す"""
    admin = env["admin"]
    t = uid()
    hook = f"https://discord.com/api/webhooks/970/{t}"
    uid_ = client.post("/api/users/", json={"username": f"bl-nt-{t}", "password": "password-1234", "role": "viewer"},
                       headers=admin).json()["id"]
    vh = _login(client, f"bl-nt-{t}", "password-1234")
    # 既定は無効（on_drift を付けないと通知しない）
    r = client.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": True,
                                                  "on_system": False, "on_drift": enable_drift}, headers=vh)
    assert r.status_code == 200 and r.json()["on_drift"] is enable_drift
    port, _state, _ = fake_sshd.start()
    d = client.post("/api/devices/", json=dict(name=f"bl-col-{t}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                               username="admin", password="pw"), headers=admin).json()
    did = d["id"]

    def collect(extra=""):
        with mock.patch.object(fake_sshd, "CONFIG", fake_sshd.CONFIG + extra):
            return worker.collect_device_config.apply(args=(did, "schedule", "admin", f"bl-{uid()}")).get()

    def mine():
        return [p for _, u, p in sent if u == hook and "基準" in p["embeds"][0]["title"]]

    def events(ev):
        return client.get("/api/activity/logs", params={"device_id": did, "event": ev}, headers=admin).json()["items"]

    def row():
        return client.get(f"/api/configs/{did}/baseline", headers=admin).json()

    def history():
        return client.get(f"/api/configs/{did}/history", headers=admin).json()

    def cleanup():
        client.delete(f"/api/devices/{did}", headers=admin)
        assert client.delete(f"/api/users/{uid_}", headers=admin).status_code == 204  # 他のテストに通知が届かないように

    return did, collect, mine, events, row, history, vh, cleanup


def test_collect_does_not_notify_when_drift_disabled(client, env, sent):
    """on_drift が無効なら、ずれなし → ずれあり でも送らない（アクティビティには残す）"""
    did, collect, mine, events, row, history, _vh, cleanup = _collect_env(client, env, sent, False)
    admin = env["admin"]
    try:
        with mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
            assert collect()["success"]
            assert collect("\r\nntp server 192.0.2.1")["success"]
            head = history()[0]["full_hash"]
            r = client.put(f"/api/configs/{did}/baseline", json={"commit_hash": head}, headers=admin).json()
            assert (r["drift_added"], r["drift_removed"]) == (0, 0)
            assert collect("\r\nntp server 192.0.2.1\r\nntp server 192.0.2.2")["success"]  # ずれなし → ずれあり
            assert row()["drift_added"] == 1
            assert mine() == [] and len(events("baseline.drift")) == 1
    finally:
        cleanup()


def test_collect_recomputes_and_notifies_only_on_change(client, env, sent):
    """収集で世代が増えたらずれを計算し直す。通知は「ずれなし → ずれあり」のときだけ"""
    did, collect, mine, events, row, history, _vh, cleanup = _collect_env(client, env, sent, True)
    admin = env["admin"]
    try:
        with mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
            assert collect()["success"]
            first = history()[0]["full_hash"]
            assert collect("\r\nntp server 192.0.2.1")["success"]  # 世代 2
            gen2 = history()[0]["full_hash"]
            # 基準を最初の世代に指定: すでにずれている状態。直後の計算では通知しない
            assert client.put(f"/api/configs/{did}/baseline", json={"commit_hash": first},
                              headers=admin).json()["drift_added"] == 1
            assert mine() == []
            # ずれたまま収集しても通知しない（計算し直されるだけ）
            assert collect("\r\nntp server 192.0.2.1\r\nntp server 192.0.2.2")["success"]
            assert row()["drift_added"] == 2 and row()["latest_hash"] != first
            assert mine() == [] and events("baseline.drift") == []
            # 基準へ戻す → ずれ 0、アクティビティだけ
            assert collect()["success"]
            assert (row()["drift_added"], row()["drift_removed"]) == (0, 0)
            assert len(events("baseline.resolved")) == 1 and mine() == []
            # ずれなし → ずれあり: 通知する
            assert collect("\r\nntp server 192.0.2.9")["success"]
            (p,) = mine()
            emb = p["embeds"][0]
            assert emb["title"].startswith("基準からのずれ: bl-col-")
            fields = {f["name"]: f["value"] for f in emb["fields"]}
            assert fields["基準からのずれ"] == "+1 行 / -0 行" and fields["基準の世代"] == first[:8]
            assert "ntp server" not in str(p)  # 差分の中身は載せない
            assert len(events("baseline.drift")) == 1
            # ずれたまま収集しても、毎回は通知しない
            assert collect("\r\nntp server 192.0.2.9\r\nntp server 192.0.2.10")["success"]
            assert len(mine()) == 1 and len(events("baseline.drift")) == 1
            # 再計算が例外でも、収集は成功のまま
            with mock.patch.object(baseline_svc, "compute_drift", side_effect=RuntimeError("boom")):
                assert collect("\r\nntp server 192.0.2.99")["success"]
            assert any("基準からのずれを通知しました" in i["message"] for i in events("notify.sent"))

            # 計算が None（基準の世代を読めない）→ 未計算に戻り、警告は 1 回だけ。前回の値は出し続けない
            with mock.patch.object(baseline_svc, "compute_drift", return_value=None):
                assert collect("\r\nvlan 5")["success"]
                assert row()["drift_added"] is None and row()["latest_hash"] is None
                assert len(events("baseline.error")) == 1
                assert collect("\r\nvlan 5\r\nvlan 6")["success"]
                assert len(events("baseline.error")) == 1  # 同じ状態が続く間は増やさない
            assert _find(client, admin, did)["state"] == "unknown"
            dash = client.get("/api/dashboard/", headers=admin).json()["baselines"]
            assert dash["unknown"] >= 1
            # 変更なしの収集でも、未計算なら計算し直す。null → ずれあり は通知しない（二重に通知しない）
            assert not collect("\r\nvlan 5\r\nvlan 6")["commit_hash"]
            assert row()["drift_added"] is not None and row()["latest_hash"] == history()[0]["full_hash"]
            assert len(mine()) == 1
            assert _find(client, admin, did)["state"] == "drift"

            # 古い値（latest_hash が HEAD と違う）も、変更なしの収集で直る（保存していた値が「ずれなし」なら通知する）
            con = sqlite3.connect(f"{TMP}/t.db")
            con.execute("update config_baselines set latest_hash=?, drift_added=0, drift_removed=0 where device_id=?",
                        ("1" * 40, did))
            con.commit()
            con.close()
            assert not collect("\r\nvlan 5\r\nvlan 6")["commit_hash"]
            assert row()["latest_hash"] == history()[0]["full_hash"] and row()["drift_added"] > 0
            assert len(mine()) == 2  # 保存していた値は「ずれなし」だったので、ずれなし → ずれあり として通知する

            # 基準を付け替えた直後の収集では通知しない（付け替えの時点でずれが計算済み）
            assert client.put(f"/api/configs/{did}/baseline", json={"commit_hash": gen2}, headers=admin).status_code == 200
            before = len(mine())
            assert collect("\r\nvlan 5\r\nvlan 6\r\nvlan 7")["success"]
            assert len(mine()) == before
    finally:
        cleanup()


def _find(client, h, did):
    r = client.get("/api/configs/baselines", params={"state": "all"}, headers=h).json()
    return next(i for i in r["items"] if i["device_id"] == did)


def test_notification_setting_defaults(client, env):
    """通知設定の on_drift は既定で無効。1 つも選ばない個別設定は受け付けない（on_drift だけなら受け付ける）"""
    t = uid()
    admin = env["admin"]
    uid_ = client.post("/api/users/", json={"username": f"bl-ns-{t}", "password": "password-1234", "role": "viewer"},
                       headers=admin).json()["id"]
    h = _login(client, f"bl-ns-{t}", "password-1234")
    hook = f"https://discord.com/api/webhooks/971/{t}"
    off = {"on_change": False, "on_violation": False, "on_failure": False, "on_system": False, "on_inventory": False,
           "on_ping": False}
    r = client.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, **off}, headers=h)
    assert r.status_code == 422
    r = client.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, **off, "on_drift": True},
                   headers=h)
    assert r.status_code == 200 and r.json()["on_drift"] is True
    assert client.get("/api/notifications/me", headers=h).json()["on_drift"] is True
    assert client.delete(f"/api/users/{uid_}", headers=admin).status_code == 204


def test_latest_unknown_and_stable_compute(client, env):
    """"latest" はサーバーが最新の世代を解決する。計算できなければ未計算で指定でき、保存の直前に最新が変わっていたら計算し直す"""
    _GROUP[0] = env["group"]
    a, op, viewer = env["a"], env["op"], env["viewer"]
    url = f"/api/configs/{a}/baseline"
    r = client.put(url, json={"commit_hash": "latest"}, headers=op)
    assert r.status_code == 200 and r.json()["commit_hash"] == env["a3"] and r.json()["drift_added"] == 0
    assert client.put(f"/api/configs/{env['c']}/baseline", json={"commit_hash": "latest"}, headers=op).status_code == 404  # 世代なし
    assert client.put("/api/configs/" + "x" * 37 + "/baseline", json={"commit_hash": "latest"}, headers=op).status_code == 422
    # 計算できなかった: 未計算（null）で指定できる。一覧は unknown、ずれている機器には数えない
    before = client.get("/api/dashboard/", headers=viewer).json()["baselines"]
    with mock.patch("app.api.config_baselines.compute_drift_stable", return_value=None):
        r = client.put(url, json={"commit_hash": env["a2"]}, headers=op)
    assert r.status_code == 200 and r.json()["drift_added"] is None and r.json()["checked_at"] is None
    item = next(i for i in _list(client, viewer, state="unknown")["items"] if i["device_id"] == a)
    assert item["state"] == "unknown"
    assert a not in [i["device_id"] for i in _list(client, viewer, state="ok")["items"]]
    assert a not in [i["device_id"] for i in _list(client, viewer, state="drift")["items"]]
    after = client.get("/api/dashboard/", headers=viewer).json()["baselines"]
    assert after["unknown"] == before["unknown"] + 1
    # 保存の直前に最新が変わっていたら 1 回だけ計算し直す（compute_drift の 1 回目が古い最新を返す想定）
    real = baseline_svc.compute_drift(a, env["a2"])
    stale = baseline_svc.Drift(9, 9, "f" * 40)
    with mock.patch("app.services.baseline.compute_drift", side_effect=[stale, real]) as m:
        r = client.put(url, json={"commit_hash": env["a2"]}, headers=op)
    assert m.call_count == 2 and (r.json()["drift_added"], r.json()["drift_removed"]) == (2, 1)


def test_conditional_update_discards_result_when_baseline_changed(client, env):
    """worker は読んだときの基準のときだけ保存する（計算の間に基準が付け替えられたら、結果を捨てる）"""
    import asyncio

    a, op = env["a"], env["op"]
    url = f"/api/configs/{a}/baseline"
    client.put(url, json={"commit_hash": env["a2"]}, headers=op)

    def swap(device_id, baseline_hash):  # 計算の途中で、API が基準を付け替えた想定
        con = sqlite3.connect(f"{TMP}/t.db")
        con.execute("update config_baselines set commit_hash=?, drift_added=0, drift_removed=0 where device_id=?",
                    (env["a3"], device_id))
        con.commit()
        con.close()
        return baseline_svc.Drift(5, 5, env["a3"])

    with mock.patch.object(baseline_svc, "compute_drift", side_effect=swap):
        assert asyncio.run(worker._recheck_baseline(a, "x", "t", None)) is None
    got = client.get(url, headers=op).json()
    assert got["commit_hash"] == env["a3"] and (got["drift_added"], got["drift_removed"]) == (0, 0)
    client.delete(url, headers=op)
