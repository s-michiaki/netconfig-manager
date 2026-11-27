"""保存し忘れ（startup-config と running-config の不一致）の検出のテスト

実機は無いので、tests/fake_sshd.py の出力で確かめる（実機の出力は未確認）
"""
import sqlite3
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from conftest import TMP
from fastapi.testclient import TestClient
from test_device_auth import dev

from app import worker
from app.core.config import settings
from app.main import app
from app.services import config_service as cs
from app.services import notify, startup_check

RUNNING = "Building configuration...\n\nCurrent configuration : 99 bytes\n! Last configuration change at 12:00:00 JST\n!\nhostname R1\nservice timestamps log datetime\nip ssh version 2\nip ssh time-out 60\ninterface Gi0/1\n description a\nend\n"
STARTUP = "Using 1234 out of 262144 bytes\n!\n! NVRAM config last updated at 12:00:00 JST\nhostname R1\nservice timestamps log datetime\nip ssh version 2\nip ssh time-out 60\ninterface Gi0/1\n description a\nend\n"


# startup の行数の下限（5 行）を超えるよう、fake の running を少し長くする（他のテストの CONFIG には影響させない）
BIG_CONFIG = fake_sshd.CONFIG.replace(
    "hostname R1\r\n", "hostname R1\r\nservice timestamps log datetime\r\nip ssh version 2\r\nip ssh time-out 60\r\n")


@pytest.fixture(autouse=True)
def _big_config(monkeypatch):
    monkeypatch.setattr(fake_sshd, "CONFIG", BIG_CONFIG)


# ---------------------------------------------------------------- 比較の関数
def test_compare_synced_ignores_header_lines():
    r = startup_check.compare(RUNNING, STARTUP, "cisco_ios")
    assert (r.state, r.added, r.removed, r.diff) == ("synced", 0, 0, None)


def test_compare_unsaved_counts_lines_and_diff_direction():
    running = RUNNING.replace(" description a", " description b\n shutdown")
    r = startup_check.compare(running, STARTUP, "cisco_ios")
    assert (r.state, r.added, r.removed) == ("unsaved", 2, 1)
    # startup → running の差分。保存されていない追加は + になる
    assert "--- startup-config" in r.diff and "+++ running-config" in r.diff
    assert "+ shutdown" in r.diff and "- description a" in r.diff


def test_compare_diff_is_cut_at_200_lines():
    base = "".join(f"vlan {i}\n" for i in range(100))
    running = RUNNING + base + "".join(f"ntp server 192.0.2.{i % 250}\n" for i in range(500))
    r = startup_check.compare(running, STARTUP + base, "cisco_ios")
    assert r.state == "unsaved" and r.added == 500
    assert len(r.diff.split("\n")) == startup_check.MAX_DIFF_LINES + 1


@pytest.mark.parametrize("startup", [None, "", "  \n\n", "startup-config is not present", "% Invalid input detected at '^' marker.",
                                     "ERROR: startup-config not found", "No startup-config"])
def test_compare_unknown(startup):
    assert startup_check.compare(RUNNING, startup, "cisco_ios").state == "unknown"


def test_compare_does_not_misread_config_body_as_error():
    # 本文の途中に error という語があっても、不明にはしない（先頭の数行だけを見る）
    body = STARTUP + "\n".join(f"line {i}" for i in range(10)) + "\n description error: none\n"
    r = startup_check.compare(RUNNING + "\n".join(f"line {i}" for i in range(10)) + "\n description error: none\n",
                              body, "cisco_ios")
    assert r.state == "synced"


def test_compare_applies_ignore_rules_to_both_sides():
    """無視する行は running と startup の両方に当てる（片方だけ消えると偽の不一致になる）"""
    run = RUNNING.replace("end\n", "ntp clock-period 1234\nclock timezone JST 9\nend\n")
    start = STARTUP.replace("end\n", "ntp clock-period 5678\nclock timezone JST 9\nend\n")  # ntp clock-period は機種の無視する行
    assert startup_check.compare(run, start, "cisco_ios").state == "synced"
    run2 = RUNNING.replace("end\n", "snmp-server contact 20261125-a\nend\n")
    start2 = STARTUP.replace("end\n", "snmp-server contact 20261124-b\nend\n")
    assert startup_check.compare(run2, start2, "cisco_ios").state == "unsaved"
    assert startup_check.compare(run2, start2, "cisco_ios", [r"^snmp-server contact "]).state == "synced"


def test_compare_nxos_and_eos_headers():
    nx_run = "!Command: show running-config\n!Running configuration last done at: Tue Nov 25 09:00:00 2026\n!Time: Tue Nov 25 09:01:00 2026\n\nversion 9.3(10)\nhostname N9K\nfeature ssh\nfeature lldp\nvlan 1\n"
    nx_start = "!Command: show startup-config\n!Startup config saved at: Tue Nov 25 08:00:00 2026\n!Time: Tue Nov 25 09:01:05 2026\n\nversion 9.3(10)\nhostname N9K\nfeature ssh\nfeature lldp\nvlan 1\n"
    assert startup_check.compare(nx_run, nx_start, "cisco_nxos").state == "synced"
    eos_run = "! Command: show running-config\n! device: sw1 (vEOS)\n!\nhostname sw1\nip routing\nspanning-tree mode mstp\nvlan 1\nend\n"
    eos_start = "! Command: show startup-config\n! Startup-config last modified at Tue Nov 25 08:00:00 2026 by admin\n! device: sw1 (vEOS)\n!\nhostname sw1\nip routing\nspanning-tree mode mstp\nvlan 1\nend\n"
    assert startup_check.compare(eos_run, eos_start, "arista_eos").state == "synced"
    assert startup_check.compare(eos_run + "vlan 10\n", eos_start, "arista_eos").state == "unsaved"


def test_compare_rejects_too_short_startup():
    """想定していないエラーの文言などを startup とみなして「未保存」にしない（行数が少なすぎるときは不明）"""
    err = "Unable to read configuration\nplease retry later\ncode 17\n"
    r = startup_check.compare(RUNNING, err, "cisco_ios")
    assert r.state == "unknown" and "行数" in r.reason
    # running の 1 割に満たない startup も不明（running が大きい）
    big = RUNNING + "".join(f"vlan {i}\n" for i in range(200))
    assert startup_check.compare(big, STARTUP, "cisco_ios").state == "unknown"
    assert startup_check.compare(big, STARTUP + "".join(f"vlan {i}\n" for i in range(30)), "cisco_ios").state == "unsaved"


def test_compare_extra_ignored_lines():
    """running と startup で見出しが違っても偽の不一致にしない（実機未確認の推測の行）"""
    run = RUNNING.replace("end\n", "!\n!\nend\n")
    start = STARTUP.replace("end\n", "Uncompressed configuration from 1234 bytes to 5678 bytes\n  !  \nend\n")
    assert startup_check.compare(run, start, "cisco_ios").state == "synced"
    eos_run = "! device: sw1 (vEOS)\n! boot system flash:/EOS.swi\nhostname sw1\nip routing\nspanning-tree mode mstp\nvlan 1\nend\n"
    eos_start = "hostname sw1\nip routing\nspanning-tree mode mstp\nvlan 1\nend\n"
    assert startup_check.compare(eos_run, eos_start, "arista_eos").state == "synced"


def test_compare_only_lines_are_not_removed_from_saved_config():
    """比べるときだけ消す行は、保存する running のコンフィグには効かせない（既存の機器で偽の変更を出さない）"""
    text = "hostname R1\nUsing 12 out of 34 bytes\n!Time: now\n"
    assert cs.normalize_config(text, "cisco_ios") == text


def test_enabled_for(monkeypatch):
    assert startup_check.enabled_for("cisco_ios") and startup_check.enabled_for("allied_telesis_awplus")
    assert {k for k, v in cs.PLATFORMS.items() if v.startup_command} == {
        "cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "allied_telesis_awplus"}
    assert not startup_check.enabled_for("fortinet") and not startup_check.enabled_for("paloalto_panos")
    monkeypatch.setattr(settings, "STARTUP_CHECK_ENABLED", False)
    assert not startup_check.enabled_for("cisco_ios")


# ---------------------------------------------------------------- 収集（fake の機器）
@pytest.mark.parametrize("mode, platform", [("cisco", "cisco_ios"), ("awplus", "allied_telesis_awplus")])
def test_collect_synced_unsaved_unknown(mode, platform):
    results = {}
    for startup in ("same", "different", "absent", "pager", "empty", "error"):
        port, state, _ = fake_sshd.start(mode=mode, startup=startup)
        r = cs.collect_config_sync(dev(port, platform=platform))
        assert r.success and r.commit_hash, (startup, r)  # startup が読めなくても収集は成功
        results[startup] = r
        cmds = state["commands"]
        # running の取得のあとに、同じ接続で送る
        assert cmds.index("show startup-config") > cmds.index("show running-config")
    assert results["same"].startup.state == "synced"
    d = results["different"].startup
    assert (d.state, d.added, d.removed) == ("unsaved", 1, 1) and "保存済みの説明" in d.diff
    for k in ("absent", "pager", "empty", "error"):
        assert results[k].startup.state == "unknown", k
    # 保存する running のコンフィグは、startup の状態に関係なく同じ（今までと 1 バイトも変えない）
    expected = cs.normalize_config(fake_sshd.CONFIG if mode == "cisco" else fake_sshd.AWPLUS_CONFIG, platform)
    for k, r in results.items():
        assert r.added == len(expected.splitlines()), k


@pytest.mark.parametrize("startup", ["silent", "close"])
def test_startup_no_response_does_not_fail_collect(monkeypatch, startup):
    """startup に応答しない・チャネルを閉じる機器でも、running は保存して収集は成功（状態は不明）。待ちには上限がある"""
    import time
    monkeypatch.setattr(settings, "STARTUP_CHECK_TIMEOUT", 2)
    port, _, _ = fake_sshd.start(startup=startup)
    d = dev(port)
    t0 = time.monotonic()
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash, r
    assert time.monotonic() - t0 < 25
    assert r.startup.state == "unknown" and r.inventory is not None  # 台帳は startup より前に取れている
    assert cs.get_config_content(d.id, r.commit_hash) == cs.normalize_config(fake_sshd.CONFIG, "cisco_ios")


def test_startup_after_inventory_failure(monkeypatch):
    """台帳の取得に失敗（ページャーで止まる）した直後に startup を取っても、収集は成功する"""
    monkeypatch.setattr(settings, "STARTUP_CHECK_TIMEOUT", 2)
    port, state, _ = fake_sshd.start()
    state["inventory_pager"] = True
    d = dev(port)
    r = cs.collect_config_sync(d)
    assert r.success and r.commit_hash and r.inventory is None, r
    assert r.startup.state in ("synced", "unknown")  # 台帳の失敗で応答が乱れていれば不明。どちらでも収集は成功
    assert cs.get_config_content(d.id, r.commit_hash) == cs.normalize_config(fake_sshd.CONFIG, "cisco_ios")


def test_startup_check_failure_does_not_fail_collect(monkeypatch):
    """比較の処理が例外になっても「保存に失敗」にしない（状態は不明）"""
    def boom(*a, **kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(startup_check, "compare", boom)
    port, _, _ = fake_sshd.start()
    r = cs.collect_config_sync(dev(port))
    assert r.success and r.commit_hash and r.startup.state == "unknown"


def test_saved_running_config_is_unchanged_by_startup_check(monkeypatch):
    saved = []
    for enabled in (True, False):
        monkeypatch.setattr(settings, "STARTUP_CHECK_ENABLED", enabled)
        port, _, _ = fake_sshd.start(startup="different")
        d = dev(port)
        assert cs.collect_config_sync(d).success
        saved.append(cs.get_config_content(d.id, cs.head_commit_hash(d.id)))
    assert saved[0] == saved[1] == cs.normalize_config(fake_sshd.CONFIG, "cisco_ios")


def test_unsupported_platform_and_disabled_send_no_command(monkeypatch):
    port, state, _ = fake_sshd.start(mode="generic", config_commands=("show running-config",))
    r = cs.collect_config_sync(dev(port, platform="cisco_asa"))
    assert r.success and r.startup.state is None and "show startup-config" not in state["commands"]
    monkeypatch.setattr(settings, "STARTUP_CHECK_ENABLED", False)
    port, state, _ = fake_sshd.start()
    r = cs.collect_config_sync(dev(port))
    assert r.success and r.startup.state is None and "show startup-config" not in state["commands"]


def test_failed_collect_has_no_startup_result():
    port, _, _ = fake_sshd.start()
    r = cs.collect_config_sync(dev(port, password="wrong"))
    assert not r.success and r.startup is None


# ---------------------------------------------------------------- worker・API・通知
@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: calls.append((kind, url, payload)))
    monkeypatch.setattr(worker.send_change_notification, "delay", lambda *a, **kw: None)
    monkeypatch.setattr(worker.send_unsaved_notification, "delay",
                        lambda *a, **kw: worker.send_unsaved_notification.apply(args=a, kwargs=kw).get())
    return calls


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_worker_state_notification_and_api(sent):
    t = uuid.uuid4().hex[:6]
    hook = f"https://discord.com/api/webhooks/980/{t}"
    port, state, _ = fake_sshd.start()
    with TestClient(app) as c, mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
        admin = _login(c, "admin", "initial-pass-123")
        uid_ = c.post("/api/users/", json={"username": f"su-{t}", "password": "password-1234", "role": "viewer"},
                      headers=admin).json()["id"]
        vh = _login(c, f"su-{t}", "password-1234")

        def setting(on):
            r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": True,
                                                     "on_system": False, "on_unsaved": on}, headers=vh)
            assert r.status_code == 200 and r.json()["on_unsaved"] is on

        setting(False)
        assert c.get("/api/notifications/me", headers=vh).json()["on_unsaved"] is False  # 既定は無効
        d = c.post("/api/devices/", json=dict(name=f"su-{t}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                              username="admin", password="pw"), headers=admin).json()
        did = d["id"]
        assert d["startup_state"] is None

        def collect():
            return worker.collect_device_config.apply(args=(did, "manual", "admin", f"su-{uuid.uuid4().hex[:4]}")).get()

        def get():
            return c.get(f"/api/devices/{did}", headers=admin).json()

        def mine():
            return [p for _, u, p in sent if u == hook and "保存し忘れ" in p["embeds"][0]["title"]]

        def events(ev):
            return c.get("/api/activity/logs", params={"device_id": did, "event": ev}, headers=admin).json()["items"]

        try:
            # 初めて比べられた回が未保存でも、通知しない（導入直後にまとめて届かないように）。状態・アクティビティには残す
            setting(True)
            state["startup"] = "different"
            assert collect()["success"]
            g = get()
            assert (g["startup_state"], g["startup_added"], g["startup_removed"]) == ("unsaved", 1, 1) and g["startup_checked_at"]
            assert mine() == [] and len(events("startup.unsaved")) == 1
            first_checked = g["startup_checked_at"]
            # 差分の本文は DeviceResponse に入れない。専用の API（CONFIG_READ）だけ
            assert "diff" not in g and "保存済みの説明" not in str(g)
            diff = c.get(f"/api/devices/{did}/startup-diff", headers=vh)
            assert diff.status_code == 200 and "保存済みの説明" in diff.json()["diff"] and diff.json()["state"] == "unsaved"
            assert c.get(f"/api/devices/{did}/startup-diff").status_code == 401
            for ev in events("startup.unsaved"):
                assert "保存済みの説明" not in str(ev)  # 記録には行数だけ
            # #35: DB の生の値は暗号化されている（DB のダンプから差分の秘密の行を読めない）
            raw_db = sqlite3.connect(f"{TMP}/t.db").execute("select startup_diff from devices where id=?", (did,)).fetchone()[0]
            assert raw_db.startswith("enc:") and "保存済みの説明" not in raw_db
            # この版より前の平文の値も読める（次に比べ直したときに暗号化される）
            con = sqlite3.connect(f"{TMP}/t.db")
            con.execute("update devices set startup_diff=? where id=?", ("--- startup\n+++ running\n+平文の差分", did))
            con.commit()
            assert "平文の差分" in c.get(f"/api/devices/{did}/startup-diff", headers=vh).json()["diff"]
            assert collect()["success"]
            raw_db = con.execute("select startup_diff from devices where id=?", (did,)).fetchone()[0]
            assert raw_db.startswith("enc:") and "平文の差分" not in raw_db
            con.close()

            # unsaved のままの間は通知しない
            assert collect()["success"] and mine() == []
            first_checked = get()["startup_checked_at"]  # 最後に比べられた日時

            # 読み取れなかった回は、状態・行数・差分・日時を上書きしない（バッジは消えない）。再び未保存でも通知しない
            for bad in ("absent", "error", "empty", "pager"):
                state["startup"] = bad
                assert collect()["success"]
                g = get()
                assert (g["startup_state"], g["startup_added"], g["startup_removed"]) == ("unsaved", 1, 1), bad
                assert g["startup_checked_at"] == first_checked, bad  # 最後に比べられた日時のまま
            assert c.get(f"/api/devices/{did}/startup-diff", headers=vh).json()["diff"]  # 差分も残る
            state["startup"] = "different"
            assert collect()["success"] and mine() == []

            # synced → unsaved のときだけ通知する
            state["startup"] = "same"
            assert collect()["success"]
            assert get()["startup_state"] == "synced" and len(events("startup.synced")) == 1
            assert c.get(f"/api/devices/{did}/startup-diff", headers=vh).json()["diff"] is None
            assert mine() == []
            state["startup"] = "different"
            assert collect()["success"]
            (p,) = mine()
            emb = p["embeds"][0]
            assert emb["title"] == f"保存し忘れ: su-{t}"
            assert {"name": "保存されていない変更", "value": "+1 行 / -1 行", "inline": True} in emb["fields"]
            assert "保存済みの説明" not in str(p)  # 通知に差分の本文は入れない
            assert collect()["success"] and len(mine()) == 1

            # 「保存し忘れ」を外すと送らない
            setting(False)
            state["startup"] = "same"
            assert collect()["success"]
            state["startup"] = "different"
            assert collect()["success"] and len(mine()) == 1
            setting(True)

            # 収集が失敗した回は状態を変えない
            before = get()
            c.put(f"/api/devices/{did}", json={"password": "wrong"}, headers=admin)
            res = collect()
            assert not res["success"]
            after = get()
            assert (after["startup_state"], after["startup_checked_at"]) == (before["startup_state"], before["startup_checked_at"])
            c.put(f"/api/devices/{did}", json={"password": "pw"}, headers=admin)

            # ダッシュボード
            dash = c.get("/api/dashboard", headers=admin).json()["startup"]
            assert dash["unsaved"] >= 1 and dash["targets"] >= 1 and dash["enabled"] is True

            # 無効にすると、コマンドを送らず状態は NULL に戻る。それまでも、API は古い値を出さない
            n = state["commands"].count("show startup-config")
            with mock.patch.object(settings, "STARTUP_CHECK_ENABLED", False):
                g = get()
                assert g["startup_state"] is None and g["startup_checked_at"] is None  # DB には残っていても出さない
                assert c.get(f"/api/devices/{did}/startup-diff", headers=vh).json()["diff"] is None
                assert c.get("/api/dashboard", headers=admin).json()["startup"]["unsaved"] == 0
                assert collect()["success"]
            assert state["commands"].count("show startup-config") == n
            g = get()
            assert g["startup_state"] is None and g["startup_added"] is None and g["startup_checked_at"] is None
            # 有効に戻すと、NULL からの比較になる（通知はしない）
            assert collect()["success"] and get()["startup_state"] == "unsaved" and len(mine()) == 1
        finally:
            c.delete(f"/api/devices/{did}", headers=admin)
            assert c.delete(f"/api/users/{uid_}", headers=admin).status_code == 204


def test_unknown_is_saved_only_when_never_compared(sent):
    """一度も比べられていない機器だけ、不明を保存する。比べられたあとは上書きしない"""
    t = uuid.uuid4().hex[:6]
    port, state, _ = fake_sshd.start(startup="absent")
    with TestClient(app) as c, mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()):
        admin = _login(c, "admin", "initial-pass-123")
        did = c.post("/api/devices/", json=dict(name=f"su2-{t}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                                username="admin", password="pw"), headers=admin).json()["id"]
        try:
            assert worker.collect_device_config.apply(args=(did, "manual", "admin", None)).get()["success"]
            g = c.get(f"/api/devices/{did}", headers=admin).json()
            assert g["startup_state"] == "unknown" and g["startup_checked_at"] is None
            state["startup"] = "same"
            assert worker.collect_device_config.apply(args=(did, "manual", "admin", None)).get()["success"]
            g = c.get(f"/api/devices/{did}", headers=admin).json()
            assert g["startup_state"] == "synced" and g["startup_checked_at"]
            state["startup"] = "absent"
            assert worker.collect_device_config.apply(args=(did, "manual", "admin", None)).get()["success"]
            g2 = c.get(f"/api/devices/{did}", headers=admin).json()
            assert {k: v for k, v in g2.items() if k.startswith("startup_")} == {k: v for k, v in g.items() if k.startswith("startup_")}
        finally:
            c.delete(f"/api/devices/{did}", headers=admin)


def test_startup_diff_is_not_loaded_by_list():
    """差分は deferred。一覧・ダッシュボードの機器の取得では読み込まない"""
    from app.models.device import Device
    assert Device.startup_diff.property.deferred is True


def test_notification_settings_validation_and_default():
    t = uuid.uuid4().hex[:6]
    hook = f"https://discord.com/api/webhooks/981/{t}"
    off = {"on_change": False, "on_violation": False, "on_failure": False, "on_system": False, "on_inventory": False,
           "on_ping": False}
    with TestClient(app) as c:
        admin = _login(c, "admin", "initial-pass-123")
        uid_ = c.post("/api/users/", json={"username": f"sv-{t}", "password": "password-1234", "role": "viewer"},
                      headers=admin).json()["id"]
        try:
            h = _login(c, f"sv-{t}", "password-1234")
            # on_unsaved だけでも「通知する内容」を選んだことになる
            r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, **off, "on_unsaved": True},
                      headers=h)
            assert r.status_code == 200 and r.json()["on_unsaved"] is True and r.json()["on_drift"] is False
            assert c.get("/api/notifications/me", headers=h).json()["on_unsaved"] is True
            r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, **off}, headers=h)
            assert r.status_code == 422
        finally:
            assert c.delete(f"/api/users/{uid_}", headers=admin).status_code == 204


def test_legacy_plaintext_startup_diffs_are_encrypted_on_startup(monkeypatch):
    """0041 より前の平文の差分は、起動時にまとめて暗号化する。暗号化済みの行はそのまま（二重に暗号化しない）。何度実行しても同じ"""
    import asyncio

    from app import main
    from app.core.crypto import decrypt, encrypt

    ids = [str(uuid.uuid4()) for _ in range(3)]
    already = encrypt("--- startup\n+++ running\n+暗号化済み")
    con = sqlite3.connect(f"{TMP}/t.db")
    for i, (did, diff) in enumerate(zip(ids, ("--- startup\n+++ running\n+平文1 secret x", "+平文2", already), strict=True)):
        con.execute("insert into devices(id,name,hostname,platform,port,username,password,is_active,created_at,updated_at,"
                    "startup_state,startup_diff) values(?,?,?,?,22,'u','enc:x',1,'2026-01-01','2026-01-01','unsaved',?)",
                    (did, f"legacy-diff-{i}-{did[:6]}", "192.0.2.10", "cisco_ios", diff))
    con.commit()

    def rows():
        return [con.execute("select startup_diff from devices where id=?", (d,)).fetchone()[0] for d in ids]

    try:
        monkeypatch.setattr(main, "LEGACY_DIFF_BATCH", 1)  # まとめて処理する区切りも通す
        with TestClient(app):  # 起動時の処理で暗号化される
            pass
        first = rows()
        assert all(v.startswith("enc:") for v in first) and not any("平文" in v for v in first)
        assert decrypt(first[0]).endswith("平文1 secret x") and decrypt(first[1]) == "+平文2"
        assert first[2] == already  # 暗号化済みの行は書き直さない
        asyncio.run(main._encrypt_legacy_startup_diffs())  # 2 回目は何もしない
        assert rows() == first
    finally:
        con.execute(f"delete from devices where id in ({','.join('?' * len(ids))})", ids)
        con.commit()
        con.close()
