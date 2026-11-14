"""コンフィグ変更の通知のテスト（送信は差し替えて、宛先の決まり方と内容を確認する）"""
import asyncio
import json
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core.database import AsyncSessionLocal
from app.main import app
from app.services import config_service as cs
from app.services import notify

D = "https://discord.com/api/webhooks/{}/tok-{}"
S = "https://hooks.slack.com/services/T000/B{}/xyz{}"


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


def uid():
    return uuid.uuid4().hex[:6]


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        users = {}
        for name, role in [("ntf-a", "viewer"), ("ntf-b", "operator"), ("ntf-c", "viewer")]:
            uname = f"{name}-{uid()}"
            u = c.post("/api/users/", json={"username": uname, "password": "password-1234", "role": role}, headers=admin).json()
            users[name] = {"id": u["id"], "h": login(c, uname, "password-1234"), "name": uname}
        g1 = c.post("/api/device-groups/", json={"name": f"本社-{uid()}"}, headers=admin).json()
        g2 = c.post("/api/device-groups/", json={"name": f"DC-{uid()}"}, headers=admin).json()
        yield {"c": c, "admin": admin, "u": users, "g1": g1["id"], "g2": g2["id"]}


@pytest.fixture
def sent(monkeypatch):
    calls = []

    def fake(kind, url, payload):
        calls.append((kind, url, payload))
        return None

    monkeypatch.setattr(notify, "send_webhook", fake)
    return calls


def resolve(group_id):
    async def run():
        async with AsyncSessionLocal() as db:
            return {(d.kind, d.url): sorted(d.via) for d in await notify.resolve_destinations(db, group_id)}
    return asyncio.run(run())


def test_validation_and_permissions(ctx):
    c, a = ctx["c"], ctx["u"]["ntf-a"]["h"]
    # 自分の設定は閲覧者でも変更できる。ユーザーグループは管理者のみ
    assert c.get("/api/notifications/me", headers=a).json()["mode"] == "inherit"
    assert c.get("/api/notifications/groups", headers=a).status_code == 403
    assert c.post("/api/notifications/groups", json={"name": "x"}, headers=a).status_code == 403
    assert c.get("/api/notifications/preview", headers=a).status_code == 403
    bad = [
        {"mode": "custom", "discord_webhook": "https://example.com/api/webhooks/1/x"},  # 公式以外の URL
        {"mode": "custom", "slack_webhook": "http://hooks.slack.com/services/T/B/x"},
        {"mode": "custom"},  # 通知先なし
        {"mode": "custom", "discord_webhook": D.format(1, "a"), "all_devices": False},  # 対象なし
        {"mode": "custom", "discord_webhook": D.format(1, "a"), "all_devices": False, "device_group_ids": ["nope"]},
    ]
    for body in bad:
        assert c.put("/api/notifications/me", json=body, headers=a).status_code == 422, body
    r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": D.format(99, "secret-token-abcd")}, headers=a)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["has_discord"] and "secret-token" not in out["discord_webhook"] and out["discord_webhook"].endswith("abcd")
    # None は変更なし、空文字は削除
    r = c.put("/api/notifications/me", json={"mode": "custom", "slack_webhook": S.format(1, 1)}, headers=a).json()
    assert r["has_discord"] and r["has_slack"]
    r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": ""}, headers=a).json()
    assert not r["has_discord"] and r["has_slack"]
    assert c.put("/api/notifications/me", json={"mode": "inherit"}, headers=a).status_code == 200
    # グループは inherit を使えない
    assert c.post("/api/notifications/groups", json={"name": f"g-{uid()}", "notification": {"mode": "inherit"}},
                  headers=ctx["admin"]).status_code == 422


def test_resolution_user_and_group(ctx):
    c, admin, u, g1, g2 = ctx["c"], ctx["admin"], ctx["u"], ctx["g1"], ctx["g2"]
    t1d, t2s, bd = D.format(11, uid()), S.format(22, uid()), D.format(33, uid())
    # チーム1（a, b）: 本社の変更を Discord へ。チーム2（b, c）: 全機器を Slack へ
    t1 = c.post("/api/notifications/groups", json={
        "name": f"チーム1-{uid()}", "member_ids": [u["ntf-a"]["id"], u["ntf-b"]["id"]],
        "notification": {"mode": "custom", "discord_webhook": t1d, "all_devices": False, "device_group_ids": [g1]},
    }, headers=admin)
    assert t1.status_code == 201, t1.text
    t2 = c.post("/api/notifications/groups", json={
        "name": f"チーム2-{uid()}", "member_ids": [u["ntf-b"]["id"], u["ntf-c"]["id"]],
        "notification": {"mode": "custom", "slack_webhook": t2s},
    }, headers=admin).json()
    assert {m["username"] for m in t2["members"]} == {u["ntf-b"]["name"], u["ntf-c"]["name"]}
    assert t1d not in str(t1.json())  # 一覧でも URL は伏せる

    # b は個別設定（DC だけ自分の Discord へ）、c は通知しない、a は設定なし（グループの設定を使う）
    c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": bd, "all_devices": False,
                                         "device_group_ids": [g2]}, headers=u["ntf-b"]["h"])
    c.put("/api/notifications/me", json={"mode": "off"}, headers=u["ntf-c"]["h"])

    r = resolve(g1)
    assert ("discord", t1d) in r and r[("discord", t1d)] == [f"グループ: {t1.json()['name']}"]
    assert ("slack", t2s) not in r  # チーム2のメンバーは個別設定・通知しないのみ
    assert ("discord", bd) not in r
    r = resolve(g2)
    assert ("discord", bd) in r and ("discord", t1d) not in r
    # c がグループの設定を使うようになれば、チーム2（全機器）にも送る。同じ URL は1回だけ
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=u["ntf-c"]["h"])
    c.put(f"/api/notifications/groups/{t2['id']}", json={
        "name": t2["name"], "member_ids": [u["ntf-a"]["id"], u["ntf-b"]["id"], u["ntf-c"]["id"]],
        "notification": {"mode": "custom", "all_devices": True},
    }, headers=admin)
    r = resolve(g1)
    assert len(r[("slack", t2s)]) == 1 and ("discord", t1d) in r
    # 未分類の機器: チーム1は対象外、チーム2（全機器）は対象
    r = resolve(None)
    assert ("slack", t2s) in r and ("discord", t1d) not in r
    # 無効にしたグループには送らない
    c.put(f"/api/notifications/groups/{t2['id']}", json={
        "name": t2["name"], "member_ids": [u["ntf-c"]["id"]], "notification": {"mode": "off"},
    }, headers=admin)
    assert ("slack", t2s) not in resolve(g1)
    # 管理者の確認画面
    prev = c.get("/api/notifications/preview", params={"device_group_id": g1}, headers=admin).json()
    assert any(p["kind"] == "discord" and "チーム1" in p["via"][0] for p in prev)
    # 所属グループは本人の画面にも出る
    me = c.get("/api/notifications/me", headers=u["ntf-a"]["h"]).json()
    assert any(g["id"] == t1.json()["id"] and g["notification"]["has_discord"] for g in me["groups"])
    # 片付け: グループを消すと設定・所属も消える
    for gid in (t1.json()["id"], t2["id"]):
        assert c.delete(f"/api/notifications/groups/{gid}", headers=admin).status_code == 204
    assert ("discord", t1d) not in resolve(g1)
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=u["ntf-b"]["h"])


def test_change_notification_end_to_end(ctx, sent, monkeypatch):
    """収集で変更が見つかったら通知タスクを投入し、要約とリンクを送る（差分の中身は載せない）"""
    c, admin, u, g1 = ctx["c"], ctx["admin"], ctx["u"], ctx["g1"]
    monkeypatch.setattr(notify.settings, "PUBLIC_URL", "https://ncm.example.local/")
    hook = D.format(44, uid())
    grp = c.post("/api/notifications/groups", json={
        "name": f"監視-{uid()}", "member_ids": [u["ntf-a"]["id"]],
        "notification": {"mode": "custom", "discord_webhook": hook, "all_devices": False, "device_group_ids": [g1]},
    }, headers=admin).json()
    slack_hook = S.format(55, uid())
    # 前のテストで登録した Discord は空文字で消す（None なら変更しない）
    c.put("/api/notifications/me", json={"mode": "custom", "slack_webhook": slack_hook, "discord_webhook": ""},
          headers=u["ntf-b"]["h"])

    port, _state, _ = fake_sshd.start()
    d = c.post("/api/devices/", json=dict(name=f"N-SW-{uid()}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                          username="admin", password="pw", group_id=g1), headers=admin).json()
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr), \
            mock.patch.object(worker.send_change_notification, "delay") as delay:
        assert worker.collect_device_config.apply(args=(d["id"], "schedule")).get()["success"]
        delay.assert_not_called()  # 初回の取得は変更ではない
        with mock.patch.object(fake_sshd, "CONFIG", fake_sshd.CONFIG + "\r\nntp server 192.0.2.1"):
            res = worker.collect_device_config.apply(args=(d["id"], "schedule")).get()
        assert res["commit_hash"]
        delay.assert_called_once()
        args = delay.call_args.args
    out = worker.send_change_notification.apply(args=args).get()
    assert out == {"sent": 2, "failed": 0}, (out, [(k, u) for k, u, _ in sent])
    by_kind = {k: (url, p) for k, url, p in sent}
    url, payload = by_kind["discord"]
    assert url == hook
    embed = payload["embeds"][0]
    assert d["name"] in embed["title"] and embed["url"] == f"https://ncm.example.local/history?device={d['id']}"
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["変更"] == "+1 行 / -0 行" and fields["収集"].startswith("スケジュール収集")
    assert "ntp server" not in str(payload)  # 差分の中身は載せない
    url, payload = by_kind["slack"]
    assert url == slack_hook and "<https://ncm.example.local/history?device=" in payload["text"]
    # 結果は通知設定に残る
    g = next(x for x in c.get("/api/notifications/groups", headers=admin).json() if x["id"] == grp["id"])
    assert g["notification"]["last_sent_at"] and g["notification"]["last_error"] is None
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=u["ntf-b"]["h"])
    c.delete(f"/api/notifications/groups/{grp['id']}", headers=admin)


def test_send_failure_is_recorded(ctx, monkeypatch):
    c, u = ctx["c"], ctx["u"]
    monkeypatch.setattr(notify, "send_webhook", lambda k, url, p: "Webhook が無効です（HTTP 404）")
    c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": D.format(66, uid())}, headers=u["ntf-c"]["h"])
    r = c.post("/api/notifications/me/test", headers=u["ntf-c"]["h"]).json()
    assert r["results"]["discord"].startswith("Webhook が無効")
    port, _, _ = fake_sshd.start()
    d = c.post("/api/devices/", json=dict(name=f"N2-{uid()}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                          username="admin", password="pw"), headers=ctx["admin"]).json()

    async def run():
        async with AsyncSessionLocal() as db:
            return await notify.notify_change(db, d["id"], "a" * 40, 3, 1, "manual")
    assert asyncio.run(run())["failed"] == 1
    me = c.get("/api/notifications/me", headers=u["ntf-c"]["h"]).json()
    assert "HTTP 404" in me["last_error"]
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=u["ntf-c"]["h"])
    # 送信先が無ければテストできない
    assert c.post("/api/notifications/me/test", headers=ctx["admin"]).status_code == 400


def test_send_webhook_rejects_other_hosts():
    assert notify.send_webhook("discord", "https://evil.example.com/api/webhooks/1/x", {}) is not None
    assert notify.valid_webhook("discord", "https://discord.com/api/webhooks/123/abc_DEF-9")
    assert notify.valid_webhook("discord", "https://canary.discord.com/api/webhooks/123/abc")
    assert notify.valid_webhook("slack", "https://hooks.slack.com/services/T00/B00/XXXX")
    assert not notify.valid_webhook("slack", "https://hooks.slack.com.evil.io/services/T/B/X")
    assert notify.mask_webhook("https://discord.com/api/webhooks/123/abcdefgh") == "https://discord.com/api/webhooks/…efgh"


def test_send_webhook_retry_and_errors(monkeypatch):
    import io
    import urllib.error
    calls = []

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def err(code, body=b"{}", headers=None):
        return urllib.error.HTTPError("u", code, "x", headers or {}, io.BytesIO(body))

    seq = [err(429, b'{"retry_after": 0.01}'), Resp(b"")]

    def fake_urlopen(req, timeout):
        calls.append(json.loads(req.data))
        r = seq.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    url = "https://discord.com/api/webhooks/1/abc"
    assert notify.send_webhook("discord", url, {"content": "日本語"}) is None
    assert len(calls) == 2 and calls[0]["content"] == "日本語"
    seq[:] = [err(404)]
    assert "Webhook が無効" in notify.send_webhook("discord", url, {})
    seq[:] = [urllib.error.URLError("Name or service not known")]
    assert notify.send_webhook("discord", url, {}).startswith("送信できません")


def test_violation_and_failure_notifications(ctx, sent):
    """通知する内容の選択（違反の発生・収集の失敗）。変更通知だけの設定には送らない"""
    c, admin = ctx["c"], ctx["admin"]
    uname = f"ntf-ev-{uid()}"
    c.post("/api/users/", json={"username": uname, "password": "password-1234", "role": "viewer"}, headers=admin)
    h = login(c, uname, "password-1234")
    hook = D.format(901, uid())
    # 内容を1つも選ばないとエラー
    bad = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": False,
                                                "on_system": False}, headers=h)
    assert bad.status_code == 422 and "通知する内容" in bad.json()["detail"]
    r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": False,
                                              "on_violation": True, "on_failure": True}, headers=h)
    assert r.status_code == 200, r.text
    me = c.get("/api/notifications/me", headers=h).json()
    assert (me["on_change"], me["on_violation"], me["on_failure"]) == (False, True, True)
    assert ("discord", hook) not in resolve(ctx["g1"])  # 変更の通知先には含まれない
    pv = c.get("/api/notifications/preview", params={"device_group_id": ctx["g1"], "event": "violation"}, headers=admin)
    assert any(uname in " ".join(x["via"]) for x in pv.json())

    devs = []
    for _ in range(2):
        d = c.post("/api/devices/", json=dict(name=f"nv-{uid()}", hostname="10.8.0.1", platform="cisco_ios",
                                              username="u", password="p", group_id=ctx["g1"]), headers=admin).json()
        cs.save_config(d["id"], "hostname X\nip http server\n", "test")
        devs.append(d)
    run_now = lambda task: mock.patch.object(task, "delay", side_effect=lambda *a: task.apply(args=a).get())  # noqa: E731

    def flush(m):
        """API のリクエスト中に投入されたタスクを、リクエストの後で実行する"""
        for call in m.call_args_list:
            worker.send_violation_notification.apply(args=call.args).get()
        m.reset_mock()

    with mock.patch.object(worker.send_violation_notification, "delay") as v:
        rule = c.post("/api/compliance/rules", json={"name": f"HTTP禁止-{uid()}", "match_type": "contains",
                                                     "expect": "absent", "pattern": "ip http server", "severity": "high",
                                                     "platforms": ["cisco_ios"]}, headers=admin).json()
        assert v.call_count == 1
        flush(v)
    mine = [p for k, u, p in sent if u == hook]
    # ルールの追加で2台が同時に違反 → この通知先へは1通にまとめる
    assert len(mine) == 1
    emb = mine[0]["embeds"][0]
    assert emb["title"].startswith("コンプライアンス違反:") and "台" in emb["title"]
    assert all(d["name"] in emb["description"] for d in devs)

    # 1台だけ違反 → 機器名・ルール・重要度を載せる
    sent.clear()
    cs.save_config(devs[0]["id"], "hostname X\n", "test")
    with mock.patch.object(worker.send_violation_notification, "delay") as v:
        c.post("/api/compliance/run", headers=admin)
        assert not v.called  # 解消は通知しない
        cs.save_config(devs[0]["id"], "hostname X\nip http server\n", "test")
        c.post("/api/compliance/run", headers=admin)
        flush(v)
    one = [p for k, u, p in sent if u == hook]
    assert len(one) == 1 and one[0]["embeds"][0]["title"] == f"コンプライアンス違反: {devs[0]['name']}"
    assert "重要度: 高" in json.dumps(one[0], ensure_ascii=False)

    # 収集の失敗（認証失敗はリトライしない）
    sent.clear()
    port, _, _ = fake_sshd.start()
    bad_dev = c.post("/api/devices/", json=dict(name=f"nf-{uid()}", hostname="127.0.0.1", port=port, platform="cisco_ios",
                                                username="admin", password="wrong", group_id=ctx["g1"]), headers=admin).json()
    with mock.patch.object(worker, "_redis", return_value=fakeredis.FakeRedis()), \
            run_now(worker.send_failure_notification):
        worker.collect_device_config.apply(args=(bad_dev["id"], "manual", "admin", "ref-nf")).get()
    fail = [p for k, u, p in sent if u == hook]
    assert len(fail) == 1 and fail[0]["embeds"][0]["title"] == f"収集失敗: {bad_dev['name']}"
    assert "認証" in json.dumps(fail[0], ensure_ascii=False)
    acts = c.get("/api/activity/logs", params={"ref": "ref-nf", "event": "notify.sent"}, headers=admin).json()["items"]
    assert acts and "収集の失敗を通知しました" in acts[0]["message"]
    c.delete(f"/api/compliance/rules/{rule['id']}", headers=admin)
    c.put("/api/notifications/me", json={"mode": "inherit"}, headers=h)
