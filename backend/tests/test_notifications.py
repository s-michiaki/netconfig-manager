"""コンフィグ変更の通知のテスト（送信は差し替えて、宛先の決まり方と内容を確認する）"""
import asyncio
import json
import re
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
                                                "on_system": False, "on_inventory": False, "on_ping": False}, headers=h)
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


# ---------------------------------------------------------------- Teams（ワークフローの Webhook）

LINKS = "[再ログインはこちら](https://evil.example/login)"  # 利用者・機器が決められる文字列に入りうるリンクの構文
TEAMS_BASE = "xxxx.environment.api.powerplatform.com"
TEAMS_PATH = "/powerautomate/automations/direct/workflows/WFIDEXAMPLE/triggers/manual/paths/invoke"
TEAMS_QUERY = "api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SIGEXAMPLE"
TEAMS_OK = f"https://{TEAMS_BASE}{TEAMS_PATH}?{TEAMS_QUERY}"


def teams_url(n=None):
    """テスト用の偽の Teams の URL（n で別の URL にする）"""
    return TEAMS_OK.replace("WFIDEXAMPLE", f"WFIDEXAMPLE{n}") if n is not None else TEAMS_OK


TEAMS_ALLOWED = [
    TEAMS_OK,
    f"https://{TEAMS_BASE}:443{TEAMS_PATH}?{TEAMS_QUERY}",  # ポート 443
    f"https://abc.def.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE",  # ホストのラベルが複数
    f"https://XXXX.Environment.Api.PowerPlatform.com{TEAMS_PATH}?sig=EXAMPLE",  # ホストの大文字小文字は問わない
    f"https://a-1.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE&sv=1.0",
    f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=a-b_c.D~e%2Bf",  # sig に使われる文字
]
TEAMS_DENIED = [
    ("", "空"),
    (f"http://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "http"),
    (f"ftp://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "ftp"),
    (f"//{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "スキームなし"),
    (f"https://evil.example.com{TEAMS_PATH}?sig=EXAMPLE", "別のホスト"),
    (f"https://{TEAMS_BASE}.evil.example.com{TEAMS_PATH}?sig=EXAMPLE", "ホストの後ろに別のドメイン"),
    (f"https://evil.example.com/{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "パスにホスト名"),
    (f"https://evil.example.com?{TEAMS_BASE}{TEAMS_PATH}&sig=1", "クエリにホスト名"),
    (f"https://environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "先頭のラベルなし"),
    (f"https://.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "先頭が空のラベル"),
    (f"https://a..environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "空のラベル"),
    (f"https://{TEAMS_BASE}.{TEAMS_PATH}?sig=EXAMPLE", "末尾のドット"),
    (f"https://-xxxx.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "ラベルがハイフンで始まる"),
    (f"https://xn--abc.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "IDN（punycode）"),
    (f"https://日本.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "全角のホスト"),
    (f"https://x_y.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE", "ホストにアンダースコア"),
    (f"https://127.0.0.1{TEAMS_PATH}?sig=EXAMPLE", "IP アドレス"),
    (f"https://192.0.2.1:443{TEAMS_PATH}?sig=EXAMPLE", "IP アドレスとポート"),
    (f"https://[::1]{TEAMS_PATH}?sig=EXAMPLE", "IPv6"),
    (f"https://user@{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "ユーザー情報"),
    (f"https://user:pass@{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "ユーザー情報とパスワード"),
    (f"https://{TEAMS_BASE}@evil.example.com{TEAMS_PATH}?sig=EXAMPLE", "@ でホストを偽装"),
    (f"https://evil.example.com@{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "@ の後ろをホストに見せる"),
    (f"https://{TEAMS_BASE}:8443{TEAMS_PATH}?sig=EXAMPLE", "別のポート"),
    (f"https://{TEAMS_BASE}:80{TEAMS_PATH}?sig=EXAMPLE", "ポート 80"),
    (f"https://{TEAMS_BASE}:{TEAMS_PATH}?sig=EXAMPLE", "ポートが空"),
    (f"https://{TEAMS_BASE}:abc{TEAMS_PATH}?sig=EXAMPLE", "ポートが数字でない"),
    (f"https://{TEAMS_BASE}/{TEAMS_PATH}?sig=EXAMPLE", "パスの先頭が //"),
    (f"https://{TEAMS_BASE}/other/path/invoke?sig=EXAMPLE", "パスが違う"),
    (f"https://{TEAMS_BASE}/powerautomate/automations/direct/workflows/W/triggers/manual/run?sig=EXAMPLE", "パスの末尾が違う"),
    (f"https://{TEAMS_BASE}/powerautomate/automations/direct/{TEAMS_PATH.rsplit('/direct/', 1)[1]}/x?sig=EXAMPLE", "末尾の後ろに続く"),
    (f"https://{TEAMS_BASE}/x{TEAMS_PATH}?sig=EXAMPLE", "パスの先頭に余分"),
    (f"https://{TEAMS_BASE}/powerautomate/automations/direct/../../x/triggers/manual/paths/invoke?sig=EXAMPLE", ".. を含む"),
    (f"https://{TEAMS_BASE}/powerautomate/automations/direct/%2e%2e/x/triggers/manual/paths/invoke?sig=EXAMPLE", "%2e%2e"),
    (f"https://{TEAMS_BASE}/powerautomate/automations/direct/a//triggers/manual/paths/invoke?sig=EXAMPLE", "// を含む"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH};x=1?sig=EXAMPLE", "パスパラメーター"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}", "クエリなし"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?", "クエリが空"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?api-version=1&sv=1.0", "sig なし"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=", "sig が空"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?xsig=EXAMPLE", "sig に似た別の名前"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=A&sig=B", "sig が 2 つ"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE#frag", "フラグメント"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE#", "空のフラグメント"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE ", "末尾の空白（strip されない直接呼び出し）"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EX AMPLE", "空白"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EX\tAMPLE", "タブ"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE\n", "改行"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE\r\nHost: evil", "ヘッダー注入"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EX\x00AMPLE", "NUL"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EX\x7fAMPLE", "DEL"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE\\evil", "バックスラッシュ"),
    (f"https:\\\\{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE", "バックスラッシュ区切り"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=例", "全角"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE&x=<script>", "記号 < >"),
    (f"https://{TEAMS_BASE}{TEAMS_PATH}?sig=EXAMPLE" + "x" * 1100, "長すぎる"),
    ("https://xxxx.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi", "旧 Office 365 コネクタ"),
    ("https://discord.com/api/webhooks/1/abc", "Discord の URL"),
    ("https://hooks.slack.com/services/T0/B0/xyz", "Slack の URL"),
    ("powerplatform.com", "ホスト名だけ"),
]
TEAMS_LEGACY = [
    "https://prod-12.japaneast.logic.azure.com:443/workflows/0123456789abcdef/triggers/manual/paths/invoke"
    "?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=EXAMPLE",
    "https://prod-12.japaneast.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=EXAMPLE",
    "https://logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=EXAMPLE",
]


@pytest.mark.parametrize("url", TEAMS_ALLOWED)
def test_teams_url_allowed(url):
    assert notify.teams_url_error(url) is None, url
    assert notify.valid_webhook("teams", url)


@pytest.mark.parametrize("url,why", TEAMS_DENIED, ids=[w for _, w in TEAMS_DENIED])
def test_teams_url_denied(url, why):
    err = notify.teams_url_error(url)
    assert err, why
    assert not notify.valid_webhook("teams", url)
    assert "SIGEXAMPLE" not in err and "sig=EXAMPLE" not in err  # 理由に URL の中身を出さない
    # 検証に通らない URL へは送信しない（サーバーから任意の URL へ送らせない）
    with mock.patch.object(notify, "_open_no_redirect") as op:
        assert notify.send_webhook("teams", url, {}) == "Webhook URL の形式が正しくありません"
        op.assert_not_called()


@pytest.mark.parametrize("url", TEAMS_LEGACY)
def test_teams_legacy_logic_azure_url_has_own_message(url):
    err = notify.teams_url_error(url)
    assert "logic.azure.com" in err and "コピーし直して" in err


def test_teams_url_denied_when_other_kind_url_given():
    # 種類ごとに検査が分かれている（Teams の URL は Discord・Slack の Webhook にならない）
    assert not notify.valid_webhook("discord", TEAMS_OK) and not notify.valid_webhook("slack", TEAMS_OK)
    assert "teams" in notify.KINDS and notify.KIND_LABELS["teams"] == "Teams"


def assert_adaptive_card(payload, title=None):
    """Teams のワークフローへ送る本文（メッセージ + Adaptive Card）の形"""
    json.dumps(payload, ensure_ascii=False)  # JSON にできる
    assert payload["type"] == "message" and len(payload["attachments"]) == 1
    att = payload["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive" and att["contentUrl"] is None
    card = att["content"]
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    assert card["body"] and card["body"][0]["type"] == "TextBlock"
    assert card["body"][0]["weight"] == "Bolder" and card["body"][0]["wrap"] is True
    for b in card["body"]:
        assert b["type"] in ("TextBlock", "FactSet")
        if b["type"] == "FactSet":
            assert b["facts"] and all(set(f) == {"title", "value"} for f in b["facts"])
        else:
            assert b["text"] and b["wrap"] is True
    for a in card.get("actions", []):
        assert a["type"] == "Action.OpenUrl" and a["url"].startswith("http") and a["title"]
    if title is not None:
        assert card["body"][0]["text"] == title
    return card


def test_teams_payload_shape(monkeypatch):
    monkeypatch.setattr(notify.settings, "PUBLIC_URL", "https://ncm.example.local")
    ev = notify.ChangeEvent("dev-1", "core-sw01", "192.0.2.10", "本社", 3, 1, "schedule", "a" * 40,
                            notify.utcnow())
    card = assert_adaptive_card(notify.build_payload("teams", ev), "コンフィグ変更: core-sw01")
    facts = {f["title"]: f["value"] for f in card["body"][1]["facts"]}
    assert facts["機器"] == "core-sw01（192.0.2.10）" and facts["変更"] == "+3 行 / -1 行" and facts["世代"] == "a" * 8
    assert card["actions"] == [{"type": "Action.OpenUrl", "title": "差分を画面で確認",
                                "url": "https://ncm.example.local/history?device=dev-1"}]
    # 差分の中身は載せない・リンクが無い設定ならボタンも無い
    monkeypatch.setattr(notify.settings, "PUBLIC_URL", "")
    assert "actions" not in assert_adaptive_card(notify.build_payload("teams", ev))
    # 本文（複数行）は TextBlock。改行は段落にする。項目が無ければ FactSet は付けない
    p = notify._message("teams", "題", [], "https://ncm.example.local/x", "開く", 0xEF4444, "1行目\n2行目")
    card = assert_adaptive_card(p, "題")
    assert [b["type"] for b in card["body"]] == ["TextBlock", "TextBlock"]
    assert card["body"][1]["text"] == "1行目\n\n2行目" and card["body"][0]["color"] == "Attention"
    t = notify.build_test_payload("teams", "ユーザー ops")
    card = assert_adaptive_card(t, "テスト通知")
    assert "ユーザー ops の通知設定" in card["body"][1]["text"]
    # ほかの手段の本文は変わらない
    assert notify.build_test_payload("slack", "x") == {"text": "NetConfig Manager からのテスト通知です（x の通知設定）"}


def test_teams_send_success_and_headers(monkeypatch):
    import io
    seen = []

    class Resp(io.BytesIO):
        status = 202

        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_open(req, timeout):
        seen.append((req.full_url, req.get_method(), dict(req.header_items()), json.loads(req.data), timeout))
        return Resp(b"")

    monkeypatch.setattr(notify, "_open_no_redirect", fake_open)
    # Discord・Slack は従来どおり urllib.request.urlopen（Teams の経路を通らない）
    monkeypatch.setattr(notify.urllib.request, "urlopen", lambda *a, **k: pytest.fail("Teams は urlopen を使わない"))
    payload = notify.build_test_payload("teams", "ops")
    assert notify.send_webhook("teams", TEAMS_OK, payload) is None  # 202 は成功
    url, method, headers, body, timeout = seen[0]
    assert url == TEAMS_OK and method == "POST" and body == payload and timeout == notify.TIMEOUT_SEC
    assert headers["Content-type"] == "application/json"


def test_teams_send_errors_do_not_leak_url(monkeypatch):
    import io
    import urllib.error
    seq = []

    def fake_open(req, timeout):
        r = seq.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def err(code, body=b"{}", headers=None):
        return urllib.error.HTTPError(TEAMS_OK, code, "x", headers or {}, io.BytesIO(body))

    monkeypatch.setattr(notify, "_open_no_redirect", fake_open)
    monkeypatch.setattr(notify.time, "sleep", lambda s: None)

    def leaks(msg):
        return any(w in (msg or "") for w in ("SIGEXAMPLE", "WFIDEXAMPLE", "powerplatform", TEAMS_BASE))

    # 本文に URL・sig を含む 5xx → 伏せる
    seq[:] = [err(500, f'{{"error": "bad {TEAMS_OK}", "x": "sig=SIGEXAMPLE"}}'.encode())]
    msg = notify.send_webhook("teams", TEAMS_OK, {})
    assert msg.startswith("HTTP 500") and not leaks(msg) and "bad" not in msg  # 相手の応答の本文は載せない
    # 接続の失敗（理由にホスト名が入る）
    seq[:] = [urllib.error.URLError(f"certificate verify failed for {TEAMS_BASE} sig=SIGEXAMPLE")]
    msg = notify.send_webhook("teams", TEAMS_OK, {})
    assert msg.startswith("送信できません") and not leaks(msg)
    # 無効（ワークフローの削除・オフ）
    for code in (400, 401, 403, 404):
        seq[:] = [err(code)]
        msg = notify.send_webhook("teams", TEAMS_OK, {})
        assert "Webhook が無効です" in msg and "ワークフロー" in msg and not leaks(msg)
    # リダイレクトはたどらない（エラーとして扱う）
    seq[:] = [err(302, b"", {"Location": "https://evil.example.com/"})]
    msg = notify.send_webhook("teams", TEAMS_OK, {})
    assert "リダイレクト" in msg and "evil" not in msg
    # 429 は一度だけ待って再送（既存の仕組みどおり）。2 回目の成功で None

    class Ok(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    seq[:] = [err(429, b'{"retry_after": 0.01}'), Ok(b"")]
    assert notify.send_webhook("teams", TEAMS_OK, {}) is None
    seq[:] = [err(429, b'{"retry_after": 0.01}'), err(429, b'{"retry_after": 0.01}')]
    assert notify.send_webhook("teams", TEAMS_OK, {}).startswith("HTTP 429")  # 再送は 1 回だけ


def test_teams_does_not_follow_redirects():
    """Teams の送信はリダイレクトをたどらない（本物の HTTP サーバーで確かめる。Discord・Slack は変えない）"""
    import threading
    import urllib.error
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer

    hits = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(("POST", self.path))
            self.send_response(302)
            self.send_header("Location", "/second")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            hits.append(("GET", self.path))
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        req = urllib.request.Request(f"{base}/first", data=b"{}", method="POST")
        with pytest.raises(urllib.error.HTTPError) as e:
            notify._open_no_redirect(req, 5)
        assert e.value.code == 302 and hits == [("POST", "/first")]  # /second へは行かない
        # 比べ: 普通の urlopen（Discord・Slack）は 302 をたどる
        hits.clear()
        with urllib.request.urlopen(urllib.request.Request(f"{base}/first", data=b"{}", method="POST"), timeout=5) as r:
            assert r.status == 202
        assert hits == [("POST", "/first"), ("GET", "/second")]
    finally:
        srv.shutdown()
        srv.server_close()


def test_teams_mask_hides_sig_and_workflow_id():
    m = notify.mask_webhook(TEAMS_OK)
    assert m == "https://xxxx…" + notify.TEAMS_HOST_SUFFIX + "/…"
    for secret in ("SIGEXAMPLE", "WFIDEXAMPLE", "sig=", "powerautomate", "api-version"):
        assert secret not in m
    assert notify.mask_webhook(f"https://abcdefgh.environment.api.powerplatform.com:443{TEAMS_PATH}?sig=EXAMPLE").startswith(
        "https://abcd…")
    assert "EXAMPLE" not in notify.mask_webhook(f"https://abcdefgh.environment.api.powerplatform.com{TEAMS_PATH}?sig=EXAMPLE")
    # 大文字のスキーム・ホストでも通常の形（保存時に小文字にそろえるが、表示側も小文字にしてから判定する）
    assert notify.mask_webhook(TEAMS_OK.replace("https://xxxx.environment.api.powerplatform.com",
                                                "HTTPS://XXXX.ENVIRONMENT.API.POWERPLATFORM.COM")) == m
    assert notify.normalize_teams_url("HTTPS://X.ENVIRONMENT.api.PowerPlatform.com:443/Path?sig=AbC") == \
        "https://x.environment.api.powerplatform.com:443/Path?sig=AbC"
    # Discord・Slack の表示は従来どおり
    assert notify.mask_webhook("https://hooks.slack.com/services/T00/B00/XXXXabcd") == "https://hooks.slack.com/services/T00/…abcd"
    assert notify.mask_webhook(None) is None and notify.mask_webhook("") is None


def _raw_teams_column(owner_id):
    from sqlalchemy import text

    async def run():
        async with AsyncSessionLocal() as db:
            return (await db.execute(text("select teams_webhook from notification_settings where owner_id = :o"),
                                     {"o": owner_id})).scalar_one()
    return asyncio.run(run())


def _new_user(c, admin, role="viewer"):
    name = f"ntf-teams-{uid()}"
    u = c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin).json()
    return {"id": u["id"], "name": name, "h": login(c, name, "password-1234")}


def _drop_user(c, admin, u):
    c.put("/api/notifications/me", json={"mode": "inherit", "teams_webhook": ""}, headers=u["h"])
    c.delete(f"/api/users/{u['id']}", headers=admin)


def test_teams_api_save_mask_encrypt_and_test_send(ctx, sent):
    c, admin = ctx["c"], ctx["admin"]
    u = _new_user(c, admin)
    hook = teams_url(uid())
    try:
        # 形式の誤り・旧形式は 422（理由は返すが URL は返さない）
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": "https://example.com/x?sig=SIGEXAMPLE"},
                  headers=u["h"])
        assert r.status_code == 422 and "Teams" in r.json()["detail"] and "SIGEXAMPLE" not in r.text
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": TEAMS_LEGACY[0]}, headers=u["h"])
        assert r.status_code == 422 and "コピーし直して" in r.json()["detail"] and "EXAMPLE" not in r.text
        # 長すぎる（API の上限）
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": TEAMS_OK + "x" * 3000}, headers=u["h"])
        assert r.status_code == 422 and "長すぎ" in r.json()["detail"]
        assert "SIGEXAMPLE" not in r.text and "powerplatform" not in r.text  # 応答に入力値（URL）を入れない
        # スキーム・ホストが大文字でも通り、小文字にそろえて保存（パス・クエリはそのまま）。伏せ字は通常の形
        upper = TEAMS_OK.replace("https://xxxx.environment.api.powerplatform.com",
                                 "HTTPS://XXXX.ENVIRONMENT.API.POWERPLATFORM.COM:443")
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": upper}, headers=u["h"])
        assert r.status_code == 200 and r.json()["teams_webhook"] == "https://xxxx…" + notify.TEAMS_HOST_SUFFIX + "/…"
        assert ("teams", f"https://{TEAMS_BASE}:443{TEAMS_PATH}?{TEAMS_QUERY}") in resolve(None)
        # Teams だけでも通知先になる。保存した URL は伏せ字で返る
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": f"  {hook}  "}, headers=u["h"])
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["has_teams"] and not out["has_discord"] and not out["has_slack"]
        assert out["teams_webhook"] == "https://xxxx…" + notify.TEAMS_HOST_SUFFIX + "/…"
        assert "SIGEXAMPLE" not in r.text and "WFIDEXAMPLE" not in r.text
        me = c.get("/api/notifications/me", headers=u["h"])
        assert me.json()["has_teams"] and "SIGEXAMPLE" not in me.text
        # DB には暗号化して保存（平文の sig を含まない）。復号すれば元の URL
        raw = _raw_teams_column(u["id"])
        assert raw.startswith("enc:") and "SIGEXAMPLE" not in raw and "powerplatform" not in raw
        assert raw != hook and len(raw) <= 2048
        # 通知先の一覧にも出るが伏せ字
        assert ("teams", hook) in resolve(None)
        # テスト送信: Teams の本文（Adaptive Card）で、設定した URL へ
        r = c.post("/api/notifications/me/test", headers=u["h"])
        assert r.status_code == 200 and r.json()["results"] == {"teams": "ok"}
        mine = [(k, url, p) for k, url, p in sent if url == hook]
        assert len(mine) == 1 and mine[0][0] == "teams"
        assert u["name"] in assert_adaptive_card(mine[0][2], "テスト通知")["body"][1]["text"]
        # None は変更なし。空文字で削除
        r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": D.format(7, uid())}, headers=u["h"])
        assert r.json()["has_teams"] and r.json()["has_discord"]
        r = c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": ""}, headers=u["h"])
        assert not r.json()["has_teams"] and r.json()["teams_webhook"] is None and r.json()["has_discord"]
        assert _raw_teams_column(u["id"]) is None
        # 監査ログ: 変更したこと・テストの結果だけ。URL は残らない
        logs = c.get("/api/audit/logs", params={"action": "notify.", "limit": 500}, headers=admin).json()["items"]
        text_all = json.dumps(logs, ensure_ascii=False)
        assert "teams_webhook" in text_all and "SIGEXAMPLE" not in text_all and "WFIDEXAMPLE" not in text_all
    finally:
        _drop_user(c, admin, u)


def test_teams_group_dedupe_and_failure_keeps_url_out_of_last_error(ctx, monkeypatch):
    """グループと個人で同じ URL なら 1 回だけ送る。失敗しても last_error・アクティビティに URL を残さない"""
    import io
    import urllib.error
    c, admin = ctx["c"], ctx["admin"]
    a, b = _new_user(c, admin), _new_user(c, admin)
    hook = teams_url(uid())
    g = c.post("/api/notifications/groups", json={
        "name": f"teams-{uid()}", "member_ids": [a["id"], b["id"]],
        "notification": {"mode": "custom", "teams_webhook": hook},
    }, headers=admin)
    assert g.status_code == 201, g.text
    gid = g.json()["id"]
    try:
        assert g.json()["notification"]["has_teams"] and "SIGEXAMPLE" not in g.text
        assert len(resolve(None)[("teams", hook)]) == 1  # メンバー 2 人でも宛先は 1 つ
        # b も個別設定で同じ URL → それでも 1 回
        c.put("/api/notifications/me", json={"mode": "custom", "teams_webhook": hook}, headers=b["h"])
        assert len([k for k in resolve(None) if k == ("teams", hook)]) == 1
        c.put("/api/notifications/me", json={"mode": "inherit", "teams_webhook": ""}, headers=b["h"])

        def boom(req, timeout):
            raise urllib.error.HTTPError(hook, 500, "x", {}, io.BytesIO(f"{hook} sig=SIGEXAMPLE".encode()))

        monkeypatch.setattr(notify, "_open_no_redirect", boom)

        def no_net(*a, **k):  # 共有 DB に残った Discord / Slack の設定で、外へ送らない
            raise urllib.error.URLError("blocked in test")

        monkeypatch.setattr(notify.urllib.request, "urlopen", no_net)
        r = c.post(f"/api/notifications/groups/{gid}/test", headers=admin)
        assert r.status_code == 200 and r.json()["results"]["teams"].startswith("HTTP 500")
        assert "SIGEXAMPLE" not in r.text and "WFIDEXAMPLE" not in r.text

        async def run():
            async with AsyncSessionLocal() as db:
                return await notify.notify_system(db, "テスト", "本文")
        asyncio.run(run())
        grp = next(x for x in c.get("/api/notifications/groups", headers=admin).json() if x["id"] == gid)
        err = grp["notification"]["last_error"] or ""
        assert err.startswith("Teams: HTTP 500") and "SIGEXAMPLE" not in err and "powerplatform" not in err
        acts = json.dumps(c.get("/api/activity/logs", params={"event": "notify.failed"}, headers=admin).json()["items"],
                          ensure_ascii=False)
        assert "Teams への" in acts
        assert "SIGEXAMPLE" not in acts and "WFIDEXAMPLE" not in acts
        # プレビューも伏せ字
        pv = c.get("/api/notifications/preview", params={"event": "change"}, headers=admin)
        assert any(p["kind"] == "teams" for p in pv.json()) and "SIGEXAMPLE" not in pv.text
    finally:
        c.delete(f"/api/notifications/groups/{gid}", headers=admin)
        for u in (a, b):
            _drop_user(c, admin, u)


def test_teams_payload_for_every_event(ctx, sent):
    """全てのイベント（変更・違反・失敗・機器情報・基準のずれ・保存し忘れ・Ping・システム・認証情報プロファイル）で Teams の本文ができる"""
    c, admin = ctx["c"], ctx["admin"]
    u = _new_user(c, admin)
    hook = teams_url(uid())
    r = c.put("/api/notifications/me", json={
        "mode": "custom", "teams_webhook": hook, "all_devices": True, "on_change": True, "on_violation": True,
        "on_failure": True, "on_system": True, "on_inventory": True, "on_ping": True, "on_drift": True,
        "on_unsaved": True}, headers=u["h"])
    assert r.status_code == 200, r.text
    devs = [c.post("/api/devices/", json=dict(name=f"tm-{uid()} {LINKS}", hostname=f"192.0.2.{i}", platform="cisco_ios",
                                              username="u", password="p"), headers=admin).json() for i in (11, 12)]
    d1, d2 = devs

    def mine():
        out = [p for k, url, p in sent if url == hook and k == "teams"]
        sent.clear()
        return out

    async def run():
        res, got = {}, {}

        def step(name, r):
            res[name] = r
            got[name] = mine()  # 直前の送信のうち、このユーザー（Teams）への分

        async with AsyncSessionLocal() as db:
            step("change", await notify.notify_change(db, d1["id"], "a" * 40, 2, 1, "manual"))
            step("v1", await notify.notify_violations(db, [(d1["id"], [(f"HTTP禁止 {LINKS}", "high")])]))
            step("v2", await notify.notify_violations(db, [(d1["id"], [(f"HTTP禁止 {LINKS}", "high")]),
                                                           (d2["id"], [("NTP必須", "low"), ("SSH", "medium")])]))
            step("f1", await notify.notify_failure(db, d1["id"], f"認証に失敗しました {LINKS}", "manual"))
            step("f2", await notify.notify_failures(db, [
                {"device_id": d1["id"], "error": f"timeout {LINKS}", "triggered_by": "schedule", "ref": None, "at": 1},
                {"device_id": d2["id"], "error": "認証に失敗しました", "triggered_by": "schedule", "ref": None, "at": 2}]))
            step("inv", await notify.notify_inventory(db, d1["id"], [["os_version", "15.1", LINKS],
                                                                     ["serial_number", "AAA", "BBB"]]))
            step("drift", await notify.notify_drift(db, d1["id"], 3, 2, "b" * 40, "c" * 40))
            step("unsaved", await notify.notify_unsaved(db, d1["id"], 1, 0))
            step("ping", await notify.notify_ping(
                db, [{"name": f"core-sw01 {LINKS}", "address": "192.0.2.1", "group_id": None, "since": "2026-11-25T01:00:00"}],
                [{"name": "core-sw02", "address": "192.0.2.2", "group_id": None}]))
            step("system", await notify.notify_system(db, "worker が止まっています", f"本文\n2行目 {LINKS}", [("止まった時刻", "10:00")]))
        step("profile", await notify.notify_profile_owner(u["id"], "プロファイルを編集", f"本文 {LINKS}", [("操作者", f"ops {LINKS}")]))
        return res, got

    try:
        res, got = asyncio.run(run())
        assert all(v["failed"] == 0 for v in res.values()), res
        cards = {}
        for name, payloads in got.items():
            assert len(payloads) == 1, (name, len(payloads))  # 宛先は 1 つ。1 イベントにつき 1 通
            cards[name] = assert_adaptive_card(payloads[0])
        titles = {k: v["body"][0]["text"] for k, v in cards.items()}
        assert titles["change"].startswith("コンフィグ変更:") and titles["v1"].startswith("コンプライアンス違反: tm-")
        assert titles["v2"] == "コンプライアンス違反: 2 台" and titles["f1"].startswith("収集失敗: tm-")
        assert titles["f2"] == "収集失敗: 2 台" and titles["inv"].startswith("機器の交換？:")
        assert titles["drift"].startswith("基準からのずれ:") and titles["unsaved"].startswith("保存し忘れ:")
        assert titles["ping"].startswith("Ping監視: 応答なし 1 件・復旧 1 件") and titles["system"] == "worker が止まっています"
        assert cards["system"]["body"][-1]["text"].startswith("本文\n\n2行目 ")
        assert "🔴 core-sw01" in cards["ping"]["body"][-1]["text"]
        assert titles["profile"] == "プロファイルを編集" and cards["profile"]["body"][1]["facts"][0]["value"].startswith("ops ")
        # 利用者・機器が決められる文字列に Markdown のリンクを入れても、どのイベントでもリンクの構文は残らない
        for name, payloads in got.items():
            assert "](" not in json.dumps(payloads, ensure_ascii=False), name
        assert "再ログインはこちら" in json.dumps(cards, ensure_ascii=False)
        # 差分の中身・パスワードは載せない
        assert "ip http" not in json.dumps(cards)
    finally:
        for d in devs:
            c.delete(f"/api/devices/{d['id']}", headers=admin)
        _drop_user(c, admin, u)


def test_teams_text_breaks_markdown_links():
    t = notify._teams_text
    for src in (LINKS, "![x](https://evil.example/a.png)", "[[a](u1)](u2)", "[a](b)[c](d)[e](f)", "](](](", "]]((", "a](b",
                "[a](\n)", "[x]\n(https://evil.example)"):
        assert "](" not in t(src), src
    assert t(LINKS) == "[再ログインはこちら]\u200b(https://evil.example/login)"  # 見た目の文字は残る
    assert t("a\nb") == "a\n\nb"
    # カードの題・項目の名前と値・本文のすべて
    card = notify._message("teams", LINKS, [(LINKS, LINKS)], "https://ncm.example.local/x", "開く", 0xEF4444, LINKS)
    assert "](" not in json.dumps(card, ensure_ascii=False)
    assert card["attachments"][0]["content"]["actions"][0]["url"] == "https://ncm.example.local/x"  # 正当なリンクは残る


def test_teams_card_is_shrunk_when_too_big():
    facts = [(f"項目{i}", "あ" * 1000) for i in range(80)]
    payload = notify._message("teams", "題", facts, "https://ncm.example.local/x", "開く", 0xEF4444, "い" * 4000)
    assert notify._teams_size(payload) <= notify.TEAMS_MAX_BYTES
    card = assert_adaptive_card(payload, "題")
    assert card["body"][0]["text"] == "題" and card["actions"]  # 題とリンクは残る
    small = notify._message("teams", "題", [("a", "b")], None, "", None, "本文")
    assert notify._teams_size(small) < 1000 and small["attachments"][0]["content"]["body"][2]["text"] == "本文"


# ---------------------------------------------------------------- Discord・Slack: 偽のリンク・メンションの無害化
HOSTILE = ("[再ログイン](https://evil.example/login) ![x](https://evil.example/a.png) <!channel> <!here> <@U123ABC|x> "
           "<https://evil.example|link> @everyone @here <@123456789012345678> &amp; & < >")
NAME_HOSTILE = "<!channel> @everyone [x](https://evil.example/l) <@U1|x> &amp; &"  # 名前の長さの上限（128）に収まる形
LEGIT_LINK = re.compile(r"\[[^\]\n]*\]\(https://ncm\.example\.local[^)]*\)")  # 自分で組み立てる正当なリンク（Discord）
LEGIT_SLACK_LINK = re.compile(r"<https://ncm\.example\.local[^>|]*\|[^>]*>")  # 同（Slack）


def test_break_md_and_slack_escape():
    assert notify.break_md(LINKS) == "[再ログインはこちら]​(https://evil.example/login)"
    assert notify.break_md("a\nb") == "a\nb" and notify.break_md("") == ""
    for src in ("](](](", "]]((", "[[a](u1)](u2)"):
        assert "](" not in notify.break_md(src), src
    assert notify.break_md(notify.break_md(LINKS)) == notify.break_md(LINKS)  # 2 回かけても同じ
    esc = notify.slack_escape
    assert esc("<!channel> <@U1|x> <https://e.example|l>") == "&lt;!channel&gt; &lt;@U1|x&gt; &lt;https://e.example|l&gt;"
    assert esc("a & b") == "a &amp; b"
    assert esc("&amp;") == "&amp;amp;"  # 入力にすでにある &amp; は、そのままの文字として見えるように置き換える
    assert esc("&lt;") == "&amp;lt;" and esc("あ→い ＜ ＞") == "あ→い ＜ ＞"
    # 定期レポートも同じ関数を使う
    from app.services import report
    assert report.notify.slack_escape is notify.slack_escape and not hasattr(report, "_break_md")


def test_discord_and_slack_payload_shape_is_unchanged_for_plain_text(monkeypatch):
    """利用者が決められる文字列に特別な文字が無ければ、見た目（文言・リンク・絵文字・改行）はこれまでどおり"""
    monkeypatch.setattr(notify.settings, "PUBLIC_URL", "https://ncm.example.local")
    d = notify._message("discord", "収集失敗: Core-SW01", [("機器", "Core-SW01（192.0.2.1）"), ("エラー", "timeout")],
                        "https://ncm.example.local/activity", "アクティビティを画面で確認", 0xFB923C, "本文\n2行目")
    e = d["embeds"][0]
    assert e["title"] == "収集失敗: Core-SW01" and e["description"] == "本文\n2行目\n[アクティビティを画面で確認](https://ncm.example.local/activity)"
    assert e["fields"] == [{"name": "機器", "value": "Core-SW01（192.0.2.1）", "inline": True},
                           {"name": "エラー", "value": "timeout", "inline": True}]
    assert d["allowed_mentions"] == {"parse": []} and d["username"] == "NetConfig Manager"
    s = notify._message("slack", "収集失敗: Core-SW01", [("機器", "Core-SW01（192.0.2.1）")],
                        "https://ncm.example.local/activity?device=1&level=error", "開く", 0xFB923C, "🔴 a\n🟢 b")
    assert s == {"text": "*収集失敗: Core-SW01*\n🔴 a\n🟢 b\n機器: Core-SW01（192.0.2.1）\n"
                         "<https://ncm.example.local/activity?device=1&level=error|開く>"}  # 正当なリンクの & は置き換えない
    ev = notify.ChangeEvent("id1", "Core-SW01", "192.0.2.1", "本社", 3, 1, "manual", "a" * 40, notify.utcnow())
    dd, ss = notify.build_payload("discord", ev), notify.build_payload("slack", ev)
    assert dd["allowed_mentions"] == {"parse": []} and dd["embeds"][0]["title"] == "コンフィグ変更: Core-SW01"
    assert ss["text"].startswith("*コンフィグ変更: Core-SW01*\n機器: Core-SW01（192.0.2.1）\nグループ: 本社\n変更: +3 行 / -1 行\n")


def test_every_discord_message_carries_allowed_mentions():
    for payload in (notify.build_test_payload("discord", "admin"),
                    notify._message("discord", "題", [], None, "", 0, "本文")):
        assert payload["allowed_mentions"] == {"parse": []}
    # 本文（content）のテスト通知: 名前に入れたメンション・リンクは働かない
    t = notify.build_test_payload("discord", f"@everyone {LINKS}")
    assert "](" not in t["content"] and "@everyone" in t["content"]  # 文字は残り、通知は飛ばない（allowed_mentions）
    assert notify.build_test_payload("slack", "<!channel>")["text"].count("<") == 0
    assert "](" not in json.dumps(notify.build_test_payload("teams", LINKS), ensure_ascii=False)


def test_email_escapes_html():
    """メールは、機器名などに HTML・リンクが入っても、HTML では文字として出る（既存の html.escape を確かめる）"""
    from app.services import mail
    msg = mail.build_message(mail.MailConfig(from_address="ncm@example.test"), "ops@example.test",
                             f"違反: {HOSTILE}", [(HOSTILE, HOSTILE)], HOSTILE, "https://ncm.example.local/x?a=1&b=2", "開く")
    html_part = msg.get_body(("html",)).get_content()
    assert "<!channel>" not in html_part and "<https://evil" not in html_part and "<@U123ABC" not in html_part
    assert html_part.count("<a ") == 1 and 'href="https://ncm.example.local/x?a=1&amp;b=2"' in html_part
    assert "&lt;!channel&gt;" in html_part


def test_every_event_neutralizes_links_and_mentions_for_discord_and_slack(ctx, monkeypatch):
    """全てのイベントで、利用者・機器が決められる文字列（機器名・グループ名・ルール名・Ping の名前・機器情報の値・エラー文・
    プロファイル名・利用者名）のリンクの構文・メンションは、Discord・Slack の本文で働かない。自分で組み立てるリンクは残る"""
    c, admin = ctx["c"], ctx["admin"]
    monkeypatch.setattr(notify.settings, "PUBLIC_URL", "https://ncm.example.local")
    got: list[tuple[str, dict]] = []

    def fake_send(kind, url, payload, cfg=None):
        got.append((kind, payload))
        return None

    monkeypatch.setattr(notify, "_send", fake_send)
    u = _new_user(c, admin)
    hooks = {"discord": D.format(777, uid()), "slack": S.format(7, uid())}
    r = c.put("/api/notifications/me", json={
        "mode": "custom", "discord_webhook": hooks["discord"], "slack_webhook": hooks["slack"], "all_devices": True,
        "on_change": True, "on_violation": True, "on_failure": True, "on_system": True, "on_inventory": True,
        "on_ping": True, "on_drift": True, "on_unsaved": True}, headers=u["h"])
    assert r.status_code == 200, r.text
    grp = c.post("/api/device-groups/", json={"name": f"g-{uid()} {NAME_HOSTILE}"}, headers=admin).json()
    devs = [c.post("/api/devices/", json=dict(name=f"tm-{uid()} {NAME_HOSTILE}", hostname=f"192.0.2.{i}", platform="cisco_ios",
                                              username="u", password="p", group_id=grp["id"] if i == 21 else None),
                   headers=admin).json() for i in (21, 22)]
    d1, d2 = devs
    assert d1.get("id") and d2.get("id"), devs

    async def run():
        out = {}

        def step(name):
            out[name] = [(k, p) for k, p in got if k in ("discord", "slack")]
            got.clear()

        async with AsyncSessionLocal() as db:
            await notify.notify_change(db, d1["id"], "a" * 40, 2, 1, "manual"); step("change")
            await notify.notify_violations(db, [(d1["id"], [(f"HTTP禁止 {HOSTILE}", "high")])]); step("v1")
            await notify.notify_violations(db, [(d1["id"], [(f"HTTP禁止 {HOSTILE}", "high")]),
                                                (d2["id"], [(f"NTP必須 {HOSTILE}", "low"), ("SSH", "medium")])]); step("v2")
            await notify.notify_failure(db, d1["id"], f"認証に失敗しました {HOSTILE}", "manual"); step("f1")
            await notify.notify_failures(db, [
                {"device_id": d1["id"], "error": f"timeout {HOSTILE}", "triggered_by": "schedule", "ref": None, "at": 1},
                {"device_id": d2["id"], "error": f"認証に失敗しました {HOSTILE}", "triggered_by": "schedule", "ref": None, "at": 2}])
            step("f2")
            await notify.notify_inventory(db, d1["id"], [["os_version", "15.1", HOSTILE], ["serial_number", HOSTILE, "BBB"]])
            step("inv")
            await notify.notify_inventory(db, d1["id"], [["os_version", "15.1", HOSTILE]]); step("inv1")
            await notify.notify_drift(db, d1["id"], 3, 2, "b" * 40, "c" * 40); step("drift")
            await notify.notify_unsaved(db, d1["id"], 1, 0); step("unsaved")
            await notify.notify_ping(
                db, [{"name": f"core-sw01 {HOSTILE}", "address": f"192.0.2.1 {HOSTILE}", "group_id": None,
                      "since": "2026-11-25T01:00:00"}],
                [{"name": f"core-sw02 {HOSTILE}", "address": "192.0.2.2", "group_id": None}]); step("ping")
            await notify.notify_system(db, f"worker が止まっています {HOSTILE}", f"本文\n2行目 {HOSTILE}",
                                       [("機器", HOSTILE)]); step("system")
        await notify.notify_profile_owner(u["id"], f"プロファイル「{HOSTILE}」を編集", f"{HOSTILE} さんが編集",
                                          [("操作した人", HOSTILE), ("機器", HOSTILE)]); step("profile")
        return out

    try:
        out = asyncio.run(run())
        for name, items in out.items():
            kinds = sorted(k for k, _ in items)
            assert kinds == ["discord", "slack"], (name, kinds)  # どのイベントも、Discord・Slack に 1 通ずつ
            for kind, payload in items:
                text = json.dumps(payload, ensure_ascii=False)
                if kind == "discord":
                    assert payload["allowed_mentions"] == {"parse": []}, name
                    assert "](" not in LEGIT_LINK.sub("", text), (name, "リンクの構文が残っている")
                else:
                    body = payload["text"]
                    rest = LEGIT_SLACK_LINK.sub("", body)
                    assert "<" not in rest and ">" not in rest, (name, rest)  # <url|text>・<!channel>・<@U…> が働かない
        # 文字そのものは見える（Slack: & は &amp; として送る = 画面には & と見える）
        slack = {n: next(p for k, p in items if k == "slack")["text"] for n, items in out.items()}
        assert "&lt;!channel&gt;" in slack["change"] and "&amp;amp;" in slack["change"]
        assert "&lt;!channel&gt;" in slack["f1"] and "&lt;!channel&gt;" in slack["ping"] and "&lt;!channel&gt;" in slack["profile"]
        assert "https://evil.example/login" in slack["inv"]  # リンクの URL の文字は残る（働かないだけ）
        discord = {n: next(p for k, p in items if k == "discord") for n, items in out.items()}
        flat = json.dumps(discord["f1"], ensure_ascii=False)
        assert "[再ログイン]​(https://evil.example/login)" in flat  # 見た目の文字は残り、リンクにならない
        # 自分で組み立てる正当なリンクは、どのイベントでも壊れていない
        for name, p in discord.items():
            assert "](https://ncm.example.local" in p["embeds"][0]["description"], name
            assert p["embeds"][0]["url"].startswith("https://ncm.example.local"), name
        for name, text in slack.items():
            assert LEGIT_SLACK_LINK.search(text), name
    finally:
        for d in devs:
            c.delete(f"/api/devices/{d['id']}", headers=admin)
        c.delete(f"/api/device-groups/{grp['id']}", headers=admin)
        c.put("/api/notifications/me", json={"mode": "inherit", "discord_webhook": "", "slack_webhook": ""}, headers=u["h"])
        c.delete(f"/api/users/{u['id']}", headers=admin)


# ---------------------------------------------------------------- 違反の通知は、保存（commit）が成功したあとにだけ投入する
HTTP_OFF = "hostname X\n"
HTTP_ON = "hostname X\nip http server\n"


@pytest.fixture
def viol(ctx):
    """違反の通知を受ける利用者と、違反しうる機器 2 台・ルール 1 つ（終わったら片付ける）"""
    c, admin = ctx["c"], ctx["admin"]
    u = _new_user(c, admin)
    r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": D.format(888, uid()), "all_devices": True,
                                              "on_change": False, "on_violation": True}, headers=u["h"])
    assert r.status_code == 200, r.text
    devs = []
    for i in (31, 32):
        d = c.post("/api/devices/", json=dict(name=f"cm-{uid()}", hostname=f"192.0.2.{i}", platform="arista_eos",
                                              username="u", password="p"), headers=admin).json()
        cs.save_config(d["id"], HTTP_OFF, "test")
        devs.append(d)
    with mock.patch.object(worker.send_violation_notification, "delay") as dl:
        rule = c.post("/api/compliance/rules", json={"name": f"HTTP禁止-{uid()}", "match_type": "contains", "expect": "absent",
                                                     "pattern": "ip http server", "severity": "high",
                                                     "platforms": ["arista_eos"]}, headers=admin).json()
        # 全台が合格 → 通知しない（共有の DB に、ほかのテストの機器・ルールが残っていても、このルールの通知は出ない）
        assert not [1 for c in dl.call_args_list for i in c.args[0] if any(r[0] == rule["name"] for r in i[1])]
        dl.reset_mock()
        yield {"c": c, "admin": admin, "devs": devs, "rule": rule, "delay": dl, "user": u}
    c.delete(f"/api/compliance/rules/{rule['id']}", headers=admin)
    for d in devs:
        c.delete(f"/api/devices/{d['id']}", headers=admin)
    _drop_user(c, admin, u)
    c.put("/api/notifications/me", json={"mode": "inherit", "discord_webhook": ""}, headers=u["h"])


def _make_pass(v):
    """全台を合格の状態にする（再検査のあと、通知の記録も消す）"""
    from app.services import compliance as svc

    for d in v["devs"]:
        cs.save_config(d["id"], HTTP_OFF, "test")

    async def run():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d["id"] for d in v["devs"]], rule_ids=[v["rule"]["id"]])
            await db.commit()
    asyncio.run(run())
    v["delay"].reset_mock()


def _mine(v):
    """投入された通知のうち、このテストの機器・ルールの分（機器の ID の並び）。共有の DB のほかの機器・ルールの分は数えない"""
    ids = {d["id"] for d in v["devs"]}
    return sorted(i[0] for c in v["delay"].call_args_list for i in c.args[0]
                  if i[0] in ids and any(r[0] == v["rule"]["name"] for r in i[1]))


def _ids(*devs):
    return sorted(d["id"] for d in devs)


def _notice_of(v, *devs):
    return [[d["id"], [(v["rule"]["name"], "high")]] for d in devs]  # ルールは (名前, 重要度) の組のまま渡される（従来どおり）


def test_violation_notice_is_enqueued_only_after_commit(viol):
    """通知は commit の成功のあとに 1 回だけ投入される（run_checks の中・commit の前には投入しない）。内容は従来どおり"""
    from app.services import compliance as svc

    v = viol
    d1, d2 = v["devs"]
    cs.save_config(d1["id"], HTTP_ON, "test")
    cs.save_config(d2["id"], HTTP_ON, "test")
    dl = v["delay"]

    async def run():
        async with AsyncSessionLocal() as db:
            r = await svc.run_checks(db, device_ids=[d1["id"], d2["id"]], rule_ids=[v["rule"]["id"]], actor="admin", ref="ref-1")
            assert r["new_violations"] == 2 and "notices" not in r  # 戻り値の形は変わらない
            assert not dl.called  # commit の前は、Redis へ何も送らない（アドバイザリロックを持っている間も）
            await db.commit()
            return r
    asyncio.run(run())
    assert dl.call_count == 1  # 2 台でも、run_checks 1 回につき 1 件（通知先ごとのまとめは notify_violations が行う）
    items, ref = dl.call_args.args
    assert sorted(items) == sorted(_notice_of(v, d1, d2)) and ref == "ref-1"

    # すでに違反のものは、再検査しても通知しない
    dl.reset_mock()

    async def again():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            await db.commit()
    asyncio.run(again())
    assert not dl.called


def test_violation_notice_is_dropped_on_rollback_or_failed_commit(viol):
    from sqlalchemy.exc import IntegrityError

    from app.models.device import Device
    from app.services import compliance as svc

    v = viol
    d1 = v["devs"][0]
    dl = v["delay"]

    async def rollback_case():
        cs.save_config(d1["id"], HTTP_ON, "test")
        async with AsyncSessionLocal() as db:
            r = await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            assert r["new_violations"] == 1
            await db.rollback()  # 呼び出し側の例外処理
            await db.commit()  # 同じセッションで、あとから別の commit をしても、投入されない
        async with AsyncSessionLocal() as db:  # 結果も保存されていない（まだ合格のまま）
            await db.commit()
    asyncio.run(rollback_case())
    assert not dl.called

    async def failed_commit_case():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            # 同じ名前の機器を足して、commit を一意制約の違反で失敗させる
            db.add(Device(name=d1["name"], hostname="192.0.2.99", platform="cisco_ios", username="u"))
            with pytest.raises(IntegrityError):
                await db.commit()
            await db.rollback()
            await db.commit()
    asyncio.run(failed_commit_case())
    assert not dl.called

    async def exception_case():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            raise_after = RuntimeError("呼び出し側の例外")
        raise raise_after  # セッションを commit せずに閉じた
    with pytest.raises(RuntimeError):
        asyncio.run(exception_case())
    assert not dl.called

    # 保存されなかった違反は、次の再検査で「新しい違反」として通知される（通知が失われたままにならない）
    async def retry():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            await db.commit()
    asyncio.run(retry())
    assert dl.call_count == 1 and dl.call_args.args[0] == _notice_of(v, d1)


def test_violation_notice_is_not_enqueued_by_commit_after_close_and_reuse(viol):
    """close() で捨てたセッションを使い回して commit しても、古い通知は投入されない"""
    from app.services import compliance as svc

    v = viol
    d1 = v["devs"][0]
    cs.save_config(d1["id"], HTTP_ON, "test")

    async def run():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            await db.close()
            await db.commit()
    asyncio.run(run())
    assert not v["delay"].called


def test_violation_notice_waits_for_the_outer_transaction_not_a_savepoint(viol):
    from app.services import compliance as svc

    v = viol
    d1, d2 = v["devs"]
    dl = v["delay"]
    cs.save_config(d1["id"], HTTP_ON, "test")
    cs.save_config(d2["id"], HTTP_ON, "test")

    async def run():
        async with AsyncSessionLocal() as db:
            async with db.begin_nested():
                await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            assert not dl.called  # SAVEPOINT を解放しただけでは投入しない
            await svc.run_checks(db, device_ids=[d2["id"]], rule_ids=[v["rule"]["id"]])  # 同じトランザクションで 2 回目
            await db.commit()
    asyncio.run(run())
    assert dl.call_count == 2  # run_checks ごとに 1 件（従来と同じ件数）
    assert sorted(c.args[0][0][0] for c in dl.call_args_list) == sorted([d1["id"], d2["id"]])


def test_no_notice_when_nobody_wants_violation(viol, monkeypatch):
    """通知する設定が 1 つも無ければ、これまでどおり投入しない"""
    from app.services import compliance as svc
    from app.services import notify as n

    v = viol
    d1 = v["devs"][0]
    cs.save_config(d1["id"], HTTP_ON, "test")

    async def no(db, event):
        return False
    monkeypatch.setattr(n, "wants_any", no)

    async def run():
        async with AsyncSessionLocal() as db:
            await svc.run_checks(db, device_ids=[d1["id"]], rule_ids=[v["rule"]["id"]])
            await db.commit()
    asyncio.run(run())
    assert not v["delay"].called


def _fail_commit_with_notice(monkeypatch):
    """違反の通知を積んだセッションの commit を失敗させる（保存に失敗した状況）"""
    from sqlalchemy.ext.asyncio import AsyncSession

    real = AsyncSession.commit

    async def commit(self):
        if self.sync_session.info.get("compliance_pending_notices"):
            raise RuntimeError("commit の失敗")
        return await real(self)
    monkeypatch.setattr(AsyncSession, "commit", commit)


def test_api_paths_enqueue_after_commit_and_not_when_commit_fails(viol, monkeypatch):
    """API の呼び出し元（全機器の再検査・ルールの変更・例外の登録と削除）: commit のあとに投入し、commit に失敗したら投入しない"""
    c, admin, dl = viol["c"], viol["admin"], viol["delay"]
    d1, d2 = viol["devs"]
    rule = viol["rule"]
    cs.save_config(d1["id"], HTTP_ON, "test")
    cs.save_config(d2["id"], HTTP_ON, "test")

    # 1) POST /compliance/run が commit に失敗 → 通知なし（結果も保存されない）
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            c.post("/api/compliance/run", headers=admin)
    assert not _mine(viol)
    res = c.get("/api/compliance/results", params={"rule_id": rule["id"]}, headers=admin).json()
    assert {x["status"] for x in res} == {"pass"}

    # 2) 成功すれば、リクエストの中の commit のあとに 1 件
    assert c.post("/api/compliance/run", headers=admin).status_code == 200
    assert _mine(viol) == _ids(d1, d2)  # 2 台とも、1 回ずつ

    # 3) ルールの変更（PUT）: 一度合格に戻してから、パターンを変えて再び違反にする
    for d in (d1, d2):
        cs.save_config(d["id"], HTTP_OFF, "test")
    assert c.post("/api/compliance/run", headers=admin).status_code == 200
    dl.reset_mock()
    for d in (d1, d2):
        cs.save_config(d["id"], HTTP_ON, "test")
    body = {"name": rule["name"], "match_type": "contains", "expect": "absent", "pattern": "ip http server",
            "severity": "high", "platforms": ["arista_eos"], "description": "変更", "enabled": True}
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            c.put(f"/api/compliance/rules/{rule['id']}", json=body, headers=admin)
    assert not _mine(viol)
    r = c.put(f"/api/compliance/rules/{rule['id']}", json=body, headers=admin)
    assert r.status_code == 200, r.text
    assert _mine(viol) == _ids(d1, d2)

    # 4) 例外の削除: 除外が外れて違反に戻る → commit のあとに通知
    ex = c.post("/api/compliance/exceptions", json={"rule_id": rule["id"], "device_id": d1["id"], "reason": "更改予定"},
                headers=admin)
    assert ex.status_code == 201, ex.text
    dl.reset_mock()
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            c.delete(f"/api/compliance/exceptions/{ex.json()['id']}", headers=admin)
    assert not _mine(viol)  # 例外の削除そのものは先に保存済み。再検査の保存に失敗したので、結果は「除外」のまま・通知なし
    res = c.get("/api/compliance/results", params={"rule_id": rule["id"], "device_id": d1["id"]}, headers=admin).json()
    assert [x["status"] for x in res] == ["exempt"]
    # 次の再検査で違反に戻り、そのとき初めて通知される（通知が失われたままにならない）
    assert c.post("/api/compliance/run", headers=admin).status_code == 200
    assert _mine(viol) == _ids(d1)
    dl.reset_mock()
    # 例外の登録（POST）は、除外になる → 通知なし
    ex2 = c.post("/api/compliance/exceptions", json={"rule_id": rule["id"], "device_id": d1["id"], "reason": "更改予定"},
                 headers=admin)
    assert ex2.status_code == 201 and not _mine(viol)
    assert c.delete(f"/api/compliance/exceptions/{ex2.json()['id']}", headers=admin).status_code == 204
    assert _mine(viol) == _ids(d1)  # 削除の再検査 → 違反に戻る → commit のあとに通知


def test_worker_paths_enqueue_after_commit_and_recheck_expired(viol, monkeypatch):
    """worker の呼び出し元（収集後の検査・スケジュールの検査・期限切れの例外の再検査）も、commit のあとにだけ投入する"""
    from datetime import timedelta

    from app.core.timeutil import utcnow
    from app.models.compliance import ComplianceException
    from app.services import compliance as svc

    c, admin, dl, rule = viol["c"], viol["admin"], viol["delay"], viol["rule"]
    d1, d2 = viol["devs"]

    # 収集後の検査（_check_compliance）
    cs.save_config(d1["id"], HTTP_ON, "test")
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            asyncio.run(worker._check_compliance(d1["id"], "admin", "ref-w1"))
    assert not _mine(viol)
    asyncio.run(worker._check_compliance(d1["id"], "admin", "ref-w1"))
    assert _mine(viol) == _ids(d1) and dl.call_args.args[1] == "ref-w1"

    # スケジュールの検査（_scheduled_compliance）
    _make_pass(viol)
    cs.save_config(d2["id"], HTTP_ON, "test")
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            asyncio.run(worker._scheduled_compliance([d1["id"], d2["id"]], "schedule:x", "ref-w2", ""))
    assert not _mine(viol)
    res = asyncio.run(worker._scheduled_compliance([d1["id"], d2["id"]], "schedule:x", "ref-w2", ""))
    assert "new_violations" in res and "notices" not in res  # 活動記録（detail）に入る戻り値の形は従来どおり
    assert _mine(viol) == _ids(d2) and dl.call_args.args[1] == "ref-w2"

    # 期限切れの例外の再検査（recheck_expired_exceptions）: 例外が切れて違反に戻る
    _make_pass(viol)
    cs.save_config(d1["id"], HTTP_ON, "test")
    ex = c.post("/api/compliance/exceptions", json={"rule_id": rule["id"], "device_id": d1["id"], "reason": "更改予定"},
                headers=admin).json()
    assert not _mine(viol)  # 例外で除外 → 違反として通知しない

    async def expire():
        async with AsyncSessionLocal() as db:
            x = await db.get(ComplianceException, ex["id"])
            x.expires_at = utcnow() - timedelta(minutes=1)
            await db.commit()
    asyncio.run(expire())

    async def recheck():
        async with AsyncSessionLocal() as db:
            return await svc.recheck_expired_exceptions(db)
    with monkeypatch.context() as m:
        _fail_commit_with_notice(m)
        with pytest.raises(RuntimeError):
            asyncio.run(recheck())
    assert not _mine(viol)  # 再検査の commit に失敗 → 通知なし
    c.delete(f"/api/compliance/exceptions/{ex['id']}", headers=admin)

    # 成功する場合（別の例外で）: ルールごとの commit のあとに 1 件
    _make_pass(viol)
    cs.save_config(d2["id"], HTTP_ON, "test")
    ex2 = c.post("/api/compliance/exceptions", json={"rule_id": rule["id"], "device_id": d2["id"], "reason": "更改予定"},
                 headers=admin).json()
    assert not _mine(viol)
    ex = ex2
    asyncio.run(expire())
    assert asyncio.run(recheck()) == 1
    assert _mine(viol) == _ids(d2)
    c.delete(f"/api/compliance/exceptions/{ex2['id']}", headers=admin)
