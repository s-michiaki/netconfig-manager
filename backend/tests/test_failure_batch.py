"""収集失敗の通知をまとめる（ネットワーク障害などで多数の機器が同時に失敗しても、通知先へは 1 通）"""
import json
import uuid
from unittest import mock

import fakeredis
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.main import app
from app.services import failure_batch, notify


def login(c, u, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


def uid():
    return uuid.uuid4().hex[:6]


HOOK = "https://discord.com/api/webhooks/{}/{}"


@pytest.fixture
def env(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: sent.append((kind, url, payload)))
    monkeypatch.setattr(settings, "NOTIFY_FAILURE_BATCH_SEC", 60)
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(worker, "_redis", lambda: r)
    scheduled = []  # 予約した送信（countdown）。テストでは予約だけ記録し、送信は直接呼ぶ
    monkeypatch.setattr(worker.flush_failure_notifications, "apply_async", lambda **kw: scheduled.append(kw))
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        t = uid()
        c.post("/api/users/", json={"username": f"fb-{t}", "password": "password-1234", "role": "viewer"}, headers=admin)
        h = login(c, f"fb-{t}", "password-1234")
        hook = HOOK.format(950, t)
        assert c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "on_change": False,
                                                     "on_failure": True, "on_system": False}, headers=h).status_code == 200
        devs = []
        for i in range(25):
            d = c.post("/api/devices/", json=dict(name=f"fb{i:02d}-{t}", hostname=f"10.77.0.{i + 1}", platform="cisco_ios",
                                                  username="u", password="p"), headers=admin).json()
            devs.append(d)
        yield {"c": c, "admin": admin, "sent": sent, "hook": hook, "r": r, "scheduled": scheduled, "devs": devs}
        for d in devs:
            c.delete(f"/api/devices/{d['id']}", headers=admin)


def mine(env):
    return [p for _, u, p in env["sent"] if u == env["hook"]]


def test_many_failures_become_one_notification(env):
    devs, r = env["devs"], env["r"]
    # 25 台が同時に失敗（理由は 2 種類）。まとめる時間の最初の 1 件だけが送信を予約する
    for i, d in enumerate(devs):
        err = "接続がタイムアウトしました (10.77.0.x:22)" if i < 20 else "認証に失敗しました\n詳しい理由: Bad password"
        worker.queue_failure_notification(d["id"], err, "schedule", "sch-1")
    assert len(env["scheduled"]) == 1 and env["scheduled"][0]["countdown"] == 60
    assert mine(env) == []  # まだ送らない
    # 予定の時刻になったら、通知先ごとに 1 通
    worker.flush_failure_notifications()
    out = mine(env)
    assert len(out) == 1
    emb = out[0]["embeds"][0]
    assert emb["title"] == "収集失敗: 25 台"
    text = json.dumps(emb, ensure_ascii=False)
    assert "接続がタイムアウトしました (10.77.0.x:22)（20 台）" in text and "認証に失敗しました（5 台）" in text
    assert "Bad password" not in emb["fields"][1]["value"]  # 理由の内訳は 1 行目だけ
    assert devs[0]["name"] in emb["description"] and "ほか 5 台" in emb["description"]  # 一覧は 20 台まで
    assert "スケジュール" in text
    # 取り出したので空。次の失敗は新しいまとめの始まりとして予約される
    assert r.llen(failure_batch.KEY_ITEMS) == 0 and not r.exists(failure_batch.KEY_WINDOW)
    worker.queue_failure_notification(devs[0]["id"], "x", "manual", None)
    assert len(env["scheduled"]) == 2
    # 送った記録は、1 回の一括収集の記録（ref）に結び付く
    acts = env["c"].get("/api/activity/logs", params={"ref": "sch-1", "event": "notify.sent"},
                        headers=env["admin"]).json()["items"]
    assert acts and "収集の失敗を通知しました" in acts[0]["message"]


def test_single_failure_keeps_detailed_message_and_duplicates(env):
    d = env["devs"][3]
    # 同じ機器が 2 回失敗したら、最後のものだけ。1 台なら機器ごとの詳しい通知（これまでと同じ形）
    worker.queue_failure_notification(d["id"], "古いエラー", "manual", "r1")
    worker.queue_failure_notification(d["id"], "認証に失敗しました", "manual", "r2")
    worker.flush_failure_notifications()
    out = mine(env)
    assert len(out) == 1 and out[0]["embeds"][0]["title"] == f"収集失敗: {d['name']}"
    text = json.dumps(out[0], ensure_ascii=False)
    assert "認証に失敗しました" in text and "古いエラー" not in text and "10.77.0.4" in text
    # 何もたまっていなければ何もしない
    assert worker.flush_failure_notifications() == {"sent": 0, "failed": 0}


def test_lost_flush_is_recovered_and_settings(env, monkeypatch):
    r, devs = env["r"], env["devs"]
    worker.queue_failure_notification(devs[0]["id"], "e", "manual", None)
    worker.queue_failure_notification(devs[1]["id"], "e", "manual", None)
    # 予約どおりなら、beat の定期実行（stale_only）は何もしない
    assert worker.flush_failure_notifications(stale_only=True) == {"sent": 0, "failed": 0} and mine(env) == []
    # 予約した送信が失われ、まとめる時間の印も期限切れになった → 定期実行が拾って送る
    r.delete(failure_batch.KEY_WINDOW)
    worker.flush_failure_notifications(stale_only=True)
    assert len(mine(env)) == 1 and mine(env)[0]["embeds"][0]["title"] == "収集失敗: 2 台"

    # 0 にすると、これまでどおり機器ごとにすぐ送る
    env["sent"].clear()
    monkeypatch.setattr(settings, "NOTIFY_FAILURE_BATCH_SEC", 0)
    with mock.patch.object(worker.send_failure_notification, "delay",
                           side_effect=lambda *a: worker.send_failure_notification.apply(args=a).get()):
        worker.queue_failure_notification(devs[2]["id"], "e2", "manual", None)
        worker.queue_failure_notification(devs[3]["id"], "e3", "manual", None)
    assert [p["embeds"][0]["title"] for p in mine(env)] == [f"収集失敗: {devs[2]['name']}", f"収集失敗: {devs[3]['name']}"]

    # Redis が使えないときも、通知は落とさない（すぐ機器ごとに送る）
    env["sent"].clear()
    monkeypatch.setattr(settings, "NOTIFY_FAILURE_BATCH_SEC", 60)
    broken = mock.Mock()
    broken.pipeline.side_effect = __import__("redis").ConnectionError()
    monkeypatch.setattr(worker, "_redis", lambda: broken)
    with mock.patch.object(worker.send_failure_notification, "delay",
                           side_effect=lambda *a: worker.send_failure_notification.apply(args=a).get()):
        worker.queue_failure_notification(devs[4]["id"], "e4", "manual", None)
    assert len(mine(env)) == 1


def test_destinations_by_device_group(env):
    """通知先ごとに、その通知先が受け取る機器（対象の機器グループ）の失敗だけをまとめる"""
    c, admin, devs = env["c"], env["admin"], env["devs"]
    t = uid()
    g = c.post("/api/device-groups/", json={"name": f"fb-g-{t}"}, headers=admin).json()
    c.post("/api/users/", json={"username": f"fbg-{t}", "password": "password-1234", "role": "viewer"}, headers=admin)
    h = login(c, f"fbg-{t}", "password-1234")
    hook2 = HOOK.format(951, t)
    assert c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook2, "on_change": False,
                                                 "on_failure": True, "on_system": False, "all_devices": False,
                                                 "device_group_ids": [g["id"]]},
                 headers=h).status_code == 200
    c.put(f"/api/devices/{devs[0]['id']}", json={"group_id": g["id"]}, headers=admin)
    for d in devs[:3]:
        worker.queue_failure_notification(d["id"], "e", "manual", None)
    worker.flush_failure_notifications()
    assert mine(env)[0]["embeds"][0]["title"] == "収集失敗: 3 台"  # すべての機器を受け取る通知先
    other = [p for _, u, p in env["sent"] if u == hook2]
    assert len(other) == 1 and other[0]["embeds"][0]["title"] == f"収集失敗: {devs[0]['name']}"  # グループの 1 台だけ
    c.put(f"/api/devices/{devs[0]['id']}", json={"group_id": None}, headers=admin)
    c.delete(f"/api/device-groups/{g['id']}", headers=admin)
