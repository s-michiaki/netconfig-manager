"""世代（変更）へのコメント（作業内容のメモ）のテスト"""
import asyncio
import json
import sqlite3
from unittest import mock

import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.device import ConfigSnapshot
from app.services import config_service as cs


@pytest.fixture(scope="module")
def client():
    with (
        mock.patch("app.api.devices.collect_device_config"),
        mock.patch("app.api.devices.collect_all_devices"),
        TestClient(app) as c,
    ):
        yield c


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def env(client):
    admin = _login(client, "admin", "initial-pass-123")
    for name, role in [("cmt-op", "operator"), ("cmt-op2", "operator"), ("cmt-view", "viewer")]:
        r = client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        assert r.status_code == 201, r.text

    def dev(name):
        r = client.post("/api/devices/", json=dict(name=name, hostname="10.6.0.1", platform="cisco_ios", username="u", password="p"),
                        headers=admin)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    a, b = dev("cmt-sw1"), dev("cmt-sw2")
    a1 = cs.save_config(a, "hostname cmt-sw1\n", "manual").commit_hash
    a2 = cs.save_config(a, "hostname cmt-sw1\nvlan 99\n", "manual").commit_hash
    b1 = cs.save_config(b, "hostname cmt-sw2\n", "manual").commit_hash
    yield {
        "admin": admin,
        "op": _login(client, "cmt-op", "password-1234"),
        "op2": _login(client, "cmt-op2", "password-1234"),
        "viewer": _login(client, "cmt-view", "password-1234"),
        "a": a, "b": b, "a1": a1, "a2": a2, "b1": b1,
    }
    for did in (a, b):
        client.delete(f"/api/devices/{did}", headers=admin)


def _history(client, h, did):
    r = client.get(f"/api/configs/{did}/history", headers=h)
    assert r.status_code == 200, r.text
    return {c["full_hash"]: c for c in r.json()}


def _db_rows(did):
    con = sqlite3.connect(f"{TMP}/t.db")
    try:
        return con.execute("select commit_hash, body, created_by, updated_by from config_comments where device_id=?",
                           (did,)).fetchall()
    finally:
        con.close()


def test_permissions_are_exposed(client, env):
    assert "config:comment" in client.get("/api/auth/me", headers=env["op"]).json()["permissions"]
    assert "config:comment" not in client.get("/api/auth/me", headers=env["viewer"]).json()["permissions"]


def test_operator_writes_and_everyone_reads(client, env):
    did = env["a"]
    # 短縮ハッシュ（8 桁）で書いても、完全な 40 桁で保存する
    r = client.put(f"/api/configs/{did}/comments/{env['a2'][:8]}", json={"body": "  CHG-123 VLAN 99 を追加\n（夜間作業）  "},
                   headers=env["op"])
    assert r.status_code == 200, r.text
    assert r.json()["commit_hash"] == env["a2"] and r.json()["body"] == "CHG-123 VLAN 99 を追加\n（夜間作業）"
    assert _db_rows(did) == [(env["a2"], "CHG-123 VLAN 99 を追加\n（夜間作業）", "cmt-op", "cmt-op")]
    for role in ("viewer", "op", "admin"):
        h = _history(client, env[role], did)
        c = h[env["a2"]]["comment"]
        assert c["body"].startswith("CHG-123") and c["created_by"] == "cmt-op" and c["created_at"].endswith("+00:00")
        assert h[env["a1"]]["comment"] is None
    # 閲覧者は書けない・消せない
    assert client.put(f"/api/configs/{did}/comments/{env['a1']}", json={"body": "x"}, headers=env["viewer"]).status_code == 403
    assert client.delete(f"/api/configs/{did}/comments/{env['a2']}", headers=env["viewer"]).status_code == 403
    assert client.put(f"/api/configs/{did}/comments/{env['a1']}", json={"body": "x"}).status_code == 401


def test_input_and_target_checks(client, env):
    did, h = env["a"], env["op"]
    url = f"/api/configs/{did}/comments/{env['a1']}"
    assert client.put(url, json={"body": "   "}, headers=h).status_code == 422
    assert client.put(url, json={"body": "あ" * 1001}, headers=h).status_code == 422
    assert client.put(url, json={"body": "あ" * 1000}, headers=h).status_code == 200
    # 存在しない世代・他の機器の世代・形式の誤り・存在しない機器
    assert client.put(f"/api/configs/{did}/comments/{'0' * 40}", json={"body": "x"}, headers=h).status_code == 404
    assert client.put(f"/api/configs/{did}/comments/{env['b1']}", json={"body": "x"}, headers=h).status_code == 404
    assert client.put(f"/api/configs/{did}/comments/--output=x", json={"body": "x"}, headers=h).status_code in (404, 422)
    assert client.put(f"/api/configs/{did}/comments/zzzzzzzz", json={"body": "x"}, headers=h).status_code == 422
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.put(f"/api/configs/{missing}/comments/{env['a1']}", json={"body": "x"}, headers=h).status_code == 404
    assert client.delete(f"/api/configs/{did}/comments/{env['a1']}", headers=h).status_code == 204
    assert client.delete(f"/api/configs/{did}/comments/{env['a1']}", headers=h).status_code == 404


def test_edit_and_delete_only_by_author_or_admin(client, env):
    did = env["a"]
    url = f"/api/configs/{did}/comments/{env['a2']}"
    # 他のオペレーターは書き換え・削除できない
    r = client.put(url, json={"body": "上書き"}, headers=env["op2"])
    assert r.status_code == 403 and "本人か管理者" in r.json()["detail"]
    assert client.delete(url, headers=env["op2"]).status_code == 403
    # 本人は書き換えられる（1 件のまま、作成者は変わらない）
    r = client.put(url, json={"body": "CHG-123 VLAN 99 を追加"}, headers=env["op"])
    assert r.status_code == 200 and r.json()["created_by"] == "cmt-op" and r.json()["updated_by"] == "cmt-op"
    # 管理者は書き換えられる
    r = client.put(url, json={"body": "CHG-123 VLAN 99 を追加（確認済み）"}, headers=env["admin"])
    assert r.status_code == 200 and r.json()["created_by"] == "cmt-op" and r.json()["updated_by"] == "admin"
    assert len(_db_rows(did)) == 1
    assert client.delete(url, headers=env["admin"]).status_code == 204
    assert _history(client, env["viewer"], did)[env["a2"]]["comment"] is None


def test_audit_log(client, env):
    did = env["b"]
    url = f"/api/configs/{did}/comments/{env['b1']}"
    client.put(url, json={"body": "初回取得"}, headers=env["op"])
    client.put(url, json={"body": "初回取得（台帳登録）"}, headers=env["op"])
    client.delete(url, headers=env["op"])
    logs = client.get("/api/audit/logs", params={"action": "config.", "q": "cmt-sw2"}, headers=env["admin"]).json()["items"]
    by = [(x["action"], json.loads(x["detail"])) for x in logs if x["target_name"] == "cmt-sw2"]
    assert by[0] == ("config.comment_delete", {"commit": env["b1"], "before": "初回取得（台帳登録）", "created_by": "cmt-op"})
    assert by[1] == ("config.comment_set", {"commit": env["b1"], "created": False, "before": "初回取得",
                                            "after": "初回取得（台帳登録）"})
    assert by[2][1]["created"] is True and by[2][1]["before"] is None
    labels = client.get("/api/audit/actions", headers=env["admin"]).json()
    assert labels["config.comment_set"] == "コンフィグ変更へのコメント" and "config.comment_delete" in labels


def test_dashboard_shows_comment(client, env):
    did = env["a"]
    body = "CHG-200 アップリンクの冗長化\n" + "x" * 80

    async def snap():
        async with AsyncSessionLocal() as db:
            db.add(ConfigSnapshot(device_id=did, commit_hash=env["a2"], collected_at=utcnow(), lines_added=1,
                                  lines_removed=0, triggered_by="manual"))
            await db.commit()
    asyncio.run(snap())
    client.put(f"/api/configs/{did}/comments/{env['a2']}", json={"body": body}, headers=env["op"])
    for role in ("viewer", "admin"):
        recent = client.get("/api/dashboard", headers=env[role]).json()["changes"]["recent"]
        mine = next(x for x in recent if x["device_id"] == did)
        assert mine["comment"].startswith("CHG-200 アップリンクの冗長化 xxx") and mine["comment"].endswith("…")
        assert len(mine["comment"]) == 61 and mine["full_commit"] == env["a2"]


def test_device_delete_removes_comments(client, env):
    admin = env["admin"]
    r = client.post("/api/devices/", json=dict(name="cmt-del", hostname="10.6.0.9", platform="cisco_ios", username="u", password="p"),
                    headers=admin)
    did = r.json()["id"]
    c = cs.save_config(did, "hostname cmt-del\n", "manual").commit_hash
    assert client.put(f"/api/configs/{did}/comments/{c}", json={"body": "撤去予定"}, headers=env["op"]).status_code == 200
    assert client.delete(f"/api/devices/{did}", headers=admin).status_code == 204
    assert _db_rows(did) == []
