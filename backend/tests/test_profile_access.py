"""認証情報プロファイルの所有者と共有範囲（編集・使用できる人を限る）"""
import sqlite3
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from app.core import migrate
from app.core.config import settings
from app.main import app
from app.services import notify

PW = "password-1234"


def login(c, u, p=PW):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


def test_owner_and_group_access():
    with TestClient(app) as c, mock.patch.object(notify, "send_webhook", return_value=None) as sent:
        root = login(c, "admin", "initial-pass-123")
        t = uuid.uuid4().hex[:6]
        users = {}
        for key, role in (("owner", "admin"), ("mgr", "admin"), ("usr", "admin"), ("other", "admin"), ("op", "operator")):
            u = c.post("/api/users/", json={"username": f"pa-{key}-{t}", "password": PW, "role": role, "confirm_password": "initial-pass-123"}, headers=root).json()
            users[key] = {"id": u["id"], "name": u["username"], "h": login(c, u["username"])}
        owner, mgr, usr, other, op = (users[k]["h"] for k in ("owner", "mgr", "usr", "other", "op"))

        def group(name, member):
            return c.post("/api/notifications/groups", json={"name": f"pa-{name}-{t}", "member_ids": [users[member]["id"]]},
                          headers=root).json()["id"]

        g_manage, g_use = group("manage", "mgr"), group("use", "usr")
        # 所有者に、ほかの人の操作が通知されるようにする（個人の通知設定）
        r = c.put("/api/notifications/me", headers=owner, json={
            "mode": "custom", "slack_webhook": "https://hooks.slack.com/services/T000/B000/" + "x" * 24})
        assert r.status_code == 200, r.text

        # 登録した人が所有者。共有範囲は登録時にも指定できる（両方に入れたグループは管理を優先）
        r = c.post("/api/credential-profiles/", headers=owner, json={
            "name": f"pa-{t}", "username": "netops", "password": "Secret-1",
            "manage_group_ids": [g_manage], "use_group_ids": [g_use, g_manage]})
        assert r.status_code == 201, r.text
        p = r.json()
        url = f"/api/credential-profiles/{p['id']}"
        assert p["owner_name"] == users["owner"]["name"] and p["can_manage"] and p["can_use"]
        assert [g["id"] for g in p["manage_groups"]] == [g_manage] and [g["id"] for g in p["use_groups"]] == [g_use]
        assert c.post("/api/credential-profiles/", headers=owner, json={
            "name": f"pa2-{t}", "username": "u", "password": "x", "use_group_ids": ["nope"]}).status_code == 422

        def mine(h):
            x = next(x for x in c.get("/api/credential-profiles/", headers=h).json() if x["id"] == p["id"])
            return x["can_manage"], x["can_use"]

        # 見えるのは全員。できることは人によって違う（オペレーターは一覧だけで、どちらも不可）
        assert mine(mgr) == (True, True) and mine(usr) == (False, True) and mine(other) == (False, False)
        assert mine(op) == (False, False) and "Secret-1" not in c.get("/api/credential-profiles/", headers=op).text

        # 編集・削除: 所有者と管理グループだけ
        assert c.put(url, json={"description": "x"}, headers=other).status_code == 403
        assert c.put(url, json={"description": "x"}, headers=usr).status_code == 403
        assert c.delete(url, headers=usr).status_code == 403
        assert c.put(url, json={"use_group_ids": []}, headers=other).status_code == 403  # 自分で共有範囲を広げられない
        sent.reset_mock()
        assert c.put(url, json={"password": "Secret-2"}, headers=mgr).status_code == 200
        # 所有者以外が変えたので、所有者へ通知（秘密の値は載せない）
        assert sent.call_count == 1 and "Secret-2" not in str(sent.call_args) and users["mgr"]["name"] in str(sent.call_args)
        sent.reset_mock()
        assert c.put(url, json={"description": "自分で変更"}, headers=owner).status_code == 200
        assert sent.call_count == 0  # 自分の操作は通知しない

        # 機器への割り当て: 所有者・管理グループ・使用グループだけ
        def new_device(h, name, **kw):
            return c.post("/api/devices/", headers=h, json={"name": f"pa-{name}-{t}", "hostname": "10.9.9.1",
                                                            "platform": "cisco_ios", **kw})

        r = new_device(other, "x", credential_profile_id=p["id"])
        assert r.status_code == 403 and "使用できません" in r.json()["detail"]
        sent.reset_mock()
        r = new_device(usr, "a", credential_profile_id=p["id"])
        assert r.status_code == 201, r.text
        dev = r.json()
        assert sent.call_count == 1 and dev["name"] in str(sent.call_args)  # 所有者へ「割り当てられました」
        plain = new_device(other, "b", username="u", password="p").json()
        assert c.put(f"/api/devices/{plain['id']}", json={"credential_profile_id": p["id"]}, headers=other).status_code == 403

        # プロファイルを使う機器の接続先（ホスト・ポート・踏み台）を変えるのも、使用できる人だけ
        durl = f"/api/devices/{dev['id']}"
        assert c.put(durl, json={"hostname": "203.0.113.9"}, headers=other).status_code == 403
        assert c.put(durl, json={"port": 2222}, headers=other).status_code == 403
        assert c.put(durl, json={"description": "説明だけ", "hostname": "10.9.9.1"}, headers=other).status_code == 200  # 接続先は同じ
        sent.reset_mock()
        assert c.put(durl, json={"hostname": "10.9.9.2"}, headers=usr).status_code == 200
        assert sent.call_count == 1 and "接続先" in str(sent.call_args)
        # プロファイルを外して自分の認証情報にするのは、機器を編集できる人なら可（プロファイルの値は使われなくなる）
        assert c.put(durl, json={"credential_profile_id": None, "username": "u", "password": "p"}, headers=other).status_code == 200
        assert c.put(durl, json={"credential_profile_id": p["id"]}, headers=other).status_code == 403

        # CSV 取り込みでも、使用できないプロファイルの行はエラー
        csv = f"名前,ホスト / IP,機種,認証情報プロファイル,ユーザー名,パスワード\npa-csv-{t},10.9.9.3,cisco_ios,pa-{t},,\n"
        files = {"file": ("d.csv", csv.encode("utf-8"), "text/csv")}
        r = c.post("/api/devices/import", headers=other, files=files).json()
        assert r["error"] == 1 and "使用できません" in str(r["rows"][0])
        assert c.post("/api/devices/import", headers=usr, files=files).json()["ok"] == 1

        # 引き継ぎ: 管理者なら実行できる（オペレーターは不可）。監査ログに残し、前の所有者へ通知する
        assert c.post(f"{url}/takeover", headers=op).status_code == 403
        assert c.post(f"{url}/takeover", headers=owner).status_code == 400  # すでに所有者
        sent.reset_mock()
        r = c.post(f"{url}/takeover", headers=other)
        assert r.status_code == 200 and r.json()["owner_name"] == users["other"]["name"] and r.json()["can_manage"]
        assert sent.call_count == 1 and "引き継ぎ" in str(sent.call_args)
        logs = c.get("/api/audit/logs", params={"action": "credential_profile.takeover", "q": f"pa-{t}"}, headers=root).json()
        assert users["owner"]["name"] in str(logs["items"][0]["detail"]) and "previous_owner" in str(logs["items"][0]["detail"])
        assert mine(owner) == (False, False)  # 前の所有者は、グループに入っていなければ使えなくなる
        # 所有者を別の管理者へ渡せる（オペレーターには渡せない）
        assert c.put(url, json={"owner_id": users["op"]["id"]}, headers=other).status_code == 422
        assert c.put(url, json={"owner_id": users["owner"]["id"]}, headers=other).status_code == 200
        assert mine(owner) == (True, True)

        # 所有者のユーザーを削除すると「所有者なし」になり、管理グループか引き継ぎで扱う
        assert c.delete(f"/api/users/{users['owner']['id']}", headers=root).status_code == 204
        x = next(x for x in c.get("/api/credential-profiles/", headers=mgr).json() if x["id"] == p["id"])
        assert x["owner_id"] is None and x["owner_name"] is None and x["can_manage"] is True
        # グループを消すと共有範囲から外れる
        assert c.delete(f"/api/notifications/groups/{g_manage}", headers=root).status_code == 204
        assert mine(mgr) == (False, False)
        # 共有範囲の選択肢（管理者だけ）
        opts = c.get("/api/credential-profiles/share-options", headers=usr).json()
        assert any(g["id"] == g_use and g["members"] == 1 for g in opts["groups"])
        assert users["usr"]["name"] in [a["username"] for a in opts["admins"]] and users["op"]["name"] not in str(opts["admins"])
        assert c.get("/api/credential-profiles/share-options", headers=op).status_code == 403

        # 後始末
        for d in c.get("/api/devices/", headers=root).json():
            if d["name"].startswith("pa-") and d["name"].endswith(t):
                c.delete(f"/api/devices/{d['id']}", headers=root)
        assert c.post(f"{url}/takeover", headers=root).status_code == 200
        assert c.delete(url, headers=root).status_code == 204


def test_migration_sets_existing_owner_to_admin(monkeypatch, tmp_path):
    path = tmp_path / "owner.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{path}")
    from alembic import command

    cfg = migrate._alembic_config()
    command.upgrade(cfg, "0024_credential_profiles")
    con = sqlite3.connect(path)
    con.execute("INSERT INTO users (id, username, hashed_password, role, is_active, token_version, created_at) "
                "VALUES ('u-op','zed','h','admin',1,0,'2025-01-01'), ('u-admin','admin','h','admin',1,0,'2026-01-01')")
    con.execute("INSERT INTO credential_profiles (id, name, username, created_at, updated_at) "
                "VALUES ('p1','old','netops','2026-01-01','2026-01-01')")
    con.commit()
    con.close()
    command.upgrade(cfg, "head")
    con = sqlite3.connect(path)
    assert con.execute("select owner_id from credential_profiles").fetchall() == [("u-admin",)]
    assert con.execute("select count(*) from credential_profile_access").fetchone()[0] == 0
