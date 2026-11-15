"""認証情報プロファイルのテスト（API・機器への割り当て・実際の接続・監査・CSV）"""
import asyncio
import json
import sqlite3
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from conftest import TMP
from fastapi.testclient import TestClient
from test_jump import ed25519_openssh

from app import worker
from app.core.database import AsyncSessionLocal
from app.main import app
from app.services.connection import load_connection_info


def login(c, u, p):
    r = c.post("/api/auth/token", data={"username": u, "password": p})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        for name, role in (("cp-op", "operator"), ("cp-viewer", "viewer")):
            c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        yield {"c": c, "admin": admin, "op": login(c, "cp-op", "password-1234"),
               "viewer": login(c, "cp-viewer", "password-1234")}


@pytest.fixture
def r():
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr):
        yield fr


def tag():
    return uuid.uuid4().hex[:6]


def raw_device(device_id):
    con = sqlite3.connect(f"{TMP}/t.db")
    row = con.execute("select username, password, private_key, key_passphrase, enable_secret, credential_profile_id "
                      "from devices where id=?", (device_id,)).fetchone()
    con.close()
    return row


def conn_info(device_id):
    async def run():
        async with AsyncSessionLocal() as db:
            return await load_connection_info(db, device_id)
    return asyncio.run(run())


def audit_items(c, h, action, q):
    return c.get("/api/audit/logs", params={"action": action, "q": q}, headers=h).json()["items"]


def test_profile_api(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    _pkey, text = ed25519_openssh("pp-9")
    base = {"name": f"共通-{t}", "username": "netops"}
    assert c.post("/api/credential-profiles/", json=base, headers=admin).status_code == 422  # 認証情報なし
    assert c.post("/api/credential-profiles/", json={**base, "private_key": "junk"}, headers=admin).status_code == 422
    r = c.post("/api/credential-profiles/", json={**base, "private_key": text, "key_passphrase": "pp-9",
                                                  "password": f"Pw-{t}", "enable_secret": f"En-{t}"}, headers=admin)
    assert r.status_code == 201, r.text
    p = r.json()
    assert p["has_password"] and p["has_private_key"] and p["has_enable_secret"] and p["device_count"] == 0
    assert p["key_info"].startswith("ssh-ed25519 SHA256:")
    # 秘密の値は返さない
    for k in ("password", "private_key", "key_passphrase", "enable_secret"):
        assert k not in p
    assert f"Pw-{t}" not in r.text and "PRIVATE KEY" not in r.text
    assert c.post("/api/credential-profiles/", json={**base, "password": "x"}, headers=admin).status_code == 409
    # DB には暗号化して保存する
    con = sqlite3.connect(f"{TMP}/t.db")
    row = con.execute("select password, private_key, enable_secret from credential_profiles where id=?",
                      (p["id"],)).fetchone()
    assert all(v.startswith("enc:") for v in row)

    # 更新: 両方の認証情報を消すことはできない。鍵だけ消すのはよい
    url = f"/api/credential-profiles/{p['id']}"
    assert c.put(url, json={"clear_password": True, "clear_private_key": True}, headers=admin).status_code == 422
    r = c.put(url, json={"clear_private_key": True, "clear_enable_secret": True, "username": "netops2"}, headers=admin)
    assert r.status_code == 200, r.text
    assert (r.json()["has_private_key"], r.json()["has_enable_secret"], r.json()["username"]) == (False, False, "netops2")
    assert c.put("/api/credential-profiles/nope", json={}, headers=admin).status_code == 404
    assert c.delete(url, headers=admin).status_code == 204
    assert all(x["id"] != p["id"] for x in c.get("/api/credential-profiles/", headers=admin).json())


def test_device_with_profile_and_switching(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    p = c.post("/api/credential-profiles/", json={"name": f"sw-{t}", "username": "netops", "password": f"Pw-{t}",
                                                  "enable_secret": f"En-{t}"}, headers=admin).json()
    # プロファイルを指定すればユーザー名・パスワードなしで登録できる。送られてきた機器側の値は保存しない
    r = c.post("/api/devices/", json={"name": f"cp-{t}", "hostname": "10.8.0.1", "platform": "cisco_ios",
                                      "credential_profile_id": p["id"], "username": "x", "password": "dev-pw"},
               headers=admin)
    assert r.status_code == 201, r.text
    d = r.json()
    assert (d["credential_profile_id"], d["credential_profile_name"], d["username"]) == (p["id"], p["name"], "netops")
    assert d["has_password"] and d["has_enable_secret"] and not d["has_private_key"]
    assert raw_device(d["id"]) == (None, None, None, None, None, p["id"])
    # 接続情報はプロファイルの値
    info = conn_info(d["id"])
    assert (info.username, info.password, info.enable_secret) == ("netops", f"Pw-{t}", f"En-{t}")
    # 存在しないプロファイル・プロファイルもユーザー名も無い登録は 422
    bad = {"name": f"cp-bad-{t}", "hostname": "10.8.0.2", "platform": "cisco_ios"}
    assert c.post("/api/devices/", json={**bad, "credential_profile_id": "nope"}, headers=admin).status_code == 422
    r = c.post("/api/devices/", json={**bad, "password": "p"}, headers=admin)
    assert r.status_code == 422 and "ユーザー名" in r.text
    assert c.post("/api/devices/", json={**bad, "username": "u"}, headers=admin).status_code == 422

    # プロファイルを外すときは、この機器の認証情報が必要
    url = f"/api/devices/{d['id']}"
    r = c.put(url, json={"credential_profile_id": None}, headers=admin)
    assert r.status_code == 422 and "認証情報プロファイルを外す" in r.json()["detail"]
    r = c.put(url, json={"credential_profile_id": None, "username": "own"}, headers=admin)
    assert r.status_code == 422
    r = c.put(url, json={"credential_profile_id": None, "password": "own-pw"}, headers=admin)
    assert r.status_code == 422
    assert raw_device(d["id"])[5] == p["id"]  # 断られたら何も変わらない
    r = c.put(url, json={"credential_profile_id": None, "username": "own", "password": f"Own-{t}"}, headers=admin)
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["credential_profile_id"], d["credential_profile_name"], d["username"]) == (None, None, "own")
    assert d["has_password"] and not d["has_enable_secret"]
    assert conn_info(d["id"]).password == f"Own-{t}"

    # 機器ごとの認証情報 → プロファイル: 機器側の古い秘密の値は消す
    r = c.put(url, json={"credential_profile_id": p["id"], "password": "ignored"}, headers=admin)
    assert r.status_code == 200 and r.json()["credential_profile_name"] == p["name"]
    assert raw_device(d["id"]) == (None, None, None, None, None, p["id"])
    # プロファイルを使っている間の、ほかの項目の変更はそのまま（認証情報の入力は要らない）
    r = c.put(url, json={"description": "メモ"}, headers=admin)
    assert r.status_code == 200 and r.json()["description"] == "メモ" and r.json()["has_password"]
    assert c.put(url, json={"credential_profile_id": "nope"}, headers=admin).status_code == 422

    # 使用中は削除できない（台数を表示）。外すか機器を消せば削除できる。機器の削除はプロファイルに影響しない
    listed = {x["id"]: x for x in c.get("/api/credential-profiles/", headers=admin).json()}
    assert listed[p["id"]]["device_count"] == 1
    r = c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)
    assert r.status_code == 409 and "1台" in r.json()["detail"]
    assert c.delete(url, headers=admin).status_code == 204
    assert c.delete(f"/api/credential-profiles/{p['id']}", headers=admin).status_code == 204


def test_collect_with_profile_and_password_change(ctx, r):
    """プロファイルの認証情報で実際に収集でき、プロファイルのパスワード変更が次の収集から全機器に反映される"""
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    port_a, state_a, _ = fake_sshd.start(password="old-pw")
    port_b, _, _ = fake_sshd.start(password="old-pw")
    p = c.post("/api/credential-profiles/", json={"name": f"col-{t}", "username": "admin", "password": "old-pw"},
               headers=admin).json()
    ids = []
    for i, port in enumerate((port_a, port_b)):
        d = c.post("/api/devices/", json={"name": f"col-{t}-{i}", "hostname": "127.0.0.1", "port": port,
                                          "platform": "cisco_ios", "credential_profile_id": p["id"]},
                   headers=admin).json()
        ids.append(d["id"])
        assert raw_device(d["id"])[:5] == (None,) * 5  # 機器側には何も無い＝プロファイルの値で接続する
    for did in ids:
        res = worker.collect_device_config.apply(args=(did, "manual")).get()
        assert res["success"], res
    assert state_a["auth_method"] == "password"

    # 機器のパスワードが変わった（新しいパスワードの偽サーバーに付け替える）→ プロファイルが古いままでは失敗する
    new_a, _, _ = fake_sshd.start(password="new-pw")
    new_b, _, _ = fake_sshd.start(password="new-pw")
    for did, port in zip(ids, (new_a, new_b), strict=True):
        assert c.put(f"/api/devices/{did}", json={"port": port}, headers=admin).status_code == 200
    with mock.patch.object(worker.collect_device_config, "max_retries", 0):
        res = worker.collect_device_config.apply(args=(ids[0], "manual")).get()
    assert not res["success"] and "認証" in res["error"], res
    # プロファイルのパスワードを 1 か所変えると、両方の機器の次の収集に効く
    r_ = c.put(f"/api/credential-profiles/{p['id']}", json={"password": "new-pw"}, headers=admin)
    assert r_.status_code == 200 and r_.json()["device_count"] == 2
    for did in ids:
        res = worker.collect_device_config.apply(args=(did, "manual")).get()
        assert res["success"], res
    # FW ヒット数の取得も同じ読み出し（worker._get_device）を通る
    info = asyncio.run(worker._get_device(ids[1]))
    assert (info.username, info.password) == ("admin", "new-pw")

    # 監査: 変更はパスワードの値を残さず、影響する台数を残す
    log = audit_items(c, admin, "credential_profile.update", p["name"])[0]
    detail = json.loads(log["detail"])
    assert detail == {"password": "（変更）", "devices": 2}
    assert "new-pw" not in json.dumps(audit_items(c, admin, "", p["name"]), ensure_ascii=False)
    for did in ids:
        c.delete(f"/api/devices/{did}", headers=admin)
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)


def test_terminal_with_profile(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    port, _, _ = fake_sshd.start(password=f"tp-{t}")
    p = c.post("/api/credential-profiles/", json={"name": f"term-{t}", "username": "admin", "password": f"tp-{t}"},
               headers=admin).json()
    d = c.post("/api/devices/", json={"name": f"term-cp-{t}", "hostname": "127.0.0.1", "port": port,
                                      "platform": "cisco_ios", "credential_profile_id": p["id"]}, headers=admin).json()
    token = admin["Authorization"].split()[1]
    with c.websocket_connect(f"/api/terminal/ws/{d['id']}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        assert "R1#" in ws.receive_text()
    c.delete(f"/api/devices/{d['id']}", headers=admin)
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)


def test_key_profile(ctx):
    pkey, text = ed25519_openssh()
    port, state, _ = fake_sshd.start(password=None, pubkey=pkey)
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    p = c.post("/api/credential-profiles/", json={"name": f"key-{t}", "username": "admin", "private_key": text},
               headers=admin).json()
    d = c.post("/api/devices/", json={"name": f"key-cp-{t}", "hostname": "127.0.0.1", "port": port,
                                      "platform": "cisco_ios", "credential_profile_id": p["id"]}, headers=admin).json()
    assert d["has_private_key"] and not d["has_password"] and d["key_info"] == p["key_info"]
    from app.services import config_service as cs
    res = cs.collect_config_sync(conn_info(d["id"]))
    assert res.success, res
    assert state["auth_method"] == "publickey"
    c.delete(f"/api/devices/{d['id']}", headers=admin)
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)


def test_permissions(ctx):
    c, admin, op, viewer = ctx["c"], ctx["admin"], ctx["op"], ctx["viewer"]
    t = tag()
    body = {"name": f"perm-{t}", "username": "u", "password": "p"}
    p = c.post("/api/credential-profiles/", json=body, headers=admin).json()
    for h in (op, viewer):
        r = c.get("/api/credential-profiles/", headers=h)
        assert r.status_code == 200 and "password" not in r.json()[0]
        assert c.post("/api/credential-profiles/", json={**body, "name": f"x-{t}"}, headers=h).status_code == 403
        assert c.put(f"/api/credential-profiles/{p['id']}", json={"password": "z"}, headers=h).status_code == 403
        assert c.delete(f"/api/credential-profiles/{p['id']}", headers=h).status_code == 403
    assert c.get("/api/credential-profiles/").status_code == 401
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)


def test_audit_has_no_secrets(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    secret = f"Sec-{t}"
    _pkey, key_text = ed25519_openssh()
    p = c.post("/api/credential-profiles/", json={"name": f"aud-{t}", "username": "u", "password": secret,
                                                  "enable_secret": secret + "e", "private_key": key_text},
               headers=admin).json()
    c.put(f"/api/credential-profiles/{p['id']}", json={"password": secret + "2", "enable_secret": secret + "3",
                                                         "name": f"aud-{t}-r"}, headers=admin)
    d = c.post("/api/devices/", json={"name": f"aud-dev-{t}", "hostname": "10.8.1.1", "platform": "cisco_ios",
                                      "username": "u", "password": secret + "d"}, headers=admin).json()
    c.put(f"/api/devices/{d['id']}", json={"credential_profile_id": p["id"]}, headers=admin)
    c.delete(f"/api/devices/{d['id']}", headers=admin)
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)

    items = c.get("/api/audit/logs", params={"q": t}, headers=admin).json()["items"]
    mine = [x for x in items if t in (x["target_name"] or "")]
    actions = {x["action"] for x in mine}
    assert {"credential_profile.create", "credential_profile.update", "credential_profile.delete",
            "device.update"} <= actions
    dumped = json.dumps(mine, ensure_ascii=False)
    assert secret not in dumped and "PRIVATE KEY" not in dumped
    create = json.loads(next(x for x in mine if x["action"] == "credential_profile.create")["detail"])
    assert create == {"username": "u", "auth": ["password", "private_key", "enable_secret"]}
    upd = json.loads(next(x for x in mine if x["action"] == "device.update")["detail"])
    assert upd == {"credential_profile_id": p["id"], "credential_profile": f"aud-{t}-r"}
    # 監査ログの画面に出す名前
    labels = c.get("/api/audit/actions", headers=admin).json()
    assert labels["credential_profile.update"] == "認証情報プロファイル変更"


def test_ledger_and_csv_import(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    p = c.post("/api/credential-profiles/", json={"name": f"共通アカウント-{t}", "username": "netops",
                                                  "password": f"Pw-{t}"}, headers=admin).json()
    header = "名前,ホスト / IP,機種,認証情報プロファイル,ユーザー名,パスワード"
    text = (f"{header}\n"
            f"csvp-{t}-a,10.8.2.1,cisco_ios,共通アカウント-{t},,\n"
            f"csvp-{t}-b,10.8.2.2,cisco_ios,共通アカウント－{t},admin,pw-b\n"  # 全角のゆれ・余分な値は警告
            f"csvp-{t}-c,10.8.2.3,cisco_ios,無いプロファイル-{t},,\n"
            f"csvp-{t}-d,10.8.2.4,cisco_ios,,admin,\n")
    files = {"file": ("d.csv", text.encode(), "text/csv")}
    res = c.post("/api/devices/import", files=files, data={"dry_run": "true"}, headers=admin).json()
    rows = {row["line"]: row for row in res["rows"]}
    assert rows[2]["status"] == "ok" and rows[2]["credential_profile"] == f"共通アカウント-{t}"
    assert rows[3]["status"] == "ok" and "使いません" in rows[3]["warnings"][0]
    assert rows[4]["status"] == "error" and "認証情報プロファイル「無いプロファイル" in rows[4]["errors"][0]
    assert rows[5]["status"] == "error" and "パスワード: 空です" in rows[5]["errors"][0]
    assert "pw-b" not in json.dumps(res, ensure_ascii=False)
    res = c.post("/api/devices/import", files=files, data={"dry_run": "false", "skip_errors": "true"},
                 headers=admin).json()
    assert res["created"] == 2
    devs = {d["name"]: d for d in c.get("/api/devices/", headers=admin).json() if d["name"].startswith(f"csvp-{t}")}
    assert set(devs) == {f"csvp-{t}-a", f"csvp-{t}-b"}
    for d in devs.values():
        assert d["credential_profile_id"] == p["id"] and d["username"] == "netops"
        assert raw_device(d["id"])[:5] == (None,) * 5  # 行のユーザー名・パスワードは保存しない
    create = audit_items(c, admin, "device.create", f"csvp-{t}-b")[0]
    assert json.loads(create["detail"])["auth"] == ["credential_profile"]

    # 台帳 CSV に「認証情報プロファイル」の列（名前だけ。認証情報の値は出さない）
    ledger = c.get("/api/devices/export", headers=admin).content.decode("utf-8-sig").splitlines()
    head = ledger[0].split(",")
    assert head.index("認証情報プロファイル") == head.index("踏み台") + 1
    line = next(x for x in ledger if x.startswith(f"csvp-{t}-a,"))
    assert line.split(",")[head.index("認証情報プロファイル")] == f"共通アカウント-{t}"
    assert f"Pw-{t}" not in "\n".join(ledger) and "netops" not in "\n".join(ledger)
    # ひな形にも同じ列がある
    tpl = c.get("/api/devices/import/template", headers=admin).content.decode("utf-8-sig").splitlines()[0]
    assert "認証情報プロファイル" in tpl.split(",")
    for d in devs.values():
        c.delete(f"/api/devices/{d['id']}", headers=admin)
    c.delete(f"/api/credential-profiles/{p['id']}", headers=admin)
