"""ロールごとの権限（RBAC）のテスト"""
import asyncio
import json
import time
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app


@pytest.fixture(scope="module")
def client():
    with mock.patch("app.api.devices.collect_device_config") as one, mock.patch(
        "app.api.devices.collect_all_devices"
    ) as all_:
        one.delay.return_value.id = "t1"
        all_.delay.return_value.id = "t2"
        with TestClient(app) as c:
            yield c


def login(client, username, password):
    r = client.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def users(client):
    admin = login(client, "admin", "initial-pass-123")
    ids = {}
    for name, role in [("op1", "operator"), ("view1", "viewer")]:
        r = client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    dev = client.post(
        "/api/devices/",
        json=dict(name="rbac-sw", hostname="10.9.9.9", platform="cisco_ios", username="u", password="p"),
        headers=admin,
    ).json()
    return {
        "admin": admin,
        "operator": login(client, "op1", "password-1234"),
        "viewer": login(client, "view1", "password-1234"),
        "ids": ids,
        "device_id": dev["id"],
    }


def test_me_returns_permissions(client, users):
    me = client.get("/api/auth/me", headers=users["viewer"]).json()
    assert me["role"] == "viewer" and me["role_label"] == "閲覧者"
    assert "device:read" in me["permissions"] and "collect:run" not in me["permissions"]


@pytest.mark.parametrize(
    "method,path,body,expected",
    [
        # (method, path, body, {role: status})
        ("get", "/api/devices/", None, {"viewer": 200, "operator": 200, "admin": 200}),
        ("post", "/api/devices/", {"name": "x", "hostname": "h", "platform": "cisco_ios", "username": "u", "password": "p"},
         {"viewer": 403, "operator": 403}),
        ("put", "/api/devices/{dev}", {"description": "d"}, {"viewer": 403, "operator": 403, "admin": 200}),
        ("post", "/api/devices/{dev}/collect", None, {"viewer": 403, "operator": 200, "admin": 200}),
        ("post", "/api/devices/collect/all", None, {"viewer": 403, "operator": 200}),
        ("get", "/api/configs/{dev}/history", None, {"viewer": 200, "operator": 200}),
        # コメントは operator 以上（未収集の機器なので、権限を通ったあと世代が見つからず 404）
        ("put", "/api/configs/{dev}/comments/0000000", {"body": "x"}, {"viewer": 403, "operator": 404, "admin": 404}),
        ("delete", "/api/configs/{dev}/comments/0000000", None, {"viewer": 403, "operator": 404}),
        # 変更の確認も operator 以上（付ける側）。一覧は閲覧者も読める
        ("put", "/api/configs/{dev}/reviews/0000000", {"status": "confirmed"}, {"viewer": 403, "operator": 404, "admin": 404}),
        ("delete", "/api/configs/{dev}/reviews/0000000", None, {"viewer": 403, "operator": 404}),
        ("post", "/api/configs/reviews/bulk", {"items": [{"device_id": "x", "commit_hash": "0000000"}], "status": "confirmed"},
         {"viewer": 403, "operator": 200}),
        ("get", "/api/configs/reviews", None, {"viewer": 200, "operator": 200, "admin": 200}),
        ("get", "/api/schedules/", None, {"viewer": 200, "operator": 200}),
        ("post", "/api/schedules/", {"name": "s", "cron_expression": "0 9 * * *"}, {"viewer": 403, "operator": 403, "admin": 201}),
        ("get", "/api/tasks/abc", None, {"viewer": 403}),
        ("get", "/api/users/", None, {"viewer": 403, "operator": 403, "admin": 200}),
        ("get", "/api/users/roles", None, {"operator": 403, "admin": 200}),
    ],
)
def test_permission_matrix(client, users, method, path, body, expected):
    path = path.replace("{dev}", users["device_id"])
    for role, status in expected.items():
        kwargs = {"headers": users[role]}
        if body is not None:
            kwargs["json"] = body
        r = getattr(client, method)(path, **kwargs)
        assert r.status_code == status, (role, method, path, r.status_code, r.text)


def _ws(client, headers, device_id):
    token = headers["Authorization"].split()[1]
    with client.websocket_connect(f"/api/terminal/ws/{device_id}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        msg = ws.receive_text()
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_text()
        return msg, e.value.code


def test_terminal_requires_permission(client, users):
    msg, code = _ws(client, users["viewer"], users["device_id"])
    assert code == 4403 and "権限がありません" in msg
    # operator は権限チェックを通過して SSH 接続へ進む（接続先が無いので失敗メッセージ）
    with mock.patch("app.api.terminal.SSHTerminal.connect", side_effect=TimeoutError("timed out")):
        msg, code = _ws(client, users["operator"], users["device_id"])
    assert "SSH接続に失敗" in msg


def test_role_change_takes_effect_immediately(client, users):
    vid = users["ids"]["view1"]
    assert client.post(f"/api/devices/{users['device_id']}/collect", headers=users["viewer"]).status_code == 403
    r = client.patch(f"/api/users/{vid}", json={"role": "operator"}, headers=users["admin"])
    assert r.status_code == 200 and r.json()["role_label"] == "オペレーター"
    # 同じトークンのまま、新しいロールの権限が使える
    assert client.post(f"/api/devices/{users['device_id']}/collect", headers=users["viewer"]).status_code == 200
    client.patch(f"/api/users/{vid}", json={"role": "viewer"}, headers=users["admin"])


def test_deactivate_and_password_reset_revoke_tokens(client, users):
    oid = users["ids"]["op1"]
    op = login(client, "op1", "password-1234")
    client.patch(f"/api/users/{oid}", json={"is_active": False}, headers=users["admin"])
    assert client.get("/api/devices/", headers=op).status_code == 401
    assert client.post("/api/auth/token", data={"username": "op1", "password": "password-1234"}).status_code == 401
    client.patch(f"/api/users/{oid}", json={"is_active": True}, headers=users["admin"])
    op = login(client, "op1", "password-1234")
    r = client.patch(f"/api/users/{oid}", json={"password": "reset-pass-5678"}, headers=users["admin"])
    assert r.status_code == 200
    assert client.get("/api/devices/", headers=op).status_code == 401  # リセット前のトークンは無効
    login(client, "op1", "reset-pass-5678")


def test_reactivate_does_not_restore_old_tokens(client, users):
    """無効化 → 有効化しても、無効化の前に発行したトークンは使えないまま"""
    r = client.post("/api/users/", json={"username": "react1", "password": "password-1234", "role": "viewer"},
                    headers=users["admin"])
    uid = r.json()["id"]
    old = login(client, "react1", "password-1234")
    client.patch(f"/api/users/{uid}", json={"is_active": False}, headers=users["admin"])
    client.patch(f"/api/users/{uid}", json={"is_active": True}, headers=users["admin"])
    assert client.get("/api/devices/", headers=old).status_code == 401
    assert client.get("/api/devices/", headers=login(client, "react1", "password-1234")).status_code == 200
    assert client.delete(f"/api/users/{uid}", headers=users["admin"]).status_code == 204


def test_force_logout(client, users):
    admin = users["admin"]
    r = client.post("/api/users/", json={"username": "kick1", "password": "password-1234", "role": "operator"},
                    headers=admin)
    uid = r.json()["id"]
    a = login(client, "kick1", "password-1234")
    b = login(client, "kick1", "password-1234")  # 別の端末からのログイン
    other = login(client, "view1", "password-1234")

    async def hashed():
        from app.core.database import AsyncSessionLocal
        from app.models.user import User
        async with AsyncSessionLocal() as db:
            return (await db.get(User, uid)).hashed_password
    before = asyncio.run(hashed())
    # 管理者のみ・自分自身は不可・存在しないユーザーは 404
    assert client.post(f"/api/users/{uid}/logout", headers=a).status_code == 403  # オペレーター（本人）
    assert client.post(f"/api/users/{uid}/logout", headers=other).status_code == 403  # 閲覧者
    me = client.get("/api/auth/me", headers=admin).json()
    assert client.post(f"/api/users/{me['id']}/logout", headers=admin).status_code == 400
    assert client.post("/api/users/no-such-user/logout", headers=admin).status_code == 404

    r = client.post(f"/api/users/{uid}/logout", headers=admin)
    assert r.status_code == 200 and r.json() == {"closed_terminals": 0}
    # その人の既存のトークンはすべて無効。パスワードは変わらず、同じパスワードで再ログインできる
    assert client.get("/api/devices/", headers=a).status_code == 401
    assert client.get("/api/devices/", headers=b).status_code == 401
    assert asyncio.run(hashed()) == before
    new = login(client, "kick1", "password-1234")
    assert client.get("/api/devices/", headers=new).status_code == 200
    # 新しいトークンでパスワードを変更しても、切られない（再発行に番号を引き継ぐ）
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password-1234", "new_password": "password-5678"}, headers=new)
    assert client.get("/api/devices/", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).status_code == 200
    # ほかのユーザーには影響しない
    assert client.get("/api/devices/", headers=other).status_code == 200
    # 監査ログ
    log = client.get("/api/audit/logs", params={"action": "user.logout"}, headers=admin).json()["items"][0]
    assert log["target_name"] == "kick1"
    assert client.delete(f"/api/users/{uid}", headers=admin).status_code == 204


def test_token_without_version_is_still_valid(client, users):
    """強制ログアウトの機能を入れる前に発行したトークン（tv なし）は、番号 0 のユーザーでは有効のまま"""
    from datetime import UTC, datetime, timedelta

    import jwt

    from app.core.config import settings
    from app.core.security import password_fingerprint

    r = client.post("/api/users/", json={"username": "legacy1", "password": "password-1234", "role": "viewer"},
                    headers=users["admin"])
    uid = r.json()["id"]

    async def user_row():
        from app.core.database import AsyncSessionLocal
        from app.models.user import User
        async with AsyncSessionLocal() as db:
            u = await db.get(User, uid)
            return u.hashed_password, u.token_version
    hashed, tv = asyncio.run(user_row())
    assert tv == 0
    now = datetime.now(UTC)

    def token(**extra):
        payload = {"sub": uid, "pwv": password_fingerprint(hashed), "iat": now, "exp": now + timedelta(minutes=5)}
        payload.update(extra)
        return {"Authorization": f"Bearer {jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)}"}
    assert client.get("/api/devices/", headers=token()).status_code == 200
    assert client.get("/api/devices/", headers=token(tv="abc")).status_code == 401
    assert client.get("/api/devices/", headers=token(tv=1)).status_code == 401
    client.post(f"/api/users/{uid}/logout", headers=users["admin"])
    assert client.get("/api/devices/", headers=token()).status_code == 401  # 強制ログアウト後は tv なしも無効
    assert client.delete(f"/api/users/{uid}", headers=users["admin"]).status_code == 204


def test_force_logout_closes_open_terminal(client, users):
    """接続中のターミナルも切り、記録の終了理由に残す"""
    import fake_sshd

    admin = users["admin"]
    port, _, _ = fake_sshd.start()
    did = client.post("/api/devices/", json=dict(name=f"kick-sw-{port}", hostname="127.0.0.1", port=port,
                                                 platform="cisco_ios", username="admin", password="pw"),
                      headers=admin).json()["id"]
    r = client.post("/api/users/", json={"username": "kick2", "password": "password-1234", "role": "operator"},
                    headers=admin)
    uid = r.json()["id"]
    tok = login(client, "kick2", "password-1234")["Authorization"].split()[1]
    with client.websocket_connect(f"/api/terminal/ws/{did}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": tok}))
        assert "R1#" in ws.receive_text()
        r = client.post(f"/api/users/{uid}/logout", headers=admin)
        assert r.status_code == 200 and r.json() == {"closed_terminals": 1}
        out = ""
        with pytest.raises(WebSocketDisconnect) as e:
            while True:
                out += ws.receive_text()
        assert e.value.code == 4401 and "強制ログアウト" in out
    # 記録（SSH の切断と保存）は切断後の後片付けで行うので、少し待つ
    for _ in range(50):
        items = client.get("/api/audit/terminal-sessions", params={"username": "kick2"}, headers=admin).json()["items"]
        if items and items[0]["end_reason"]:
            break
        time.sleep(0.1)
    assert items[0]["end_reason"] == "管理者が切断（管理者による強制ログアウト）"
    log = client.get("/api/audit/logs", params={"action": "user.logout"}, headers=admin).json()["items"][0]
    assert log["target_name"] == "kick2" and "1" in str(log["detail"])
    client.delete(f"/api/devices/{did}", headers=admin)
    assert client.delete(f"/api/users/{uid}", headers=admin).status_code == 204


def _open_terminal(client, did, tok):
    ws = client.websocket_connect(f"/api/terminal/ws/{did}").__enter__()
    ws.send_text(json.dumps({"type": "auth", "token": tok}))
    assert "R1#" in ws.receive_text()
    return ws


def _closed_with(ws, text):
    out = ""
    with pytest.raises(WebSocketDisconnect) as e:
        while True:
            out += ws.receive_text()
    return e.value.code == 4401 and text in out


def _end_reason(client, admin, username):
    for _ in range(50):
        items = client.get("/api/audit/terminal-sessions", params={"username": username}, headers=admin).json()["items"]
        if items and items[0]["end_reason"]:
            return items[0]["end_reason"]
        time.sleep(0.1)
    return None


def test_role_change_and_own_password_change_close_terminal(client, users):
    """ターミナルの権限が無くなるロールへの変更、本人のパスワード変更でも、開いているターミナルを切る"""
    import fake_sshd

    admin = users["admin"]
    port, _, _ = fake_sshd.start()
    did = client.post("/api/devices/", json=dict(name=f"kick3-sw-{port}", hostname="127.0.0.1", port=port,
                                                 platform="cisco_ios", username="admin", password="pw"),
                      headers=admin).json()["id"]
    uid = client.post("/api/users/", json={"username": "kick3", "password": "password-1234", "role": "operator"},
                      headers=admin).json()["id"]
    tok = login(client, "kick3", "password-1234")["Authorization"].split()[1]

    # オペレーター → 管理者はターミナルの権限が残るので切らない
    ws = _open_terminal(client, did, tok)
    assert client.patch(f"/api/users/{uid}", json={"role": "admin"}, headers=admin).status_code == 200
    ws.send_text(json.dumps({"type": "input", "data": "\r"}))
    assert "R1#" in ws.receive_text()
    # 管理者 → 閲覧者で切る（ログインそのものは残る）
    assert client.patch(f"/api/users/{uid}", json={"role": "viewer"}, headers=admin).status_code == 200
    assert _closed_with(ws, "ロールの変更")
    ws.__exit__(None, None, None)
    assert _end_reason(client, admin, "kick3") == "管理者が切断（ロールの変更）"
    assert client.get("/api/devices/", headers={"Authorization": f"Bearer {tok}"}).status_code == 200

    # 本人のパスワード変更
    assert client.patch(f"/api/users/{uid}", json={"role": "operator"}, headers=admin).status_code == 200
    ws = _open_terminal(client, did, tok)
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password-1234", "new_password": "changed-pass-777"},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert _closed_with(ws, "パスワードの変更")
    ws.__exit__(None, None, None)
    assert _end_reason(client, admin, "kick3") == "本人のパスワード変更で切断"  # 新しい順なので先頭が今回の記録
    client.delete(f"/api/devices/{did}", headers=admin)
    assert client.delete(f"/api/users/{uid}", headers=admin).status_code == 204


def test_change_password_returns_new_token(client, users):
    old = login(client, "view1", "password-1234")
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "password-1234", "new_password": "changed-pass-999"},
        headers=old,
    )
    assert r.status_code == 200
    new = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/devices/", headers=old).status_code == 401
    assert client.get("/api/devices/", headers=new).status_code == 200


def test_admin_safeguards(client, users):
    admin = users["admin"]
    me = client.get("/api/auth/me", headers=admin).json()
    assert client.patch(f"/api/users/{me['id']}", json={"role": "viewer"}, headers=admin).status_code == 400
    assert client.patch(f"/api/users/{me['id']}", json={"is_active": False}, headers=admin).status_code == 400
    assert client.delete(f"/api/users/{me['id']}", headers=admin).status_code == 400
    assert client.post("/api/users/", json={"username": "op1", "password": "password-1234"}, headers=admin).status_code == 409
    assert client.post("/api/users/", json={"username": "bad name", "password": "password-1234"}, headers=admin).status_code == 422
    assert client.post("/api/users/", json={"username": "short", "password": "short"}, headers=admin).status_code == 422
    assert client.post("/api/users/", json={"username": "r", "password": "password-1234", "role": "root"}, headers=admin).status_code == 422
    # 別の管理者を作って削除できる
    r = client.post("/api/users/", json={"username": "admin2", "password": "password-1234", "role": "admin"}, headers=admin)
    assert client.delete(f"/api/users/{r.json()['id']}", headers=admin).status_code == 204


def test_every_protected_route_declares_a_permission():
    """ログイン必須のAPIはすべて require(Perm.xxx) を持つこと（付け忘れ防止）"""
    from fastapi.routing import APIRoute

    missing = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/"):
            continue
        if route.path.startswith(("/api/auth/", "/api/health")):
            continue
        names = {getattr(d.call, "__qualname__", "") for d in route.dependant.dependencies}
        if not any(n.startswith("require.") for n in names):
            missing.append(f"{sorted(route.methods)} {route.path}")
    assert not missing, missing
