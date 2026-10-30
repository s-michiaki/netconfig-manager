"""ロールごとの権限（RBAC）のテスト"""
import json
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
