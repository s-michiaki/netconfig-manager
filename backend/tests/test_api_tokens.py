"""API トークン（app/api/api_tokens.py・app/api/deps.py・app/api/token_policy.py）のテスト"""
import asyncio
import hashlib
import json
import logging
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import select, update
from starlette.websockets import WebSocketDisconnect

from app.api.deps import SESSION_REQUIRED
from app.api.token_policy import TOKEN_ALLOWED, route_keys
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.permissions import READ_ONLY_PERMS
from app.core.timeutil import utcnow
from app.main import app
from app.models.api_token import ApiToken
from app.models.audit import AuditLog
from app.services import api_tokens as svc
from app.services import login_limit

PW = "password-1234"

# ---------------------------------------------------------------- 全ルートの表
# T: API トークンで呼べる（ロール・範囲の権限の判定は別）/ S: ログインのセッションだけ（トークンでは 403）
# P: 認証なしで呼べる（トークンは使わない）
# 新しいルートを作ったら、ここに足す（足さないとテストが落ちる）。T にするなら token_policy.TOKEN_ALLOWED にも足す
T, S, P = "token", "session", "public"
ROUTES = {
    "GET /openapi.json": P, "HEAD /openapi.json": P, "GET /docs": P, "HEAD /docs": P,
    "GET /docs/oauth2-redirect": P, "HEAD /docs/oauth2-redirect": P, "GET /redoc": P, "HEAD /redoc": P,
    "GET /api/health": P,
    # 認証・自分のアカウント
    "POST /api/auth/token": P,
    "POST /api/auth/mfa/verify": P,
    "POST /api/auth/mfa/setup": S,
    "POST /api/auth/mfa/enable": S,
    "POST /api/auth/mfa/recovery-codes": S,
    "POST /api/auth/mfa/disable": S,
    "GET /api/auth/me": T,
    "POST /api/auth/change-password": S,
    "GET /api/auth/tokens": S,
    "POST /api/auth/tokens": S,
    "DELETE /api/auth/tokens/{token_id}": S,
    # 機器
    "GET /api/devices/": T,
    "GET /api/devices/export": T,
    "POST /api/devices/": S,  # 認証情報を受け取る
    "GET /api/devices/import/template": S,
    "POST /api/devices/import": S,  # 認証情報を受け取る
    "GET /api/devices/defaults": T,
    "GET /api/devices/collect-status": T,
    "GET /api/devices/platforms": T,
    "POST /api/devices/collect/all": T,
    "GET /api/devices/{device_id}": T,
    "GET /api/devices/{device_id}/startup-diff": T,
    "PUT /api/devices/{device_id}": S,  # 認証情報を受け取る
    "DELETE /api/devices/{device_id}": T,
    "POST /api/devices/{device_id}/collect": T,
    "GET /api/device-groups/": T,
    "POST /api/device-groups/": T,
    "PUT /api/device-groups/order": T,
    "PUT /api/device-groups/{group_id}": T,
    "DELETE /api/device-groups/{group_id}": T,
    "POST /api/device-groups/{group_id}/collect": T,
    "POST /api/device-groups/assign": T,
    "GET /api/jump-hosts/": T,
    "POST /api/jump-hosts/": S,
    "PUT /api/jump-hosts/{jump_id}": S,
    "DELETE /api/jump-hosts/{jump_id}": S,
    "POST /api/jump-hosts/{jump_id}/test": S,
    "GET /api/credential-profiles/": T,
    "GET /api/credential-profiles/share-options": S,
    "POST /api/credential-profiles/": S,
    "PUT /api/credential-profiles/{profile_id}": S,
    "POST /api/credential-profiles/{profile_id}/takeover": S,
    "DELETE /api/credential-profiles/{profile_id}": S,
    # コンフィグ
    "GET /api/configs/compare": T,
    "GET /api/configs/{device_id}/history": T,
    "GET /api/configs/{device_id}/diff": T,
    "GET /api/configs/{device_id}/content/{commit_hash}": T,
    "GET /api/configs/{device_id}/download/{commit_hash}": T,
    "POST /api/configs/search": T,
    "POST /api/configs/search/export": T,
    "PUT /api/configs/{device_id}/comments/{commit_hash}": T,
    "DELETE /api/configs/{device_id}/comments/{commit_hash}": T,
    "GET /api/configs/baselines": T,
    "GET /api/configs/{device_id}/baseline": T,
    "PUT /api/configs/{device_id}/baseline": T,
    "DELETE /api/configs/{device_id}/baseline": T,
    "GET /api/configs/reviews": T,
    "PUT /api/configs/{device_id}/reviews/{commit_hash}": T,
    "DELETE /api/configs/{device_id}/reviews/{commit_hash}": T,
    "POST /api/configs/reviews/bulk": T,
    "GET /api/schedules/": T,
    "POST /api/schedules/": T,
    "DELETE /api/schedules/{schedule_id}": T,
    "PATCH /api/schedules/{schedule_id}/toggle": T,
    "GET /api/tasks/{task_id}": T,
    # 構成図・コマンド実行・コンプライアンス・無視する行
    "GET /api/topology/maps": T,
    "POST /api/topology/maps": T,
    "GET /api/topology/maps/{map_id}": T,
    "GET /api/topology/maps/{map_id}/status": T,
    "POST /api/topology/device-status": T,
    "PUT /api/topology/maps/{map_id}": T,
    "DELETE /api/topology/maps/{map_id}": T,
    "GET /api/commands/limits": T,
    "GET /api/commands/check": T,
    "POST /api/commands/runs": T,
    "GET /api/commands/runs": T,
    "GET /api/commands/runs/{run_id}": T,
    "GET /api/commands/runs/{run_id}/export": T,
    "GET /api/compliance/templates": T,
    "GET /api/compliance/rules": T,
    "POST /api/compliance/rules": T,
    "PUT /api/compliance/rules/{rule_id}": T,
    "DELETE /api/compliance/rules/{rule_id}": T,
    "POST /api/compliance/rules/test": T,
    "GET /api/compliance/exceptions": T,
    "POST /api/compliance/exceptions": T,
    "DELETE /api/compliance/exceptions/{exception_id}": T,
    "POST /api/compliance/run": T,
    "GET /api/compliance/results": T,
    "GET /api/compliance/summary": T,
    "GET /api/ignore-rules/": T,
    "POST /api/ignore-rules/": T,
    "PUT /api/ignore-rules/{rule_id}": T,
    "DELETE /api/ignore-rules/{rule_id}": T,
    "POST /api/ignore-rules/preview": T,
    # 監査ログ（ターミナルの記録の中身・検索はセッションだけ）
    "GET /api/audit/actions": T,
    "GET /api/audit/logs": T,
    "GET /api/audit/logs/export": T,
    "GET /api/audit/terminal-sessions": T,
    "GET /api/audit/terminal-sessions/export": T,
    "GET /api/audit/terminal-sessions/{session_id}/recording": S,
    "GET /api/audit/terminal-sessions/{session_id}/text": S,
    "POST /api/audit/terminal-sessions/search": S,
    "GET /api/activity/events": T,
    "GET /api/activity/logs": T,
    "GET /api/activity/logs/export": T,
    # Ping監視
    "GET /api/ping/targets": T,
    "POST /api/ping/targets": T,
    "PUT /api/ping/targets/{target_id}": T,
    "DELETE /api/ping/targets/{target_id}": T,
    "GET /api/ping/monitors": T,
    "PUT /api/ping/monitors/{key}": T,
    "GET /api/ping/monitors/{key}/history": T,
    # システム・メール・ダッシュボード・モニタリング
    "GET /api/system/status": T,
    "POST /api/system/git-export": S,
    "POST /api/system/outbound-check": S,  # 外部へ送る操作（管理者がログインして行う）
    "GET /api/mail/server": S,
    "PUT /api/mail/server": S,
    "POST /api/mail/server/test": S,
    "POST /api/mail/google/authorize": S,
    "POST /api/mail/google/complete": S,
    "DELETE /api/mail/google": S,
    "GET /api/dashboard": T,
    "GET /api/monitoring/snmp": T,
    "PUT /api/monitoring/snmp/{device_id}": S,  # community・鍵を受け取る
    "DELETE /api/monitoring/snmp/{device_id}": S,
    "POST /api/monitoring/snmp/{device_id}/test": T,
    "POST /api/monitoring/snmp/poll": T,
    "GET /api/monitoring/interfaces": T,
    "GET /api/monitoring/interfaces/top": T,
    "GET /api/monitoring/interfaces/{interface_id}/samples": T,
    "GET /api/monitoring/fw": T,
    "GET /api/monitoring/fw/{device_id}/rules": T,
    "POST /api/monitoring/fw/{device_id}/collect": T,
    "GET /api/monitoring/fw/{device_id}/raw": T,
    # 脆弱性・サポート終了日（閲覧は T。確認済み・手入力・いま取得は S）
    "GET /api/vulns/summary": T,
    "GET /api/vulns/matches": T,
    "GET /api/vulns/matches/export": T,
    "GET /api/vulns/devices": T,
    "GET /api/vulns/unknown": T,
    "GET /api/vulns/advisories/{advisory_id}": T,
    "POST /api/vulns/matches/{match_id}/ack": S,
    "POST /api/vulns/matches/{match_id}/unack": S,
    "GET /api/vulns/eol": T,
    "PUT /api/vulns/eol": S,
    "DELETE /api/vulns/eol/{eol_id}": S,
    "GET /api/vulns/eol/devices": T,
    "POST /api/vulns/fetch": S,
    "POST /api/vulns/fortinet/import": S,
    "GET /api/vulns/fortinet/import": S,
    # 通知の設定（送信先・Webhook の URL を含む）
    "GET /api/notifications/me": S,
    "PUT /api/notifications/me": S,
    "POST /api/notifications/me/test": S,
    "GET /api/notifications/report-preview": S,  # 定期レポートの集計（機器名・件数。通知設定と同じくセッションだけ）
    "POST /api/notifications/me/report": S,  # 自分の宛先へ定期レポートを送る
    "GET /api/notifications/groups": S,
    "POST /api/notifications/groups": S,
    "PUT /api/notifications/groups/{group_id}": S,
    "DELETE /api/notifications/groups/{group_id}": S,
    "POST /api/notifications/groups/{group_id}/test": S,
    "GET /api/notifications/preview": S,
    # ユーザー管理
    "GET /api/users/roles": S,
    "GET /api/users/": S,
    "POST /api/users/": S,
    "PATCH /api/users/{user_id}": S,
    "POST /api/users/{user_id}/mfa-reset": S,
    "POST /api/users/{user_id}/logout": S,
    "DELETE /api/users/{user_id}": S,
    "GET /api/users/{user_id}/tokens": S,
    "DELETE /api/users/{user_id}/tokens": S,
}
# WebSocket はログインのトークンだけ（API トークンは受け付けない）
WEBSOCKETS = {"/api/terminal/ws/{device_id}", "/api/ping/ws"}


def _all_route_keys() -> set[str]:
    return set().union(*route_keys(app).values())


def test_route_table_covers_every_route():
    """表に無いルートが増えたら落ちる。表の「T」と token_policy の一覧が一致すること"""
    actual = _all_route_keys()
    assert actual - ROUTES.keys() == set(), "表に無いルートがあります（ROUTES に T / S / P を書いてください）"
    assert ROUTES.keys() - actual == set(), "表に、もう無いルートが残っています"
    assert {k for k, v in ROUTES.items() if v == T} == set(TOKEN_ALLOWED)
    ws = {rc.path for rc in iter_route_contexts(app.routes) if rc.methods is None and rc.path.startswith("/api/")}
    assert ws == WEBSOCKETS


# ---------------------------------------------------------------- 準備


@pytest.fixture(scope="module")
def client():
    with mock.patch("app.api.devices.collect_device_config") as one, mock.patch(
        "app.api.devices.collect_all_devices"
    ) as all_:
        one.delay.return_value.id = "t1"
        all_.delay.return_value.id = "t2"
        with TestClient(app) as c:
            yield c


def login(c, username, password=PW):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def bearer(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def ctx(client):
    admin = login(client, "admin", "initial-pass-123")
    ids = {}
    for name, role in [("tok-op", "operator"), ("tok-view", "viewer"), ("tok-adm", "admin")]:
        r = client.post("/api/users/", json={"username": name, "password": PW, "role": role}, headers=admin)
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    dev = client.post(
        "/api/devices/",
        json=dict(name="tok-sw", hostname="192.0.2.10", platform="cisco_ios", username="u", password="p"),
        headers=admin,
    ).json()
    return {"admin": admin, "ids": ids, "device_id": dev["id"]}


def create(c, headers, name="script", scope="read", days=30, password=PW):
    return c.post("/api/auth/tokens", json={"name": name, "scope": scope, "days": days, "password": password},
                  headers=headers)


def new_token(c, username, scope="read", name="script", days=30) -> tuple[str, str]:
    r = create(c, login(c, username), name=name, scope=scope, days=days)
    assert r.status_code == 201, r.text
    return r.json()["token"], r.json()["id"]


def _db(coro_fn):
    async def run():
        async with AsyncSessionLocal() as db:
            out = await coro_fn(db)
            await db.commit()
            return out
    return asyncio.run(run())


def _token_row(token_id: str) -> ApiToken:
    return _db(lambda db: db.get(ApiToken, token_id))


def _audits(action: str) -> list[AuditLog]:
    return _db(lambda db: _scalars(db, select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.at)))


async def _scalars(db, q):
    return list((await db.execute(q)).scalars().all())


# ---------------------------------------------------------------- 発行・一覧・保存の仕方


def test_create_list_and_only_hash_is_stored(client, ctx, caplog):
    caplog.set_level(logging.DEBUG)
    sess = login(client, "tok-view")
    r = create(client, sess, name="夜間の確認", scope="read", days=7)
    assert r.status_code == 201, r.text
    # 値を含む応答はキャッシュさせない
    assert r.headers["cache-control"] == "no-store" and r.headers["pragma"] == "no-cache"
    body = r.json()
    tok = body["token"]
    assert tok.startswith("ncm_") and len(tok) == 4 + 43
    assert body["prefix"] == tok[:12] and body["scope"] == "read" and body["status"] == "active"
    # 一覧には値を返さない（先頭の識別用だけ）
    listing = client.get("/api/auth/tokens", headers=sess).json()
    items = listing["items"]
    assert listing["max_days"] == settings.API_TOKEN_MAX_DAYS and listing["max_tokens"] == 10 and listing["default_days"] == 90
    mine = next(x for x in items if x["id"] == body["id"])
    assert "token" not in mine and mine["prefix"] == tok[:12] and mine["name"] == "夜間の確認"
    assert tok not in json.dumps(items)
    # 使える
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    # DB にはハッシュだけ
    row = _token_row(body["id"])
    assert row.token_hash == hashlib.sha256(tok.encode()).hexdigest() and row.prefix == tok[:12]
    db_file = Path(settings.DATABASE_URL.split("///", 1)[1])
    assert tok.encode() not in db_file.read_bytes()
    for wal in (db_file.with_name(db_file.name + "-wal"), db_file.with_name(db_file.name + "-journal")):
        if wal.exists():
            assert tok.encode() not in wal.read_bytes()
    # 監査ログ・ログにも値が出ない（先頭は出てよい）
    logs = _audits("api_token.create")
    assert logs and all(tok not in (x.detail or "") for x in logs)
    assert tok[:12] in (logs[-1].detail or "")
    assert tok not in caplog.text
    # 期限は日数どおり
    assert abs((row.expires_at - row.created_at) - timedelta(days=7)) < timedelta(seconds=5)


def test_create_requires_password_and_valid_input(client, ctx):
    sess = login(client, "tok-view")
    assert create(client, sess, password="wrong-pass").status_code == 422
    assert client.post("/api/auth/tokens", json={"name": "x", "scope": "read", "days": 1}, headers=sess).status_code == 422
    assert create(client, sess, days=0).status_code == 422
    assert create(client, sess, days=366).status_code == 422
    assert create(client, sess, scope="admin").status_code == 422
    assert create(client, sess, name="").status_code == 422
    assert create(client, sess, name="x" * 65).status_code == 422
    assert create(client, sess, name="a\nb").status_code == 422
    assert create(client, sess, name="abc\u202edef").status_code == 422  # 右から左への切り替え（書式文字）
    assert create(client, sess, name="a\u200bb").status_code == 422  # ゼロ幅スペース
    r = client.post("/api/auth/tokens", json={"name": "x", "scope": "read", "days": "7", "password": PW}, headers=sess)
    assert r.status_code == 422  # 日数は整数だけ（文字列・小数は不可）
    r = client.post("/api/auth/tokens", json={"name": "x", "scope": "read", "days": 7.5, "password": PW}, headers=sess)
    assert r.status_code == 422
    assert create(client, sess, days=365).status_code == 201
    # 失敗した発行は監査ログに残る（パスワード誤り）
    assert any(not x.success for x in _audits("api_token.create"))


def test_max_days_setting(client, ctx, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN_MAX_DAYS", 30)
    sess = login(client, "tok-view")
    r = create(client, sess, days=31)
    assert r.status_code == 422 and "30 日以内" in r.text
    assert create(client, sess, days=30).status_code == 201


def test_limit_per_user(client, ctx):
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-many", "password": PW, "role": "viewer"}, headers=admin)
    assert r.status_code == 201
    sess = login(client, "tok-many")
    ids = [create(client, sess, name=f"t{i}").json()["id"] for i in range(svc.MAX_TOKENS_PER_USER)]
    r = create(client, sess, name="over")
    assert r.status_code == 409 and "10 個まで" in r.text
    # 失効させれば作れる（失効・期限切れは数えない）
    assert client.delete(f"/api/auth/tokens/{ids[0]}", headers=sess).status_code == 204
    assert create(client, sess, name="again").status_code == 201


def test_password_failures_on_create_are_limited(client, ctx, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 3)
    sess = login(client, "tok-op")
    for _ in range(3):
        assert create(client, sess, password="wrong-pass").status_code == 422
    assert create(client, sess, password="wrong-pass").status_code == 429
    assert create(client, sess).status_code == 429  # 正しいパスワードでも、しばらくは止める


def test_token_cannot_manage_tokens_or_account(client, ctx):
    tok, tid = new_token(client, "tok-adm", scope="full")
    h = bearer(tok)
    for method, path, body in [
        ("get", "/api/auth/tokens", None),
        ("post", "/api/auth/tokens", {"name": "x", "scope": "full", "days": 1, "password": PW}),
        ("delete", f"/api/auth/tokens/{tid}", None),
        ("post", "/api/auth/change-password", {"current_password": PW, "new_password": "another-pass-123"}),
        ("post", "/api/auth/mfa/setup", None),
        ("get", "/api/users/", None),
        ("delete", f"/api/users/{ctx['ids']['tok-view']}/tokens", None),
        ("get", "/api/mail/server", None),
        ("get", "/api/notifications/me", None),
    ]:
        r = client.request(method, path, json=body, headers=h)
        assert r.status_code == 403 and r.json()["detail"] == SESSION_REQUIRED, (path, r.text)
    # パスワードは変わっていない・トークンは増えていない
    login(client, "tok-adm")
    assert _token_row(tid).revoked_at is None


def _fill(path: str) -> str:
    return (path.replace("{device_id}", "x").replace("{commit_hash}", "0000000").replace("{key}", "k")
            .replace("{task_id}", "t").replace("{session_id}", "s").replace("{token_id}", "x").replace("{user_id}", "x")
            .replace("{group_id}", "x").replace("{jump_id}", "x").replace("{profile_id}", "x").replace("{rule_id}", "x")
            .replace("{map_id}", "x").replace("{run_id}", "x").replace("{exception_id}", "x").replace("{target_id}", "x")
            .replace("{interface_id}", "1"))


@pytest.mark.parametrize("key", sorted(k for k, v in ROUTES.items() if v == S))
def test_every_session_only_route_rejects_full_admin_token(client, ctx, key, admin_full_token):
    """表で「セッションだけ」のルートは、管理者の full のトークンでも 403（ログインして操作してください）"""
    method, path = key.split(" ", 1)
    r = client.request(method, _fill(path), headers=bearer(admin_full_token))
    assert r.status_code == 403 and r.json()["detail"] == SESSION_REQUIRED, (key, r.status_code, r.text)


@pytest.fixture(scope="module")
def admin_full_token(client, ctx):
    return new_token(client, "tok-adm", scope="full", name="all-routes")[0]


@pytest.mark.parametrize("path", ["/api/auth/me", "/api/devices/", "/api/dashboard", "/api/audit/logs",
                                  "/api/configs/baselines", "/api/compliance/summary", "/api/activity/logs"])
def test_allowed_routes_work_with_token(client, ctx, path, admin_full_token):
    assert client.get(path, headers=bearer(admin_full_token)).status_code == 200


# ---------------------------------------------------------------- 範囲（read / full）とロール


def test_read_scope_is_get_only_and_read_permissions(client, ctx):
    tok, _ = new_token(client, "tok-op", scope="read")
    h = bearer(tok)
    did = ctx["device_id"]
    me = client.get("/api/auth/me", headers=h).json()
    assert me["api_token_scope"] == "read" and me["username"] == "tok-op"
    assert set(me["permissions"]) <= {p.value for p in READ_ONLY_PERMS} and "collect:run" not in me["permissions"]
    assert client.get("/api/devices/", headers=h).status_code == 200
    assert client.get(f"/api/configs/{did}/history", headers=h).status_code == 200
    # オペレーターでも、read のトークンでは収集（POST）できない
    r = client.post(f"/api/devices/{did}/collect", headers=h)
    assert r.status_code == 403 and "読み取り専用" in r.json()["detail"]
    # GET でも、閲覧ではない権限（コマンド実行の結果）は使えない
    assert client.get("/api/commands/runs", headers=h).status_code == 403
    # 閲覧の POST（検索）も read では不可
    assert client.post("/api/configs/search", json={"pattern": "x"}, headers=h).status_code == 403


def test_full_scope_follows_role_and_never_exceeds_it(client, ctx):
    did = ctx["device_id"]
    tok, _ = new_token(client, "tok-op", scope="full")
    h = bearer(tok)
    me = client.get("/api/auth/me", headers=h).json()
    assert me["api_token_scope"] == "full" and "collect:run" in me["permissions"] and "user:admin" not in me["permissions"]
    assert client.post(f"/api/devices/{did}/collect", headers=h).status_code == 200
    # ロールに無い権限は、full でも使えない
    assert client.get("/api/audit/logs", headers=h).status_code == 403
    assert client.delete(f"/api/devices/{did}", headers=h).status_code == 403
    # 閲覧者の full のトークンは、閲覧者の権限のまま
    vtok, _ = new_token(client, "tok-view", scope="full")
    assert client.post(f"/api/devices/{did}/collect", headers=bearer(vtok)).status_code == 403
    assert client.get("/api/devices/", headers=bearer(vtok)).status_code == 200


def test_role_change_revokes_tokens(client, ctx):
    """ロールを変えると全失効（昇格で以前の full のトークンが強くならないように。降格も同じ）"""
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-demote", "password": PW, "role": "viewer"}, headers=admin)
    uid = r.json()["id"]
    tok, tid = new_token(client, "tok-demote", scope="full")
    assert client.patch(f"/api/users/{uid}", json={"role": "admin"}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    assert _token_row(tid).revoked_at is not None
    log = [x for x in _audits("user.update") if x.target_id == uid][-1]
    assert json.loads(log.detail)["revoked_tokens"] == 1
    tok2, _ = new_token(client, "tok-demote", scope="full")
    assert client.patch(f"/api/users/{uid}", json={"role": "operator"}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok2)).status_code == 401
    # ロールの変更を伴わない編集（有効のまま保存）では失効させない
    tok3, _ = new_token(client, "tok-demote", scope="full")
    assert client.patch(f"/api/users/{uid}", json={"role": "operator", "is_active": True}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok3)).status_code == 200


def test_role_is_checked_on_every_request(client, ctx):
    """API を通らずにロールが変わった場合（DB を直接変えたなど）も、判定のたびにいまのロールを見る"""
    from app.models.user import User
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-direct", "password": PW, "role": "admin"}, headers=admin)
    uid = r.json()["id"]
    tok, _ = new_token(client, "tok-direct", scope="full")
    assert client.get("/api/audit/logs", headers=bearer(tok)).status_code == 200
    _db(lambda db: db.execute(update(User).where(User.id == uid).values(role="viewer")))
    assert client.get("/api/audit/logs", headers=bearer(tok)).status_code == 403
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    assert "audit:read" not in client.get("/api/auth/me", headers=bearer(tok)).json()["permissions"]


def test_me_lists_only_permissions_usable_with_token(client, ctx, admin_full_token):
    me = client.get("/api/auth/me", headers=bearer(admin_full_token)).json()
    assert me["api_token_scope"] == "full"
    perms = set(me["permissions"])
    assert {"device:read", "audit:read", "collect:run", "command:run"} <= perms
    # トークンで呼べる API が無い権限（ユーザー管理・ターミナル・自分の通知設定）は出さない
    assert not perms & {"user:admin", "terminal:use", "notify:self"}
    # ログインのセッションではロールの権限そのまま
    assert "user:admin" in client.get("/api/auth/me", headers=ctx["admin"]).json()["permissions"]


# 認証を通ったあとの処理で、テスト環境に無い Celery / Redis に届かず 500 になるのが分かっているルート（これだけ 500 を許す）。
# POST /api/devices/collect/all などの収集の起動は、client フィクスチャが Celery をモックしているので 500 にならない
EXPECTED_500 = {"GET /api/tasks/{task_id}"}


@pytest.mark.parametrize("key", sorted(k for k, v in ROUTES.items() if v == T))
def test_every_token_route_is_not_rejected_as_session_only(client, ctx, key, admin_full_token):
    """表で「トークン可」のルートは、管理者の full のトークンで「トークンでは行えません」の 403 にならない（404・422 などは可）"""
    method, path = key.split(" ", 1)
    # 例外を送出させず 500 として受け取る（例外を無条件に合格にしない）
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.request(method, _fill(path), headers=bearer(admin_full_token))
    assert r.status_code != 401, (key, r.text)
    assert not (r.status_code == 403 and r.json().get("detail") == SESSION_REQUIRED), (key, r.text)
    if key not in EXPECTED_500:
        assert r.status_code != 500, (key, r.text)


# ---------------------------------------------------------------- 失効・期限切れ


def test_self_revoke_and_other_users_token(client, ctx):
    tok, tid = new_token(client, "tok-view")
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    other = login(client, "tok-op")
    assert client.delete(f"/api/auth/tokens/{tid}", headers=other).status_code == 404  # 他人のものは消せない
    sess = login(client, "tok-view")
    assert client.delete(f"/api/auth/tokens/{tid}", headers=sess).status_code == 204
    assert client.delete(f"/api/auth/tokens/{tid}", headers=sess).status_code == 204  # 2 回目は何もしない
    r = client.get("/api/devices/", headers=bearer(tok))
    assert r.status_code == 401 and "失効" in r.json()["detail"]
    item = next(x for x in client.get("/api/auth/tokens", headers=sess).json()["items"] if x["id"] == tid)
    assert item["status"] == "revoked" and item["revoked_at"]
    assert any(x.target_id == tid for x in _audits("api_token.revoke"))


def test_admin_list_and_revoke_all(client, ctx):
    admin = ctx["admin"]
    uid = ctx["ids"]["tok-op"]
    tok, tid = new_token(client, "tok-op", name="admin-view")
    items = client.get(f"/api/users/{uid}/tokens", headers=admin).json()
    assert any(x["id"] == tid for x in items) and tok not in json.dumps(items)
    users = client.get("/api/users/", headers=admin).json()
    assert next(u for u in users if u["id"] == uid)["api_tokens"] >= 1
    r = client.delete(f"/api/users/{uid}/tokens", headers=admin)
    assert r.status_code == 200 and r.json()["revoked_tokens"] >= 1
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    assert next(u for u in client.get("/api/users/", headers=admin).json() if u["id"] == uid)["api_tokens"] == 0
    assert _audits("api_token.revoke_all")[-1].target_id == uid
    # ログインはそのまま
    login(client, "tok-op")


def test_force_logout_revokes_tokens(client, ctx):
    admin = ctx["admin"]
    tok, tid = new_token(client, "tok-view", name="kick")
    r = client.post(f"/api/users/{ctx['ids']['tok-view']}/logout", headers=admin)
    assert r.status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    assert _token_row(tid).revoked_at is not None
    assert "revoked_tokens" in (_audits("user.logout")[-1].detail or "")


def test_deactivate_and_delete_user(client, ctx):
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-off", "password": PW, "role": "operator"}, headers=admin)
    uid = r.json()["id"]
    tok, tid = new_token(client, "tok-off")
    assert client.patch(f"/api/users/{uid}", json={"is_active": False}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    # 有効に戻しても、無効化の前のトークンは使えない（失効済み）
    assert client.patch(f"/api/users/{uid}", json={"is_active": True}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    assert _token_row(tid).revoked_at is not None
    # 削除するとトークンも消える
    tok2, tid2 = new_token(client, "tok-off")
    assert client.delete(f"/api/users/{uid}", headers=admin).status_code == 204
    assert client.get("/api/devices/", headers=bearer(tok2)).status_code == 401
    assert _token_row(tid2) is None


def test_inactive_user_token_is_rejected_even_if_not_revoked(client, ctx):
    """失効の処理を通らずに無効になった場合（DB を直接変えたなど）も、毎回 is_active を見る"""
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-inact", "password": PW, "role": "viewer"}, headers=admin)
    uid = r.json()["id"]
    tok, _ = new_token(client, "tok-inact")
    from app.models.user import User
    _db(lambda db: db.execute(update(User).where(User.id == uid).values(is_active=False)))
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401


def test_password_change_by_self_keeps_tokens_but_admin_reset_revokes(client, ctx):
    admin = ctx["admin"]
    r = client.post("/api/users/", json={"username": "tok-pw", "password": PW, "role": "viewer"}, headers=admin)
    uid = r.json()["id"]
    tok, _ = new_token(client, "tok-pw")
    sess = login(client, "tok-pw")
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-999"},
                    headers=sess)
    assert r.status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200  # 本人の変更では失効させない
    assert client.patch(f"/api/users/{uid}", json={"password": "reset-pass-0000"}, headers=admin).status_code == 200
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401  # 管理者のリセットでは失効


def test_expired_token_and_purge(client, ctx):
    tok, tid = new_token(client, "tok-view", name="old")
    past = utcnow() - timedelta(seconds=1)
    _db(lambda db: db.execute(update(ApiToken).where(ApiToken.id == tid).values(expires_at=past)))
    r = client.get("/api/devices/", headers=bearer(tok))
    assert r.status_code == 401 and "期限" in r.json()["detail"]
    sess = login(client, "tok-view")
    assert next(x for x in client.get("/api/auth/tokens", headers=sess).json()["items"] if x["id"] == tid)["status"] == "expired"
    # 期限切れから 30 日までは一覧に残し、過ぎたら毎日の掃除で消す
    assert _db(lambda db: svc.purge_old(db)) >= 0 and _token_row(tid) is not None
    long_ago = utcnow() - timedelta(days=svc.KEEP_DAYS + 1)
    _db(lambda db: db.execute(update(ApiToken).where(ApiToken.id == tid).values(expires_at=long_ago)))
    assert _db(lambda db: svc.purge_old(db)) >= 1 and _token_row(tid) is None


def test_worker_purge_includes_tokens(client, ctx):
    from app import worker
    _, tid = new_token(client, "tok-view", name="worker-purge")
    long_ago = utcnow() - timedelta(days=svc.KEEP_DAYS + 1)
    _db(lambda db: db.execute(update(ApiToken).where(ApiToken.id == tid).values(revoked_at=long_ago)))
    assert worker.purge_audit_logs.apply().get()["api_tokens"] >= 1
    assert _token_row(tid) is None


def test_disabled_setting(client, ctx, monkeypatch):
    tok, _ = new_token(client, "tok-view", name="disabled")
    monkeypatch.setattr(settings, "API_TOKENS_ENABLED", False)
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 401
    assert create(client, login(client, "tok-view")).status_code == 409


# ---------------------------------------------------------------- 記録（最後に使った日時・監査ログ）


def test_last_used_is_throttled(client, ctx):
    tok, tid = new_token(client, "tok-view", name="last-used")
    assert _token_row(tid).last_used_at is None
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    first = _token_row(tid)
    assert first.last_used_at is not None and first.last_used_ip == "testclient"
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    assert _token_row(tid).last_used_at == first.last_used_at  # 1 分以内は書かない
    two_min = utcnow() - timedelta(minutes=2)
    _db(lambda db: db.execute(update(ApiToken).where(ApiToken.id == tid).values(last_used_at=two_min)))
    assert client.get("/api/devices/", headers=bearer(tok)).status_code == 200
    assert _token_row(tid).last_used_at > two_min


def test_audit_log_marks_token(client, ctx):
    did = ctx["device_id"]
    tok, _ = new_token(client, "tok-op", scope="full", name="collector")
    assert client.post(f"/api/devices/{did}/collect", headers=bearer(tok)).status_code == 200
    log = [x for x in _audits("collect.run") if x.username == "tok-op"][-1]
    assert json.loads(log.detail)["via_token"] == "collector"
    assert tok not in log.detail
    # ログインのセッションからの操作には付かない
    assert client.post(f"/api/devices/{did}/collect", headers=login(client, "tok-op")).status_code == 200
    log = [x for x in _audits("collect.run") if x.username == "tok-op"][-1]
    assert "via_token" not in (log.detail or "")


# ---------------------------------------------------------------- 不正なトークン（総当たり）


@pytest.fixture
def ip(monkeypatch):
    """接続元 IP は TestClient では変えられないため、client_ip を差し替える（ログインと API トークンの両方）"""
    from app.api import auth
    from app.services import audit
    fake = lambda req: req.headers.get("x-test-ip", "testclient") if req else None  # noqa: E731
    monkeypatch.setattr(audit, "client_ip", fake)
    monkeypatch.setattr(auth, "client_ip", fake)
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 5)
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 3)


def _bad(i: int) -> str:
    return "ncm_" + ("A" * 42) + str(i % 10)


def test_invalid_tokens_are_limited_without_blocking_login_or_good_tokens(client, ctx, ip):
    good, _ = new_token(client, "tok-view", name="brute")
    h = {"x-test-ip": "198.51.100.7"}
    for i in range(4):
        r = client.get("/api/devices/", headers={**h, **bearer(_bad(i))})
        assert r.status_code == 401 and _bad(i) not in r.text
    assert client.get("/api/devices/", headers={**h, **bearer("ncm_short")}).status_code == 401  # 形式違いも数える（5 回目）
    # (c) 上限（5 回）を超えた接続元からの不正なトークンは 429
    r = client.get("/api/devices/", headers={**h, **bearer(_bad(9))})
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert any("API トークン" in (x.detail or "") for x in _audits("auth.login_locked"))
    # (b) 正しいトークンは、ロック中の接続元からでも通す
    assert client.get("/api/devices/", headers={**h, **bearer(good)}).status_code == 200
    # (a) 同じ接続元のログインは止めない（別のカウンタ）
    r = client.post("/api/auth/token", data={"username": "tok-view", "password": PW}, headers=h)
    assert r.status_code == 200, r.text


def test_login_lock_does_not_block_tokens(client, ctx, ip):
    good, _ = new_token(client, "tok-view", name="login-locked")
    h = {"x-test-ip": "198.51.100.8"}
    for i in range(6):
        client.post("/api/auth/token", data={"username": f"nobody{i}", "password": "x"}, headers=h)
    assert client.post("/api/auth/token", data={"username": "tok-view", "password": PW}, headers=h).status_code == 429
    # ログインの上限に達した接続元でも、正しいトークンも、不正なトークン（401）もログインのロックの影響を受けない
    assert client.get("/api/devices/", headers={**h, **bearer(good)}).status_code == 200
    assert client.get("/api/devices/", headers={**h, **bearer(_bad(1))}).status_code == 401


def test_revoked_or_deleted_tokens(client, ctx, ip):
    """失効・期限切れ（行が残っているもの）は数えない。掃除で行が消えたトークンは不正なトークンとして数える"""
    tok, tid = new_token(client, "tok-view", name="revoked-many")
    client.delete(f"/api/auth/tokens/{tid}", headers=login(client, "tok-view"))
    h = {"x-test-ip": "198.51.100.20", **bearer(tok)}
    for _ in range(8):
        assert client.get("/api/devices/", headers=h).status_code == 401
    long_ago = utcnow() - timedelta(days=svc.KEEP_DAYS + 1)
    _db(lambda db: db.execute(update(ApiToken).where(ApiToken.id == tid).values(revoked_at=long_ago)))
    _db(lambda db: svc.purge_old(db))
    codes = [client.get("/api/devices/", headers=h).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[-1] == 429


def test_redis_down_does_not_block_tokens(client, ctx, ip, monkeypatch):
    class Down:
        async def ttl(self, *a):
            raise RedisConnectionError("down")
        set = delete = decrby = ttl

        def pipeline(self, **kw):
            raise RedisConnectionError("down")

    good, _ = new_token(client, "tok-view", name="redis-down")
    monkeypatch.setattr(login_limit, "_client", Down())
    h = {"x-test-ip": "198.51.100.30"}
    for _ in range(8):
        assert client.get("/api/devices/", headers={**h, **bearer("ncm_" + "B" * 43)}).status_code == 401
    assert client.get("/api/devices/", headers={**h, **bearer(good)}).status_code == 200


# ---------------------------------------------------------------- WebSocket


def _ws_close_code(client, path, token):
    with client.websocket_connect(path) as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        with pytest.raises(WebSocketDisconnect) as e:
            while True:
                ws.receive_text()
        return e.value.code


def test_websockets_reject_api_tokens(client, ctx):
    tok, _ = new_token(client, "tok-adm", scope="full", name="ws")
    assert _ws_close_code(client, f"/api/terminal/ws/{ctx['device_id']}", tok) == 4401
    assert _ws_close_code(client, "/api/ping/ws", tok) == 4401


def test_mfa_user_creates_token_from_mfa_session(client, ctx):
    """2 段階認証を設定した人は、2 段階認証を通ったログインから発行する（途中の印・トークンからは発行できない）"""
    from app.core import totp
    admin = ctx["admin"]
    assert client.post("/api/users/", json={"username": "tok-mfa", "password": PW, "role": "operator"},
                       headers=admin).status_code == 201
    sess = login(client, "tok-mfa")
    secret = client.post("/api/auth/mfa/setup", headers=sess).json()["secret"]
    r = client.post("/api/auth/mfa/enable", json={"code": totp.code_at(secret, totp.current_step())}, headers=sess)
    recovery = r.json()["recovery_codes"]
    first = client.post("/api/auth/token", data={"username": "tok-mfa", "password": PW}).json()
    assert first["mfa_required"] and first["access_token"] is None
    # パスワードだけ通った途中の印では発行できない
    assert create(client, bearer(first["mfa_token"])).status_code == 401
    r = client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": recovery[0]})
    mfa_sess = bearer(r.json()["access_token"])
    r = create(client, mfa_sess, scope="full")
    assert r.status_code == 201
    tok = r.json()["token"]
    # トークンでは 2 段階認証の解除・予備コードの作り直しはできない
    assert client.post("/api/auth/mfa/disable", json={"password": PW, "code": recovery[1]},
                       headers=bearer(tok)).status_code == 403
    assert client.post("/api/auth/mfa/recovery-codes", json={"code": "000000"}, headers=bearer(tok)).status_code == 403
    assert client.get("/api/auth/me", headers=mfa_sess).json()["mfa_enabled"] is True
