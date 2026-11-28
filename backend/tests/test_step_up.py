"""本人の確認のやり直し（step-up）・照合の回数の制限・セッションの失効（#28・#29、ログアウト）

攻撃のシナリオ: 漏れたログインのトークン（JWT）だけを持つ攻撃者が、
- パスワード・確認コードを照合する API で総当たりする（#28）
- 自分の認証アプリを登録して本人を締め出す・管理者の重い操作をパスワードなしで行う（#29）
- 本人がログアウト・2 段階認証の設定をしても、そのトークンを使い続ける（#29・ログアウト）
"""
import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core import totp
from app.main import app

ADMIN_PW = "initial-pass-123"
PW = "password-1234"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(c, username, password=PW) -> dict:
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin(client):
    return login(client, "admin", ADMIN_PW)


@pytest.fixture
def user(client, admin):
    """使い捨ての利用者（作ったものはテストの終わりに消す）"""
    name = f"su-{uuid.uuid4().hex[:6]}"
    uid = client.post("/api/users/", json={"username": name, "password": PW, "role": "operator"}, headers=admin).json()["id"]
    yield {"id": uid, "name": name}
    client.delete(f"/api/users/{uid}", headers=admin)


def _audits(client, admin, action, username=None):
    params = {"action": action, **({"username": username} if username else {})}
    return client.get("/api/audit/logs", params=params, headers=admin).json()["items"]


def _enable_mfa(client, h) -> tuple[str, list[str], dict]:
    """（秘密鍵, 予備コード, 有効にしたあとの新しいトークンのヘッダー）"""
    s = client.post("/api/auth/mfa/setup", json={"password": PW}, headers=h).json()
    r = client.post("/api/auth/mfa/enable", json={"code": totp.code_at(s["secret"], totp.current_step())}, headers=h)
    assert r.status_code == 200, r.text
    return s["secret"], r.json()["recovery_codes"], {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------- #28 照合の回数の制限


def test_change_password_is_rate_limited(client, admin, user):
    """現在のパスワードの総当たりは、ログインと同じ回数（LOGIN_MAX_FAILURES）で止まる。止まると正しい値でも 429"""
    h = login(client, user["name"])
    codes = [client.post("/api/auth/change-password", json={"current_password": f"guess-{i:04d}x",
                                                             "new_password": "changed-pass-000"}, headers=h).status_code
             for i in range(7)]
    assert codes[:5] == [400] * 5 and codes[5] == 429, codes
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-000"},
                    headers=h)
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert client.get("/api/auth/me", headers=h).status_code == 200  # 変わっていない（トークンも生きている）
    # 誤りは監査ログに残り、ロックの開始も残る
    fails = [x for x in _audits(client, admin, "auth.password_change", user["name"]) if not x["success"]]
    assert len(fails) == 5 and all("パスワード誤り" in json.dumps(x["detail"], ensure_ascii=False) for x in fails)
    locked = _audits(client, admin, "auth.login_locked", user["name"])
    assert locked and "パスワード変更" in json.dumps(locked[0]["detail"], ensure_ascii=False)


def test_step_up_success_does_not_clear_earlier_failures(client, user):
    """M2': 本人の確認に成功しても、それまでの誤りの回数は消さない（成功の 1 回分だけ戻す）。
    誤り 4 回 → 成功 → 誤りを続けると、上限（5 回）を超えた時点で 429"""
    h = login(client, user["name"])

    def wrong():
        return client.post("/api/auth/change-password", json={"current_password": "wrong-pass-x",
                                                              "new_password": "changed-pass-000"}, headers=h).status_code
    assert [wrong() for _ in range(4)] == [400] * 4
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-001"},
                    headers=h)
    assert r.status_code == 200
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert [wrong(), wrong()] == [400, 429]


def test_correct_step_ups_alone_do_not_lock(client, user):
    """正しい操作だけを続ける人は止めない（成功の分は数えない）"""
    h = login(client, user["name"])
    for i in range(8):
        r = client.post("/api/auth/tokens", json={"name": f"s{i}", "scope": "read", "days": 1, "password": PW}, headers=h)
        assert r.status_code in (201, 409), r.text


@pytest.mark.parametrize("success", ["token", "token_409", "mfa_login_password"])
def test_alternating_success_cannot_reset_code_bruteforce(client, user, monkeypatch, success):
    """M2': 確認コードの誤りと、知っているパスワードでの成功（トークンの発行・個数の上限で 409 でも／2 段階認証の人の
    ログインのパスワード段階）を交互に送っても、回数は消えず、総当たりは 429 で止まる"""
    from app.services import api_tokens
    _, _, h = _enable_mfa(client, login(client, user["name"]))
    if success == "token_409":
        monkeypatch.setattr(api_tokens, "MAX_TOKENS_PER_USER", 0)
    statuses = []
    for cycle in range(4):
        for i in range(4):
            statuses.append(client.post("/api/auth/mfa/recovery-codes", json={"code": f"{cycle * 10 + i:06d}"},
                                        headers=h).status_code)
        if success == "mfa_login_password":
            r = client.post("/api/auth/token", data={"username": user["name"], "password": PW})
            statuses.append(("login", r.status_code))
        else:
            r = client.post("/api/auth/tokens", json={"name": f"r{cycle}", "scope": "read", "days": 1, "password": PW},
                            headers=h)
            statuses.append(("tok", r.status_code))
    assert 429 in statuses, statuses
    assert statuses.index(429) <= 6, statuses  # 最初の数回で止まる


def test_recovery_codes_are_rate_limited(client, admin, user):
    """予備コードの作り直し（6 桁のコードだけで確認）の総当たりを止める"""
    _, _, h = _enable_mfa(client, login(client, user["name"]))
    codes = [client.post("/api/auth/mfa/recovery-codes", json={"code": f"{i:06d}"}, headers=h).status_code
             for i in range(1, 8)]
    assert 429 in codes and codes[0] == 422, codes
    fails = [x for x in _audits(client, admin, "auth.mfa_recovery", user["name"]) if not x["success"]]
    assert fails and "確認コード誤り" in json.dumps(fails[0]["detail"], ensure_ascii=False)


def test_mfa_disable_is_rate_limited(client, user):
    _, recovery, h = _enable_mfa(client, login(client, user["name"]))
    codes = [client.post("/api/auth/mfa/disable", json={"password": f"guess-{i:04d}x", "code": "123456"},
                         headers=h).status_code for i in range(7)]
    assert 429 in codes and codes[0] == 422, codes
    # 止まっている間は、正しいパスワードと予備コードでも解除できない
    assert client.post("/api/auth/mfa/disable", json={"password": PW, "code": recovery[0]}, headers=h).status_code == 429
    assert client.get("/api/auth/me", headers=h).json()["mfa_enabled"] is True


def test_mfa_setup_needs_password_and_is_rate_limited(client, user):
    """#29: 漏れたトークンだけでは、攻撃者が自分の認証アプリを登録できない"""
    h = login(client, user["name"])
    assert client.post("/api/auth/mfa/setup", headers=h).status_code == 422
    codes = [client.post("/api/auth/mfa/setup", json={"password": f"guess-{i:04d}x"}, headers=h).status_code
             for i in range(7)]
    assert 429 in codes, codes
    assert client.get("/api/auth/me", headers=h).json()["mfa_enabled"] is False


# ---------------------------------------------------------------- #29 管理者の重い操作


def test_admin_heavy_operations_need_admin_password(client, admin, user):
    name = f"su-adm-{uuid.uuid4().hex[:6]}"
    body = {"username": name, "password": PW, "role": "admin"}
    # 管理者のユーザーの作成
    assert client.post("/api/users/", json=body, headers=admin).status_code == 422
    assert client.post("/api/users/", json={**body, "confirm_password": "wrong-pass-x"}, headers=admin).status_code == 422
    assert name not in [u["username"] for u in client.get("/api/users/", headers=admin).json()]
    r = client.post("/api/users/", json={**body, "confirm_password": ADMIN_PW}, headers=admin)
    assert r.status_code == 201
    adm2 = r.json()["id"]
    # 閲覧者・オペレーターの作成には要らない（今までどおり）
    assert user["id"]
    # 他人のパスワードのリセット
    uid = user["id"]
    assert client.patch(f"/api/users/{uid}", json={"password": "reset-pass-0000"}, headers=admin).status_code == 422
    assert client.patch(f"/api/users/{uid}", json={"password": "reset-pass-0000", "confirm_password": "wrong-pass-x"},
                        headers=admin).status_code == 422
    login(client, user["name"])  # 変わっていない
    assert client.patch(f"/api/users/{uid}", json={"password": "reset-pass-0000", "confirm_password": ADMIN_PW},
                        headers=admin).status_code == 200
    login(client, user["name"], "reset-pass-0000")
    # 管理者への変更（昇格）。降格・無効化には要らない
    assert client.patch(f"/api/users/{uid}", json={"role": "admin"}, headers=admin).status_code == 422
    assert client.patch(f"/api/users/{uid}", json={"role": "admin", "confirm_password": ADMIN_PW},
                        headers=admin).status_code == 200
    assert client.patch(f"/api/users/{uid}", json={"role": "viewer"}, headers=admin).status_code == 200
    # 誤りは監査ログに残る（パスワードの値は残さない）
    fails = [x for x in _audits(client, admin, "user.update") if not x["success"] and x["target_id"] == uid]
    assert fails and "wrong-pass-x" not in json.dumps(fails, ensure_ascii=False)
    assert client.delete(f"/api/users/{adm2}", headers=admin).status_code == 204


def test_admin_confirmation_is_rate_limited(client, admin, user):
    """管理者のトークンだけを持つ攻撃者が、管理者のパスワードを総当たりできない"""
    me = client.post("/api/users/", json={"username": f"su-a2-{uuid.uuid4().hex[:6]}", "password": PW, "role": "admin",
                                          "confirm_password": ADMIN_PW}, headers=admin).json()
    h = login(client, me["username"])
    codes = [client.patch(f"/api/users/{user['id']}", json={"password": "reset-pass-0000",
                                                            "confirm_password": f"guess-{i:04d}x"}, headers=h).status_code
             for i in range(7)]
    assert 429 in codes, codes
    assert client.patch(f"/api/users/{user['id']}", json={"password": "reset-pass-0000", "confirm_password": PW},
                        headers=h).status_code == 429
    login(client, user["name"])  # リセットされていない
    assert client.delete(f"/api/users/{me['id']}", headers=admin).status_code == 204


def test_admin_cannot_reset_own_mfa(client, admin):
    """自分を対象にした mfa-reset は拒否する（管理者のトークンだけで自分の 2 段階認証を外させない）"""
    me = client.post("/api/users/", json={"username": f"su-a3-{uuid.uuid4().hex[:6]}", "password": PW, "role": "admin",
                                          "confirm_password": ADMIN_PW}, headers=admin).json()
    _, _, h = _enable_mfa(client, login(client, me["username"]))
    r = client.post(f"/api/users/{me['id']}/mfa-reset", json={"confirm_password": PW}, headers=h)
    assert r.status_code == 400 and "2 段階認証" in r.json()["detail"]
    assert client.get("/api/auth/me", headers=h).json()["mfa_enabled"] is True
    assert client.delete(f"/api/users/{me['id']}", headers=admin).status_code == 204


def test_admin_rows_are_locked_when_counting():
    """#29: 「有効な管理者が 0 人になる」かの確認で、管理者の行を FOR UPDATE でロックする（同時の降格・無効化・削除に耐える）"""
    from sqlalchemy.dialects import postgresql

    from app.api import users

    sql = str(users.lock_admins_stmt().compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql and "ORDER BY" in sql
    # 対象の人も含めてロックする（除くと、互いを降格する 2 つの操作が別の行をロックして両方通る）
    assert "!=" not in sql and "<>" not in sql


def test_admin_count_uses_the_lock(monkeypatch):
    from app.api import users

    called = []
    real = users.lock_admins_stmt
    monkeypatch.setattr(users, "lock_admins_stmt", lambda: called.append(1) or real())
    with TestClient(app) as c:
        h = login(c, "admin", ADMIN_PW)
        me = c.get("/api/auth/me", headers=h).json()
        uid = c.post("/api/users/", json={"username": f"su-a4-{uuid.uuid4().hex[:6]}", "password": PW, "role": "admin",
                                          "confirm_password": ADMIN_PW}, headers=h).json()["id"]
        assert c.patch(f"/api/users/{uid}", json={"role": "viewer"}, headers=h).status_code == 200
        assert called
        assert c.patch(f"/api/users/{me['id']}", json={"role": "viewer"}, headers=h).status_code == 400
        assert c.delete(f"/api/users/{uid}", headers=h).status_code == 204


# ---------------------------------------------------------------- #29 セッションの失効・ログアウト


def test_mfa_enable_revokes_earlier_sessions(client, user):
    """設定する前に発行した（攻撃者が持っているかもしれない）トークンは、設定の後は使えない"""
    other = login(client, user["name"])  # 別の端末（または攻撃者）
    _, _, h = _enable_mfa(client, login(client, user["name"]))
    assert client.get("/api/auth/me", headers=other).status_code == 401
    assert client.get("/api/auth/me", headers=h).status_code == 200


def test_change_password_can_revoke_api_tokens(client, user):
    h = login(client, user["name"])
    r = client.post("/api/auth/tokens", json={"name": "s", "scope": "read", "days": 1, "password": PW}, headers=h)
    tok = {"Authorization": f"Bearer {r.json()['token']}"}
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-002",
                                                       "revoke_api_tokens": True}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/devices/", headers=tok).status_code == 401


def test_logout_revokes_only_this_session(client, admin, user):
    a = login(client, user["name"])
    b = login(client, user["name"])
    r = client.post("/api/auth/tokens", json={"name": "s", "scope": "read", "days": 1, "password": PW}, headers=a)
    tok = {"Authorization": f"Bearer {r.json()['token']}"}
    r = client.post("/api/auth/logout", headers=a)
    assert r.status_code == 200 and r.json()["scope"] == "session"
    assert client.get("/api/auth/me", headers=a).status_code == 401  # ログアウトしたトークンは使えない
    assert client.get("/api/auth/me", headers=b).status_code == 200  # ほかの端末はそのまま
    assert client.get("/api/devices/", headers=tok).status_code == 200  # API トークンもそのまま
    # すぐにログインし直せる（同じ秒に発行しても別のトークン）
    c2 = login(client, user["name"])
    assert client.get("/api/auth/me", headers=c2).status_code == 200
    assert _audits(client, admin, "auth.logout", user["name"])


def test_logout_falls_back_to_all_devices_when_redis_fails(client, user, monkeypatch):
    """失効を Redis に書けないときは、ログアウトしたつもりのトークンが使えたままにならないよう、すべての端末から切る"""
    from app.services import sessions

    async def fail(*a, **k):
        return False
    monkeypatch.setattr(sessions, "revoke", fail)
    a, b = login(client, user["name"]), login(client, user["name"])
    r = client.post("/api/auth/logout", headers=a)
    assert r.status_code == 200 and r.json()["scope"] == "all"
    assert client.get("/api/auth/me", headers=a).status_code == 401
    assert client.get("/api/auth/me", headers=b).status_code == 401


def test_revocation_check_does_not_block_when_redis_is_down(client, user, monkeypatch):
    """Redis が止まっても、ログイン中の人は使える（login_limit と同じ方針）"""
    from redis.exceptions import ConnectionError as RedisConnectionError

    from app.services import login_limit, sessions

    h = login(client, user["name"])

    class Down:
        async def exists(self, *a, **k):
            raise RedisConnectionError("down")
        get = set = eval = exists  # 無操作の確認（services/idle.py）も同じ Redis を使う
    monkeypatch.setattr(login_limit, "_client", Down())
    monkeypatch.setattr(sessions, "_skip_until", 0.0)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    monkeypatch.setattr(sessions, "_skip_until", 0.0)


def test_logout_all(client, admin, user):
    a, b = login(client, user["name"]), login(client, user["name"])
    r = client.post("/api/auth/tokens", json={"name": "s", "scope": "read", "days": 1, "password": PW}, headers=a)
    tok = {"Authorization": f"Bearer {r.json()['token']}"}
    r = client.post("/api/auth/logout-all", json={}, headers=a)
    assert r.status_code == 200 and r.json()["scope"] == "all"
    assert client.get("/api/auth/me", headers=a).status_code == 401
    assert client.get("/api/auth/me", headers=b).status_code == 401
    assert client.get("/api/devices/", headers=tok).status_code == 200  # 選ばなければ API トークンは残す
    c2 = login(client, user["name"])
    r = client.post("/api/auth/logout-all", json={"revoke_api_tokens": True}, headers=c2)
    assert r.json()["revoked_tokens"] == 1
    assert client.get("/api/devices/", headers=tok).status_code == 401
    assert _audits(client, admin, "auth.logout_all", user["name"])


def _open_ping(client, token):
    ws = client.websocket_connect("/api/ping/ws")
    ws.__enter__()
    ws.send_text(json.dumps({"type": "auth", "token": token}))
    ws.send_text(json.dumps({"type": "start", "keys": [], "interval": 1}))
    assert json.loads(ws.receive_text())["type"] == "targets"  # 認証と登録が済んだ
    return ws


def _closed_code(ws, max_ticks: int = 5) -> int:
    """切られたときの close コード。切られないまま（tick が 1 秒ごとに届き続ける）なら、数回で失敗にする（止まったままにしない）"""
    with pytest.raises(WebSocketDisconnect) as e:
        for _ in range(max_ticks):
            ws.receive_text()
        ws.close()
        ws.__exit__(None, None, None)
        pytest.fail("WebSocket が切られませんでした")
    ws.__exit__(None, None, None)
    return e.value.code


@pytest.mark.parametrize("how", ["force_logout", "logout", "logout_all", "password_change"])
def test_ping_websocket_is_closed_on_revocation(client, admin, user, how):
    """#29: Ping 監視の WebSocket も、ターミナルと同じく強制ログアウト・ログアウトなどで切れる"""
    h = login(client, user["name"])
    tok = h["Authorization"].split()[1]
    ws = _open_ping(client, tok)
    other = _open_ping(client, login(client, user["name"])["Authorization"].split()[1])  # 別の端末
    if how == "force_logout":
        assert client.post(f"/api/users/{user['id']}/logout", headers=admin).status_code == 200
    elif how == "logout":
        assert client.post("/api/auth/logout", headers=h).status_code == 200
    elif how == "logout_all":
        assert client.post("/api/auth/logout-all", json={}, headers=h).status_code == 200
    else:
        assert client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-003"},
                           headers=h).status_code == 200
    # 本人の操作で新しいトークンを返したとき（パスワード変更）は、その操作に使ったトークンの接続は 4409（つなぎ直せる）
    assert _closed_code(ws) == (4409 if how == "password_change" else 4401)
    if how == "logout":
        # 本人のログアウトは、そのトークンで開いたものだけ切る
        other.send_text(json.dumps({"type": "start", "keys": [], "interval": 1}))
        assert json.loads(other.receive_text())["type"] in ("targets", "tick")
        other.close()
        other.__exit__(None, None, None)
    else:
        assert _closed_code(other) == 4401
    # 登録は後片付けで消える
    from app.api import terminal

    async def wait_unregistered():
        for _ in range(50):
            if user["id"] not in terminal._live:
                return True
            await asyncio.sleep(0.05)
        return False
    assert asyncio.run(wait_unregistered())


def test_role_change_keeps_ping_websocket(client, admin, user):
    """ロールの変更ではターミナルだけを切る（Ping監視はどのロールでも使えるので、ログインと同じく切らない）"""
    ws = _open_ping(client, login(client, user["name"])["Authorization"].split()[1])
    assert client.patch(f"/api/users/{user['id']}", json={"role": "viewer"}, headers=admin).status_code == 200
    ws.send_text(json.dumps({"type": "start", "keys": [], "interval": 1}))
    assert json.loads(ws.receive_text())["type"] in ("targets", "tick")
    ws.close()
    ws.__exit__(None, None, None)


def test_logout_closes_terminal_opened_with_that_token(client, admin, user):
    """本人のログアウトで、そのトークンで開いたターミナルも切る（記録の終了理由は「本人のログアウトで切断」）"""
    import fake_sshd
    from test_rbac import _closed_with, _end_reason, _open_terminal

    port, _, _ = fake_sshd.start()
    did = client.post("/api/devices/", json=dict(name=f"su-sw-{port}", hostname="127.0.0.1", port=port,
                                                 platform="cisco_ios", username="admin", password="pw"),
                      headers=admin).json()["id"]
    try:
        h = login(client, user["name"])
        ws = _open_terminal(client, did, h["Authorization"].split()[1])
        assert client.post("/api/auth/logout", headers=h).json()["closed_terminals"] == 1
        assert _closed_with(ws, "ログアウト")
        ws.__exit__(None, None, None)
        assert _end_reason(client, admin, user["name"]) == "本人のログアウトで切断"
    finally:
        client.delete(f"/api/devices/{did}", headers=admin)


def test_mfa_enable_closes_own_ping_with_refresh_code(client, user):
    """H1: 本人が 2 段階認証を設定すると、その操作に使ったトークンの Ping 監視は 4409（画面はトークンを消さずにつなぎ直す）。
    ほかの端末（別のトークン）のものは 4401。応答（予備コード・新しいトークン）は切る前に返す"""
    h = login(client, user["name"])
    tok = h["Authorization"].split()[1]
    mine = _open_ping(client, tok)
    other = _open_ping(client, login(client, user["name"])["Authorization"].split()[1])
    s = client.post("/api/auth/mfa/setup", json={"password": PW}, headers=h).json()
    r = client.post("/api/auth/mfa/enable", json={"code": totp.code_at(s["secret"], totp.current_step())}, headers=h)
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10 and r.json()["access_token"]
    assert _closed_code(mine) == 4409
    assert _closed_code(other) == 4401
    # 新しいトークンでつなぎ直せる
    again = _open_ping(client, r.json()["access_token"])
    again.close()
    again.__exit__(None, None, None)


def test_step_up_failures_do_not_lock_the_whole_source(client, admin, user, monkeypatch):
    """M2: 本人の確認の誤りは「利用者 × 接続元」だけで数える（同じ NAT の内側のほかの人のログインは止めない）"""
    from app.core.config import settings
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 3)
    h = login(client, user["name"])
    codes = [client.post("/api/auth/change-password", json={"current_password": f"guess-{i:04d}x",
                                                             "new_password": "changed-pass-000"}, headers=h).status_code
             for i in range(7)]
    assert 429 in codes
    login(client, "admin", ADMIN_PW)  # 同じ接続元のほかの人は入れる（接続元の上限 3 回を超えて誤っても）
    # 本人は、その接続元からのログインも止まる（ログインと同じカウンタ）
    assert client.post("/api/auth/token", data={"username": user["name"], "password": PW}).status_code == 429


def test_reactivating_an_admin_needs_confirmation(client, admin):
    """M3: 管理者のロールのまま無効になっている人を有効に戻すのは、昇格と同じく管理者のパスワードが要る"""
    me = client.post("/api/users/", json={"username": f"su-a5-{uuid.uuid4().hex[:6]}", "password": PW, "role": "admin",
                                          "confirm_password": ADMIN_PW}, headers=admin).json()
    uid = me["id"]
    assert client.patch(f"/api/users/{uid}", json={"is_active": False}, headers=admin).status_code == 200  # 無効化は要らない
    assert client.patch(f"/api/users/{uid}", json={"is_active": True}, headers=admin).status_code == 422
    assert client.patch(f"/api/users/{uid}", json={"role": "admin", "is_active": True}, headers=admin).status_code == 422
    assert client.patch(f"/api/users/{uid}", json={"is_active": True, "confirm_password": ADMIN_PW},
                        headers=admin).status_code == 200
    # 無効のまま閲覧者に変えてから有効に戻すのは要らない
    assert client.patch(f"/api/users/{uid}", json={"is_active": False}, headers=admin).status_code == 200
    assert client.patch(f"/api/users/{uid}", json={"role": "viewer", "is_active": True}, headers=admin).status_code == 200
    assert client.delete(f"/api/users/{uid}", headers=admin).status_code == 204


def test_revocation_warning_is_logged_once(client, user, monkeypatch, caplog):
    """M4: Redis に届かない間、警告は 1 回だけ（毎要求には出さない）"""
    from redis.exceptions import ConnectionError as RedisConnectionError

    from app.services import login_limit, sessions

    h = login(client, user["name"])

    class Down:
        async def exists(self, *a, **k):
            raise RedisConnectionError("down")
        get = set = eval = exists  # 無操作の確認（services/idle.py）も同じ Redis を使う
    monkeypatch.setattr(login_limit, "_client", Down())
    with caplog.at_level("WARNING", logger="app.services.sessions"):
        for _ in range(3):
            monkeypatch.setattr(sessions, "_skip_until", 0.0)  # 休みの期間を過ぎたことにする
            assert client.get("/api/auth/me", headers=h).status_code == 200
    assert len([r for r in caplog.records if "確認ができません" in r.getMessage()]) == 1


def test_other_devices_are_closed_before_the_response(client, user, monkeypatch):
    """L-a: ほかの端末の接続は応答の前に 4401 で切る（後回しの処理が動かない経路でも残さない）。
    操作に使ったトークンの接続だけを、応答のあと（BackgroundTasks）で 4409 にする"""
    from starlette.background import BackgroundTasks
    h = login(client, user["name"])
    mine = _open_ping(client, h["Authorization"].split()[1])
    other = _open_ping(client, login(client, user["name"])["Authorization"].split()[1])
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, *a, **k: None)  # 後回しの処理が動かない
    assert client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-004"},
                       headers=h).status_code == 200
    assert _closed_code(other) == 4401
    mine.send_text(json.dumps({"type": "start", "keys": [], "interval": 1}))
    assert json.loads(mine.receive_text())["type"] in ("targets", "tick")  # 自分のものは後回しの側
    mine.close()
    mine.__exit__(None, None, None)


def test_mfa_enable_code_is_rate_limited(client, admin, user):
    """/mfa/enable のコードの照合も、ほかの本人の確認と同じ回数の制限の中で行う（誤りは監査ログに残る）"""
    h = login(client, user["name"])
    assert client.post("/api/auth/mfa/setup", json={"password": PW}, headers=h).status_code == 200
    codes = [client.post("/api/auth/mfa/enable", json={"code": f"{i:06d}"}, headers=h).status_code for i in range(1, 8)]
    assert codes[0] == 422 and 429 in codes, codes
    fails = [x for x in _audits(client, admin, "auth.mfa_enable", user["name"]) if not x["success"]]
    assert any("確認コード誤り" in json.dumps(x["detail"], ensure_ascii=False) for x in fails)
    assert client.get("/api/auth/me", headers=h).json()["mfa_enabled"] is False


def test_api_token_lock_is_audited(client, admin, user):
    """API トークンの発行でロックが始まったときも、ほかの本人の確認と同じく監査ログに残す"""
    h = login(client, user["name"])
    codes = [client.post("/api/auth/tokens", json={"name": "x", "scope": "read", "days": 1, "password": f"guess-{i:04d}x"},
                         headers=h).status_code for i in range(7)]
    assert 429 in codes, codes
    locked = _audits(client, admin, "auth.login_locked", user["name"])
    assert locked and "API トークンの発行" in json.dumps(locked[0]["detail"], ensure_ascii=False)
