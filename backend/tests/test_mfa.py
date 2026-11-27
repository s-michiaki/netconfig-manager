"""2 段階認証（ワンタイムパスワード）"""
import uuid

from fastapi.testclient import TestClient

from app.core import totp
from app.main import app


def test_totp_rfc6238_vector():
    # RFC 6238 の SHA-1 のテストベクター（秘密鍵 "12345678901234567890"、8 桁の下 6 桁）
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 59 // 30) == "287082"
    assert totp.code_at(secret, 1111111109 // 30) == "081804"
    step = totp.verify(secret, "287082", now=59)
    assert step == 1 and totp.verify(secret, "287082", last_step=step, now=59) is None  # 同じコードは 2 度使えない
    assert totp.verify(secret, "287 082", now=59 + 30) == 1  # 30 秒のずれまでは受け付ける
    assert totp.verify(secret, "287082", now=59 + 90) is None
    assert totp.verify(secret, "12345", now=59) is None
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 10 and all(totp.looks_like_recovery(c) for c in codes)
    assert totp.hash_recovery(codes[0].upper()) == totp.hash_recovery(codes[0].replace("-", ""))
    assert "otpauth://totp/NetConfig%20Manager%3Aalice?secret=" in totp.provisioning_uri("ABC", "alice", "NetConfig Manager")
    assert totp.qr_svg("otpauth://totp/x?secret=ABC").startswith("<svg")


def _token(c, u, p):
    return c.post("/api/auth/token", data={"username": u, "password": p})


def _now_code(secret: str, offset: int = 0) -> str:
    return totp.code_at(secret, totp.current_step() + offset)


def test_mfa_flow():
    with TestClient(app) as c:
        admin = {"Authorization": "Bearer " + _token(c, "admin", "initial-pass-123").json()["access_token"]}
        name = f"mfa-{uuid.uuid4().hex[:6]}"
        uid = c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "operator"},
                     headers=admin).json()["id"]
        r = _token(c, name, "password-1234")
        h = {"Authorization": "Bearer " + r.json()["access_token"]}
        assert r.json()["mfa_required"] is False and c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is False

        # 設定: パスワードを入れ直して QR コードを出し、認証アプリのコードで確認する
        assert c.post("/api/auth/mfa/setup", headers=h).status_code == 422  # パスワードが無い
        assert c.post("/api/auth/mfa/setup", json={"password": "wrong-pass-xx"}, headers=h).status_code == 422
        s = c.post("/api/auth/mfa/setup", json={"password": "password-1234"}, headers=h).json()
        assert s["qr_svg"].startswith("<svg") and s["secret"] in s["uri"]
        assert c.post("/api/auth/mfa/enable", json={"code": "000000"}, headers=h).status_code == 422
        r = c.post("/api/auth/mfa/enable", json={"code": _now_code(s["secret"])}, headers=h)
        assert r.status_code == 200
        recovery = r.json()["recovery_codes"]
        assert len(recovery) == 10
        # 設定する前のトークンは使えなくなり、新しいトークンが返る（#29）
        assert c.get("/api/auth/me", headers=h).status_code == 401
        h = {"Authorization": "Bearer " + r.json()["access_token"]}
        assert c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is True
        assert c.post("/api/auth/mfa/setup", json={"password": "password-1234"}, headers=h).status_code == 409
        users = {u["id"]: u for u in c.get("/api/users/", headers=admin).json()}
        assert users[uid]["mfa_enabled"] is True

        # ログイン: パスワードだけではトークンが出ない。途中の印は API に使えない
        r = _token(c, name, "password-1234").json()
        assert r["mfa_required"] and r["access_token"] is None and r["mfa_token"]
        assert c.get("/api/devices/", headers={"Authorization": f"Bearer {r['mfa_token']}"}).status_code == 401
        bad = c.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": "000000"})
        assert bad.status_code == 401
        # 有効にしたときのコードは再利用できない（同じ時間枠）→ 次の時間枠のコードで入る
        ok = c.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": _now_code(s["secret"], 1)})
        assert ok.status_code == 200 and ok.json()["access_token"]
        h = {"Authorization": "Bearer " + ok.json()["access_token"]}
        assert c.get("/api/devices/", headers=h).status_code == 200
        # 予備コードでも入れる（1 回だけ）
        r = _token(c, name, "password-1234").json()
        assert c.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": recovery[0]}).status_code == 200
        r = _token(c, name, "password-1234").json()
        assert c.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": recovery[0]}).status_code == 401
        logs = c.get("/api/audit/logs", params={"action": "auth.login", "username": name}, headers=admin).json()["items"]
        assert any("予備コード" in str(x["detail"]) for x in logs)
        # 偽の印・パスワード変更後の印は使えない
        assert c.post("/api/auth/mfa/verify", json={"mfa_token": "x.y.z", "code": "123456"}).status_code == 401

        # 解除（本人）: パスワードとコードで確認
        assert c.post("/api/auth/mfa/disable", json={"password": "wrong-pass-xx", "code": recovery[1]},
                      headers=h).status_code == 422
        r = c.post("/api/auth/mfa/disable", json={"password": "password-1234", "code": recovery[1]}, headers=h)
        assert r.status_code == 200
        # 解除する前のトークンは使えなくなり、新しいトークンが返る（#29）
        assert c.get("/api/auth/me", headers=h).status_code == 401
        h = {"Authorization": "Bearer " + r.json()["access_token"]}
        assert c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is False
        assert _token(c, name, "password-1234").json()["access_token"]

        # 管理者による解除（管理者のパスワードの入れ直しが必要）
        s = c.post("/api/auth/mfa/setup", json={"password": "password-1234"}, headers=h).json()
        h = {"Authorization": "Bearer " + c.post("/api/auth/mfa/enable", json={"code": _now_code(s["secret"])},
                                                 headers=h).json()["access_token"]}
        assert _token(c, name, "password-1234").json()["mfa_required"]
        assert c.post(f"/api/users/{uid}/mfa-reset", json={}, headers=admin).status_code == 422
        assert c.post(f"/api/users/{uid}/mfa-reset", json={"confirm_password": ""}, headers=admin).status_code == 422
        assert c.post(f"/api/users/{uid}/mfa-reset", json={"confirm_password": "wrong-pass-xx"},
                      headers=admin).status_code == 422
        assert c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is True  # 誤りでは解除されない
        r = c.post(f"/api/users/{uid}/mfa-reset", json={"confirm_password": "initial-pass-123"}, headers=admin)
        assert r.status_code == 200 and r.json()["mfa_enabled"] is False
        assert c.get("/api/auth/me", headers=h).status_code == 401  # 解除された人のトークンも使えなくなる
        assert c.post(f"/api/users/{uid}/mfa-reset", json={"confirm_password": "initial-pass-123"},
                      headers=admin).status_code == 409
        h = {"Authorization": "Bearer " + _token(c, name, "password-1234").json()["access_token"]}
        assert c.post(f"/api/users/{uid}/mfa-reset", json={"confirm_password": "password-1234"},
                      headers=h).status_code == 403
        assert _token(c, name, "password-1234").json()["access_token"]
        acts = c.get("/api/audit/logs", params={"action": "user.mfa_reset"}, headers=admin).json()["items"]
        assert acts and acts[0]["target_name"] == name
        assert c.delete(f"/api/users/{uid}", headers=admin).status_code == 204


def test_mfa_code_failures_are_limited():
    """パスワードが漏れていても、確認コードを総当たりさせない（ログインの失敗として数える）"""
    with TestClient(app) as c:
        admin = {"Authorization": "Bearer " + _token(c, "admin", "initial-pass-123").json()["access_token"]}
        name = f"mfab-{uuid.uuid4().hex[:6]}"
        uid = c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"},
                     headers=admin).json()["id"]
        h = {"Authorization": "Bearer " + _token(c, name, "password-1234").json()["access_token"]}
        s = c.post("/api/auth/mfa/setup", json={"password": "password-1234"}, headers=h).json()
        c.post("/api/auth/mfa/enable", json={"code": _now_code(s["secret"])}, headers=h)
        mfa_token = _token(c, name, "password-1234").json()["mfa_token"]
        codes = [c.post("/api/auth/mfa/verify", json={"mfa_token": mfa_token, "code": f"{i:06d}"}).status_code
                 for i in range(1, 9)]
        assert 429 in codes
        # 止まっている間は正しいコードでも入れない
        assert c.post("/api/auth/mfa/verify",
                      json={"mfa_token": mfa_token, "code": _now_code(s["secret"], 1)}).status_code == 429
        assert c.delete(f"/api/users/{uid}", headers=admin).status_code == 204



def test_mfa_logins_do_not_fill_the_ip_counter(monkeypatch):
    """#13: 2 段階認証のログインに成功しても、接続元の回数が増えて残らない（NAT の内側の全員が止まらない）"""
    import asyncio

    from app.core.config import settings
    from app.core.database import AsyncSessionLocal
    from app.models.user import User
    from app.services import login_limit

    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 4)

    async def forget_last_step(uid):  # 同じ時間枠のコードは 2 度使えないため、試験では最後の時間枠を消す
        async with AsyncSessionLocal() as db:
            u = await db.get(User, uid)
            u.mfa_last_step = None
            await db.commit()

    with TestClient(app) as c:
        admin = {"Authorization": "Bearer " + _token(c, "admin", "initial-pass-123").json()["access_token"]}
        name = f"mfac-{uuid.uuid4().hex[:6]}"
        uid = c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"},
                     headers=admin).json()["id"]
        h = {"Authorization": "Bearer " + _token(c, name, "password-1234").json()["access_token"]}
        s = c.post("/api/auth/mfa/setup", json={"password": "password-1234"}, headers=h).json()
        c.post("/api/auth/mfa/enable", json={"code": _now_code(s["secret"])}, headers=h)
        # 接続元の上限（4 回）を超える 6 回、続けてログインに成功しても止まらない
        for i in range(6):
            asyncio.run(forget_last_step(uid))
            t = _token(c, name, "password-1234")
            assert t.status_code == 200, (i, t.text)
            r = c.post("/api/auth/mfa/verify", json={"mfa_token": t.json()["mfa_token"], "code": _now_code(s["secret"])})
            assert r.status_code == 200, (i, r.text)
        n = asyncio.run(login_limit.client().get(f"{login_limit.PREFIX}:fail:ip:testclient"))
        assert n is None, n  # 成功だけなら回数は残らない
        # 確認コードを間違えた分は数える
        asyncio.run(forget_last_step(uid))
        t = _token(c, name, "password-1234").json()
        assert c.post("/api/auth/mfa/verify", json={"mfa_token": t["mfa_token"], "code": "000000"}).status_code == 401
        assert int(asyncio.run(login_limit.client().get(f"{login_limit.PREFIX}:fail:ip:testclient"))) == 2
        assert c.delete(f"/api/users/{uid}", headers=admin).status_code == 204
