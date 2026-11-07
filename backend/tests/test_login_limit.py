"""ログインの失敗回数の制限"""
import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import settings
from app.main import app
from app.services import login_limit


def _login(c, user, pw, ip="10.0.0.1"):
    # 接続元 IP は TestClient では変えられないため、client_ip を差し替えて試す
    return c.post("/api/auth/token", data={"username": user, "password": pw}, headers={"x-test-ip": ip})


@pytest.fixture
def c(monkeypatch):
    from app.api import auth
    monkeypatch.setattr(auth, "client_ip", lambda req: req.headers.get("x-test-ip", "testclient"))
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 3)
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 6)
    with TestClient(app) as client:
        yield client


def _audit(c, action):
    tok = _login(c, "admin", "initial-pass-123", ip="10.9.9.9").json()["access_token"]
    logs = c.get("/api/audit/logs", params={"action": action, "limit": 50}, headers={"Authorization": f"Bearer {tok}"}).json()
    return logs["items"] if isinstance(logs, dict) else logs


def test_lock_after_repeated_failures(c):
    for _ in range(3):
        assert _login(c, "admin", "wrong-pass").status_code == 401
    # 上限に達したら、正しいパスワードでも止める
    r = _login(c, "admin", "initial-pass-123")
    assert r.status_code == 429 and 0 < int(r.headers["Retry-After"]) <= settings.LOGIN_LOCK_MIN * 60
    assert "一時的にログインできません" in r.json()["detail"]
    # ほかの接続元からは管理者がログインできる（他人に締め出されない）
    assert _login(c, "admin", "initial-pass-123", ip="10.0.0.2").status_code == 200
    locks = _audit(c, "auth.login_locked")
    assert any(x["username"] == "admin" and x["ip"] == "10.0.0.1" for x in locks)


def test_unknown_user_is_locked_the_same_way(c):
    """存在しないユーザー名でも同じように止まる（応答からユーザーの有無が分からない）"""
    for _ in range(3):
        assert _login(c, "no-such-user", "x").status_code == 401
    assert _login(c, "no-such-user", "x").status_code == 429


def test_success_resets_and_ip_limit(c):
    for _ in range(2):
        _login(c, "admin", "wrong-pass", ip="10.0.0.3")
    assert _login(c, "admin", "initial-pass-123", ip="10.0.0.3").status_code == 200
    for _ in range(2):  # 成功で回数が消えているので、ここではまだ止まらない
        _login(c, "admin", "wrong-pass", ip="10.0.0.3")
    assert _login(c, "admin", "initial-pass-123", ip="10.0.0.3").status_code == 200
    # ユーザー名を変えながらの試行は、接続元 IP の上限で止まる
    for i in range(6):
        assert _login(c, f"user{i}", "x", ip="10.0.0.4").status_code == 401
    assert _login(c, "admin", "initial-pass-123", ip="10.0.0.4").status_code == 429


def test_redis_down_does_not_block_login(c, monkeypatch):
    class Down:
        async def ttl(self, *a):
            raise RedisConnectionError("down")
        set = delete = decr = ttl

        def pipeline(self, **kw):
            raise RedisConnectionError("down")

    monkeypatch.setattr(login_limit, "_client", Down())
    for _ in range(5):
        assert _login(c, "admin", "wrong-pass").status_code == 401
    assert _login(c, "admin", "initial-pass-123").status_code == 200


def test_concurrent_attempts_are_limited(monkeypatch):
    """同時に送ったログインも、照合（bcrypt）まで進むのは上限の回数だけ（#11）"""
    import asyncio

    import httpx

    from app.api import auth
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 3)
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_IP", 6)
    monkeypatch.setattr(auth, "client_ip", lambda req: "10.0.1.1")
    calls = []
    real = auth.verify_password

    def counting(pw, hashed):
        calls.append(1)
        return real(pw, hashed)

    monkeypatch.setattr(auth, "verify_password", counting)

    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
            rs = await asyncio.gather(*[
                ac.post("/api/auth/token", data={"username": "admin", "password": f"wrong-{i}"}) for i in range(30)])
            first_calls = len(calls)
            # ユーザー名を変えながら同時に送っても、接続元の上限で止まる
            rs2 = await asyncio.gather(*[
                ac.post("/api/auth/token", data={"username": f"u{i}", "password": "x"}) for i in range(30)])
        return rs, rs2, first_calls

    with TestClient(app):  # 起動処理（初期ユーザーの作成など）を済ませる
        rs, rs2, first_calls = asyncio.run(run())
    codes = sorted(r.status_code for r in rs)
    # 30件同時でも、照合まで進むのは「ユーザー名 × 接続元」の上限の 3 回だけ（以前は 30 回とも照合された）
    assert first_calls == 3 and codes.count(401) == 3 and codes.count(429) == 27
    # ユーザー名を変えても、照合の合計は「接続元」の上限（6 回）を超えない
    assert [r.status_code for r in rs2].count(429) >= 27
    assert len(calls) <= 6


def test_counters_have_expiry():
    """試行のカウンタには必ず期限が付く（期限の無いカウンタが残らない）"""
    import asyncio

    async def run():
        await login_limit.begin_attempt("someone", "10.0.2.2")
        r = login_limit.client()
        return [await r.ttl(k) for k in await r.keys("netconfig:login:fail:*")]

    ttls = asyncio.run(run())
    assert len(ttls) == 2 and all(0 < t <= settings.LOGIN_FAILURE_WINDOW_MIN * 60 for t in ttls)
