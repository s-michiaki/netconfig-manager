"""無操作によるタイムアウト（services/idle.py・POST /api/auth/activity・WebSocket の切断）

時間は idle._now を差し替えて進める（sleep で待たない）。Redis はテストごとに空の偽物（conftest.py）
"""
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from app.api import ping as ping_api
from app.core.config import Settings, settings
from app.core.security import password_fingerprint
from app.main import app
from app.services import idle, login_limit

ADMIN_PW = "initial-pass-123"
PW = "password-1234"
MIN = 60


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(c, username, password=PW) -> dict:
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def tok(h: dict) -> str:
    return h["Authorization"].split()[1]


@pytest.fixture
def clock(monkeypatch):
    """idle の時計。clock.advance(分) で進める"""
    class Clock:
        now = time.time()

        def advance(self, minutes: float) -> None:
            self.now += minutes * MIN

    c = Clock()
    monkeypatch.setattr(idle, "_now", lambda: c.now)
    monkeypatch.setattr(settings, "IDLE_TIMEOUT_MIN", 30)
    return c


@pytest.fixture(autouse=True)
def redis_sync(monkeypatch):
    """テストの Redis（偽物）。アプリは非同期のクライアント、テストは同じサーバーを同期のクライアントで読み書きする
    （共有の非同期のクライアントを、別のイベントループから使わないように）"""
    import fakeredis

    server = fakeredis.FakeServer()
    monkeypatch.setattr(login_limit, "_client", fakeredis.FakeAsyncRedis(server=server))
    return fakeredis.FakeRedis(server=server)


def _wait_for(cond, what: str, limit: float = 10.0) -> None:
    """cond() が真になるまで短い間隔で待つ（上限つき。固定の待ち時間にしない）"""
    deadline = time.monotonic() + limit
    while not cond():
        if time.monotonic() > deadline:
            pytest.fail(f"{what}まで待てませんでした")
        time.sleep(0.02)


def _idle_key(token: str) -> str:
    return f"{idle.PREFIX}:{jwt.decode(token, options={'verify_signature': False})['jti']}"


@pytest.fixture
def user(client):
    """使い捨ての利用者。管理者は作る・消すたびにログインし直す（時計を進めると管理者のログインも切れるため）"""
    name = f"idle-{uuid.uuid4().hex[:6]}"
    uid = client.post("/api/users/", json={"username": name, "password": PW, "role": "operator"},
                      headers=login(client, "admin", ADMIN_PW)).json()["id"]
    yield {"id": uid, "name": name}
    client.delete(f"/api/users/{uid}", headers=login(client, "admin", ADMIN_PW))


def _idle_logouts(client, username) -> list[dict]:
    items = client.get("/api/audit/logs", params={"action": "auth.logout", "username": username},
                       headers=login(client, "admin", ADMIN_PW)).json()["items"]
    return [x for x in items if "無操作" in json.dumps(x["detail"], ensure_ascii=False)]


def _is_idle_401(r) -> bool:
    return (r.status_code == 401 and r.headers.get("X-Logout-Reason") == "idle_timeout"
            and r.json()["detail"] == idle.DETAIL)


# ---------------------------------------------------------------- HTTP


def test_expires_without_activity_and_cannot_be_revived(client, clock, user):
    h = login(client, user["name"])
    assert client.get("/api/auth/me", headers=h).json()["idle_timeout_min"] == 30
    clock.advance(29)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    clock.advance(2)  # ログインから 31 分（ふつうの要求では延びない）
    r = client.get("/api/auth/me", headers=h)
    assert _is_idle_401(r), r.text
    # あとから操作の合図を送っても生き返らない。何度送っても理由つきの 401
    assert _is_idle_401(client.post("/api/auth/activity", headers=h))
    assert _is_idle_401(client.get("/api/devices/", headers=h))
    # 監査ログには 1 回だけ（ログアウト・理由は無操作）
    logs = _idle_logouts(client, user["name"])
    assert len(logs) == 1 and logs[0]["success"]
    # すぐにログインし直せる
    assert client.get("/api/auth/me", headers=login(client, user["name"])).status_code == 200


def test_activity_extends_but_plain_requests_do_not(client, clock, user):
    h = login(client, user["name"])
    for _ in range(3):
        clock.advance(20)
        r = client.post("/api/auth/activity", headers=h)
        assert r.status_code == 200 and r.json() == {"idle_timeout_min": 30}
    assert client.get("/api/auth/me", headers=h).status_code == 200  # ログインから 60 分でも、最後の操作から 20 分
    # 自動の更新（GET を繰り返す）では延びない
    for _ in range(3):
        clock.advance(4)
        assert client.get("/api/devices/", headers=h).status_code == 200
    clock.advance(19)  # 最後の操作から 31 分
    assert _is_idle_401(client.get("/api/devices/", headers=h))


def test_disabled_when_zero(client, clock, user, monkeypatch):
    monkeypatch.setattr(settings, "IDLE_TIMEOUT_MIN", 0)
    h = login(client, user["name"])
    assert client.get("/api/auth/me", headers=h).json()["idle_timeout_min"] == 0
    clock.advance(600)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert client.post("/api/auth/activity", headers=h).json() == {"idle_timeout_min": 0}
    assert not _idle_logouts(client, user["name"])


def test_api_token_is_not_affected(client, clock, user):
    h = login(client, user["name"])
    r = client.post("/api/auth/tokens", json={"name": "idle", "scope": "read", "days": 1, "password": PW}, headers=h)
    assert r.status_code in (200, 201), r.text
    t = {"Authorization": f"Bearer {r.json()['token']}"}
    clock.advance(120)
    assert client.get("/api/devices/", headers=t).status_code == 200
    assert client.get("/api/auth/me", headers=t).json()["idle_timeout_min"] == 0
    assert client.post("/api/auth/activity", headers=t).status_code == 403  # トークンでは送れない（対象外）
    assert _is_idle_401(client.get("/api/devices/", headers=h))  # ログインのほうは切れる


def test_missing_record_starts_counting(client, clock, user, redis_sync):
    """記録が無い（更新の前からのログイン・Redis の再起動）ときは切らず、そこから数える"""
    h = login(client, user["name"])
    clock.advance(40)
    redis_sync.flushall()  # Redis の再起動（記録が消えた）
    assert client.get("/api/auth/me", headers=h).status_code == 200
    clock.advance(29)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    clock.advance(2)
    assert _is_idle_401(client.get("/api/auth/me", headers=h))


def test_non_numeric_record_restarts_counting(client, clock, user, redis_sync):
    """数字でない記録（壊れた値）は、記録が無いときと同じく「いま」から数える"""
    h = login(client, user["name"])
    clock.advance(40)
    redis_sync.set(_idle_key(tok(h)), "garbage", ex=3600)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert float(redis_sync.get(_idle_key(tok(h)))) == clock.now
    redis_sync.set(_idle_key(tok(h)), "garbage", ex=3600)
    assert client.post("/api/auth/activity", headers=h).status_code == 200  # touch も同じ
    assert float(redis_sync.get(_idle_key(tok(h)))) == clock.now
    clock.advance(31)
    assert _is_idle_401(client.get("/api/auth/me", headers=h))


def test_script_error_is_logged_as_error_and_lets_requests_through(client, clock, user, monkeypatch, caplog):
    """Redis には届くがスクリプトが断られる（ResponseError）: 通すが、error のログを間引いて出す（届かないときの文は出さない）"""
    from redis.exceptions import ResponseError

    h = login(client, user["name"])
    real = login_limit.client()

    class NoEval:
        def __getattr__(self, name):
            return getattr(real, name)

        async def eval(self, *a, **k):
            raise ResponseError("NOSCRIPT eval is disabled")
    monkeypatch.setattr(login_limit, "_client", NoEval())
    clock.advance(40)
    with caplog.at_level("WARNING", logger="app.services.idle"):
        for _ in range(3):
            assert client.get("/api/auth/me", headers=h).status_code == 200
    errors = [r for r in caplog.records if r.levelname == "ERROR" and "スクリプトを実行できませんでした" in r.getMessage()]
    assert len(errors) == 1  # 毎要求では出さない
    assert not any("Redis に届くまで" in r.getMessage() for r in caplog.records)
    monkeypatch.setattr(idle, "_error_logged", -1e9)  # 間隔を過ぎたら、また出す
    caplog.clear()
    with caplog.at_level("ERROR", logger="app.services.idle"):
        assert client.get("/api/auth/me", headers=h).status_code == 200
    assert any("スクリプトを実行できませんでした" in r.getMessage() for r in caplog.records)


def test_redis_down_lets_requests_through(client, clock, user, monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    h = login(client, user["name"])
    clock.advance(40)

    class Down:
        def __getattr__(self, name):
            async def fail(*a, **k):
                raise RedisConnectionError("down")
            return fail
    monkeypatch.setattr(login_limit, "_client", Down())
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert client.post("/api/auth/activity", headers=h).status_code == 200


def test_redis_down_warning_is_logged_once(client, clock, user, monkeypatch, caplog):
    from redis.exceptions import ConnectionError as RedisConnectionError

    h = login(client, user["name"])

    class Down:
        def __getattr__(self, name):
            async def fail(*a, **k):
                raise RedisConnectionError("down")
            return fail
    monkeypatch.setattr(login_limit, "_client", Down())
    with caplog.at_level("WARNING", logger="app.services.idle"):
        for _ in range(3):
            monkeypatch.setattr(idle, "_skip_until", 0.0)  # 休みの期間を過ぎたことにする
            assert client.get("/api/auth/me", headers=h).status_code == 200
    assert sum("無操作の時間を確かめられません" in r.getMessage() for r in caplog.records) == 1


def test_old_token_without_jti(client, clock, user):
    """jti の無い（以前の版で発行した）トークンは、トークンのハッシュで数える"""
    from app.core.database import AsyncSessionLocal
    from app.models.user import User

    async def load():
        async with AsyncSessionLocal() as db:
            return await db.get(User, user["id"])
    import asyncio
    u = asyncio.run(load())
    now = datetime.now(UTC)
    old = jwt.encode({"sub": u.id, "pwv": password_fingerprint(u.hashed_password), "tv": u.token_version or 0,
                      "iat": now, "exp": now + timedelta(hours=8)}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    h = {"Authorization": f"Bearer {old}"}
    assert client.get("/api/auth/me", headers=h).status_code == 200  # 記録が無い → ここから数える
    clock.advance(20)
    assert client.post("/api/auth/activity", headers=h).status_code == 200
    clock.advance(20)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    clock.advance(11)
    assert _is_idle_401(client.get("/api/auth/me", headers=h))


def test_other_logins_of_same_user_are_independent(client, clock, user):
    a, b = login(client, user["name"]), login(client, user["name"])
    clock.advance(20)
    assert client.post("/api/auth/activity", headers=b).status_code == 200
    clock.advance(15)
    assert _is_idle_401(client.get("/api/auth/me", headers=a))
    assert client.get("/api/auth/me", headers=b).status_code == 200


def test_new_tokens_start_counting_when_issued(client, clock, user):
    """パスワード変更で返す新しいトークン・すべての端末からログアウトのあとのログインは、発行したときから数える"""
    h = login(client, user["name"])
    clock.advance(25)
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "changed-pass-901"},
                    headers=h)
    assert r.status_code == 200, r.text
    n = {"Authorization": f"Bearer {r.json()['access_token']}"}
    clock.advance(25)  # 最初のログインから 50 分。新しいトークンの発行からは 25 分
    assert client.get("/api/auth/me", headers=n).status_code == 200
    assert client.post("/api/auth/logout-all", json={}, headers=n).status_code == 200
    m = login(client, user["name"], "changed-pass-901")
    clock.advance(29)
    assert client.get("/api/auth/me", headers=m).status_code == 200
    clock.advance(2)
    assert _is_idle_401(client.get("/api/auth/me", headers=m))


def test_settings_validation():
    for bad in (-1, 1, 1441):
        with pytest.raises(ValidationError):
            Settings(IDLE_TIMEOUT_MIN=bad)
    assert Settings(IDLE_TIMEOUT_MIN=0).IDLE_TIMEOUT_MIN == 0
    assert Settings(IDLE_TIMEOUT_MIN=2).IDLE_TIMEOUT_MIN == 2
    assert Settings().IDLE_TIMEOUT_MIN == 30


# ---------------------------------------------------------------- WebSocket


@pytest.fixture
def fast_ws(monkeypatch):
    """WebSocket の側の確認の間隔を短くし、PING は差し替える（ICMP を送らない）"""
    monkeypatch.setattr(idle, "WS_CHECK_SEC", 0.05)
    monkeypatch.setattr(idle, "PING_TOUCH_SEC", 0.0)

    runs: list = []  # PING を送った監視のタスク（止まったことを待つため）

    async def fake_ping_many(addresses, timeout=None):
        import asyncio
        task = asyncio.current_task()
        if task not in runs:
            runs.append(task)
        return dict.fromkeys(addresses, 1.0)

    async def fake_resolve(address):
        if address.endswith(".invalid"):
            raise ValueError("名前解決できません")
        return address
    monkeypatch.setattr(ping_api, "ping_many", fake_ping_many)
    monkeypatch.setattr(ping_api, "resolve", fake_resolve)
    return runs


@pytest.fixture
def ping_keys(client):
    """Ping 監視の対象（名前解決できるもの・できないもの）。キーを返し、終わったら消す"""
    h = login(client, "admin", ADMIN_PW)
    made = [client.post("/api/ping/targets", json={"name": f"idle-{n}-{uuid.uuid4().hex[:4]}", "address": a},
                        headers=h).json() for n, a in (("ok", "192.0.2.80"), ("bad", "no-such-host.invalid"))]
    yield {"ok": made[0]["key"], "bad": made[1]["key"]}
    h = login(client, "admin", ADMIN_PW)
    for t in made:
        client.delete(f"/api/ping/targets/{t['id']}", headers=h)


def _registered(token: str) -> int:
    from app.api import terminal
    from app.services import sessions
    key = sessions.token_key(token)
    return sum(1 for group in list(terminal._live.values()) for t in list(group) if t.token_key == key)


def _open_ping(client, token, keys=None):
    """接続して認証する（認証が済んで登録されるまで待つ）。keys を渡すと監視を始める（最初の tick まで待つ）"""
    before = _registered(token)
    ws = client.websocket_connect("/api/ping/ws").__enter__()
    ws.send_text(json.dumps({"type": "auth", "token": token}))
    for _ in range(100):
        if _registered(token) > before:
            break
        time.sleep(0.02)
    else:
        pytest.fail("WebSocket の認証が終わりませんでした")
    if keys is not None:
        ws.send_text(json.dumps({"type": "start", "keys": keys, "interval": 1}))
        assert json.loads(ws.receive_text())["type"] == "targets"
        assert json.loads(ws.receive_text())["type"] == "tick"
    return ws




def _close_of(ws, max_msgs: int = 10) -> tuple[int, str]:
    """サーバーから切られたときの（コード, reason）。切られないまま届き続けるなら失敗にする"""
    with pytest.raises(WebSocketDisconnect) as e:
        for _ in range(max_msgs):
            ws.receive_text()
        ws.__exit__(None, None, None)
        pytest.fail("WebSocket が切られませんでした")
    ws.__exit__(None, None, None)
    return e.value.code, e.value.reason


def _wait_unregistered(user_id) -> None:
    from app.api import terminal
    _wait_for(lambda: user_id not in terminal._live, "WebSocket の登録が外れる")


def test_ping_running_keeps_login_alive(client, clock, user, fast_ws, ping_keys, redis_sync):
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h), [ping_keys["ok"]])
    for _ in range(3):  # 合わせて 60 分。tick のたびに時刻を進めるので切れない
        clock.advance(20)
        # 進めた時刻を、監視の tick が書くまで待つ（届いた tick は読み捨てる）
        _wait_for(lambda: (ws.receive_text() and False) or redis_sync.get(_idle_key(tok(h))) == repr(clock.now).encode(),
                  "監視が時刻を進める")
    # 同じログインのほかの API（ほかのタブ）も切れない
    assert client.get("/api/auth/me", headers=h).status_code == 200
    # 止めたあとは、そこから数えて切れる（監視のタスクが止まるまで待つ）
    ws.send_text(json.dumps({"type": "stop"}))
    _wait_for(lambda: fast_ws and all(t.done() for t in fast_ws), "監視が止まる")
    clock.advance(29)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    clock.advance(2)
    assert _close_of(ws) == (4401, "idle_timeout")
    assert _is_idle_401(client.get("/api/auth/me", headers=h))
    assert len(_idle_logouts(client, user["name"])) == 1
    _wait_unregistered(user["id"])


def test_ping_connected_only_does_not_extend(client, clock, user, fast_ws):
    """接続しただけ（常時監視のタブを見ているだけ）では延びない。要求が来なくてもサーバー側から切る"""
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h))  # 認証・登録（と WebSocket の側の確認の開始）まで待つ
    clock.advance(31)
    assert _close_of(ws) == (4401, "idle_timeout")
    assert len(_idle_logouts(client, user["name"])) == 1
    # 切れたあとの接続は、理由つきで断る
    ws2 = client.websocket_connect("/api/ping/ws").__enter__()
    ws2.send_text(json.dumps({"type": "auth", "token": tok(h)}))
    assert _close_of(ws2) == (4401, "idle_timeout")
    _wait_unregistered(user["id"])


def test_ping_disconnect_stops_extending(client, clock, user, fast_ws, ping_keys):
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h), [ping_keys["ok"]])
    ws.close()
    ws.__exit__(None, None, None)
    _wait_unregistered(user["id"])
    clock.advance(31)
    assert _is_idle_401(client.get("/api/auth/me", headers=h))


def test_terminal_is_closed_after_idle(client, clock, user, fast_ws):
    import fake_sshd
    from test_rbac import _end_reason, _open_terminal

    port, _, _ = fake_sshd.start()
    admin = login(client, "admin", ADMIN_PW)
    did = client.post("/api/devices/", json=dict(name=f"idle-sw-{port}", hostname="127.0.0.1", port=port,
                                                 platform="cisco_ios", username="admin", password="pw"),
                      headers=admin).json()["id"]
    try:
        h = login(client, user["name"])
        ws = _open_terminal(client, did, tok(h))
        clock.advance(31)
        out = ""
        with pytest.raises(WebSocketDisconnect) as e:
            for _ in range(50):
                out += ws.receive_text()
        ws.__exit__(None, None, None)
        assert (e.value.code, e.value.reason) == (4401, "idle_timeout")
        assert "操作が無い時間が続いたため" in out
        assert _end_reason(client, login(client, "admin", ADMIN_PW), user["name"]) == "無操作による切断"
        assert len(_idle_logouts(client, user["name"])) == 1
    finally:
        client.delete(f"/api/devices/{did}", headers=login(client, "admin", ADMIN_PW))


@pytest.mark.parametrize("which", ["none", "unresolvable"])
def test_ping_without_real_targets_does_not_extend(client, clock, user, fast_ws, ping_keys, which):
    """実際に PING を送る対象が無い（0 件・すべて名前解決できない）start では延びない"""
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h), [] if which == "none" else [ping_keys["bad"]])
    clock.advance(20)
    json.loads(ws.receive_text())
    clock.advance(11)
    assert _close_of(ws) == (4401, "idle_timeout")
    assert _is_idle_401(client.get("/api/auth/me", headers=h))
    _wait_unregistered(user["id"])


def test_ping_start_after_expiry_does_not_revive(client, clock, user, fast_ws, ping_keys, monkeypatch, redis_sync):
    """止めたまま時間を過ぎ、WebSocket の側の確認より先に start が届いても、生き返らない（touch が期限を確かめる）"""
    monkeypatch.setattr(idle, "WS_CHECK_SEC", 600)  # 定期の確認では切らせない
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h))
    clock.advance(31)
    ws.send_text(json.dumps({"type": "start", "keys": [ping_keys["ok"]], "interval": 1}))
    assert _close_of(ws) == (4401, "idle_timeout")
    assert redis_sync.get(_idle_key(tok(h))) == b"expired"
    assert _is_idle_401(client.get("/api/auth/me", headers=h))
    assert len(_idle_logouts(client, user["name"])) == 1
    _wait_unregistered(user["id"])


def test_ping_start_on_expired_record_does_not_write(client, clock, user, fast_ws, ping_keys, monkeypatch,
                                                     redis_sync):
    """失効済み（expired）の記録には、Ping 監視の経路でも書かない"""
    monkeypatch.setattr(idle, "WS_CHECK_SEC", 600)
    h = login(client, user["name"])
    ws = _open_ping(client, tok(h))
    redis_sync.set(_idle_key(tok(h)), "expired", ex=3600)
    ws.send_text(json.dumps({"type": "start", "keys": [ping_keys["ok"]], "interval": 1}))
    assert _close_of(ws) == (4401, "idle_timeout")
    assert redis_sync.get(_idle_key(tok(h))) == b"expired"
    _wait_unregistered(user["id"])


def test_ping_connect_does_not_touch(client, clock, user, fast_ws):
    """接続（認証）しただけでは時刻を進めない"""
    h = login(client, user["name"])
    clock.advance(10)
    ws = _open_ping(client, tok(h))  # 認証・登録まで待つ
    clock.advance(21)  # ログインから 31 分。接続からは 21 分
    r = client.get("/api/auth/me", headers=h)
    if not _is_idle_401(r):
        ws.close()
        ws.__exit__(None, None, None)
        pytest.fail(f"接続で時刻が進んでいる: {r.status_code}")
    assert _close_of(ws) == (4401, "idle_timeout")
    _wait_unregistered(user["id"])


def test_audit_once_and_all_websockets_closed(client, clock, user, fast_ws, monkeypatch):
    """同じトークンの WebSocket が 2 本・要求が何度来ても、監査ログは 1 件。どちらの接続もすぐに切れる

    失効の記録に書けない（sessions.revoke の失敗）ときも、あとの要求は判定（expired）を通るが、監査は増えない
    """
    from app.services import sessions

    async def cannot_revoke(*a, **k):
        return False
    monkeypatch.setattr(sessions, "revoke", cannot_revoke)
    h = login(client, user["name"])
    a, b = _open_ping(client, tok(h)), _open_ping(client, tok(h))  # どちらも認証・登録まで待つ
    clock.advance(31)
    started = time.monotonic()
    assert _close_of(a) == (4401, "idle_timeout")
    assert _close_of(b) == (4401, "idle_timeout")
    assert time.monotonic() - started < 5
    for _ in range(3):
        assert _is_idle_401(client.get("/api/auth/me", headers=h))
    assert len(_idle_logouts(client, user["name"])) == 1
    _wait_unregistered(user["id"])


# ---------------------------------------------------------------- 画面の時計で時間が来たとき（logout の reason=idle）


def test_idle_logout_only_this_login(client, clock, user):
    a, b = login(client, user["name"]), login(client, user["name"])
    r = client.post("/api/auth/logout", json={"reason": "idle"}, headers=a)
    assert r.status_code == 200 and r.json()["scope"] == "session"
    assert _is_idle_401(client.get("/api/auth/me", headers=a))  # ほかのタブも理由つきで移る
    assert client.get("/api/auth/me", headers=b).status_code == 200  # ほかの端末はそのまま
    assert _idle_logouts(client, user["name"]) and len(_idle_logouts(client, user["name"])) == 1
    # サーバーの判定とも合わせて 1 回だけ
    clock.advance(31)
    assert _is_idle_401(client.get("/api/auth/me", headers=a))
    assert len(_idle_logouts(client, user["name"])) == 1


def test_idle_logout_with_redis_down_does_not_log_out_everywhere(client, clock, user, monkeypatch):
    """Redis に届かないとき、画面の時計による無操作のログアウトは token_version を上げない（ほかの端末を切らない）"""
    from redis.exceptions import ConnectionError as RedisConnectionError

    a, b = login(client, user["name"]), login(client, user["name"])

    class Down:
        def __getattr__(self, name):
            async def fail(*a, **k):
                raise RedisConnectionError("down")
            return fail
    monkeypatch.setattr(login_limit, "_client", Down())
    r = client.post("/api/auth/logout", json={"reason": "idle"}, headers=a)
    assert r.status_code == 200 and r.json()["scope"] == "none"  # 何も失効させられなかった
    assert client.get("/api/auth/me", headers=b).status_code == 200
    # ふつうのログアウトは今までどおり（Redis に書けなければ、すべての端末）
    r = client.post("/api/auth/logout", headers=a)
    assert r.json()["scope"] == "all"
    assert client.get("/api/auth/me", headers=b).status_code == 401


def test_startup_warns_when_idle_is_not_shorter_than_login(monkeypatch, caplog):
    import logging
    log = logging.getLogger("test-idle")
    monkeypatch.setattr(settings, "IDLE_TIMEOUT_MIN", 480)
    with caplog.at_level("WARNING", logger="test-idle"):
        idle.startup_log(log)
    assert any("実質働きません" in r.getMessage() for r in caplog.records)
    caplog.clear()
    monkeypatch.setattr(settings, "IDLE_TIMEOUT_MIN", 30)
    with caplog.at_level("WARNING", logger="test-idle"):
        idle.startup_log(log)
    assert not caplog.records
