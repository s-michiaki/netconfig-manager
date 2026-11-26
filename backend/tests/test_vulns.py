"""脆弱性・サポート終了日（J-1: 取得の枠組み・Palo Alto・KEV・endoflife.date・手入力・API・照合の移り変わり）のテスト

外部へは実際につながない: vuln_fetch._open（urlopen 相当）を差し替え、tests/fixtures/vuln/ の見本の応答を返す。
差し替えていない通信（許可リスト外のホストなど）は、テストが落ちる。作ったデータはテストの終わりに消す
"""
import asyncio
import base64
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app import worker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.audit import AuditLog
from app.models.device import Device
from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
from app.services import system, vuln_service
from app.services import vuln_fetch as vf

FIX = Path(__file__).parent / "fixtures" / "vuln"
PW = "password-1234"


def fixture_bytes(name: str) -> bytes:
    return (FIX / name).read_bytes()


def fixture_json(name: str):
    return json.loads(fixture_bytes(name))


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- 通信の差し替え


class FakeResp:
    """urlopen の応答の代わり（本文・最終的な URL・ヘッダー）"""

    def __init__(self, body: bytes, url: str, headers: dict | None = None):
        self._b, self._url, self.headers = body, url, headers or {}
        self.pos = 0

    def read(self, n=-1):
        n = len(self._b) - self.pos if n is None or n < 0 else n
        out = self._b[self.pos:self.pos + n]
        self.pos += len(out)
        return out

    def geturl(self):
        return self._url

    def close(self):
        pass


class Net:
    """URL ごとの応答（bytes / 例外 / 関数）。呼ばれた URL・ヘッダーを記録する"""

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.calls: list[urllib.request.Request] = []

    def __call__(self, req, timeout):
        self.calls.append(req)
        r = self.routes.get(req.full_url)
        if r is None:
            raise AssertionError(f"テストで想定していない通信です: {req.full_url}")
        if isinstance(r, BaseException):
            raise r
        if callable(r):
            return r(req)
        return FakeResp(r, req.full_url)

    @property
    def urls(self) -> list[str]:
        return [c.full_url for c in self.calls]


def standard_routes() -> dict[str, object]:
    return {
        vf.URL_PALOALTO: fixture_bytes("paloalto_panos.json"),
        vf.URL_KEV: fixture_bytes("kev.json"),
        vf.URL_EOL.format(product="panos"): fixture_bytes("eol_panos.json"),
        vf.URL_EOL.format(product="fortios"): fixture_bytes("eol_fortios.json"),
        vf.URL_EOL.format(product="cisco-ios-xe"): fixture_bytes("eol_cisco_ios_xe.json"),
    }


@pytest.fixture(autouse=True)
def net(monkeypatch):
    """既定では、通信しようとしたらテストが落ちる。必要なテストが net.routes に応答を入れる"""
    n = Net()
    monkeypatch.setattr(vf, "_open", n)
    return n


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "VULN_ENABLED", True)
    monkeypatch.setattr(settings, "VULN_SOURCES", "paloalto,kev,eol")


# ---------------------------------------------------------------- 後片付け


async def _cleanup():
    async with AsyncSessionLocal() as db:
        await db.execute(delete(VulnMatch))
        await db.execute(delete(VulnAdvisory))
        await db.execute(delete(EolDate))
        await db.execute(delete(VulnSource))
        await db.execute(delete(Device).where(Device.name.like("vuln-%")))
        await db.execute(delete(AuditLog).where(AuditLog.action.like("vuln.%")))
        await db.commit()


@pytest.fixture(scope="module", autouse=True)
def _schema():
    from app.core import migrate

    migrate.run_migrations()  # アプリを起動しないテストでも表がある状態にする（何度呼んでも同じ）


@pytest.fixture(autouse=True)
def clean(_schema):
    run(_cleanup())
    yield
    run(_cleanup())


async def _mk_device(name: str, platform: str, os_version: str | None, model: str | None = None,
                     hostname: str = "192.0.2.10") -> str:
    async with AsyncSessionLocal() as db:
        d = Device(name=name, hostname=hostname, platform=platform, username="u", password="p",
                   os_version=os_version, model=model)
        db.add(d)
        await db.commit()
        return d.id


def mk_device(name, platform, os_version, **kw):
    return run(_mk_device(f"vuln-{name}", platform, os_version, **kw))


async def _set_version(device_id: str, v: str | None):
    async with AsyncSessionLocal() as db:
        (await db.get(Device, device_id)).os_version = v
        await db.commit()


async def _fetch(sources=None, now=None):
    async with AsyncSessionLocal() as db:
        return await vuln_service.run_fetch(db, sources, now)


async def _reconcile(ids=None):
    async with AsyncSessionLocal() as db:
        r = await vuln_service.reconcile(db, ids)
        await db.commit()
        return r


async def _matches(device_id: str) -> dict[str, tuple[str, str | None]]:
    """勧告の ID → (state, note)"""
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(VulnMatch, VulnAdvisory.ext_id).join(
            VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id).where(VulnMatch.device_id == device_id))).all()
        return {ext: (m.state, m.note) for m, ext in rows}


def sources_state() -> dict[str, VulnSource]:
    async def go():
        async with AsyncSessionLocal() as db:
            return {s.source: s for s in (await db.execute(select(VulnSource))).scalars()}
    return run(go())


# ================================================================ 取得の枠組み


@pytest.mark.parametrize("url", [
    "http://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories",  # https 以外
    "https://evil.example.test/known_exploited_vulnerabilities.json",  # 許可リスト外
    "https://security.paloaltonetworks.com.evil.example.test/x",  # 似たホスト
    "https://user:pw@www.cisa.gov/x.json",  # 認証情報つき
    "https://www.cisa.gov:8443/x.json",  # 別のポート
    "ftp://www.cisa.gov/x.json",
    "//www.cisa.gov/x.json",
])
def test_check_url_rejects(url, net):
    with pytest.raises(vf.FetchError):
        vf.check_url(url)
    with pytest.raises(vf.FetchError):
        vf.fetch_bytes(url)
    assert net.calls == []  # 許可リスト外へは、接続を試みる前に止まる


def test_check_url_allows_listed_hosts():
    for u in (vf.URL_PALOALTO, vf.URL_KEV, vf.URL_EOL.format(product="panos"),
              "https://services.nvd.nist.gov/rest/json/cves/2.0", "https://www.fortiguard.com/x", "https://filestore.fortinet.com/x"):
        vf.check_url(u)
    assert vf.safe_url("https://www.cisa.gov/x") and vf.safe_url("http://www.cisa.gov/x") is None
    assert vf.safe_url("https://evil.example.test/x") is None and vf.safe_url(None) is None
    assert vf.safe_url("https://www.cisa.gov/" + "a" * 600) is None


def test_redirect_only_within_allowlist():
    h = vf._AllowlistRedirect()
    req = urllib.request.Request("https://www.cisa.gov/a.json")
    with pytest.raises(vf.FetchError):
        h.redirect_request(req, None, 302, "Found", {}, "https://evil.example.test/a.json")
    with pytest.raises(vf.FetchError):
        h.redirect_request(req, None, 302, "Found", {}, "http://www.cisa.gov/a.json")  # https 以外へ落とす転送
    new = h.redirect_request(req, None, 302, "Found", {}, "https://www.cisa.gov/other.json")  # 同じ許可リストの中
    assert new is not None and new.full_url == "https://www.cisa.gov/other.json"


def test_final_url_outside_allowlist_fails(net):
    net.routes[vf.URL_KEV] = lambda req: FakeResp(b"{}", "https://evil.example.test/x")
    with pytest.raises(vf.FetchError):
        vf.fetch_json(vf.URL_KEV)


def test_fetch_json_ok_and_headers(net, monkeypatch):
    net.routes[vf.URL_KEV] = b'{"a": 1}'
    monkeypatch.setattr(vf, "_ua", "netconfig-manager/9.9.9")
    assert vf.fetch_json(vf.URL_KEV) == {"a": 1}
    req = net.calls[0]
    assert req.get_header("User-agent") == "netconfig-manager/9.9.9" and req.get_method() == "GET"
    assert req.data is None


@pytest.mark.parametrize("route,needle", [
    (b"not json", "JSON"),
    (b"\xff\xfe", "JSON"),
    (b"[" * 100000, "JSON"),  # 深すぎる入れ子でも落ちない
    (urllib.error.HTTPError(vf.URL_KEV, 429, "Too Many", {}, None), "429"),
    (urllib.error.HTTPError(vf.URL_KEV, 500, "x", {}, None), "HTTP 500"),
    (urllib.error.HTTPError(vf.URL_KEV, 302, "x", {}, None), "リダイレクト"),
    (urllib.error.URLError(TimeoutError("timed out")), "時間切れ"),
    (TimeoutError("read timed out"), "時間切れ"),
    (urllib.error.URLError(ConnectionRefusedError()), "拒否"),
    (vf.FetchError("許可リストにない宛先です"), "許可リスト"),  # リダイレクトの検査が open の中で失敗した場合
])
def test_fetch_failures_are_fetch_errors(net, route, needle):
    net.routes[vf.URL_KEV] = route
    with pytest.raises(vf.FetchError) as e:
        vf.fetch_json(vf.URL_KEV)
    assert needle in str(e.value)


def test_fetch_too_large_and_total_timeout(net, monkeypatch):
    monkeypatch.setattr(vf, "MAX_BYTES", 100)
    net.routes[vf.URL_KEV] = b"x" * 500
    with pytest.raises(vf.FetchError, match="大きすぎ"):
        vf.fetch_bytes(vf.URL_KEV)
    net.routes[vf.URL_KEV] = lambda req: FakeResp(b"{}", req.full_url, {"Content-Length": "999999999"})
    with pytest.raises(vf.FetchError, match="大きすぎ"):
        vf.fetch_bytes(vf.URL_KEV)
    monkeypatch.setattr(vf, "MAX_BYTES", 50 * 1024 * 1024)
    monkeypatch.setattr(vf, "TOTAL_TIMEOUT", -1)  # 全体の時間を過ぎている
    net.routes[vf.URL_KEV] = b"{}"
    with pytest.raises(vf.FetchError, match="時間切れ"):
        vf.fetch_bytes(vf.URL_KEV)


def test_error_text_has_no_url_query_or_proxy_credentials(net, monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxyuser:proxypass@proxy.example.test:3128")
    leak = "http://proxyuser:proxypass@proxy.example.test:3128 https://www.cisa.gov/x?token=SECRET123"
    for exc in (urllib.error.URLError(OSError(f"Tunnel connection failed: 407 Proxy Authentication Required {leak}")),
                urllib.error.URLError(OSError(leak)), OSError(leak), ValueError(leak)):
        net.routes[vf.URL_KEV] = exc
        with pytest.raises(vf.FetchError) as e:
            vf.fetch_json(vf.URL_KEV)
        text = str(e.value)
        assert "proxypass" not in text and "proxyuser" not in text and "SECRET123" not in text and "proxy.example" not in text
    net.routes[vf.URL_KEV] = urllib.error.URLError(OSError("Tunnel connection failed: 407 Proxy Authentication Required"))
    with pytest.raises(vf.FetchError, match="HTTP 407"):
        vf.fetch_json(vf.URL_KEV)


@pytest.fixture
def real_open(monkeypatch):
    """autouse で差し替えた _open を本物に戻す（通信先は 127.0.0.1 の試験用サーバーだけ）"""
    monkeypatch.setattr(vf, "_open", _REAL_OPEN)
    monkeypatch.setattr(vf, "check_url", lambda url: None)


_REAL_OPEN = vf._open


class _LocalServer:
    """試験用の TCP サーバー。mode ごとに、応答を少しずつ返す（stop で止める）"""

    def __init__(self, mode: str, interval: float = 0.3):
        self.mode, self.interval = mode, interval
        self.stop = threading.Event()
        self.requests: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def url(self, path="/x"):
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.sock.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _drip(self, conn, data: bytes):
        for b in data:
            if self.stop.is_set():
                return
            conn.sendall(bytes([b]))
            time.sleep(self.interval)

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            self.requests.append(req)
            if self.mode == "slow_headers":  # ヘッダーを 1 文字ずつ（終わらないヘッダー）
                self._drip(conn, b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 100000)
            elif self.mode == "slow_body":  # 本文を 1 文字ずつ（Content-Length は大きい）
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n")
                self._drip(conn, b"{" + b" " * 998 + b"}")
            elif self.mode == "slow_chunked":  # chunked で 1 チャンクずつ
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
                for _ in range(1000):
                    if self.stop.is_set():
                        return
                    conn.sendall(b"1\r\n \r\n")
                    time.sleep(self.interval)
            elif self.mode == "ok":
                body = b'{"ok": true}'
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            elif self.mode == "bad_status":
                conn.sendall(b"SECRET-LINE-FROM-PEER\r\n\r\n")
            elif self.mode == "long_header":
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-Long: " + b"z" * 70000 + b"\r\n\r\n")
            elif self.mode == "short_body":  # Content-Length より少ないところで閉じる
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


@pytest.mark.parametrize("mode", ["slow_headers", "slow_body", "slow_chunked"])
def test_total_timeout_cuts_off_dribbling_peer(monkeypatch, real_open, mode):
    """相手が少しずつ返し続けても、全体の期限（テストでは 2 秒）＋数秒以内に FetchError で終わる（3 通り）"""
    monkeypatch.setattr(vf, "TOTAL_TIMEOUT", 2)
    srv = _LocalServer(mode)
    try:
        t0 = time.monotonic()
        with pytest.raises(vf.FetchError, match="時間切れ"):
            vf.fetch_bytes(srv.url())
        elapsed = time.monotonic() - t0
    finally:
        srv.close()
    print(f"timeout-test {mode}: {elapsed:.2f}s")
    assert 1.5 <= elapsed <= 2 + 3


def test_real_open_reads_normal_response(real_open):
    srv = _LocalServer("ok")
    try:
        assert vf.fetch_json(srv.url()) == {"ok": True}
        req = srv.requests[0].decode()
        assert req.startswith("GET /x HTTP/1.1") and "User-Agent: netconfig-manager" in req
    finally:
        srv.close()


@pytest.mark.parametrize("mode", ["bad_status", "long_header", "short_body"])
def test_http_client_errors_become_fetch_error_without_peer_text(real_open, mode):
    """BadStatusLine・LineTooLong・IncompleteRead も FetchError にし、相手が返した行は出さない"""
    srv = _LocalServer(mode)
    try:
        with pytest.raises(vf.FetchError) as e:
            vf.fetch_bytes(srv.url())
    finally:
        srv.close()
    assert "SECRET-LINE" not in str(e.value) and "zzzz" not in str(e.value) and "abc" not in str(e.value)
    assert "形式" in str(e.value) or "接続" in str(e.value)


def test_production_check_url_still_blocks_local_and_http(monkeypatch):
    """テストの差し替えは check_url だけ。本番のコードは 127.0.0.1・http を許さない"""
    for bad in ("http://127.0.0.1:8080/x", "https://127.0.0.1/x", "https://localhost/x", "http://security.paloaltonetworks.com/"):
        with pytest.raises(vf.FetchError):
            vf.check_url(bad)


def test_lock_timeout_is_longer_than_worst_case_fetch():
    """worker の Redis ロックが先に切れて、次の取得と重ならない（情報源の数 × 全体の期限 < ロックの期限）"""
    from app import worker

    assert vuln_service.MAX_FETCH_SECONDS < worker.VULN_FETCH_LOCK_TIMEOUT
    assert (2 + len(vf.EOL_PRODUCTS)) * vf.TOTAL_TIMEOUT <= vuln_service.MAX_FETCH_SECONDS


class _ProxyServer(_LocalServer):
    """CONNECT を受けて 407 を返すプロキシ（認証つきのヘッダーが来るか確かめる）"""

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            self.requests.append(req)
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()


def test_proxy_setting_is_used_for_connect_and_env_proxy_is_ignored(monkeypatch):
    """OUTBOUND_PROXY へ CONNECT する（認証情報は Proxy-Authorization だけ・環境変数のプロキシ／NO_PROXY は見ない）"""
    monkeypatch.setattr(vf, "_open", _REAL_OPEN)
    proxy = _ProxyServer("proxy")
    try:
        monkeypatch.setenv("NO_PROXY", "security.paloaltonetworks.com,*")  # 環境変数の迂回指定は効かない
        monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", f"http://proxyuser:proxypass@127.0.0.1:{proxy.port}")
        with pytest.raises(vf.FetchError) as e:
            vf.fetch_bytes(vf.URL_PALOALTO)
        text = str(e.value)
        assert "HTTP 407" in text and "proxypass" not in text and "proxyuser" not in text and "127.0.0.1" not in text
        req = proxy.requests[0].decode()
        assert req.startswith("CONNECT security.paloaltonetworks.com:443 HTTP/1.1")
        assert "Proxy-Authorization: Basic " + base64.b64encode(b"proxyuser:proxypass").decode() in req
        assert "/api/v1/products" not in req  # 暗号化の前の通信には、URL の中身も機器の情報も出ない
    finally:
        proxy.close()


def test_no_proxy_means_direct_and_env_proxy_unused(monkeypatch):
    seen = {}
    real = vf._GuardedHTTPS.__init__

    def spy(self, host, *a, **kw):
        seen["proxy"] = kw.get("proxy")
        raise OSError("stop")

    monkeypatch.setattr(vf, "_open", _REAL_OPEN)
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "")
    monkeypatch.setattr(vf._GuardedHTTPS, "__init__", spy)
    with pytest.raises(vf.FetchError):
        vf.fetch_bytes(vf.URL_KEV)
    monkeypatch.setattr(vf._GuardedHTTPS, "__init__", real)
    assert seen["proxy"] is None


@pytest.mark.parametrize("value,ok", [
    ("", True), ("http://proxy.example.test:3128", True), ("http://u:p@proxy.example.test:8080", True),
    # https:// のプロキシは受け付けない（プロキシとの間を TLS にせず、認証情報を平文で送ってしまうため）
    ("https://topsecret-user:topsecret-pw@proxy.example.test:8443", False), ("HTTPS://topsecret:1@proxy.example.test", False),
    ("topsecret-user:topsecret-pw@proxy.example.test:3128", False), ("ftp://topsecret-user:pw@host", False),
    ("http://", False), ("socks5://topsecret:1", False), ("http://topsecret-user:pw@host.example.test:99999", False),
])
def test_proxy_setting_is_validated_without_echoing_value(value, ok):
    from cryptography.fernet import Fernet
    from pydantic import ValidationError

    from app.core.config import Settings

    base = {"SECRET_KEY": "x" * 40, "DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "OUTBOUND_PROXY": value}
    if ok:
        assert value == Settings(_env_file=None, **base).OUTBOUND_PROXY
    else:
        with pytest.raises(ValidationError) as e:
            Settings(_env_file=None, **base)
        assert "OUTBOUND_PROXY" in str(e.value) and "topsecret" not in str(e.value)
        if value.lower().startswith("https://"):
            assert "http:// で指定" in str(e.value) and "暗号化されません" in str(e.value)


def test_https_proxy_is_refused_at_connect_time_too(monkeypatch):
    """設定の検査をすり抜けても（実行中の差し替えなど）、https:// のプロキシへは接続しない（認証情報を送らない）"""
    monkeypatch.setattr(vf, "_open", _REAL_OPEN)
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "https://topsecret-user:topsecret-pw@127.0.0.1:9")
    with pytest.raises(vf.FetchError) as e:
        vf.fetch_bytes(vf.URL_PALOALTO)
    assert "http://" in str(e.value) and "topsecret" not in str(e.value) and "127.0.0.1" not in str(e.value)


def test_proxy_auth_failure_recorded_in_last_error_without_secrets(monkeypatch, enabled, caplog):
    """407: 情報源の last_error・取得の結果・ログに、プロキシのユーザー名・パスワード・Proxy-Authorization を残さない"""
    import logging

    from fake_proxy import FakeProxy

    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(vf, "_open", _REAL_OPEN)
    user, pw = "vuln-proxy-MARKU", "pw:MARK@P"
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    with FakeProxy(mode="407") as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(user, urllib.parse.quote(pw, safe="")))
        res = run(_fetch(["kev"]))
    err = res["sources"]["kev"]["error"]
    saved = sources_state()["kev"].last_error or ""
    assert "プロキシの認証に失敗しました" in err and err == saved
    for text in (err, saved, json.dumps(res, ensure_ascii=False, default=str), caplog.text):
        assert "MARKU" not in text and "MARK@P" not in text and "MARK%40P" not in text and token not in text
    assert f"Basic {token}" in px.connects[0]


# ================================================================ 解析


def _core(item: dict) -> dict:
    """判定に使う項目だけ（説明の raw・元の値の src を除く）"""
    return {k: v for k, v in item.items() if k not in ("raw", "src", "entry")}


def test_parse_paloalto_fixture():
    advs = vf.parse_paloalto(fixture_json("paloalto_panos.json"))
    by = {a["ext_id"]: a for a in advs}
    assert set(by) == {"CVE-2099-0001", "PAN-SA-2099-0001"}  # Prisma だけ・取り下げ・壊れた記録は含めない
    a = by["CVE-2099-0001"]
    assert a["severity"] == "critical" and a["cvss"] == 9.3 and a["cve_ids"] == ["CVE-2099-0001"]
    assert a["products"] == ["paloalto_panos"] and a["source"] == "paloalto"
    assert [_core(x) for x in a["affected"]] == [
        {"status": "affected", "branch": "10.2", "ge": "10.2.0", "fixes": ["10.2.5-h2"]},  # lessThan と changes が同じ
        {"status": "affected", "branch": "10.2", "ge": "10.2.6", "fixes": ["10.2.9"], "lt_only": ["10.2.9"]},  # lessThan だけ
        {"status": "unaffected", "branch": "10.2", "ge": "10.2.9", "open": True},  # 影響なしの行（10.2.9 以上）
        {"status": "affected", "branch": "11.1", "ge": "11.1.0", "fixes": ["11.1.2-h3"]},  # changes だけ
    ]
    # 元の値を残す（判定の理由を追える）
    assert a["affected"][0]["src"] == {
        "product": "PAN-OS", "defaultStatus": "unaffected", "version": "10.2.0", "lessThan": "10.2.5-h2", "status": "affected",
        "versionType": "custom", "changes": [{"at": "10.2.5-h2", "status": "unaffected"}]}
    assert a["affected"][0]["raw"] == "10.2.0 以上・修正 10.2.5-h2"
    assert a["url"] == "https://security.paloaltonetworks.com/CVE-2099-0001"
    assert a["published_at"] == datetime(2099, 1, 10, 17, 0) and a["modified_at"] == datetime(2099, 1, 12, 0, 0)
    b = by["PAN-SA-2099-0001"]
    assert [_core(x) for x in b["affected"]] == [{"status": "affected", "all": True, "branch": None}]
    assert b["cve_ids"] == [] and b["severity"] == "medium"
    assert b["url"] == "https://security.paloaltonetworks.com/PAN-SA-2099-0001"  # 許可リスト外の参照 URL は保存しない


def test_parse_paloalto_sanitizes_and_rejects_bad_shapes():
    rec = fixture_json("paloalto_panos.json")["data"][0]
    rec["containers"]["cna"]["title"] = "題\x00\x1b[31m" + "あ" * 1000
    rec["containers"]["cna"]["references"] = [{"url": "javascript:alert(1)"}, {"url": "https://www.cisa.gov/x"}]
    a = vf.parse_paloalto({"data": [rec]})[0]
    assert len(a["title"]) <= vf.TITLE_MAX and "\x00" not in a["title"] and "\x1b" not in a["title"]
    assert a["url"] == "https://www.cisa.gov/x"  # 許可リストの https の URL だけ使う
    for bad in (None, [], {}, {"data": []}, {"data": "x"}, {"success": False}, {"data": [{"cveMetadata": {}}]}):
        with pytest.raises(vf.FetchError):
            vf.parse_paloalto(bad)


def test_ranges_from_versions_variants():
    r = vf.ranges_from_versions([
        {"status": "affected", "version": "10.1", "lessThan": "10.1.14*"},  # 読めない上限（* だけの形ではない）
        {"status": "affected", "version": "9.1.0", "lessThanOrEqual": "9.1.5"},
        {"status": "affected", "version": "9.0.1"},  # version だけ: その系列の 9.0.1 以上すべて（修正版なし）
        {"status": "affected", "version": "12.x.y", "lessThan": "13"},  # 読めない
        {"status": "unaffected", "version": "11.0.0"},  # 影響なし: その系列の 11.0.0 以上
        {"status": "affected", "version": ""},
        "broken",
        {"status": "unknown", "version": ""},  # 本物にある形（判定できない）
        {"status": "affected", "version": "10.2.0", "versionType": "semver", "lessThan": "10.2.9"},  # 想定外の versionType
        {"status": "affected", "version": "12.2", "lessThan": "12.2.4-h1", "changes": [{"at": "12.2.4-h1", "status": "unaffected"}]},
    ])
    assert [(None if x.get("unreadable") else x["status"], x.get("branch"), x.get("ge"), x.get("le"), x.get("open"),
             bool(x.get("unreadable"))) for x in r] == [
        (None, "10.1", None, None, None, True), ("affected", "9.1", "9.1.0", "9.1.5", None, False),
        ("affected", "9.0", "9.0.1", None, True, False), (None, None, None, None, None, True),
        ("unaffected", "11.0", "11.0.0", None, True, False), (None, None, None, None, None, True),
        (None, None, None, None, None, True), (None, None, None, None, None, True), (None, "10.2", None, None, None, True),
        ("affected", "12.2", "12.2.0", None, None, False)]  # "12.2" は "12.2.0" として読む
    assert r[7]["status"] == "unknown" and r[0]["status"] == "affected"  # 読めない行にも元の状態を残す
    assert all("src" in x for x in r)
    assert vf.ranges_from_versions(None) == []


def test_ranges_default_status_and_branch_products():
    # defaultStatus が affected: 記載のない系列の扱いを 1 件足す。unaffected・無しは足さない
    r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0"}], default_status="affected")
    assert [_core(x) for x in r] == [{"status": "affected", "branch": "10.2", "ge": "10.2.0", "open": True},
                                     {"kind": "default", "default": "affected"}]
    assert len(vf.ranges_from_versions([], default_status="unaffected")) == 0
    assert _core(vf.ranges_from_versions([], default_status="weird")[0]) == {"kind": "default", "default": "unknown"}
    # 製品名に系列が付く "PAN-OS 11.1"（本物にある形）: "All" はその系列すべて。別の系列の版は読まない
    r = vf.ranges_from_versions([{"status": "unaffected", "version": "All", "versionType": "custom"},
                                 {"status": "affected", "version": "10.2.0"}], product="PAN-OS 11.1", product_branch="11.1")
    assert _core(r[0]) == {"status": "unaffected", "all": True, "branch": "11.1"}
    assert r[1]["unreadable"] and r[1]["branch"] is None  # 製品名の系列と版の系列が違う: 全系列で判定できない
    # 行が多すぎる・versions の形が違う
    many = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0"}] * (vf.MAX_RANGES + 1))
    assert len(many) == vf.MAX_RANGES + 1 and many[-1]["unreadable"] and many[-1]["branch"] is None
    assert vf.ranges_from_versions("x")[0]["unreadable"]


def test_ranges_hotfix_changes_any_order_and_lessthan_is_a_fix():
    asc = [{"at": a, "status": "unaffected"} for a in ("10.2.7-h40", "10.2.10-h43", "10.2.13-h28", "10.2.16-h13", "10.2.18-h14")]
    desc = list(reversed(asc))
    want = ["10.2.7-h40", "10.2.10-h43", "10.2.13-h28", "10.2.16-h13", "10.2.18-h14"]
    for changes in (asc, desc, [asc[2], asc[4], asc[0], asc[3], asc[1]]):
        a = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.18-h14", "changes": changes}])[0]
        assert _core(a) == {"status": "affected", "branch": "10.2", "ge": "10.2.0", "fixes": want}
        b = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "changes": changes}])[0]  # changes だけ
        assert b["fixes"] == want
        # lessThan が修正点の最小（CVE-2026-0273 の形）でも、修正点として持つ（lessThan で打ち切らない）
        c = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.7-h40", "changes": changes}])[0]
        assert c["fixes"] == want
    # 読めない at・unaffected 以外の状態・系列の外の修正点・同じ保守版に 2 つの修正点は、その行を「判定できない」にする
    for bad in ([{"at": "zzz", "status": "unaffected"}], [{"at": "10.2.5", "status": "unknown"}],
                [{"at": "10.2.5-h1", "status": "unaffected"}, {"at": "10.2.5-h3", "status": "unaffected"}],
                ["x"], [{"at": "10.2.0", "status": "unaffected"}]):
        r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9", "changes": bad}])[0]
        assert r.get("unreadable") and r["branch"] == "10.2", bad
    # 系列の外の修正点（系列をまたぐ行）は、系列なしの読めない行（全系列で判定できない）
    r = vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9",
                                  "changes": [{"at": "11.1.5", "status": "unaffected"}]}])[0]
    assert r.get("unreadable") and r["branch"] is None


def test_ranges_wildcard_upper_bound_and_reaffected_and_platforms():
    r = vf.ranges_from_versions([
        {"status": "affected", "version": "10.2.0", "lessThan": "*"},  # その系列だけか全体か決められない → 全系列で判定できない
        {"status": "affected", "version": "11.1.0", "lessThan": "11.1.*"},
        {"status": "affected", "version": "11.2.0", "lessThanOrEqual": "11.2.*"},
        {"status": "affected", "version": "9.1.0", "lessThan": "10.*"},  # 始まりと系列が違うワイルドカードは読まない
        {"status": "affected", "version": "10.1.0", "lessThan": "10.1.9", "changes": [
            {"at": "10.1.5", "status": "unaffected"}, {"at": "10.1.7", "status": "affected"}]},  # 途中からまた該当
    ], ["Panorama"])
    assert [(x["branch"], x.get("open"), x.get("fixes"), bool(x.get("unreadable"))) for x in r] == [
        (None, None, None, True), ("11.1", True, None, False), ("11.2", True, None, False),
        ("9.1", None, None, True), ("10.1", None, None, True)]
    assert all(x["platforms"] == ["Panorama"] for x in r)
    assert vf.ranges_from_versions([{"status": "affected", "version": "10.2.0", "lessThan": "10.2.9"}])[0].get("platforms") is None


def test_parse_paloalto_hotfix_fixture():
    """本物の応答の形（lessThan＋複数の changes、changes だけ、platforms つき、読めない範囲）。作り物の ID と題"""
    advs = {a["ext_id"]: a for a in vf.parse_paloalto(fixture_json("paloalto_panos_hotfix.json"))}
    assert set(advs) == {"CVE-2099-1001", "CVE-2099-1002", "CVE-2099-1003"}
    a = advs["CVE-2099-1001"]
    assert a["affected"][0]["fixes"] == ["10.2.7-h40", "10.2.10-h43", "10.2.13-h28", "10.2.16-h13", "10.2.18-h14"]
    assert _core(a["affected"][1]) == {"status": "affected", "branch": "11.1", "ge": "11.1.0", "fixes": ["11.1.4-h39", "11.1.6-h41"]}
    assert a["cvss"] == 8.7 and a["severity"] == "high"  # Prisma Access の場面の点（9.9）は採らない
    b = advs["CVE-2099-1002"]
    assert all(x["platforms"] == ["Panorama"] for x in b["affected"]) and b["unreadable"] == 0
    c = advs["CVE-2099-1003"]
    assert c["unreadable"] == 2 and c["affected"][0]["open"] is True and c["cvss"] == 6.1  # 区別できなければ最も高い点


def test_cvss_picks_panos_scenario_or_representative():
    def m(score, text):
        return {"cvssV4_0": {"baseScore": score}, "scenarios": [{"lang": "en", "value": text}]}

    assert vf._cvss_of([m(9.9, "Prisma Access exposure"), m(8.7, "PA-Series and VM-Series firewalls")]) == (8.7, "high")
    assert vf._cvss_of([m(9.9, "Prisma Access exposure"), m(5.0, "Cloud NGFW")]) == (9.9, "critical")  # 区別できない: 代表の点
    assert vf._cvss_of([{"cvssV3_1": {"baseScore": 5.3}}]) == (5.3, "medium")  # scenarios が無い
    assert vf._cvss_of(None) == (None, "none")


def test_parse_kev():
    kev = vf.parse_kev(fixture_json("kev.json"))
    assert kev == {"CVE-2099-0001": "2099-02-01", "CVE-2099-7777": "2099-02-08"}  # 形の違う ID は読まない
    for bad in (None, {}, {"vulnerabilities": "x"}, {"vulnerabilities": []}, {"vulnerabilities": [{"cveID": "x"}]}):
        with pytest.raises(vf.FetchError):
            vf.parse_kev(bad)


def test_parse_eol():
    rows = vf.parse_eol("panos", fixture_json("eol_panos.json"))
    assert {(r["platform"], r["branch"], r["eol_date"]) for r in rows} == {
        ("paloalto_panos", "11.1", date(2099, 6, 30)), ("paloalto_panos", "10.2", date(2025, 8, 27))}  # eolFrom が null・不正な名前は除く
    assert vf.parse_eol("cisco-ios-xe", fixture_json("eol_cisco_ios_xe.json"))[0]["platform"] == "cisco_xe"
    assert vf.parse_eol("fortios", fixture_json("eol_fortios.json"))[0]["url"] == "https://endoflife.date/fortios"
    # API の形が変わっても、落ちずに「取得に失敗」として扱える
    for bad in (None, [], {"result": None}, {"result": {"releases": "x"}}, {"result": {"releases": []}},
                {"result": {"releases": [{"name": "1.0", "eolFrom": False}]}}):
        with pytest.raises(vf.FetchError):
            vf.parse_eol("panos", bad)


# ================================================================ 取得の実行・照合の移り変わり


def test_run_fetch_stores_and_matches_without_sending_device_info(net, enabled):
    net.routes.update(standard_routes())
    secret_name, secret_host = "vuln-secret-core-sw01", "10.77.88.99"
    d1 = run(_mk_device(secret_name, "paloalto_panos", "10.2.5-h1", model="PA-SECRETMODEL", hostname=secret_host))
    d2 = mk_device("fw2", "paloalto_panos", "10.2.5-h2")
    d3 = mk_device("fw3", "paloalto_panos", "PAN-OS ???")  # 判定できない
    d4 = mk_device("sw4", "cisco_ios", "17.9.4a")  # 脆弱性の情報源が未対応の機種

    res = run(_fetch())
    assert {k: v["ok"] for k, v in res["sources"].items()} == {"kev": True, "paloalto": True, "eol": True}
    assert res["sources"]["paloalto"]["count"] == 2 and res["sources"]["kev"]["count"] == 2

    # 取得は製品単位の固定の URL だけ。機器名・IP・モデル・バージョンは、URL にもヘッダーにも入らない
    assert sorted(net.urls) == sorted(standard_routes())
    blob = " ".join(net.urls + [f"{k}:{v}" for c in net.calls for k, v in c.header_items()])
    for secret in (secret_name, secret_host, "SECRETMODEL", "10.2.5", "paloalto_panos"):
        assert secret not in blob
    assert all("?" not in u and "#" not in u for u in net.urls)

    async def advs():
        async with AsyncSessionLocal() as db:
            return {a.ext_id: a for a in (await db.execute(select(VulnAdvisory))).scalars()}
    a = run(advs())
    assert a["CVE-2099-0001"].kev is True and a["CVE-2099-0001"].kev_due == date(2099, 2, 1)  # KEV の印
    assert a["PAN-SA-2099-0001"].kev is False and a["PAN-SA-2099-0001"].kev_due is None

    m1, m2 = run(_matches(d1)), run(_matches(d2))
    assert m1 == {"CVE-2099-0001": ("open", None), "PAN-SA-2099-0001": ("open", None)}
    assert m2 == {"PAN-SA-2099-0001": ("open", None)}  # 10.2.5-h2 は修正済み。全バージョンの勧告 B だけ
    assert run(_matches(d3)) == {} and run(_matches(d4)) == {}

    st = sources_state()
    assert all(s.last_ok_at and s.last_error is None for s in st.values())
    assert st["paloalto"].last_count == 2 and "CVE-2099-0001" in st["kev"].cursor

    async def eols():
        async with AsyncSessionLocal() as db:
            return {(e.platform, e.branch): e for e in (await db.execute(select(EolDate))).scalars()}
    e = run(eols())
    assert set(e) == {("paloalto_panos", "11.1"), ("paloalto_panos", "10.2"), ("fortinet", "7.2"), ("fortinet", "7.0"),
                      ("cisco_xe", "17.9"), ("cisco_xe", "17.18")}
    assert e[("paloalto_panos", "10.2")].source == "endoflife.date" and e[("paloalto_panos", "10.2")].kind == "os"

    # 2 回目（同じ内容）は、勧告・照合結果を増やさない
    run(_fetch())
    assert run(_matches(d1)) == m1 and len(run(eols())) == 6


def test_match_transitions_open_ack_fixed_reopen(net, enabled):
    net.routes.update(standard_routes())
    d = mk_device("fw", "paloalto_panos", "10.2.5-h1")
    run(_fetch())
    assert run(_matches(d)) == {"CVE-2099-0001": ("open", None), "PAN-SA-2099-0001": ("open", None)}

    async def ack(ext_id):
        async with AsyncSessionLocal() as db:
            m = (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                  .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == ext_id))).scalar_one()
            m.state, m.note, m.acked_by = "ack", "メンテナンス窓で対応予定", "operator"
            await db.commit()
    run(ack("CVE-2099-0001"))
    # バージョンが変わっても、まだ該当なら ack のまま（10.2.6 は 2 つ目の範囲に入る）
    run(_set_version(d, "10.2.6"))
    r = run(_reconcile([d]))
    assert r["new"] == [] and r["fixed"] == 0
    assert run(_matches(d)) == {"CVE-2099-0001": ("ack", "メンテナンス窓で対応予定"), "PAN-SA-2099-0001": ("open", None)}
    # 読み取れないバージョンになった（収集の失敗など）: 判定を変えない
    run(_set_version(d, "garbage"))
    assert run(_reconcile([d]))["devices"] == 0
    assert run(_matches(d))["CVE-2099-0001"][0] == "ack"
    # 修正版へ上げた: ack も open も外れる（全バージョンの B は残る）。ack は fixed になる
    run(_set_version(d, "10.2.9"))
    r = run(_reconcile([d]))
    assert r["fixed"] == 1 and r["new"] == []
    assert run(_matches(d)) == {"CVE-2099-0001": ("fixed", "メンテナンス窓で対応予定"), "PAN-SA-2099-0001": ("open", None)}
    # 外れたあとは、何度照合しても変わらない
    assert run(_reconcile([d]))["fixed"] == 0
    # また該当するバージョンになった（戻した）: open に戻り、確認済みの印は外れる。新しい該当として返す
    run(_set_version(d, "10.2.5"))
    r = run(_reconcile([d]))
    assert len(r["new"]) == 1 and r["new"][0][0] == d
    assert run(_matches(d))["CVE-2099-0001"] == ("open", None)


def test_reconcile_limited_to_given_devices_and_ignores_other_platforms(net, enabled):
    net.routes.update(standard_routes())
    a = mk_device("a", "paloalto_panos", "10.2.5-h1")
    b = mk_device("b", "paloalto_panos", "10.2.0")
    run(_fetch())
    run(_set_version(a, "10.2.9"))
    run(_set_version(b, "10.2.9"))
    run(_reconcile([a]))  # a だけやり直す
    assert run(_matches(a))["CVE-2099-0001"][0] == "fixed" and run(_matches(b))["CVE-2099-0001"][0] == "open"
    assert run(_reconcile([]))["devices"] == 0
    assert run(_reconcile())["devices"] == 2


def test_failure_of_one_source_does_not_stop_others(net, enabled):
    net.routes.update(standard_routes())
    net.routes[vf.URL_PALOALTO] = urllib.error.HTTPError(vf.URL_PALOALTO, 500, "x", {}, None)
    res = run(_fetch())
    assert res["sources"]["paloalto"] == {"ok": False, "count": None, "error": "HTTP 500"}
    assert res["sources"]["kev"]["ok"] and res["sources"]["eol"]["ok"]
    st = sources_state()
    assert st["paloalto"].last_error == "HTTP 500" and st["paloalto"].last_ok_at is None and st["paloalto"].last_at
    assert st["kev"].last_error is None and st["eol"].last_ok_at
    # 次に成功すると、エラーは消える
    net.routes[vf.URL_PALOALTO] = fixture_bytes("paloalto_panos.json")
    run(_fetch(["paloalto"]))
    assert sources_state()["paloalto"].last_error is None


@pytest.mark.parametrize("exc,needle", [
    (urllib.error.HTTPError(vf.URL_PALOALTO, 429, "x", {}, None), "429"),
    (urllib.error.URLError(TimeoutError()), "時間切れ"),
    (b"<html>not json</html>", "JSON"),
    (b'{"data": [{"cveMetadata": {}}]}', "形"),
])
def test_source_failures_recorded_without_secrets(net, enabled, exc, needle):
    net.routes.update(standard_routes())
    net.routes[vf.URL_PALOALTO] = exc
    res = run(_fetch())
    err = res["sources"]["paloalto"]["error"]
    assert needle in err and "://" not in err and "?" not in err
    assert res["sources"]["kev"]["ok"]
    assert "?" not in (sources_state()["paloalto"].last_error or "")


def test_unexpected_exception_is_recorded_by_type_only(net, enabled):
    net.routes.update(standard_routes())
    net.routes[vf.URL_KEV] = RuntimeError("boom https://www.cisa.gov/x?token=SECRET123")
    res = run(_fetch())
    assert res["sources"]["kev"]["error"] == "想定外のエラーです（RuntimeError）"
    assert "SECRET123" not in (sources_state()["kev"].last_error or "")
    assert res["sources"]["paloalto"]["ok"]


def test_eol_partial_failure_keeps_fetched_products(net, enabled):
    net.routes.update(standard_routes())
    net.routes[vf.URL_EOL.format(product="fortios")] = urllib.error.HTTPError("u", 404, "x", {}, None)
    net.routes[vf.URL_EOL.format(product="cisco-ios-xe")] = b'{"result": {"releases": "changed"}}'  # 形が変わった（Beta の API）
    res = run(_fetch(["eol"]))
    assert res["sources"]["eol"]["ok"] is False
    err = res["sources"]["eol"]["error"]
    assert "fortios: HTTP 404" in err and "cisco-ios-xe" in err
    st = sources_state()["eol"]
    assert st.last_ok_at is None and st.last_error

    async def n():
        async with AsyncSessionLocal() as db:
            return {(e.platform) for e in (await db.execute(select(EolDate))).scalars()}
    assert run(n()) == {"paloalto_panos"}  # 取れた製品は保存してある


def test_sources_setting_limits_fetch(net, enabled, monkeypatch):
    net.routes.update(standard_routes())
    monkeypatch.setattr(settings, "VULN_SOURCES", "eol, FORTINET ,nvd")
    assert vuln_service.active_sources() == ["eol"] and vuln_service.unknown_sources() == ["fortinet", "nvd"]
    res = run(_fetch())
    assert list(res["sources"]) == ["eol"]
    assert all("endoflife.date" in u for u in net.urls)


def test_due_sources_schedule(enabled):
    now = utcnow()
    at = lambda h: datetime(2026, 11, 26, h, 30)  # noqa: E731

    async def due(now_local, **kw):
        async with AsyncSessionLocal() as db:
            return await vuln_service.due_sources(db, now, now_local)
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(settings.TIMEZONE)
    assert run(due(at(3).replace(tzinfo=tz))) == []  # VULN_FETCH_HOUR（4 時）の前
    assert run(due(at(4).replace(tzinfo=tz))) == ["kev", "paloalto", "eol"]  # 取得したことがない
    # 今日成功したものは取らない。失敗したものは間をあけて再試行
    async def mark():
        async with AsyncSessionLocal() as db:
            n = utcnow()
            db.add(VulnSource(source="kev", last_at=n, last_ok_at=n))
            db.add(VulnSource(source="paloalto", last_at=n, last_error="HTTP 500"))
            db.add(VulnSource(source="eol", last_at=n - timedelta(hours=4), last_error="HTTP 500"))
            await db.commit()
    run(mark())
    today = datetime.now(tz).replace(hour=12)
    assert run(due(today)) == ["eol"]


# ================================================================ サポート終了日（手入力が優先）


def test_manual_eol_overrides_auto_and_survives_refetch(net, enabled):
    net.routes.update(standard_routes())
    d = mk_device("fw", "paloalto_panos", "10.2.5", model="PA-9999")
    run(_fetch(["eol"]))

    async def info():
        async with AsyncSessionLocal() as db:
            dev = await db.get(Device, d)
            return vuln_service.device_eol(await vuln_service.eol_rows(db), dev, date(2026, 11, 26))
    e = run(info())
    assert e["os"]["source"] == "endoflife.date" and e["os"]["eol_date"] == "2025-08-27" and e["os"]["days_left"] < 0
    assert e["branch"] == "10.2" and e["hardware"] is None

    async def put_manual():
        async with AsyncSessionLocal() as db:
            db.add(EolDate(platform="paloalto_panos", kind="os", branch="10.2", model="", eol_date=date(2028, 1, 31),
                           source="manual", note="延長保守契約", updated_by="operator"))
            db.add(EolDate(platform="paloalto_panos", kind="hardware", branch="", model="pa-9999",
                           eol_date=date(2027, 3, 31), source="manual", updated_by="operator"))
            await db.commit()
    run(put_manual())
    e = run(info())
    assert e["os"]["source"] == "manual" and e["os"]["eol_date"] == "2028-01-31" and e["os"]["note"] == "延長保守契約"
    assert e["hardware"]["eol_date"] == "2027-03-31"  # モデルは大文字小文字を区別しない
    run(_fetch(["eol"]))  # 自動取得をやり直しても、手入力は上書きされない
    assert run(info())["os"]["source"] == "manual"

    async def drop_manual():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(EolDate).where(EolDate.source == "manual"))
            await db.commit()
    run(drop_manual())
    assert run(info())["os"]["source"] == "endoflife.date"  # 手入力を消すと自動取得に戻る


def test_eol_for_iosxe_registered_as_cisco_ios(net, enabled):
    net.routes.update(standard_routes())
    d = mk_device("xe", "cisco_ios", "17.09.04a")  # 0 埋め・再ビルドの書き方でも、系列 17.9 の終了日に当たる
    run(_fetch(["eol"]))

    async def info():
        async with AsyncSessionLocal() as db:
            return vuln_service.device_eol(await vuln_service.eol_rows(db), await db.get(Device, d), date(2026, 11, 26))
    e = run(info())
    assert e["branch"] == "17.9" and e["os"]["eol_date"] == "2027-06-30" and e["os"]["days_left"] == 216


# ================================================================ 無効のとき


def test_disabled_does_nothing(net):
    assert settings.VULN_ENABLED is False  # 既定は無効
    with TestClient(app) as c:
        h = _login(c, "admin", "initial-pass-123")
        assert c.get("/api/health").json()["features"]["vuln"] is False
        for path in ("/summary", "/matches", "/devices", "/unknown", "/eol", "/eol/devices", "/matches/export"):
            r = c.get(f"/api/vulns{path}", headers=h)
            assert r.status_code == 404 and "VULN_ENABLED" in r.json()["detail"], path
        assert c.post("/api/vulns/fetch", headers=h).status_code == 404
        assert c.put("/api/vulns/eol", json={}, headers=h).status_code == 404
    assert worker.fetch_vulns.apply().get() == {"disabled": True}
    assert worker.fetch_vulns.apply(args=(True,)).get() == {"disabled": True}
    assert net.calls == []  # 外へは一切つながない
    comp = run(_check_vuln())
    assert comp.status == "unknown"


async def _check_vuln():
    async with AsyncSessionLocal() as db:
        return await system.check_vuln(db, utcnow())


def test_beat_task_fetches_only_when_due(net, enabled, monkeypatch):
    import fakeredis
    net.routes.update(standard_routes())
    monkeypatch.setattr(worker, "_redis", lambda: fakeredis.FakeRedis())
    from zoneinfo import ZoneInfo
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime(2026, 11, 26, 3, 0, tzinfo=ZoneInfo(settings.TIMEZONE)))
    assert worker.fetch_vulns.apply().get() == {"due": []}  # 4 時前
    assert net.calls == []
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime.now(ZoneInfo(settings.TIMEZONE)).replace(hour=12))
    res = worker.fetch_vulns.apply().get()
    assert {k: v["ok"] for k, v in res["sources"].items()} == {"kev": True, "paloalto": True, "eol": True}
    assert worker.fetch_vulns.apply().get() == {"due": []}  # 今日は取得済み
    assert worker.fetch_vulns.apply(args=(True,)).get()["sources"]  # 「いま取得」は何度でも（API 側で間隔を制限）
    # 同時には 1 つだけ
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(worker, "_redis", lambda: r)
    lock = r.lock("netconfig:vuln-fetch", timeout=60)
    lock.acquire()
    assert worker.fetch_vulns.apply(args=(True,)).get() == {"skipped": True}


def test_collect_hook_reconciles_one_device(net, enabled):
    net.routes.update(standard_routes())
    d = mk_device("fw", "paloalto_panos", "10.2.9")
    other = mk_device("fw-other", "paloalto_panos", "10.2.9")
    run(_fetch())
    run(_set_version(d, "10.2.1"))
    run(_set_version(other, "10.2.1"))
    run(worker._reconcile_vulns(d))  # 収集のあとの照合（その機器だけ。外へはつながない）
    assert run(_matches(d))["CVE-2099-0001"][0] == "open"
    assert "CVE-2099-0001" not in run(_matches(other))  # 照合したのは d だけ
    assert len(net.calls) == 5  # 取得のときの 5 本だけ


# ================================================================ システム状態


def test_system_check_vuln(net, enabled):
    now = utcnow()
    assert run(_check_vuln()).status == "ok" and "まだ取得していません" in run(_check_vuln()).summary

    async def put(**rows):
        async with AsyncSessionLocal() as db:
            await db.execute(delete(VulnSource))
            for name, kw in rows.items():
                db.add(VulnSource(source=name, **kw))
            await db.commit()
    run(put(kev={"last_ok_at": now}, paloalto={"last_ok_at": now}, eol={"last_ok_at": now}))
    assert run(_check_vuln()).status == "ok"
    run(put(kev={"last_ok_at": now}, paloalto={"last_ok_at": now - timedelta(days=1), "last_error": "HTTP 500"}, eol={"last_ok_at": now}))
    c = run(_check_vuln())
    assert c.status == "warn" and "Palo Alto" in c.summary and c.detail["failed"]
    run(put(kev={"last_ok_at": now}, paloalto={"last_ok_at": now - timedelta(days=4)}, eol={"last_ok_at": now}))
    c = run(_check_vuln())
    assert c.status == "warn" and "3 日以上" in c.summary and "Palo Alto" in c.summary
    assert "last_success" in c.detail


# ================================================================ API


def _login(c, u, p):
    r = c.post("/api/auth/token", data={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = _login(c, "admin", "initial-pass-123")
        hs, ids = {}, []
        for role in ("operator", "viewer"):
            name = f"vuln-{role}-{uuid.uuid4().hex[:4]}"
            r = c.post("/api/users/", json={"username": name, "password": PW, "role": role}, headers=admin)
            assert r.status_code == 201, r.text
            ids.append(r.json()["id"])
            hs[role] = (name, _login(c, name, PW))
        yield {"c": c, "admin": admin, "op": hs["operator"][1], "view": hs["viewer"][1], "op_name": hs["operator"][0]}
        for i in ids:
            c.delete(f"/api/users/{i}", headers=admin)


def populate(net):
    net.routes.update(standard_routes())
    a = mk_device("fw-a", "paloalto_panos", "10.2.5-h1", model="PA-440")
    b = mk_device("fw-b", "paloalto_panos", "10.2.9")
    mk_device("fw-c", "paloalto_panos", "weird")
    mk_device("sw-d", "cisco_ios", "17.9.4a")
    mk_device("rtr-e", "yamaha", "Rev.15.02.17")
    mk_device("fw-f", "paloalto_panos", None)
    run(_fetch())
    return a, b


def test_api_roles_and_lists(ctx, net, enabled):
    c, admin, op, view = ctx["c"], ctx["admin"], ctx["op"], ctx["view"]
    a, _b = populate(net)
    assert c.get("/api/health").json()["features"]["vuln"] is True
    for h in (view, op, admin):
        assert c.get("/api/vulns/summary", headers=h).status_code == 200  # 全ロールが閲覧できる
    s = c.get("/api/vulns/summary", headers=view).json()
    # fw-a は A（重大・KEV）と B（中）、fw-b は B だけ
    assert s["counts"]["critical"] == 1 and s["counts"]["medium"] == 2 and s["counts"]["kev"] == 1
    # 判定できない: weird・Cisco（情報源が未対応）・Yamaha・未取得。ほかのテストの機器も数えるので「以上」
    assert s["counts"]["candidate"] == 0 and s["unknown_devices"] >= 4 and s["eol"]["ended"] >= 2
    assert [x["source"] for x in s["sources"]] == ["kev", "paloalto", "eol"] and all(x["last_ok_at"] for x in s["sources"])
    assert s["unknown_sources"] == []

    m = c.get("/api/vulns/matches", headers=view).json()
    assert m["total"] == 3  # fw-a が A と B、fw-b（10.2.9 は A では修正済み）が B
    first = m["items"][0]
    assert first["advisory"]["ext_id"] == "CVE-2099-0001" and first["advisory"]["kev"] is True  # 悪用確認済み・重大が先頭
    assert first["confidence"] == "confirmed" and first["state"] == "open" and first["device_name"] == "vuln-fw-a"
    assert c.get("/api/vulns/matches", params={"severity": "critical"}, headers=view).json()["total"] == 1
    assert c.get("/api/vulns/matches", params={"kev": "true"}, headers=view).json()["total"] == 1
    assert c.get("/api/vulns/matches", params={"device_id": a}, headers=view).json()["total"] == 2
    assert c.get("/api/vulns/matches", params={"confidence": "candidate"}, headers=view).json()["total"] == 0
    assert c.get("/api/vulns/matches", params={"state": "fixed"}, headers=view).json()["total"] == 0
    assert c.get("/api/vulns/matches", params={"limit": 1}, headers=view).json()["items"].__len__() == 1
    assert c.get("/api/vulns/matches", params={"severity": "bogus"}, headers=view).status_code == 422

    d = {x["name"]: x for x in c.get("/api/vulns/devices", headers=view).json()["items"] if x["name"].startswith("vuln-")}
    assert set(d) == {"vuln-fw-a", "vuln-fw-b"} and d["vuln-fw-a"]["critical"] == 1 and d["vuln-fw-a"]["kev"] == 1
    u = {x["name"]: x["reason"] for x in c.get("/api/vulns/unknown", headers=view).json()["items"] if x["name"].startswith("vuln-")}
    assert u == {"vuln-fw-c": "unparseable", "vuln-sw-d": "no_vuln_source", "vuln-rtr-e": "unsupported", "vuln-fw-f": "no_version"}

    adv = c.get("/api/vulns/advisories/" + first["advisory"]["id"], headers=view).json()
    assert _core(adv["affected"][0]) == {"status": "affected", "branch": "10.2", "ge": "10.2.0", "fixes": ["10.2.5-h2"]}
    assert adv["affected"][0]["src"]["lessThan"] == "10.2.5-h2"  # 元の値も返す（判定の理由を追える）
    assert c.get("/api/vulns/advisories/nope", headers=view).status_code == 404


def test_api_ack_permissions_notes_and_audit(ctx, net, enabled):
    c, admin, op, view = ctx["c"], ctx["admin"], ctx["op"], ctx["view"]
    populate(net)
    items = c.get("/api/vulns/matches", headers=admin).json()["items"]
    mid = items[0]["id"]
    assert c.post(f"/api/vulns/matches/{mid}/ack", json={"note": "対応済みの予定"}, headers=view).status_code == 403
    assert c.post(f"/api/vulns/matches/{mid}/unack", headers=view).status_code == 403
    for bad in ({}, {"note": ""}, {"note": "   "}, {"note": "x" * 501}):  # メモは必須
        assert c.post(f"/api/vulns/matches/{mid}/ack", json=bad, headers=op).status_code == 422
    assert c.post("/api/vulns/matches/nope/ack", json={"note": "x"}, headers=op).status_code == 404
    r = c.post(f"/api/vulns/matches/{mid}/ack", json={"note": "  修正版へ上げる計画です "}, headers=op)
    assert r.status_code == 200 and r.json()["state"] == "ack" and r.json()["note"] == "修正版へ上げる計画です"
    assert r.json()["acked_by"] == ctx["op_name"]
    assert c.get("/api/vulns/matches", headers=view).json()["total"] == len(items) - 1  # 既定は未確認だけ
    acked = c.get("/api/vulns/matches", params={"state": "ack"}, headers=view).json()["items"]
    assert [x["id"] for x in acked] == [mid] and acked[0]["note"] == "修正版へ上げる計画です"
    assert c.get("/api/vulns/summary", headers=view).json()["counts"]["acked"] == 1
    assert c.post(f"/api/vulns/matches/{mid}/unack", headers=op).status_code == 200
    assert c.post(f"/api/vulns/matches/{mid}/unack", headers=op).status_code == 409  # 確認済みではない
    # 解消したものは確認済みにできない
    async def fix():
        async with AsyncSessionLocal() as db:
            (await db.get(VulnMatch, mid)).state = "fixed"
            await db.commit()
    run(fix())
    assert c.post(f"/api/vulns/matches/{mid}/ack", json={"note": "x"}, headers=op).status_code == 409
    # 監査ログ
    logs = c.get("/api/audit/logs", params={"action": "vuln.ack"}, headers=admin).json()["items"]
    assert logs and logs[0]["action"] == "vuln.ack" and logs[0]["username"] == ctx["op_name"]


def test_api_eol_manual_crud_and_priority(ctx, net, enabled):
    c, admin, op, view = ctx["c"], ctx["admin"], ctx["op"], ctx["view"]
    a, _ = populate(net)
    body = {"platform": "paloalto_panos", "kind": "os", "branch": "10.2", "eol_date": "2030-01-31", "note": "延長保守"}
    assert c.put("/api/vulns/eol", json=body, headers=view).status_code == 403
    for bad in ({**body, "platform": "nope"}, {**body, "branch": "10 2!"}, {**body, "branch": ""},
                {**body, "kind": "hardware", "branch": "", "model": ""}, {**body, "eol_date": "2030-13-01"},
                {**body, "note": "x" * 501}):
        assert c.put("/api/vulns/eol", json=bad, headers=op).status_code == 422, bad
    r = c.put("/api/vulns/eol", json=body, headers=op)
    assert r.status_code == 200 and r.json()["source"] == "manual" and r.json()["updated_by"] == ctx["op_name"]
    eid = r.json()["id"]
    assert c.put("/api/vulns/eol", json={**body, "eol_date": "2031-01-31"}, headers=op).json()["id"] == eid  # 同じキーは更新
    hw = c.put("/api/vulns/eol", json={"platform": "paloalto_panos", "kind": "hardware", "model": "PA-440",
                                       "eol_date": "2029-05-31", "eos_date": "2026-05-31"}, headers=admin)
    assert hw.status_code == 200 and hw.json()["branch"] == ""
    rows = c.get("/api/vulns/eol", headers=view).json()
    assert {(x["source"], x["kind"]) for x in rows["items"]} >= {("manual", "os"), ("manual", "hardware"), ("endoflife.date", "os")}
    assert any(p["id"] == "paloalto_panos" for p in rows["platforms"])

    dev = {x["device_id"]: x for x in c.get("/api/vulns/eol/devices", headers=view).json()["items"]}[a]
    assert dev["os"]["source"] == "manual" and dev["os"]["eol_date"] == "2031-01-31"  # 手入力が自動取得より優先
    assert dev["hardware"]["eol_date"] == "2029-05-31" and dev["branch"] == "10.2" and dev["days_left"] > 0
    run(_fetch(["eol"]))
    dev = {x["device_id"]: x for x in c.get("/api/vulns/eol/devices", headers=view).json()["items"]}[a]
    assert dev["os"]["source"] == "manual"  # 自動取得のやり直しでも変わらない

    auto = next(x for x in rows["items"] if x["source"] == "endoflife.date")
    assert c.delete(f"/api/vulns/eol/{auto['id']}", headers=admin).status_code == 409  # 自動取得の分は消せない
    assert c.delete(f"/api/vulns/eol/{eid}", headers=view).status_code == 403
    assert c.delete(f"/api/vulns/eol/{eid}", headers=op).status_code == 204
    assert c.delete(f"/api/vulns/eol/{eid}", headers=op).status_code == 404
    dev = {x["device_id"]: x for x in c.get("/api/vulns/eol/devices", headers=view).json()["items"]}[a]
    assert dev["os"]["source"] == "endoflife.date"


def test_api_fetch_now_admin_only_with_interval(ctx, net, enabled):
    c, admin, op = ctx["c"], ctx["admin"], ctx["op"]
    with mock.patch.object(worker, "fetch_vulns") as task:
        task.delay.return_value.id = "t1"
        assert c.post("/api/vulns/fetch", headers=op).status_code == 403  # 管理者だけ
        r = c.post("/api/vulns/fetch", headers=admin)
        assert r.status_code == 202 and r.json()["queued"] is True
        task.delay.assert_called_once_with(True)
        r2 = c.post("/api/vulns/fetch", headers=admin)  # 間隔の制限
        assert r2.status_code == 429 and int(r2.headers["Retry-After"]) > 0
        assert task.delay.call_count == 1
    assert net.calls == []  # API 自身は外へつながない（worker が行う）


def test_api_csv_export_neutralizes_formulas(ctx, net, enabled):
    c, view = ctx["c"], ctx["view"]
    populate(net)

    async def evil():
        async with AsyncSessionLocal() as db:
            a = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-0001"))).scalar_one()
            a.title = "=HYPERLINK(\"https://evil.example.test\")"
            await db.commit()
    run(evil())
    r = c.get("/api/vulns/matches/export", headers=view)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8-sig")
    assert "'=HYPERLINK" in text and "\r\n=HYPERLINK" not in text and ",=HYPERLINK" not in text
    assert "vuln-fw-a" in text and "該当" in text
    assert text.splitlines()[0].startswith("機器,")


def test_api_token_read_only_scope(ctx, net, enabled):
    c = ctx["c"]
    populate(net)
    sess = _login(c, "admin", "initial-pass-123")
    r = c.post("/api/auth/tokens", json={"name": "vuln-test", "scope": "read", "days": 1, "password": "initial-pass-123"}, headers=sess)
    assert r.status_code == 201, r.text
    tok, tid = r.json()["token"], r.json()["id"]
    h = {"Authorization": f"Bearer {tok}"}
    try:
        assert c.get("/api/vulns/summary", headers=h).status_code == 200  # 読み取りはトークンで呼べる
        assert c.get("/api/vulns/matches", headers=h).status_code == 200
        mid = c.get("/api/vulns/matches", headers=h).json()["items"][0]["id"]
        assert c.post(f"/api/vulns/matches/{mid}/ack", json={"note": "x"}, headers=h).status_code == 403  # 書き込みはログインだけ
        assert c.put("/api/vulns/eol", json={"platform": "paloalto_panos", "branch": "10.2", "eol_date": "2030-01-01"},
                     headers=h).status_code == 403
        assert c.post("/api/vulns/fetch", headers=h).status_code == 403
    finally:
        c.delete(f"/api/auth/tokens/{tid}", headers=sess)


# ================================================================ レビュー指摘の反映（ホットフィックス・Panorama・読めない範囲・手入力の EOL など）


def hotfix_routes() -> dict[str, object]:
    return {**standard_routes(), vf.URL_PALOALTO: fixture_bytes("paloalto_panos_hotfix.json")}


async def _conf(device_id: str) -> dict[str, tuple[str, str]]:
    """勧告の ID → (state, confidence)"""
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(VulnMatch, VulnAdvisory.ext_id).join(
            VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id).where(VulnMatch.device_id == device_id))).all()
        return {ext: (m.state, m.confidence) for m, ext in rows}


def test_reconcile_hotfix_levels_from_real_shape(net, enabled):
    """CVE-2026-0331 と同じ形（lessThan＋changes）: 修正済みのホットフィックスは非該当、それ以外は該当"""
    net.routes.update(hotfix_routes())
    cases = {
        "10.2.13-h28": False, "10.2.7-h40": False, "10.2.16-h13": False, "10.2.18-h14": False, "10.2.19": False, "10.1.5": False,
        "10.2.13-h27": True, "10.2.7": True, "10.2.14": True, "10.2.17": True, "10.2.18-h13": True,
        "11.1.4-h39": False, "11.1.4-h38": True, "11.1.5": True, "11.1.6-h41": False,
    }
    ids = {v: mk_device(f"hf-{i}", "paloalto_panos", v, model="PA-440") for i, v in enumerate(cases)}
    run(_fetch())
    for v, hit in cases.items():
        got = run(_matches(ids[v])).get("CVE-2099-1001")
        assert (got is not None) == hit, (v, got)


def test_panorama_only_advisory_follows_model(net, enabled):
    net.routes.update(hotfix_routes())
    fw = mk_device("fw", "paloalto_panos", "10.2.7", model="PA-440")
    vmx = mk_device("vm", "paloalto_panos", "10.2.7", model="VM-50")
    pano = mk_device("pano", "paloalto_panos", "10.2.7", model="Panorama")
    m600 = mk_device("m600", "paloalto_panos", "10.2.7", model="M-600")
    unk = mk_device("unk", "paloalto_panos", "10.2.7", model=None)
    run(_fetch())
    assert "CVE-2099-1002" not in run(_conf(fw)) and "CVE-2099-1002" not in run(_conf(vmx))  # ファイアウォールには当たらない
    assert run(_conf(pano))["CVE-2099-1002"] == ("open", "confirmed") and run(_conf(m600))["CVE-2099-1002"] == ("open", "confirmed")
    assert run(_conf(unk))["CVE-2099-1002"] == ("open", "candidate")  # 判別できない: 候補
    assert run(_conf(fw))["CVE-2099-1001"] == ("open", "confirmed")  # platforms の無い勧告は全機器
    # モデルが分かったら、候補は確定する／当たらないものは外れる
    async def set_model(d, m):
        async with AsyncSessionLocal() as db:
            (await db.get(Device, d)).model = m
            await db.commit()
    run(set_model(unk, "PA-220"))
    run(_reconcile([unk]))
    assert run(_conf(unk))["CVE-2099-1002"][0] == "fixed"
    run(set_model(unk, "M-200"))
    run(_reconcile([unk]))
    assert run(_conf(unk))["CVE-2099-1002"] == ("open", "confirmed")


def test_unreadable_ranges_are_not_matched_nor_fixed_and_are_counted(net, enabled):
    net.routes.update(hotfix_routes())
    a = mk_device("a", "paloalto_panos", "12.1.3", model="PA-440")  # 上限が * の範囲 → 該当
    b = mk_device("b", "paloalto_panos", "10.1.7", model="PA-440")  # 修正のあとにまた該当になる形 → 判定できない
    c = mk_device("c", "paloalto_panos", "9.1.0", model="PA-440")  # 読めない上限 → 判定できない
    d = mk_device("d", "paloalto_panos", "11.0.1", model="PA-440")  # どの行にも当たらない
    run(_fetch())
    assert run(_conf(a))["CVE-2099-1003"] == ("open", "confirmed")
    assert "CVE-2099-1003" not in run(_conf(b)) and "CVE-2099-1003" not in run(_conf(c)) and "CVE-2099-1003" not in run(_conf(d))
    assert sources_state()["paloalto"].skipped == 2  # 取得のとき、読めなかった行の数を記録する

    async def pairs():
        async with AsyncSessionLocal() as db:
            devs = list((await db.execute(select(Device).where(Device.name.like("vuln-%")))).scalars())
            advs = list((await db.execute(select(VulnAdvisory))).scalars())
            return {x.name: v for x in devs if (v := vuln_service.unreadable_by_device(devs, advs).get(x.id))}
    assert run(pairs()) == {"vuln-b": ["CVE-2099-1003"], "vuln-c": ["CVE-2099-1003"]}

    # すでにある判定は、読めない範囲のせいで「解消」にしない
    async def add_open(dev_id):
        async with AsyncSessionLocal() as db:
            adv = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
            db.add(VulnMatch(device_id=dev_id, advisory_id=adv.id, confidence="confirmed", state="open"))
            await db.commit()
    run(add_open(b))
    r = run(_reconcile([b]))
    assert r["fixed"] == 0 and run(_conf(b))["CVE-2099-1003"] == ("open", "confirmed")


def test_api_candidate_unreadable_and_skipped_counts(ctx, net, enabled):
    c, view = ctx["c"], ctx["view"]
    net.routes.update(hotfix_routes())
    mk_device("unk", "paloalto_panos", "10.2.7", model=None)
    mk_device("b", "paloalto_panos", "10.1.7", model="PA-440")
    run(_fetch())
    s = c.get("/api/vulns/summary", headers=view).json()
    assert s["counts"]["candidate"] >= 1 and s["range_unreadable"]["pairs"] >= 1 and s["range_unreadable"]["advisories"] >= 1
    pa = next(x for x in s["sources"] if x["source"] == "paloalto")
    assert pa["skipped"] == 2 and pa["last_count"] == 3
    cand = c.get("/api/vulns/matches", params={"confidence": "candidate"}, headers=view).json()
    mine = [x for x in cand["items"] if x["device_name"] == "vuln-unk"]
    assert len(mine) == 1 and mine[0]["advisory"]["ext_id"] == "CVE-2099-1002"
    assert "Panorama だけに影響する勧告です" in mine[0]["candidate_reason"] and "判別できませんでした" in mine[0]["candidate_reason"]
    assert c.get("/api/vulns/matches", headers=view).json()["items"][0]["candidate_reason"] is None
    unk = c.get("/api/vulns/unknown", headers=view).json()
    ru = [x for x in unk["range_unreadable"] if x["name"] == "vuln-b"]
    assert ru and ru[0]["count"] == 1 and ru[0]["advisories"] == ["CVE-2099-1003"]
    adv = c.get("/api/vulns/advisories/" + mine[0]["advisory"]["id"], headers=view).json()
    assert adv["affected"][0]["platforms"] == ["Panorama"]


async def _put_eol(**kw):
    async with AsyncSessionLocal() as db:
        db.add(EolDate(**{"kind": "os", "branch": "", "model": "", "source": "manual", "updated_by": "operator", **kw}))
        await db.commit()


async def _eol_info(device_id: str, today=date(2026, 11, 26)):
    async with AsyncSessionLocal() as db:
        return vuln_service.device_eol(await vuln_service.eol_rows(db), await db.get(Device, device_id), today)


def test_manual_eol_for_all_ledger_platforms_by_branch(net, enabled):
    """手入力は「機器の platform ＋ 分解した系列」で引く（PAN-OS・FortiOS・IOS XE 以外の機種でも）"""
    cases = [("juniper_junos", "21.4R3-S5", "21.4"), ("cisco_nxos", "9.3(10)", "9.3"), ("cisco_asa", "9.18(3)56", "9.18"),
             ("arista_eos", "4.28.3M", "4.28"), ("cisco_ios", "15.2(7)E7", "15.2")]
    for i, (plat, ver, branch) in enumerate(cases):
        d = mk_device(f"e{i}", plat, ver)
        assert run(_eol_info(d))["os"] is None
        run(_put_eol(platform=plat, branch=branch, eol_date=date(2027, 1, 31)))
        e = run(_eol_info(d))
        assert e["os"]["eol_date"] == "2027-01-31" and e["os"]["source"] == "manual" and e["branch"] == branch, plat
        other = run(_eol_info(mk_device(f"o{i}", plat, ver.replace(ver[0:2], "99", 1))))  # 別の系列には当たらない
        assert other["os"] is None


def test_manual_eol_wildcard_for_unparseable_platforms_and_hardware(net, enabled):
    yam = mk_device("yam", "yamaha", "Rev.15.02.17", model="RTX1210")
    weird = mk_device("weird", "paloalto_panos", "garbage")
    nover = mk_device("nover", "alliedware", None)
    for d in (yam, weird, nover):
        assert run(_eol_info(d))["os"] is None
    run(_put_eol(platform="yamaha", branch="*", eol_date=date(2030, 3, 31)))
    run(_put_eol(platform="paloalto_panos", branch="*", eol_date=date(2031, 3, 31)))
    run(_put_eol(platform="alliedware", kind="hardware", model="x510-28gtx", eol_date=date(2029, 3, 31)))
    assert run(_eol_info(yam))["os"]["eol_date"] == "2030-03-31"
    assert run(_eol_info(weird))["os"]["eol_date"] == "2031-03-31"  # 読めない版でも「その機種のすべて」で引く
    assert run(_eol_info(nover))["os"] is None

    async def with_model(d, m):
        async with AsyncSessionLocal() as db:
            (await db.get(Device, d)).model = m
            await db.commit()
    run(with_model(nover, "X510-28GTX"))
    assert run(_eol_info(nover))["hardware"]["eol_date"] == "2029-03-31"
    # 系列を指定した手入力は、「*」より優先する
    pan = mk_device("pan", "paloalto_panos", "10.2.5")
    assert run(_eol_info(pan))["os"]["eol_date"] == "2031-03-31"
    run(_put_eol(platform="paloalto_panos", branch="10.2", eol_date=date(2028, 1, 31)))
    assert run(_eol_info(pan))["os"]["eol_date"] == "2028-01-31"


def test_manual_eol_for_ios_xe_registered_either_way(net, enabled):
    """cisco_ios で登録された IOS XE（17.x）は、cisco_ios でも cisco_xe でも引ける。両方あれば手入力を優先"""
    net.routes.update(standard_routes())
    d = mk_device("xe", "cisco_ios", "17.9.4a")
    x = mk_device("xe2", "cisco_xe", "17.9.4a")
    run(_fetch(["eol"]))
    assert run(_eol_info(d))["os"]["source"] == "endoflife.date" and run(_eol_info(x))["os"]["source"] == "endoflife.date"
    run(_put_eol(platform="cisco_ios", branch="17.9", eol_date=date(2029, 1, 1)))
    assert run(_eol_info(d))["os"]["eol_date"] == "2029-01-01" and run(_eol_info(d))["os"]["source"] == "manual"
    assert run(_eol_info(x))["os"]["eol_date"] == "2029-01-01"  # cisco_xe の機器も、cisco_ios で入れた手入力に当たる
    run(_put_eol(platform="cisco_xe", branch="17.9", eol_date=date(2030, 1, 1)))
    assert run(_eol_info(d))["os"]["eol_date"] in ("2029-01-01", "2030-01-01")  # どちらも手入力。機器の platform が先
    assert run(_eol_info(d))["os"]["eol_date"] == "2029-01-01" and run(_eol_info(x))["os"]["eol_date"] == "2030-01-01"


def test_api_manual_eol_wildcard_branch_and_local_today(ctx, net, enabled, monkeypatch):
    c, op, view = ctx["c"], ctx["op"], ctx["view"]
    d = mk_device("yam", "yamaha", "Rev.15.02.17", model="RTX1210")
    body = {"platform": "yamaha", "kind": "os", "branch": "*", "eol_date": "2030-01-12"}
    assert c.put("/api/vulns/eol", json=body, headers=op).status_code == 200
    assert c.put("/api/vulns/eol", json={**body, "branch": "**"}, headers=op).status_code == 422
    # 残り日数は TIMEZONE の「今日」で数える（UTC の日付ではない）
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime(2030, 1, 2, 8, 0))
    dev = {x["device_id"]: x for x in c.get("/api/vulns/eol/devices", headers=view).json()["items"]}[d]
    assert dev["os"]["days_left"] == 10 and dev["days_left"] == 10 and dev["reason"] == "unsupported"


def test_local_today_uses_configured_timezone(monkeypatch):
    for tz in ("Pacific/Kiritimati", "Etc/GMT+12"):  # UTC+14 と UTC-12。同じ瞬間でも日付が 1〜2 日ずれうる
        monkeypatch.setattr(settings, "TIMEZONE", tz)
        from zoneinfo import ZoneInfo
        assert vuln_service.local_today() == datetime.now(ZoneInfo(tz)).date()


def test_delete_device_removes_vuln_matches_explicitly(ctx, net, enabled):
    c, admin = ctx["c"], ctx["admin"]
    net.routes.update(standard_routes())
    d = mk_device("gone", "paloalto_panos", "10.2.5-h1")
    run(_fetch())
    assert run(_matches(d))

    async def count():
        async with AsyncSessionLocal() as db:
            return len((await db.execute(select(VulnMatch).where(VulnMatch.device_id == d))).scalars().all())
    assert run(count()) == 2
    assert c.delete(f"/api/devices/{d}", headers=admin).status_code == 204
    assert run(count()) == 0  # SQLite では CASCADE が効かないので、削除の処理が消す


def test_lock_vuln_writes_takes_advisory_lock_only_on_postgres():
    from types import SimpleNamespace

    class FakeDB:
        def __init__(self, dialect):
            self.dialect, self.sql = dialect, []

        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))

        async def execute(self, stmt, params=None):
            self.sql.append((str(stmt), params))

    pg, lite = FakeDB("postgresql"), FakeDB("sqlite")
    run(vuln_service.lock_vuln_writes(pg))
    run(vuln_service.lock_vuln_writes(lite))
    assert len(pg.sql) == 1 and "pg_advisory_xact_lock" in pg.sql[0][0] and pg.sql[0][1] == {"k": vuln_service.VULN_WRITE_LOCK_KEY}
    assert lite.sql == []


def test_reconcile_takes_lock_before_reading(monkeypatch):
    order = []
    real = vuln_service.lock_vuln_writes

    async def spy(db):
        order.append("lock")
        await real(db)
    monkeypatch.setattr(vuln_service, "lock_vuln_writes", spy)
    run(_reconcile())
    assert order == ["lock"]


# ================================================================ 本物の形の見本（取得 → 照合 → API）・サポート終了日の優先順位


def test_reconcile_real_shapes_lessthan_min_and_default_affected(ctx, net, enabled):
    """lessThan が修正点の最小の行（CVE-2026-0273 の形）・defaultStatus が affected（CVE-2026-0279 の形）を、取得から照合まで通す"""
    c, view = ctx["c"], ctx["view"]
    net.routes.update({**standard_routes(), vf.URL_PALOALTO: fixture_bytes("paloalto_panos_shapes.json")})
    d5 = mk_device("s-1215", "paloalto_panos", "12.1.5", model="PA-440")  # 12.1.4-h7 より後でも、12.1.7 より前は該当
    d7 = mk_device("s-1217", "paloalto_panos", "12.1.7", model="PA-440")
    d0 = mk_device("s-1103", "paloalto_panos", "11.0.3", model="PA-440")  # どの勧告の表にも無い系列
    run(_fetch(["paloalto"]))
    assert run(_conf(d5))["CVE-2099-2002"] == ("open", "confirmed")
    assert "CVE-2099-2002" not in run(_conf(d7))
    assert run(_conf(d0))["CVE-2099-2003"] == ("open", "candidate")  # 記載のない系列も影響あり → 候補
    assert "CVE-2099-2001" not in run(_conf(d0))
    assert sources_state()["paloalto"].skipped == 4  # 読めなかった行（unknown 1・SX の 3）
    cand = c.get("/api/vulns/matches", params={"confidence": "candidate", "device_id": d0}, headers=view).json()["items"]
    by = {x["advisory"]["ext_id"]: x for x in cand}
    assert sorted(by) == ["CVE-2099-2003", "PAN-SA-2099-2013"]
    assert by["CVE-2099-2003"]["candidate_reason"].startswith("勧告は、記載のない系列も影響ありとしています")
    assert by["PAN-SA-2099-2013"]["candidate_reason"] == (
        "特定の機種だけに影響する勧告です（対象: PA-3200, PA-5200, PA-7000）。機種を確かめてください")
    adv = c.get("/api/vulns/advisories/" + by["CVE-2099-2003"]["advisory"]["id"], headers=view).json()
    assert adv["affected"][-1]["kind"] == "default" and adv["affected"][-1]["src"]["defaultStatus"] == "affected"
    assert adv["affected"][3]["open"] is True and adv["affected"][3]["src"]["version"] == "10.2.0"


def test_eol_priority_specific_auto_beats_wildcard_manual(net, enabled):
    """優先: 特定の系列の手入力 → 特定の系列の自動取得 → 「*」の手入力"""
    net.routes.update(standard_routes())
    pan = mk_device("pan", "paloalto_panos", "10.2.5")
    old = mk_device("pan-old", "paloalto_panos", "9.1.3")  # 自動取得の表に無い系列
    run(_fetch(["eol"]))
    run(_put_eol(platform="paloalto_panos", branch="*", eol_date=date(2031, 3, 31)))
    e = run(_eol_info(pan))["os"]
    assert e["source"] == "endoflife.date" and e["eol_date"] == "2025-08-27"  # 「*」の手入力は、特定の系列の自動取得に負ける
    assert run(_eol_info(old))["os"]["eol_date"] == "2031-03-31" and run(_eol_info(old))["os"]["branch"] == "*"
    run(_put_eol(platform="paloalto_panos", branch="10.2", eol_date=date(2028, 1, 31)))
    assert run(_eol_info(pan))["os"]["eol_date"] == "2028-01-31"  # 特定の系列の手入力が最優先


def test_eol_wildcard_manual_is_not_cross_referenced_between_ios_and_xe(net, enabled):
    """cisco_ios と cisco_xe の相互参照では「*」の手入力を引かない（classic IOS 向けの「*」が IOS XE の機器に当たらない）"""
    xe = mk_device("xe-173", "cisco_xe", "17.3.1")  # 自動取得の表に無い系列
    ios = mk_device("ios-152", "cisco_ios", "15.2(7)E7")
    run(_put_eol(platform="cisco_ios", branch="*", eol_date=date(2032, 1, 31)))
    assert run(_eol_info(ios))["os"]["eol_date"] == "2032-01-31"
    assert run(_eol_info(xe))["os"] is None
    run(_put_eol(platform="cisco_ios", branch="17.3", eol_date=date(2027, 3, 31)))  # 特定の系列の手入力は相互に引く
    assert run(_eol_info(xe))["os"]["eol_date"] == "2027-03-31"
    xe2 = mk_device("xe-174", "cisco_xe", "17.4.1")
    run(_put_eol(platform="cisco_xe", branch="*", eol_date=date(2033, 1, 31)))
    assert run(_eol_info(xe2))["os"]["eol_date"] == "2033-01-31"  # 機器そのものの platform の「*」は引く
    assert run(_eol_info(ios))["os"]["eol_date"] == "2032-01-31"  # cisco_xe の「*」は classic IOS に当たらない


# ================================================================ TLS（ハンドシェイクの期限・証明書とホスト名の検証）


class _SilentServer:
    """接続を受けて、何も返さずに持ち続ける相手（TLS のハンドシェイクの途中で止まる）"""

    def __init__(self):
        self.stop = threading.Event()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.conns: list[socket.socket] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
                self.conns.append(conn)
            except OSError:
                continue

    def close(self):
        self.stop.set()
        self.thread.join(5)
        for c in self.conns:
            c.close()
        self.sock.close()


def test_tls_handshake_stall_is_cut_off_by_total_timeout(monkeypatch, real_open):
    """ハンドシェイクの途中で止まる相手でも、全体の期限（テストでは 2 秒）＋数秒以内に、取得のスレッドごと終わる"""
    monkeypatch.setattr(vf, "TOTAL_TIMEOUT", 2)
    monkeypatch.setattr(vf, "CONNECT_TIMEOUT", 30)  # 1 回の読み取りの待ちでは終わらないようにする
    before = set(threading.enumerate())
    srv = _SilentServer()
    try:
        t0 = time.monotonic()
        with pytest.raises(vf.FetchError, match="時間切れ"):
            vf.fetch_bytes(f"https://127.0.0.1:{srv.port}/x")
        elapsed = time.monotonic() - t0
        workers = [t for t in set(threading.enumerate()) - before if t.name == "vuln-fetch"]
        for t in workers:
            t.join(3)
        alive = [t for t in workers if t.is_alive()]
    finally:
        srv.close()
    assert 1.5 <= elapsed <= 2 + 3 and not alive, (elapsed, alive)


def _cert_files(tmp_path, *, ip: str | None = "127.0.0.1", dns: str | None = None, self_signed: bool = False):
    """テスト用の CA と、その CA が署名したサーバー証明書（self_signed なら CA なしの自己署名）を一時的に作る"""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)

    def key():
        return ec.generate_private_key(ec.SECP256R1())

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def pem_key(k):
        return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    ca_key, srv_key = key(), key()
    ca = (x509.CertificateBuilder().subject_name(name("テスト用の CA")).issuer_name(name("テスト用の CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    sans = ([x509.IPAddress(ipaddress.ip_address(ip))] if ip else []) + ([x509.DNSName(dns)] if dns else [])
    b = (x509.CertificateBuilder().subject_name(name("test-server")).public_key(srv_key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
         .not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName(sans), critical=False)
         .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if self_signed:
        cert = b.issuer_name(name("test-server")).sign(srv_key, hashes.SHA256())
    else:
        cert = (b.issuer_name(ca.subject)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
    paths = {}
    for label, data in (("ca", ca.public_bytes(serialization.Encoding.PEM)),
                        ("cert", cert.public_bytes(serialization.Encoding.PEM)), ("key", pem_key(srv_key))):
        paths[label] = tmp_path / f"{label}.pem"
        paths[label].write_bytes(data)
    return paths


class _TLSServer(_SilentServer):
    """TLS で受けて、ハンドシェイクが通れば {"ok": true} を返す"""

    def __init__(self, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        super().__init__()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                req = b""
                while b"\r\n\r\n" not in req:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    req += chunk
                body = b'{"ok": true}'
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()


def test_tls_context_verifies_certificate_and_hostname():
    ctx = vf._tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


@pytest.mark.parametrize("case", ["trusted", "untrusted_ca", "wrong_host", "self_signed"])
def test_tls_rejects_untrusted_and_wrong_host_certificates(monkeypatch, real_open, tmp_path, case):
    """テスト用の CA を信頼したときだけ通る。信頼しない CA・別のホスト名の証明書・自己署名は拒否する（検証を弱めていない）"""
    files = _cert_files(tmp_path, ip=None if case == "wrong_host" else "127.0.0.1",
                        dns="other.example.test" if case == "wrong_host" else None, self_signed=case == "self_signed")
    if case in ("trusted", "wrong_host"):  # テスト用の CA を信頼する（untrusted_ca・self_signed は既定の設定のまま）
        monkeypatch.setattr(vf, "_tls_context", lambda: ssl.create_default_context(cafile=str(files["ca"])))
    srv = _TLSServer(files["cert"], files["key"])
    try:
        url = f"https://127.0.0.1:{srv.port}/x"
        if case == "trusted":
            assert vf.fetch_json(url) == {"ok": True}  # 試験の組み立てが正しいこと（信頼する CA なら通る）
        else:
            with pytest.raises(vf.FetchError, match="証明書を検証できません"):
                vf.fetch_bytes(url)
    finally:
        srv.close()


# ================================================================ 版が変わって判定できなくなった「該当」（stale）


def test_stale_when_version_changes_to_unreadable_keeps_state_and_note(ctx, net, enabled):
    """該当だった機器の版が変わり、いまの版では範囲を読めない: 該当のまま据え置かず「判定できない」に移す（確認済み・メモは残す）"""
    c, view = ctx["c"], ctx["view"]
    net.routes.update(hotfix_routes())
    d = mk_device("st", "paloalto_panos", "12.1.3", model="PA-440")  # CVE-2099-1003 の 12.1 の行（上限 *）で該当
    run(_fetch(["paloalto"]))
    assert run(_conf(d))["CVE-2099-1003"] == ("open", "confirmed")

    async def ack_and_get():
        async with AsyncSessionLocal() as db:
            m = (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                  .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
            m.state, m.note, m.acked_by = "ack", "保守の時間に更新する予定", "operator"
            await db.commit()

    async def get_match():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                     .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
    run(ack_and_get())
    before = c.get("/api/vulns/summary", headers=view).json()["counts"]["acked"]
    run(_set_version(d, "10.1.7"))  # 修正のあとにまた影響ありになる行（読めない）の系列
    r = run(_reconcile([d]))
    m = run(get_match())
    assert r["stale"] == 1 and r["fixed"] == 0
    assert m.stale is True and m.state == "ack" and m.note == "保守の時間に更新する予定" and m.os_version == "12.1.3"
    # 該当の件数・一覧から外れ、「判定できない機器」に前回の版つきで出る
    s = c.get("/api/vulns/summary", headers=view).json()
    assert s["counts"]["acked"] == before - 1 and s["range_unreadable"]["stale"] == 1
    assert not [x for x in c.get("/api/vulns/matches", params={"state": "all", "device_id": d}, headers=view).json()["items"]
                if x["advisory"]["ext_id"] == "CVE-2099-1003"]
    dev = next(x for x in c.get("/api/vulns/devices", headers=view).json()["items"] if x["device_id"] == d)
    assert dev["acked"] == 0 and dev["open"] == 0
    row = next(x for x in c.get("/api/vulns/unknown", headers=view).json()["range_unreadable"] if x["device_id"] == d)
    assert row["stale"] == [{"advisory": "CVE-2099-1003", "previous_version": "12.1.3", "state": "ack",
                             "note": "保守の時間に更新する予定",
                             "label": "前回（版 12.1.3）は該当。版が変わり、いまの版では判定できません"}]
    # 別の読めない版へ変わっても stale のまま（数え直さない）
    run(_set_version(d, "10.1.8"))
    assert run(_reconcile([d]))["stale"] == 0 and run(get_match()).stale is True
    # また判定できる版になって該当すれば、stale を外して該当に戻す（確認済みのまま）
    run(_set_version(d, "12.1.4"))
    run(_reconcile([d]))
    m = run(get_match())
    assert m.stale is False and m.state == "ack" and m.os_version == "12.1.4"


def test_unreadable_with_same_version_is_kept_as_is(net, enabled):
    """判定を出したときと同じ版なら、範囲を読めなくなっても前回の判定を据え置く（その版についての判定なので有効）"""
    net.routes.update(hotfix_routes())
    d = mk_device("same", "paloalto_panos", "10.1.7", model="PA-440")
    run(_fetch(["paloalto"]))

    async def add(ver):
        async with AsyncSessionLocal() as db:
            adv = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
            db.add(VulnMatch(device_id=d, advisory_id=adv.id, confidence="confirmed", state="open", os_version=ver,
                             model="PA-440"))
            await db.commit()

    async def stale_of():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnMatch.stale).where(VulnMatch.device_id == d))).scalar_one()
    run(add("10.1.7"))
    r = run(_reconcile([d]))
    assert r["stale"] == 0 and r["fixed"] == 0 and run(stale_of()) is False
    assert run(_conf(d))["CVE-2099-1003"] == ("open", "confirmed")


# ================================================================ 版が読めない・platform が変わった機器（中-5）と、勧告の取り下げ（L-1）


def _counts_for(c, view, device_id: str, device_name: str) -> dict:
    """要約・一覧・CSV・機器別の、この機器の未確認＋確認済みの件数（食い違わないこと）"""
    s = c.get("/api/vulns/summary", headers=view).json()
    lst = c.get("/api/vulns/matches", params={"state": "all", "device_id": device_id}, headers=view).json()
    csv_rows = [x for x in c.get("/api/vulns/matches/export", params={"state": "all"}, headers=view)
                .content.decode("utf-8-sig").splitlines()[1:] if x.startswith(device_name + ",")]
    dev = next((x for x in c.get("/api/vulns/devices", headers=view).json()["items"] if x["device_id"] == device_id), None)
    open_ack = [x for x in lst["items"] if x["state"] in ("open", "ack")]
    return {"summary": sum(s["counts"][k] for k in ("critical", "high", "medium", "low", "none")) + s["counts"]["candidate"]
            + s["counts"]["acked"], "list": len(open_ack), "csv": len([x for x in csv_rows if ",解消," not in x]),
            "devices": (dev["open"] + dev["acked"]) if dev else 0, "stale": s["range_unreadable"]["stale"]}


@pytest.mark.parametrize("change", ["garbage_version", "platform"])
def test_stale_when_version_unparseable_or_platform_changes(ctx, net, enabled, change):
    c, view = ctx["c"], ctx["view"]
    net.routes.update(hotfix_routes())
    d = mk_device("st5", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))
    before = _counts_for(c, view, d, "vuln-st5")
    assert before["summary"] == before["list"] == before["csv"] == before["devices"] >= 1 and before["stale"] == 0

    async def change_device():
        async with AsyncSessionLocal() as db:
            dev = await db.get(Device, d)
            if change == "platform":
                dev.platform = "fortinet"  # 脆弱性の対象外の機種に変わった（版はそのまま）
            else:
                dev.os_version = "PAN-OS ???"
            await db.commit()
    run(change_device())
    r = run(_reconcile([d]))
    after = _counts_for(c, view, d, "vuln-st5")
    assert r["stale"] == before["summary"] and r["fixed"] == 0
    assert after == {"summary": 0, "list": 0, "csv": 0, "devices": 0, "stale": before["summary"]}
    assert all(state == "open" for state, _ in run(_matches(d)).values())  # 状態は消さない


def test_stale_comparison_ignores_surrounding_spaces(net, enabled):
    """前後の空白だけが違う版は「同じ版」（据え置く）"""
    net.routes.update(hotfix_routes())
    d = mk_device("sp", "paloalto_panos", "10.1.7", model="PA-440")
    run(_fetch(["paloalto"]))

    async def add():
        async with AsyncSessionLocal() as db:
            adv = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
            db.add(VulnMatch(device_id=d, advisory_id=adv.id, confidence="confirmed", state="open", os_version=" 10.1.7 ",
                             model=" pa-440 "))  # 前後の空白・大文字小文字だけが違うモデルも同じ
            await db.commit()
    run(add())
    assert run(_reconcile([d]))["stale"] == 0


def test_rejected_advisory_closes_matches_and_keeps_notes(net, enabled):
    net.routes.update(hotfix_routes())
    d = mk_device("rj", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))
    assert run(_conf(d))["CVE-2099-1001"] == ("open", "confirmed")

    async def ack():
        async with AsyncSessionLocal() as db:
            m = (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                  .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
            m.state, m.note = "ack", "作り物のメモ"
            await db.commit()
    run(ack())
    data = fixture_json("paloalto_panos_hotfix.json")
    for rec in data["data"]:
        if rec["cveMetadata"]["cveId"] == "CVE-2099-1001":
            rec["cveMetadata"]["state"] = "REJECTED"  # 取り下げ
    net.routes[vf.URL_PALOALTO] = json.dumps(data).encode()
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))

    async def adv_rejected():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnAdvisory.rejected).where(VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
    assert run(adv_rejected()) is True
    assert run(_matches(d))["CVE-2099-1001"] == ("fixed", "作り物のメモ")  # 解消。メモは残す
    run(_reconcile([d]))
    assert run(_matches(d))["CVE-2099-1001"][0] == "fixed"  # 取り下げた勧告では、また該当にしない
    # 再び公開されたら、取り下げの印を外して照合に戻す
    net.routes[vf.URL_PALOALTO] = fixture_bytes("paloalto_panos_hotfix.json")
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=2)))
    assert run(adv_rejected()) is False and run(_conf(d))["CVE-2099-1001"] == ("open", "confirmed")


# ================================================================ 読めなかった勧告・改訂で空になった勧告（M6）、モデルの変化（L4）、再公開（L5）


def _with_records(change) -> bytes:
    """hotfix の見本に手を加えた応答（change は記録の一覧を受け取って書き換える）"""
    data = fixture_json("paloalto_panos_hotfix.json")
    change(data["data"])
    return json.dumps(data).encode()


def test_broken_and_emptied_advisories_are_not_silently_kept(net, enabled):
    net.routes.update(hotfix_routes())
    d = mk_device("m6", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))
    assert run(_conf(d))["CVE-2099-1001"] == ("open", "confirmed")

    def change(recs):
        for rec in recs:
            cid = rec["cveMetadata"]["cveId"]
            if cid == "CVE-2099-1001":  # 記録として読めない（affected が配列でない）
                rec["containers"]["cna"]["affected"] = {"0": {"product": "PAN-OS"}}
            if cid == "CVE-2099-1003":  # 改訂で、影響なしの行だけになった
                rec["containers"]["cna"]["affected"] = [{"product": "PAN-OS", "versions": [
                    {"version": "12.1 All", "status": "unaffected"}]}]
        recs.append({"cveMetadata": {"cveId": "CVE-2099-1009", "state": "Published"}, "containers": {"cna": {}}})  # 状態が想定外
        recs.append({"cveMetadata": {"cveId": "CVE-2099-1010", "state": "PUBLISHED"},
                     "containers": {"cna": {"title": "作り物", "affected": [{"product": "PAN-OS®", "versions": [
                         {"version": "10.2.0", "lessThan": "10.2.9", "status": "affected"}]}]}}})
    net.routes[vf.URL_PALOALTO] = _with_records(change)
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))

    async def advs():
        async with AsyncSessionLocal() as db:
            return {a.ext_id: a.affected for a in (await db.execute(select(VulnAdvisory))).scalars()}
    a = run(advs())
    # 保存済みの勧告が読めなくなった: 古い範囲のまま判定を続けず、「範囲を読み取れない」に上書き
    assert a["CVE-2099-1001"][0]["unreadable"] is True and a["CVE-2099-1001"][0]["branch"] is None
    assert "読み取れません" in a["CVE-2099-1001"][0]["raw"]
    assert a["CVE-2099-1009"][0]["unreadable"] is True  # 新しい読めない勧告も、ID つきで残す
    assert a["CVE-2099-1010"][0]["unreadable"] is True  # 製品名が決まった形でない PAN-OS の行
    assert a["CVE-2099-1003"] == []  # 影響なしだけに改訂: 範囲を空にする
    assert sources_state()["paloalto"].skipped >= 2 + 1  # 読めない行（1002 は 0）＋読めない勧告 2 件（1001・1009）
    # 判定: 読めない勧告は「判定できない」
    async def unreadable_ids():
        async with AsyncSessionLocal() as db:
            devs = list((await db.execute(select(Device).where(Device.id == d))).scalars())
            return vuln_service.unreadable_by_device(devs, list((await db.execute(select(VulnAdvisory))).scalars())).get(d, [])
    assert {"CVE-2099-1001", "CVE-2099-1009", "CVE-2099-1010"} <= set(run(unreadable_ids()))

    # 1001 の前回の「該当」は古い範囲によるもの: 版が同じでも据え置かず stale（該当の件数から外れる）
    async def stale_1001():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnMatch.stale).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                     .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
    assert run(stale_1001()) is True


def test_emptied_advisory_closes_existing_matches(net, enabled):
    net.routes.update(hotfix_routes())
    d = mk_device("m6e", "paloalto_panos", "12.1.3", model="PA-440")
    run(_fetch(["paloalto"]))
    assert run(_conf(d))["CVE-2099-1003"] == ("open", "confirmed")

    def change(recs):
        for rec in recs:
            if rec["cveMetadata"]["cveId"] == "CVE-2099-1003":
                rec["containers"]["cna"]["affected"] = [{"product": "PAN-OS", "versions": [
                    {"version": "12.1 All", "status": "unaffected"}]}]
    net.routes[vf.URL_PALOALTO] = _with_records(change)
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))
    assert run(_conf(d))["CVE-2099-1003"][0] == "fixed"


def test_stale_when_model_changes_and_unreadable(net, enabled):
    """判定を出したときからモデルが変わり、いまは判定できない: stale（L4）。モデルが同じなら据え置く"""
    net.routes.update(hotfix_routes())
    d = mk_device("m4", "paloalto_panos", "10.1.7", model="PA-440")
    run(_fetch(["paloalto"]))

    async def add_and_set(model):
        async with AsyncSessionLocal() as db:
            adv = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-1003"))).scalar_one()
            db.add(VulnMatch(device_id=d, advisory_id=adv.id, confidence="confirmed", state="open", os_version="10.1.7",
                             model="PA-440"))
            (await db.get(Device, d)).model = model
            await db.commit()

    async def stale_of():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnMatch.stale).where(VulnMatch.device_id == d))).scalar_one()
    run(add_and_set("PA-3220"))
    assert run(_reconcile([d]))["stale"] == 1 and run(stale_of()) is True

    async def set_model(m):
        async with AsyncSessionLocal() as db:
            (await db.get(Device, d)).model = m
            await db.commit()
    run(set_model("PA-440"))  # モデルが戻った: 前回の判定はこのモデル・版についてのものなので据え置く
    run(_reconcile([d]))
    assert run(stale_of()) is False


def test_republished_after_rejection_keeps_ack_and_note(net, enabled):
    net.routes.update(hotfix_routes())
    d = mk_device("l5", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))

    async def ack():
        async with AsyncSessionLocal() as db:
            m = (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                  .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
            m.state, m.note, m.acked_by, m.acked_at = "ack", "作り物のメモ", "operator", utcnow()
            await db.commit()
    run(ack())

    def reject(recs):
        for rec in recs:
            if rec["cveMetadata"]["cveId"] == "CVE-2099-1001":
                rec["cveMetadata"]["state"] = "REJECTED"
    net.routes[vf.URL_PALOALTO] = _with_records(reject)
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))
    assert run(_matches(d))["CVE-2099-1001"] == ("fixed", "作り物のメモ")
    net.routes[vf.URL_PALOALTO] = fixture_bytes("paloalto_panos_hotfix.json")
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=2)))
    assert run(_matches(d))["CVE-2099-1001"] == ("ack", "作り物のメモ")  # 再公開: 確認済みとメモを残して戻す


def test_api_marks_rejected_advisory(ctx, net, enabled):
    c, view = ctx["c"], ctx["view"]
    net.routes.update(hotfix_routes())
    d = mk_device("rjapi", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))

    def reject(recs):
        for rec in recs:
            if rec["cveMetadata"]["cveId"] == "CVE-2099-1001":
                rec["cveMetadata"]["state"] = "REJECTED"
    net.routes[vf.URL_PALOALTO] = _with_records(reject)
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))
    items = c.get("/api/vulns/matches", params={"state": "fixed", "device_id": d}, headers=view).json()["items"]
    row = next(x for x in items if x["advisory"]["ext_id"] == "CVE-2099-1001")
    assert row["advisory"]["rejected"] is True


def test_rejected_reason_is_cleared_when_republished_and_not_affected(net, enabled):
    """取り下げ → 解消 → 再公開のとき非該当: 取り下げの印を外す。あとで該当したら、ふつうの新しい該当（未確認・メモなし）"""
    net.routes.update(hotfix_routes())
    d = mk_device("l5b", "paloalto_panos", "10.2.7", model="PA-440")
    run(_fetch(["paloalto"]))

    async def ack():
        async with AsyncSessionLocal() as db:
            m = (await db.execute(select(VulnMatch).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                  .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
            m.state, m.note, m.acked_by, m.acked_at = "ack", "作り物のメモ", "operator", utcnow()
            await db.commit()
    run(ack())

    def reject(recs):
        for rec in recs:
            if rec["cveMetadata"]["cveId"] == "CVE-2099-1001":
                rec["cveMetadata"]["state"] = "REJECTED"
    net.routes[vf.URL_PALOALTO] = _with_records(reject)
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=1)))

    async def reason():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(VulnMatch.fixed_reason).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                     .where(VulnMatch.device_id == d, VulnAdvisory.ext_id == "CVE-2099-1001"))).scalar_one()
    assert run(reason()) == "rejected"
    run(_set_version(d, "10.2.19"))  # 修正済みの版にしてから再公開
    net.routes[vf.URL_PALOALTO] = fixture_bytes("paloalto_panos_hotfix.json")
    run(_fetch(["paloalto"], now=utcnow() + timedelta(days=2)))
    assert run(_matches(d))["CVE-2099-1001"][0] == "fixed" and run(reason()) is None
    run(_set_version(d, "10.2.13-h27"))  # ずっと後で、また該当する版になった
    run(_reconcile([d]))
    assert run(_matches(d))["CVE-2099-1001"] == ("open", None)  # 昔の確認済みとメモは戻らない
