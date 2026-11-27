"""外部への接続（core/outbound.py）: プロキシ・追加の CA・NO_PROXY・伏せ字と、通知・メール・脆弱性の取得の載せ替え

外部へは実際につながない。プロキシは tests/fake_proxy.py の偽物（127.0.0.1。CONNECT を受けて自分で TLS に応答する）。
直接の接続（127.0.0.1 以外へ）は block_direct が止めて記録する（宛先の名前解決もしない）
"""
import base64
import json
import logging
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.fernet import Fernet
from fake_proxy import FakeProxy, TestCA, closed_port
from pydantic import ValidationError

from app.core import outbound
from app.core.config import Settings, settings
from app.services import mail, notify
from app.services import vuln_fetch as vf

# 目印（どこにも出てはいけない）。パスワードは記号を含み、URL エンコードして設定に書く
USER = "proxy-user-MARKU1"
PASS = "p@ss:MARKP2/#x"
ENC_PASS = urllib.parse.quote(PASS, safe="")
TOKEN = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
SECRETS = (USER, PASS, ENC_PASS, TOKEN, "MARKU1", "MARKP2")

DISCORD = "https://discord.com/api/webhooks/123456/tok-EXAMPLE"
TEAMS = ("https://xxxx.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/WFIDEXAMPLE"
         "/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SIGEXAMPLE")


def no_secret(text) -> bool:
    text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False, default=str)
    return not any(s in text for s in SECRETS)


@pytest.fixture(scope="module")
def corp_ca():
    return TestCA("Example Corp CA")


@pytest.fixture(scope="module")
def other_ca():
    return TestCA("Other Test CA")


@pytest.fixture(autouse=True)
def clean_settings(monkeypatch):
    for k in ("OUTBOUND_PROXY", "OUTBOUND_NO_PROXY", "OUTBOUND_CA_FILE"):
        monkeypatch.setattr(settings, k, "")
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    mail.clear_token_cache()
    yield
    mail.clear_token_cache()


@pytest.fixture(autouse=True)
def block_direct(monkeypatch):
    """127.0.0.1 以外への直接の接続を止めて記録する（外部へ出ないこと・直接つなごうとした宛先を確かめる）"""
    tried: list[tuple] = []
    real = socket.create_connection

    def guarded(address, *a, **kw):
        if address[0] not in ("127.0.0.1", "localhost", "::1"):
            tried.append(tuple(address))
            raise ConnectionRefusedError("blocked in test")
        return real(address, *a, **kw)

    monkeypatch.setattr(socket, "create_connection", guarded)
    return tried


@pytest.fixture
def trust(monkeypatch, tmp_path):
    """CA を OUTBOUND_CA_FILE に設定する"""
    def _set(ca: TestCA):
        p = ca.write_pem(tmp_path / f"ca-{id(ca)}.pem")
        monkeypatch.setattr(settings, "OUTBOUND_CA_FILE", str(p))
        return p
    return _set


def use(monkeypatch, proxy: FakeProxy, auth: bool = False):
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", proxy.url(USER, ENC_PASS) if auth else proxy.url())


# ================================================================ 設定の解析（表）


@pytest.mark.parametrize("value,expect", [
    ("", None),
    ("http://proxy.example.test:3128", ("proxy.example.test", 3128, "", "")),
    ("HTTP://Proxy.Example.Test:8080/", ("proxy.example.test", 8080, "", "")),
    ("http://user01:secret@proxy.example.test:8080", ("proxy.example.test", 8080, "user01", "secret")),
    # 記号は URL エンコード（@ : / # % と空白）。デコードして使う
    ("http://user%40corp:p%40ss%3Aw%2Fo%23r%25d%20x@proxy.example.test:8080",
     ("proxy.example.test", 8080, "user@corp", "p@ss:w/o#r%d x")),
    ("http://user01:@proxy.example.test:8080", ("proxy.example.test", 8080, "user01", "")),
    ("http://[2001:db8::1]:3128", ("2001:db8::1", 3128, "", "")),
])
def test_parse_proxy_ok(value, expect):
    p = outbound.parse_proxy(value)
    if expect is None:
        assert p is None
    else:
        assert (p.host, p.port, p.username, p.password) == expect
        assert p.display.endswith(f":{expect[1]}") and "@" not in p.display
        assert p.auth == bool(expect[2] or expect[3])


@pytest.mark.parametrize("value,needle", [
    ("https://topsecret-u:topsecret-p@proxy.example.test:8443", "https:// のプロキシには対応していません"),
    ("socks5://topsecret-u:topsecret-p@proxy.example.test:1080", "http:// で始まる"),
    ("topsecret-u:topsecret-p@proxy.example.test:3128", "http:// で始まる"),
    ("proxy.example.test:3128", "http:// で始まる"),
    ("http://", "ホストとポート"),
    ("http://topsecret-u:topsecret-p@proxy.example.test", "ポートを書いてください"),
    ("http://proxy.example.test/", "ポートを書いてください"),
    ("http://topsecret-u:topsecret-p@proxy.example.test:", "ポートを書いてください"),
    ("http://topsecret-u:topsecret-p@proxy.example.test:99999", "形式が正しくありません"),
    ("http://topsecret-u:topsecret-p@proxy.example.test:0", "ホストとポート"),
    ("http://topsecret-u:topsecret-p@proxy.example.test:3128/path", "パス"),
    ("http://topsecret-u:topsecret-p@proxy.example.test:3128?x=1", "パス"),
    ("http://topsecret u:p@proxy.example.test:3128", "空白"),
    ("http://topsecret%0Au:topsecret-p@proxy.example.test:3128", "使えない文字"),
    ("http://topsecret-u@proxy.example.test:3128", "パスワードも書いてください"),
    ("http://topsecret%40u@proxy.example.test:3128", "パスワードも書いてください"),
])
def test_parse_proxy_rejects_without_echo(value, needle):
    with pytest.raises(ValueError) as e:
        outbound.parse_proxy(value)
    assert needle in str(e.value) and "topsecret" not in str(e.value)


def _settings(**kw):
    return Settings(_env_file=None, SECRET_KEY="x" * 40, DEVICE_ENCRYPTION_KEY=Fernet.generate_key().decode(), **kw)


def test_settings_validate_at_startup_without_echo(tmp_path, corp_ca):
    assert _settings(OUTBOUND_PROXY=" http://u:p@proxy.example.test:3128 ").OUTBOUND_PROXY == "http://u:p@proxy.example.test:3128"
    for bad in ("https://topsecret:1@proxy.example.test", "socks5h://topsecret@proxy.example.test:1080"):
        with pytest.raises(ValidationError) as e:
            _settings(OUTBOUND_PROXY=bad)
        assert "OUTBOUND_PROXY" in str(e.value) and "topsecret" not in str(e.value)
    with pytest.raises(ValidationError, match="OUTBOUND_NO_PROXY"):
        _settings(OUTBOUND_NO_PROXY="ok.example.test,bad_entry!")
    assert _settings(OUTBOUND_NO_PROXY="a.example.test, .b.example.test 10.0.0.0/8").OUTBOUND_NO_PROXY
    # CA: 読めない・PEM でない・証明書が無い・秘密鍵を含む → 起動時にエラー。正しいものは通る
    good = corp_ca.write_pem(tmp_path / "good.pem")
    (tmp_path / "text.pem").write_text("hello")
    (tmp_path / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    _, key = corp_ca.issue("server.example.test")
    (tmp_path / "withkey.pem").write_bytes(corp_ca.pem() + Path(key).read_bytes())
    (tmp_path / "empty.pem").write_text("")
    cases = {str(tmp_path / "missing.pem"): "読めません", str(tmp_path / "text.pem"): "PEM の証明書ではありません",
             str(tmp_path / "broken.pem"): "読めません", str(tmp_path / "withkey.pem"): "秘密鍵",
             str(tmp_path / "empty.pem"): "PEM の証明書ではありません", "bad name.pem": "ファイルの名前"}
    for value, needle in cases.items():
        with pytest.raises(ValidationError) as e:
            _settings(OUTBOUND_CA_FILE=value)
        assert "OUTBOUND_CA_FILE" in str(e.value) and needle in str(e.value), (value, str(e.value))
    loaded = _settings(OUTBOUND_CA_FILE=str(good))
    assert str(good) == loaded.OUTBOUND_CA_FILE
    # 名前だけなら、コンテナの中の固定の場所（certs-outbound/ のマウント先）
    assert outbound.resolve_ca_path("outbound-ca.pem") == "/etc/netconfig/outbound/outbound-ca.pem"
    with pytest.raises(ValidationError, match="certs-outbound"):
        _settings(OUTBOUND_CA_FILE="outbound-ca.pem")  # テストの環境には無い


@pytest.mark.parametrize("host,rules,direct", [
    ("localhost", "", True), ("LOCALHOST.", "", True), ("app.localhost", "", True), ("127.0.0.1", "", True),
    ("127.10.0.1", "", True), ("::1", "", True), ("[::1]", "", True),
    ("db", "", True), ("redis", "", True), ("backend", "", True), ("frontend", "", True),
    ("discord.com", "", False), ("10.1.2.3", "", False),
    ("intranet.example.test", "intranet.example.test", True), ("x.intranet.example.test", "intranet.example.test", True),
    ("notintranet.example.test", "intranet.example.test", False),
    ("a.corp.example.test", ".corp.example.test", True), ("corp.example.test", ".corp.example.test", True),
    ("a.corp.example.test", "*.corp.example.test", True), ("example.test", ".corp.example.test", False),
    ("10.1.2.3", "10.0.0.0/8", True), ("11.1.2.3", "10.0.0.0/8", False), ("192.0.2.7", "192.0.2.7", True),
    ("2001:db8::5", "2001:db8::/32", True), ("[2001:db8::5]", "[2001:db8::5]", True),
    ("discord.com", "*", True), ("DISCORD.COM", "discord.com", True),
    ("discord.com", "a.example.test, discord.com 10.0.0.0/8", True),
])
def test_no_proxy_table(host, rules, direct):
    assert outbound.bypass(host, outbound.parse_no_proxy(rules)) is direct


@pytest.mark.parametrize("bad", ["bad_entry!", "a..b", "http://x.example.test", "-x.example.test", "10.0.0.0/33x"])
def test_no_proxy_rejects(bad):
    with pytest.raises(ValueError, match="OUTBOUND_NO_PROXY"):
        outbound.parse_no_proxy(bad)


def test_scrub_hides_url_credentials_and_header(monkeypatch):
    raw = f"http://{USER}:{ENC_PASS}@proxy.example.test:3128"
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", raw)
    samples = [raw, f"失敗 {raw} です", f"user {USER}:x", f"by {USER}@proxy", f"pw={PASS}", f"enc={ENC_PASS}", f"Proxy-Authorization: Basic {TOKEN}",
               f"proxy-authorization={TOKEN}", f"b64 {TOKEN}", "http://other:pw-MARKP2@host.example.test/"]
    for s in samples:
        out = outbound.scrub(s)
        assert no_secret(out) and "***" in out, (s, out)
    assert outbound.scrub("プロキシ proxy.example.test:3128 に接続できません") == "プロキシ proxy.example.test:3128 に接続できません"
    # 同じパスワードの別のエンコード（%xx の大文字小文字・記号をすべてエンコード）も伏せる
    for alt in (ENC_PASS.lower(), urllib.parse.quote(PASS), urllib.parse.quote(PASS, safe=":@")):
        assert "MARKP2" not in outbound.scrub(f"x {alt} y").replace("***", ""), alt
    # ユーザー名がふつうの語（proxy）でも、文中のほかの proxy・ホスト名は伏せない（user: / user@ の形だけ）
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy:pw-%2A-MARK@proxy.example.test:3128")
    out = outbound.scrub("proxy に接続できません: proxy.example.test:3128 proxy:pw-*-MARK と pw-%2a-MARK と proxy@x")
    assert out == "proxy に接続できません: proxy.example.test:3128 ***:*** と *** と ***@x", out
    # 認証なしのプロキシでも URL そのものは伏せる
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy.example.test:3128")
    assert outbound.scrub("x http://proxy.example.test:3128 y") == "x *** y"


def test_tls_context_adds_ca_and_keeps_verification(trust, corp_ca):
    base = outbound.tls_context()
    assert base.verify_mode == ssl.CERT_REQUIRED and base.check_hostname
    n0 = base.cert_store_stats()["x509_ca"]
    trust(corp_ca)
    ctx = outbound.tls_context()
    assert ctx is not base and ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.cert_store_stats()["x509_ca"] == n0 + 1  # OS の既定の信頼に「足す」（置き換えない）
    assert outbound.tls_context() is ctx  # ファイルが変わらなければ使い回す


# ================================================================ プロキシ経由で届く（通知・メール・脆弱性）


def test_discord_via_proxy_with_auth(monkeypatch, trust, corp_ca, block_direct):
    with FakeProxy(corp_ca, auth=(USER, PASS)) as px:
        use(monkeypatch, px, auth=True)
        trust(corp_ca)
        monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")  # 環境変数のプロキシは使わない
        monkeypatch.setenv("NO_PROXY", "discord.com")  # 環境変数の迂回指定も効かない
        assert notify.send_webhook("discord", DISCORD, {"content": "日本語"}) is None
    assert len(px.connects) == 1 and px.connects[0].startswith("CONNECT discord.com:443 HTTP/1.1")
    assert f"Proxy-Authorization: Basic {TOKEN}" in px.connects[0]  # デコードした認証情報で Basic
    assert "/api/webhooks" not in px.connects[0]  # トンネルの外（平文）には URL の中身を出さない
    inner = px.inner[0]
    assert inner["method"] == "POST" and inner["path"] == "/api/webhooks/123456/tok-EXAMPLE"
    assert json.loads(inner["body"]) == {"content": "日本語"} and "proxy-authorization" not in inner["headers"]
    assert inner["headers"]["host"] == "discord.com" and not block_direct


def test_webhooks_do_not_follow_redirects(monkeypatch, trust, corp_ca):
    """#32: Teams に加えて Discord・Slack もリダイレクトをたどらない（転送先が http://・社内の宛先でも直接つながない）"""
    def respond(method, path, headers, body):
        if path.startswith("/powerautomate") and b"redirect" in body:
            return 302, {"Location": "https://evil.example.test/x"}, b""
        if path.startswith("/services/first"):
            return 302, {"Location": "http://192.0.2.1/second"}, b""
        if path.startswith("/api/webhooks/1/first"):
            return 308, {"Location": "https://evil.example.test/y"}, b""
        return 202, {}, b""

    with FakeProxy(corp_ca, respond=respond) as px:
        use(monkeypatch, px)
        trust(corp_ca)
        assert notify.send_webhook("teams", TEAMS, {"x": 1}) is None
        msg = notify.send_webhook("teams", TEAMS, {"x": "redirect"})
        assert "リダイレクト" in msg and "evil" not in msg
        assert notify.send_webhook("slack", "https://hooks.slack.com/services/ok", {"text": "a"}) is None
        msg = notify.send_webhook("slack", "https://hooks.slack.com/services/first", {"text": "a"})
        assert "リダイレクトされました（HTTP 302）" in msg and "192.0.2.1" not in msg
        msg = notify.send_webhook("discord", "https://discord.com/api/webhooks/1/first", {"content": "a"})
        assert "リダイレクトされました（HTTP 308）" in msg and "evil" not in msg
    hosts = [c.split()[1] for c in px.connects]
    assert hosts[:2] == ["xxxx.environment.api.powerplatform.com:443"] * 2
    assert "evil.example.test:443" not in hosts and not any("192.0.2.1" in h for h in hosts)
    assert [i["path"] for i in px.inner if i["host"] == "hooks.slack.com"] == ["/services/ok", "/services/first"]


def test_mail_token_via_proxy(monkeypatch, trust, corp_ca):
    def respond(method, path, headers, body):
        assert path == "/tenant-1/oauth2/v2.0/token"
        return 200, {"Content-Type": "application/json"}, b'{"access_token": "tok-123", "expires_in": 3600}'

    with FakeProxy(corp_ca, auth=(USER, PASS), respond=respond) as px:
        use(monkeypatch, px, auth=True)
        trust(corp_ca)
        cfg = mail.MailConfig(enabled=True, auth="microsoft", ms_tenant_id="tenant-1", ms_client_id="cid",
                              ms_client_secret="csecret", username="notify@example.test")
        assert mail.fetch_token(cfg) == ("tok-123", 3600)
    assert px.connects[0].startswith("CONNECT login.microsoftonline.com:443")
    assert b"client_secret=csecret" in px.inner[0]["body"]  # 本文はトンネルの中（TLS）だけ
    assert "csecret" not in px.connects[0]


def test_vuln_fetch_via_proxy_keeps_guard(monkeypatch, trust, corp_ca):
    """脆弱性の取得: 自前の接続（許可リスト・期限の見張り）のまま、プロキシと CA は outbound から"""
    seen = []
    real_add = vf._Guard.add
    monkeypatch.setattr(vf._Guard, "add", lambda self, sock: (seen.append(type(sock).__name__), real_add(self, sock))[1])

    def respond(method, path, headers, body):
        return 200, {"Content-Type": "application/json"}, b'{"vulnerabilities": []}'

    with FakeProxy(corp_ca, auth=(USER, PASS), respond=respond) as px:
        use(monkeypatch, px, auth=True)
        trust(corp_ca)
        assert vf.fetch_json(vf.URL_KEV) == {"vulnerabilities": []}
    assert px.connects[0].startswith("CONNECT www.cisa.gov:443") and f"Basic {TOKEN}" in px.connects[0]
    assert px.inner[0]["path"] == urllib.parse.urlsplit(vf.URL_KEV).path
    assert "socket" in seen and "SSLSocket" in seen  # TCP（プロキシへ）と TLS のあとのソケットを見張りに登録している


def test_vuln_conditional_get_and_xml_via_proxy(monkeypatch, trust, corp_ca):
    """Fortinet: 条件つき GET（304）と XML（RSS）も、プロキシの CONNECT のトンネルの中で（条件はトンネルの中だけに載る）"""
    rss = (b"<?xml version='1.0' encoding='UTF-8'?><rss xmlns:csaf=\"https://fortiguard.fortinet.com/rss/ns/csaf\"><channel>"
           b"<item><link>https://fortiguard.fortinet.com/psirt/FG-IR-99-101</link><csaf:link>"
           b"https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-99-101.json</csaf:link></item></channel></rss>")

    def respond(method, path, headers, body):
        if headers.get("if-none-match") == '"r1"':
            return 304, {"ETag": '"r1"'}, b""
        return 200, {"Content-Type": "text/xml", "ETag": '"r1"'}, rss

    with FakeProxy(corp_ca, auth=(USER, PASS), respond=respond) as px:
        use(monkeypatch, px, auth=True)
        trust(corp_ca)
        got = vf.fetch(vf.URL_FORTINET_RSS, accept=vf.ACCEPT_XML)
        assert got.status == 200 and got.etag == '"r1"'
        assert vf.parse_fortinet_rss(got.body)[0][0]["ext_id"] == "FG-IR-99-101"
        again = vf.fetch(vf.URL_FORTINET_RSS, accept=vf.ACCEPT_XML, etag=got.etag)
        assert again.status == 304 and again.body == b""
    assert all(c.startswith("CONNECT filestore.fortinet.com:443") for c in px.connects)
    assert all('"r1"' not in c for c in px.connects)  # 条件（ETag）は CONNECT には載らない


# ================================================================ HTTPS を検査するプロキシ（組織の CA）


def _send(path: str):
    if path == "notify":
        return notify.send_webhook("discord", DISCORD, {"content": "x"})
    if path == "mail":
        try:
            mail.fetch_token(mail.MailConfig(auth="google_user", google_client_id="a", google_client_secret="b",
                                             google_refresh_token="c"))
        except mail.MailError as e:
            return str(e)
        return None
    try:
        vf.fetch_bytes(vf.URL_EOL.format(product="panos"))
    except vf.FetchError as e:
        return str(e)
    return None


def _token_respond(method, path, headers, body):
    return 200, {"Content-Type": "application/json"}, b'{"access_token": "t", "expires_in": 3600}'


@pytest.mark.parametrize("path", ["notify", "mail", "vuln"])
def test_inspecting_proxy_needs_ca_and_hostname_still_checked(monkeypatch, trust, corp_ca, other_ca, path):
    with FakeProxy(corp_ca, respond=_token_respond) as px:
        use(monkeypatch, px)
        # 追加の CA なし: 組織の CA で署名された証明書は信頼しない
        msg = _send(path)
        assert msg and "証明書を検証できません" in msg and "OUTBOUND_CA_FILE" in msg, msg
        # 別の CA を足しても通らない
        trust(other_ca)
        assert "証明書を検証できません" in (_send(path) or "")
        # 組織の CA を足すと通る
        trust(corp_ca)
        assert _send(path) is None
    # 組織の CA を足しても、名前の違う証明書は拒否する（ホスト名の確認は弱めていない）
    with FakeProxy(corp_ca, cert_name="other.example.test", respond=_token_respond) as px2:
        use(monkeypatch, px2)
        msg = _send(path)
        assert msg and "証明書を検証できません" in msg, msg
        assert not px2.inner


# ================================================================ 失敗の文（407・届かない・時間切れ）と伏せ字


def _all_paths():
    out = {"notify": notify.send_webhook("discord", DISCORD, {}), "teams": notify.send_webhook("teams", TEAMS, {})}
    try:
        mail.fetch_token(mail.MailConfig(auth="microsoft", ms_tenant_id="t1", ms_client_id="a", ms_client_secret="b"))
    except mail.MailError as e:
        out["mail"] = str(e)
    try:
        vf.fetch_bytes(vf.URL_KEV)
    except vf.FetchError as e:
        out["vuln"] = str(e)
    out["check"] = outbound.check_connectivity()
    return out


@pytest.mark.parametrize("mode", ["407", "unreachable", "timeout"])
def test_proxy_failures_are_explained_without_secrets(monkeypatch, trust, corp_ca, caplog, mode):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(notify, "TIMEOUT_SEC", 1)
    monkeypatch.setattr(mail, "TIMEOUT_SEC", 1)
    monkeypatch.setattr(vf, "CONNECT_TIMEOUT", 1)
    monkeypatch.setattr(outbound, "CHECK_TIMEOUT", 1)
    trust(corp_ca)
    px = FakeProxy(corp_ca, mode="hang" if mode == "timeout" else "407")
    try:
        url = px.url(USER, ENC_PASS)
        if mode == "unreachable":
            url = f"http://{USER}:{ENC_PASS}@127.0.0.1:{closed_port()}"
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", url)
        out = _all_paths()
    finally:
        px.close()
    want = {"407": "プロキシの認証に失敗しました", "unreachable": "プロキシに接続できません", "timeout": "時間切れ"}[mode]
    for k in ("notify", "teams", "mail", "vuln"):
        assert want in out[k], (k, out[k])
    assert out["check"]["result"] == {"407": "proxy_auth", "unreachable": "proxy_unreachable", "timeout": "timeout"}[mode]
    assert want in out["check"]["message"] or (mode == "timeout" and "時間切れ" in out["check"]["message"])
    assert no_secret(out), out
    assert no_secret(caplog.text), caplog.text
    if mode == "407":
        assert all(f"Basic {TOKEN}" in c for c in px.connects)  # 認証情報はプロキシへの CONNECT にだけ載る


def test_runtime_https_proxy_is_refused_without_sending(monkeypatch):
    """設定の検査をすり抜けても（実行中の差し替え）、https:// のプロキシには認証情報を送らない"""
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", f"https://{USER}:{ENC_PASS}@127.0.0.1:{closed_port()}")
    out = _all_paths()
    for k in ("notify", "teams", "mail", "vuln"):
        assert "OUTBOUND_PROXY は" in out[k] and "で指定" in out[k], (k, out[k])
    assert out["check"]["result"] == "config" and no_secret(out)


# ================================================================ プロキシへ行かないもの


def test_no_proxy_destination_goes_direct(monkeypatch, corp_ca, block_direct):
    with FakeProxy(corp_ca) as px:
        use(monkeypatch, px)
        monkeypatch.setattr(settings, "OUTBOUND_NO_PROXY", "discord.com,.cisa.gov")
        assert notify.send_webhook("discord", DISCORD, {}).startswith("送信できません")
        with pytest.raises(vf.FetchError):
            vf.fetch_bytes(vf.URL_KEV)
        assert notify.send_webhook("slack", "https://hooks.slack.com/services/x", {}) is not None  # こちらはプロキシへ
    assert ("discord.com", 443) in block_direct and ("www.cisa.gov", 443) in block_direct
    assert [c.split()[1] for c in px.connects] == ["hooks.slack.com:443"]


def test_env_proxy_is_ignored(monkeypatch, corp_ca, block_direct):
    with FakeProxy(corp_ca) as env_px:
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY"):
            monkeypatch.setenv(k, env_px.url())
        assert notify.send_webhook("discord", DISCORD, {}).startswith("送信できません")
        with pytest.raises(mail.MailError):
            mail.fetch_token(mail.MailConfig(auth="microsoft", ms_tenant_id="t1", ms_client_id="a", ms_client_secret="b"))
        with pytest.raises(vf.FetchError):
            vf.fetch_bytes(vf.URL_KEV)
    assert not env_px.connects and not env_px.plain
    assert {("discord.com", 443), ("login.microsoftonline.com", 443), ("www.cisa.gov", 443)} <= set(block_direct)


class _Plain(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self):
        _Plain.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_internal_and_plain_http(monkeypatch, corp_ca):
    """内向き（127.0.0.1）は直接。平文の宛先をプロキシ経由では送らない（認証情報を平文の要求に付けない）"""
    srv = HTTPServer(("127.0.0.1", 0), _Plain)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with FakeProxy(corp_ca) as px:
            monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(USER, ENC_PASS))
            with outbound.urlopen(f"http://127.0.0.1:{srv.server_port}/inside", timeout=5) as r:
                assert r.read() == b"ok"
            with outbound.urlopen(f"http://localhost:{srv.server_port}/inside2", timeout=5) as r:
                assert r.read() == b"ok"
            with pytest.raises(urllib.error.URLError) as e:
                outbound.urlopen("http://plain.example.test/x", timeout=5)
            assert outbound.classify(e.value)[0] == "plain_http"
            assert not outbound.use_proxy("redis") and not outbound.use_proxy("db") and outbound.use_proxy("discord.com")
        assert not px.connects and not px.plain and _Plain.hits == ["/inside", "/inside2"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_summary_and_startup_log(monkeypatch, caplog, trust, corp_ca):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", f"http://{USER}:{ENC_PASS}@proxy.example.test:3128")
    trust(corp_ca)
    s = outbound.summary()
    assert s["proxy"] == "proxy.example.test:3128" and s["proxy_auth"] is True and no_secret(s)
    monkeypatch.setenv("VULN_HTTPS_PROXY", "http://old:secret@proxy.example.test:3128")
    outbound.startup_log()
    assert "プロキシ proxy.example.test:3128（認証あり）・追加の CA 1 件" in caplog.text
    assert "VULN_HTTPS_PROXY は廃止しました" in caplog.text and "old:secret" not in caplog.text and no_secret(caplog.text)
    info = outbound.ca_info()
    assert info["count"] == 1 and info["days_left"] >= 360 and not info["expired"]


def test_check_connectivity_total_deadline_against_dribbling_proxy(monkeypatch, corp_ca):
    """少しずつ返し続けるプロキシでも、接続の確認は全体の期限（テストでは 2 秒）で「時間切れ」になる"""
    import time

    monkeypatch.setattr(outbound, "CHECK_TOTAL", 2)
    monkeypatch.setattr(outbound, "CHECK_TIMEOUT", 1)  # 1 回ごとの待ち（0.2 秒ごとに届くので切れない）
    with FakeProxy(corp_ca, mode="drip") as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(USER, ENC_PASS))
        t0 = time.monotonic()
        res = outbound.check_connectivity()
        elapsed = time.monotonic() - t0
    assert res["result"] == "timeout" and "時間切れ" in res["message"] and no_secret(res)
    assert 1.5 <= elapsed <= 5, elapsed


def test_empty_proxy_env_means_no_proxy(monkeypatch):
    """compose は http_proxy などを空で渡す。空の値は「プロキシなし」と同じ（urllib の環境変数の読み取り）"""
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(k, "")
    found = urllib.request.getproxies_environment()
    assert not {"http", "https", "all"} & set(found), found
