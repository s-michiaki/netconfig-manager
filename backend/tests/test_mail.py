"""メール通知のテスト（SMTP サーバー・トークンの取得先は差し替える）"""
import asyncio
import base64
import json
import smtplib
import urllib.parse
import uuid
from typing import ClassVar

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core.database import AsyncSessionLocal
from app.main import app
from app.services import mail, notify


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


class FakeSMTP:
    """smtplib.SMTP の代わり。呼ばれた順番と送ったメールを残す"""

    log: ClassVar[list] = []
    sent: ClassVar[list] = []
    auth_fail: ClassVar[bytes | None] = None
    features: ClassVar[dict] = {"auth": "LOGIN PLAIN XOAUTH2", "starttls": ""}

    def __init__(self, host, port, timeout=None, context=None):
        self.log.append(("connect", host, port, type(self).__name__))
        self.esmtp_features = dict(self.features)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.log.append(("quit",))

    def ehlo(self):
        self.log.append(("ehlo",))

    def starttls(self, context=None):
        self.log.append(("starttls", context.verify_mode))

    def has_extn(self, name):
        return name.lower() in self.esmtp_features

    def login(self, user, password):
        self.log.append(("login", user, password))
        if self.auth_fail:
            raise smtplib.SMTPAuthenticationError(535, self.auth_fail)

    def auth(self, mech, authobject):
        first = authobject()
        self.log.append(("auth", mech, first))
        if self.auth_fail:
            assert authobject("eyJzdGF0dXMiOiI0MDAifQ==") == ""  # 失敗の理由（334）には空で答える
            raise smtplib.SMTPAuthenticationError(535, self.auth_fail)

    def send_message(self, msg, from_addr=None):
        self.sent.append((from_addr, msg))


class FakeSMTPSSL(FakeSMTP):
    pass


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.log, FakeSMTP.sent, FakeSMTP.auth_fail = [], [], None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    mail.clear_token_cache()
    yield FakeSMTP
    mail.clear_token_cache()


@pytest.fixture
def token_server(monkeypatch):
    """トークンの取得先（_post_form）の代わり"""
    calls = []

    def fake(url, data):
        calls.append((url, data))
        if data.get("grant_type") == "authorization_code":
            return {"access_token": "at", "refresh_token": "rt-new", "expires_in": 3600, "scope": mail.GOOGLE_SCOPE}
        return {"access_token": f"token-{len(calls)}", "expires_in": 3600}

    monkeypatch.setattr(mail, "_post_form", fake)
    return calls


def cfg(**kw):
    base = dict(enabled=True, auth="password", host="smtp.example.test", port=587, security="starttls",
                username="notify@example.test", password="pw", from_address="notify@example.test",
                subject_prefix="[NetConfig]")
    base.update(kw)
    return mail.MailConfig(**base)


# ---------------------------------------------------------------- 組み立て・宛先


def test_build_message_escapes_and_strips():
    m = mail.build_message(cfg(from_name="監視"), "ops@example.test", "変更\r\nBcc: evil@example.test",
                           [("機器", "<core-sw01>"), ("変更", "+1 行")], body="本文", url="https://ncm.example.test/x?a=1&b=2",
                           link_text="差分を画面で確認")
    assert m["Subject"] == "[NetConfig] 変更 Bcc: evil@example.test" and m["Bcc"] is None  # 改行は空白に
    assert m["To"] == "ops@example.test" and m["Auto-Submitted"] == "auto-generated"
    assert "notify@example.test" in m["From"] and m["Message-ID"].endswith("@example.test>")
    text = m.get_body(("plain",)).get_content()
    page = m.get_body(("html",)).get_content()
    assert "機器: <core-sw01>" in text and "差分を画面で確認: https://ncm.example.test/x?a=1&b=2" in text
    assert "&lt;core-sw01&gt;" in page and "<core-sw01>" not in page and 'href="https://ncm.example.test/x?a=1&amp;b=2"' in page


def test_addresses_and_domains():
    assert mail.parse_addresses("a@example.test, B@example.test\nb@example.test;c@x.test") == [
        "a@example.test", "B@example.test", "c@x.test"]
    assert mail.check_address("ops@example.test", []) is None
    assert "形式" in mail.check_address("ops@", [])
    assert mail.check_address("ops@sub.example.test", ["example.test"]) is None  # サブドメインも可
    assert "送れません" in mail.check_address("ops@notexample.test", ["example.test"])
    assert mail.parse_domains(" @Example.test, corp.test ") == ["example.test", "corp.test"]


def test_check_config():
    assert "無効" in mail.check_config(cfg(enabled=False))
    assert "ユーザー名・パスワード" in mail.check_config(cfg(password=""))
    assert "暗号化" in mail.check_config(cfg(auth="microsoft", security="none"))
    assert mail.check_config(cfg(auth="none", username="", password="")) is None


# ---------------------------------------------------------------- 送信


def test_send_with_password(smtp):
    assert mail.send_notification(cfg(), "ops@example.test", {"title": "テスト", "facts": [("a", "b")]}) is None
    assert smtp.log[0] == ("connect", "smtp.example.test", 587, "FakeSMTP")
    assert ("login", "notify@example.test", "pw") in smtp.log and smtp.log[2][0] == "starttls"
    from_addr, msg = smtp.sent[0]
    assert from_addr == "notify@example.test" and msg["Subject"] == "[NetConfig] テスト"

    # SSL/TLS（465）・証明書を確認しない
    smtp.log.clear()
    mail.send_notification(cfg(security="ssl", port=465), "ops@example.test", {"title": "x"})
    assert smtp.log[0] == ("connect", "smtp.example.test", 465, "FakeSMTPSSL")
    smtp.log.clear()
    mail.send_notification(cfg(verify_tls=False), "ops@example.test", {"title": "x"})
    import ssl
    assert ("starttls", ssl.CERT_NONE) in smtp.log


def test_send_errors(smtp):
    smtp.auth_fail = b"5.7.139 Authentication unsuccessful, basic authentication is disabled."
    err = mail.send_notification(cfg(), "ops@example.test", {"title": "x"})
    assert "認証に失敗" in err and "OAuth 2.0 を使ってください" in err and "pw" not in err
    smtp.auth_fail = b"5.7.8 Username and Password not accepted."
    assert "アプリパスワード" in mail.send_notification(cfg(), "ops@example.test", {"title": "x"})
    assert "送れません" in mail.send_notification(cfg(allowed_domains=["corp.test"]), "ops@example.test", {"title": "x"})
    assert not smtp.sent


def test_send_with_microsoft_oauth(smtp, token_server):
    c = cfg(auth="microsoft", host="smtp.office365.com", password="", ms_tenant_id="contoso.onmicrosoft.com",
            ms_client_id="cid", ms_client_secret="secret")
    for _ in range(2):
        assert mail.send_notification(c, "ops@example.test", {"title": "x"}) is None
    assert len(token_server) == 1  # 2 通目はトークンを使い回す
    url, data = token_server[0]
    assert url == "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
    assert data == {"grant_type": "client_credentials", "client_id": "cid", "client_secret": "secret",
                    "scope": "https://outlook.office365.com/.default"}
    auth = next(x for x in smtp.log if x[0] == "auth")
    assert auth[1] == "XOAUTH2" and auth[2] == "user=notify@example.test\x01auth=Bearer token-1\x01\x01"
    assert not any(x[0] == "login" for x in smtp.log)

    # 認証に失敗したらトークンを捨て、次は取り直す
    smtp.auth_fail = b"5.7.3 Authentication unsuccessful"
    assert "認証に失敗" in mail.send_notification(c, "ops@example.test", {"title": "x"})
    smtp.auth_fail = None
    mail.send_notification(c, "ops@example.test", {"title": "x"})
    assert len(token_server) == 2

    # サーバーが XOAUTH2 に対応していない・テナント ID が不正
    smtp.features = {"auth": "LOGIN PLAIN"}
    try:
        assert "XOAUTH2" in mail.send_notification(c, "ops@example.test", {"title": "x"})
    finally:
        smtp.features = FakeSMTP.features = {"auth": "LOGIN PLAIN XOAUTH2", "starttls": ""}
    mail.clear_token_cache()
    assert "形式" in mail.send_notification(cfg(auth="microsoft", ms_tenant_id="../evil", ms_client_id="a",
                                                ms_client_secret="b"), "ops@example.test", {"title": "x"})


def test_google_service_account_jwt(smtp, token_server):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    sa = json.dumps({"type": "service_account", "client_email": "ncm@proj.iam.gserviceaccount.com", "private_key": pem})
    c = cfg(auth="google_sa", host="smtp.gmail.com", password="", google_sa_json=sa, username="notify@example.test")
    assert mail.send_notification(c, "ops@example.test", {"title": "x"}) is None
    url, data = token_server[0]
    assert url == mail.GOOGLE_TOKEN_URL and data["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    claims = jwt.decode(data["assertion"], key.public_key(), algorithms=["RS256"], audience=mail.GOOGLE_TOKEN_URL)
    assert claims["iss"] == "ncm@proj.iam.gserviceaccount.com" and claims["sub"] == "notify@example.test"
    assert claims["scope"] == "https://mail.google.com/" and claims["exp"] - claims["iat"] == 3600
    assert "読めません" in mail.send_notification(cfg(auth="google_sa", google_sa_json="{bad"), "o@example.test",
                                                  {"title": "x"})


def test_google_user_refresh(smtp, token_server):
    c = cfg(auth="google_user", host="smtp.gmail.com", password="", google_client_id="gid", google_client_secret="gs",
            google_refresh_token="rt")
    assert mail.send_notification(c, "ops@example.test", {"title": "x"}) is None
    assert token_server[0][1] == {"grant_type": "refresh_token", "client_id": "gid", "client_secret": "gs",
                                  "refresh_token": "rt"}
    assert "同意がまだ" in mail.send_notification(cfg(auth="google_user", google_client_id="g2", google_client_secret="s",
                                                     google_refresh_token=""), "ops@example.test", {"title": "x"})


def test_token_errors_are_readable(monkeypatch):
    import io
    import urllib.error

    def boom(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "x", {}, io.BytesIO(json.dumps(
            {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace"}
        ).encode()))

    monkeypatch.setattr(mail, "_urlopen", boom)
    with pytest.raises(mail.MailError) as e:
        mail.fetch_token(cfg(auth="microsoft", ms_tenant_id="t1", ms_client_id="a", ms_client_secret="b"))
    assert str(e.value) == "トークンを取得できません（AADSTS7000215: Invalid client secret provided.）"


# ---------------------------------------------------------------- 画面（API）・通知


@pytest.fixture(scope="module")
def api():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        name = f"mail-v-{uuid.uuid4().hex[:6]}"
        uid = c.post("/api/users/", json={"username": name, "password": "password-1234", "role": "viewer"},
                     headers=admin).json()["id"]
        yield {"c": c, "admin": admin, "viewer": login(c, name, "password-1234"), "viewer_id": uid}
        c.put("/api/mail/server", json={"enabled": False}, headers=admin)
        c.put("/api/notifications/me", json={"mode": "inherit", "email_to": ""}, headers=admin)
        c.delete(f"/api/users/{uid}", headers=admin)


SERVER = {"enabled": True, "auth": "password", "host": "smtp.example.test", "port": 587, "security": "starttls",
          "username": "notify@example.test", "password": "smtp-secret-pw", "from_address": "notify@example.test",
          "from_name": "NetConfig", "subject_prefix": "[NCM]", "allowed_domains": "example.test"}


def test_server_settings_api(api, smtp):
    c, admin = api["c"], api["admin"]
    assert c.get("/api/mail/server", headers=api["viewer"]).status_code == 403
    assert c.put("/api/mail/server", json=SERVER, headers=api["viewer"]).status_code == 403
    r = c.put("/api/mail/server", json=SERVER, headers=admin)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["has_password"] and "smtp-secret-pw" not in r.text and out["allowed_domains"] == "example.test"
    # 秘密の値は省略すれば変わらない
    r = c.put("/api/mail/server", json={**SERVER, "password": None, "port": 2525}, headers=admin).json()
    assert r["has_password"] and r["port"] == 2525
    for bad, msg in [({"from_address": "nope"}, "送信元"), ({"password": ""}, "パスワード"),
                     ({"allowed_domains": "bad domain!"}, "ドメイン"), ({"auth": "microsoft", "ms_tenant_id": "a/b"}, "テナント"),
                     ({"auth": "google_sa", "google_sa_json": "{}"}, "client_email")]:
        r = c.put("/api/mail/server", json={**SERVER, "password": None, **bad}, headers=admin)
        assert r.status_code == 422 and msg in r.json()["detail"], (bad, r.text)

    # テスト送信
    r = c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin).json()
    assert r == {"ok": True, "error": None} and smtp.sent[-1][1]["Subject"] == "[NCM] テストメール"
    assert ("connect", "smtp.example.test", 2525, "FakeSMTP") in smtp.log
    # 続けては送れない（管理者ごとに 60 秒に 1 回）。試験では間隔の記録を消してから続ける
    r2 = c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin)
    assert r2.status_code == 429 and "続けて送れません" in r2.json()["detail"]
    from app.services import login_limit
    asyncio.run(login_limit.client().delete(*asyncio.run(login_limit.client().keys("netconfig:report:mail-test:*"))))
    r = c.post("/api/mail/server/test", json={"to": "ops@other.test"}, headers=admin).json()
    assert not r["ok"] and "送れません" in r["error"]
    assert c.get("/api/mail/server", headers=admin).json()["last_result"]["ok"] is False
    logs = c.get("/api/audit/", params={"action": "mail.update"}, headers=admin).json()
    assert "smtp-secret-pw" not in json.dumps(logs)


def test_email_notifications(api, smtp):
    c, admin, viewer = api["c"], api["admin"], api["viewer"]
    c.put("/api/mail/server", json={**SERVER, "enabled": False}, headers=admin)
    r = c.put("/api/notifications/me", json={"mode": "custom", "email_to": "me@example.test"}, headers=viewer)
    assert r.status_code == 422 and "メール送信が設定されていません" in r.json()["detail"]
    c.put("/api/mail/server", json=SERVER, headers=admin)
    r = c.put("/api/notifications/me", json={"mode": "custom", "email_to": "me@outside.test"}, headers=viewer)
    assert r.status_code == 422 and "送れません" in r.json()["detail"]  # 社外へは送らせない
    many = ",".join(f"u{i}@example.test" for i in range(11))
    assert c.put("/api/notifications/me", json={"mode": "custom", "email_to": many}, headers=viewer).status_code == 422
    r = c.put("/api/notifications/me", json={"mode": "custom", "email_to": "me@example.test\nteam@example.test",
                                             "on_system": True}, headers=viewer)
    assert r.status_code == 200 and r.json()["email_to"] == ["me@example.test", "team@example.test"]
    # 管理者も同じ宛先（大文字小文字違い）→ 1 通だけ
    c.put("/api/notifications/me", json={"mode": "custom", "email_to": "Team@example.test", "on_system": True},
          headers=admin)

    # テスト通知（宛先ごとの結果）
    r = c.post("/api/notifications/me/test", headers=viewer).json()["results"]
    assert r == {"email:me@example.test": "ok", "email:team@example.test": "ok"}

    smtp.sent.clear()

    async def run():
        async with AsyncSessionLocal() as db:
            return await notify.notify_system(db, "worker が止まっています", "本文", [("止まった時刻", "10:00")])
    res = asyncio.run(run())
    to = sorted(m["To"].lower() for _, m in smtp.sent)
    assert to == ["me@example.test", "team@example.test"] and res["failed"] == 0
    body = smtp.sent[0][1].get_body(("plain",)).get_content()
    assert "worker が止まっています" in body and "止まった時刻: 10:00" in body

    # 送信に失敗 → アクティビティ（宛先は残さない）とシステム状態
    smtp.auth_fail = b"5.7.8 Username and Password not accepted."
    res = asyncio.run(run())
    smtp.auth_fail = None
    assert res["failed"] == 2
    acts = c.get("/api/activity/logs", params={"event": "notify.failed"}, headers=admin).json()
    items = acts["items"] if isinstance(acts, dict) else acts
    assert any("メール への" in a["message"] for a in items) and "me@example.test" not in json.dumps(items)
    comp = {x["key"]: x for x in c.get("/api/system/status", headers=admin).json()["components"]}["mail"]
    assert comp["status"] == "error" and "アプリパスワード" in comp["summary"]
    asyncio.run(run())
    comp = {x["key"]: x for x in c.get("/api/system/status", headers=admin).json()["components"]}["mail"]
    assert comp["status"] == "ok"

    # 宛先を消す
    r = c.put("/api/notifications/me", json={"mode": "custom", "email_to": "", "discord_webhook": ""}, headers=viewer)
    assert r.status_code == 422 and "通知先" in r.json()["detail"]
    c.put("/api/notifications/me", json={"mode": "inherit", "email_to": ""}, headers=viewer)


def test_google_authorization_flow(api, token_server):
    c, admin = api["c"], api["admin"]
    c.put("/api/mail/server", json={**SERVER, "auth": "google_user", "host": "smtp.gmail.com", "password": "",
                                    "google_client_id": "gid.apps.googleusercontent.com", "google_client_secret": "gsec"},
          headers=admin)
    url = c.post("/api/mail/google/authorize", headers=admin).json()["url"]
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert url.startswith(mail.GOOGLE_AUTH_URL) and q["redirect_uri"] == ["http://127.0.0.1"]
    assert q["scope"] == ["https://mail.google.com/"] and q["access_type"] == ["offline"]
    assert q["code_challenge_method"] == ["S256"] and q["login_hint"] == ["notify@example.test"]
    state = q["state"][0]

    # 別の state・同意しなかった・コードが無い
    for bad, msg in [("http://127.0.0.1/?state=x&code=c", "有効期限"), ("http://127.0.0.1/?error=access_denied", "同意されません"),
                     ("http://127.0.0.1/", "認可コード")]:
        r = c.post("/api/mail/google/complete", json={"url": bad}, headers=admin)
        assert r.status_code == 400 and msg in r.json()["detail"], (bad, r.text)

    r = c.post("/api/mail/google/complete", json={"url": f"http://127.0.0.1/?state={state}&code=4%2Fabc&scope=x"},
               headers=admin)
    assert r.status_code == 200 and r.json()["google_authorized"], r.text
    data = token_server[-1][1]
    assert data["code"] == "4/abc" and data["redirect_uri"] == "http://127.0.0.1"
    verifier = data["code_verifier"]
    challenge = base64.urlsafe_b64encode(__import__("hashlib").sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert q["code_challenge"] == [challenge]
    # 同じ state は 2 度使えない
    r = c.post("/api/mail/google/complete", json={"url": f"http://127.0.0.1/?state={state}&code=x"}, headers=admin)
    assert r.status_code == 400

    async def stored():
        async with AsyncSessionLocal() as db:
            return (await mail.load_config(db)).google_refresh_token
    assert asyncio.run(stored()) == "rt-new"
    # クライアント ID を変えると同意は無効になる
    r = c.put("/api/mail/server", json={**SERVER, "auth": "google_user", "host": "smtp.gmail.com", "password": None,
                                        "google_client_id": "other"}, headers=admin).json()
    assert not r["google_authorized"]
    assert c.delete("/api/mail/google", headers=admin).status_code == 200

