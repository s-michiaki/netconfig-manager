"""通知・メールの悪用と障害への備え（#30・#31・#32）

- #30: 閲覧者が組織の SMTP・Webhook からテスト通知を連打できない。宛先のドメインを制限していないことに気づける
- #31: 1 つの経路（メール）の想定外の例外で、その回のほかの経路（Webhook）の送信と記録が失われない
- #32: SMTP の危険な組み合わせを新しく保存させない（保存済みのものは止めずに注意）。外部 Git の http:// に注意。
       利用者・機器が決められる文字列の中の URL を、メールでもリンクにしない
外へは実際に通信しない（SMTP・Webhook は差し替える）。メールサーバーの設定（1 件）はテストの終わりに無効へ戻す
"""
import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from test_mail import FakeSMTP, FakeSMTPSSL, cfg

from app.core.database import AsyncSessionLocal
from app.main import app
from app.models.mail import MailServer
from app.services import mail, notify

ADMIN_PW = "initial-pass-123"
PW = "password-1234"
SERVER = {"enabled": True, "auth": "password", "host": "smtp.example.test", "port": 587, "security": "starttls",
          "username": "notify@example.test", "password": "smtp-secret-pw", "from_address": "notify@example.test",
          "from_name": "NetConfig", "subject_prefix": "[NCM]", "allowed_domains": "example.test"}


def login(c, u, p=PW):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture
def smtp(monkeypatch):
    import smtplib
    FakeSMTP.log, FakeSMTP.sent, FakeSMTP.auth_fail = [], [], None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    mail.clear_token_cache()
    yield FakeSMTP
    mail.clear_token_cache()


@pytest.fixture
def hooks(monkeypatch):
    """Webhook の送信の代わり（外へ送らない）"""
    calls = []

    def fake(kind, url, payload):
        calls.append((kind, url, payload))
        return None
    monkeypatch.setattr(notify, "send_webhook", fake)
    return calls


@pytest.fixture(scope="module")
def api():
    with TestClient(app) as c:
        admin = login(c, "admin", ADMIN_PW)
        name = f"ns-v-{uuid.uuid4().hex[:6]}"
        uid = c.post("/api/users/", json={"username": name, "password": PW, "role": "viewer"}, headers=admin).json()["id"]
        yield {"c": c, "admin": admin, "viewer": login(c, name), "viewer_id": uid}
        c.put("/api/notifications/me", json={"mode": "inherit", "email_to": "", "discord_webhook": ""},
              headers=login(c, name))
        _reset_server()
        c.delete(f"/api/users/{uid}", headers=admin)


def _reset_server():
    """メールサーバーの設定を「無効・危険な組み合わせなし」に戻す（ほかのテストの保存に影響させない）"""
    async def run():
        async with AsyncSessionLocal() as db:
            row = await db.get(MailServer, "default")
            if row is not None:
                row.enabled, row.auth, row.security, row.verify_tls = False, "password", "starttls", True
                await db.commit()
    asyncio.run(run())


def _set_row(**values):
    """画面の検査を通さずに保存済みの状態を作る（以前の版で保存した設定の再現）"""
    async def run():
        async with AsyncSessionLocal() as db:
            row = await db.get(MailServer, "default")
            for k, v in values.items():
                setattr(row, k, v)
            await db.commit()
    asyncio.run(run())


def _status(c, admin) -> dict:
    return {x["key"]: x for x in c.get("/api/system/status", headers=admin).json()["components"]}


# ---------------------------------------------------------------- #30 テスト通知の間隔・宛先のドメイン


def test_my_test_notification_is_rate_limited(api, hooks):
    c, viewer = api["c"], api["viewer"]
    hook = f"https://discord.com/api/webhooks/9301/ns-{uuid.uuid4().hex[:6]}"
    assert c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook}, headers=viewer).status_code == 200
    assert c.post("/api/notifications/me/test", headers=viewer).status_code == 200
    codes = [c.post("/api/notifications/me/test", headers=viewer).status_code for _ in range(5)]
    assert codes == [429] * 5
    r = c.post("/api/notifications/me/test", headers=viewer)
    assert "Retry-After" in r.headers and "続けて送れません" in r.json()["detail"]
    assert len([x for x in hooks if x[1] == hook]) == 1  # 連打しても 1 回しか送らない
    # ほかの人は止めない（利用者ごと）
    admin = api["admin"]
    c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook + "x"}, headers=admin)
    assert c.post("/api/notifications/me/test", headers=admin).status_code == 200
    c.put("/api/notifications/me", json={"mode": "inherit", "discord_webhook": ""}, headers=admin)
    c.put("/api/notifications/me", json={"mode": "inherit", "discord_webhook": ""}, headers=viewer)


def test_group_test_notification_is_rate_limited(api, hooks):
    c, admin = api["c"], api["admin"]
    hook = f"https://discord.com/api/webhooks/9302/ns-{uuid.uuid4().hex[:6]}"
    g = c.post("/api/notifications/groups", json={"name": f"ns-g-{uuid.uuid4().hex[:6]}", "member_ids": [],
                                                  "notification": {"mode": "custom", "discord_webhook": hook}},
               headers=admin).json()
    assert c.post(f"/api/notifications/groups/{g['id']}/test", headers=admin).status_code == 200
    assert c.post(f"/api/notifications/groups/{g['id']}/test", headers=admin).status_code == 429
    assert len([x for x in hooks if x[1] == hook]) == 1
    assert c.delete(f"/api/notifications/groups/{g['id']}", headers=admin).status_code == 204


def test_unrestricted_domains_are_flagged(api, smtp):
    """宛先のドメインを制限していないときは、メールサーバーの画面とシステム状態に注意を出す（動きは変えない）"""
    c, admin, viewer = api["c"], api["admin"], api["viewer"]
    r = c.put("/api/mail/server", json={**SERVER, "allowed_domains": ""}, headers=admin)
    assert r.status_code == 200 and any("宛先のドメインを制限していません" in w for w in r.json()["warnings"])
    # システム状態は正常のまま、文だけ出す（既定の設定で恒常的に注意にしない）
    notes = _status(c, admin)["notes"]
    assert notes["status"] == "ok" and "宛先のドメインを制限していません" in notes["summary"]
    # 今までどおり登録はできる（新しい制限を既定で強制しない）
    assert c.put("/api/notifications/me", json={"mode": "custom", "email_to": "me@outside.test"},
                 headers=viewer).status_code == 200
    c.put("/api/notifications/me", json={"mode": "inherit", "email_to": ""}, headers=viewer)
    # 設定すると注意は消える
    r = c.put("/api/mail/server", json=SERVER, headers=admin)
    assert r.json()["warnings"] == []
    notes = _status(c, admin)["notes"]
    assert notes["status"] == "ok" and "宛先" not in notes["summary"]


def test_notes_are_not_notified():
    """注意（notes）は画面に出すだけで、システムの異常として通知しない（既存の環境で更新のたびに通知を出さない）"""
    from app.services import system
    assert "notes" not in system.ALERT_KEYS


# ---------------------------------------------------------------- #31 1 つの経路の失敗でほかを止めない


def test_unexpected_mail_error_does_not_drop_webhooks(api, smtp, hooks, monkeypatch):
    c, admin, viewer = api["c"], api["admin"], api["viewer"]
    assert c.put("/api/mail/server", json=SERVER, headers=admin).status_code == 200
    hook = f"https://discord.com/api/webhooks/9303/ns-{uuid.uuid4().hex[:6]}"
    r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, "email_to": "me@example.test",
                                             "on_system": True}, headers=viewer)
    assert r.status_code == 200, r.text

    def boom(*a, **k):
        raise RuntimeError("想定外")
    monkeypatch.setattr(mail, "build_message", boom)  # メールの組み立てで想定外の例外

    async def run():
        async with AsyncSessionLocal() as db:
            return await notify.notify_system(db, "テストの異常", "本文")
    res = asyncio.run(run())
    assert res["failed"] >= 1
    assert any(x[1] == hook for x in hooks)  # Webhook には届く
    me = c.get("/api/notifications/me", headers=viewer).json()
    assert "メール: 送信できません（想定外のエラー: RuntimeError" in (me["last_error"] or "")  # last_error に残る
    acts = c.get("/api/activity/logs", params={"event": "notify.failed"}, headers=admin).json()["items"]
    assert any("想定外のエラー" in a["message"] for a in acts)
    comp = _status(c, admin)["mail"]
    assert comp["status"] == "error" and "想定外のエラー" in comp["summary"]  # システム状態に出る
    c.put("/api/notifications/me", json={"mode": "inherit", "email_to": "", "discord_webhook": ""}, headers=viewer)


def test_send_all_survives_a_raising_sender(monkeypatch):
    """送信の関数そのものが例外を出しても（return_exceptions）、ほかの結果は失わない"""
    def fake(kind, url, payload, cfg):
        if kind == "email":
            raise ValueError("boom")
        return None
    monkeypatch.setattr(notify, "_send", fake)
    out = asyncio.run(notify.send_all([("email", "a@example.test", {}), ("discord", "u", {})], None))
    assert out[0].startswith("送信できません（想定外のエラー: ValueError") and out[1] is None


def test_broken_service_account_key(api, smtp):
    """途中の欠けた鍵は保存させない。保存済みの壊れた鍵でも、送信は MailError（説明）になり例外で止まらない"""
    c, admin = api["c"], api["admin"]
    broken = json.dumps({"type": "service_account", "client_email": "ncm@proj.example.test",
                         "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"})
    r = c.put("/api/mail/server", json={**SERVER, "auth": "google_sa", "host": "smtp.gmail.com", "password": None,
                                        "google_sa_json": broken}, headers=admin)
    assert r.status_code == 422 and "署名できません" in r.json()["detail"]
    assert "MIIEvQ" not in r.text  # 鍵の中身は応答に出さない
    err = mail.send_notification(cfg(auth="google_sa", host="smtp.gmail.com", google_sa_json=broken), "o@example.test",
                                 {"title": "x"})
    assert "署名できません" in err and "MIIEvQ" not in err


def test_token_response_without_numeric_expiry(monkeypatch):
    monkeypatch.setattr(mail, "_post_form", lambda url, data: {"access_token": "t", "expires_in": "soon"})
    assert mail.fetch_token(cfg(auth="microsoft", ms_tenant_id="t1", ms_client_id="a", ms_client_secret="b")) == ("t", 3600)


def test_sender_name_with_newline(api, smtp):
    c, admin = api["c"], api["admin"]
    r = c.put("/api/mail/server", json={**SERVER, "from_name": "監視\nBcc: x@example.test"}, headers=admin)
    assert r.status_code == 422 and "送信者名" in r.json()["detail"]
    # 以前の版で保存した改行入りの名前でも、例外にならずに送れる
    assert mail.send_notification(cfg(from_name="監視\r\nBcc: x@example.test"), "ops@example.test", {"title": "x"}) is None
    assert smtp.sent[-1][1]["Bcc"] is None


# ---------------------------------------------------------------- #32 SMTP の危険な組み合わせ・外部 Git・URL


def test_plaintext_password_needs_explicit_acceptance(api, smtp):
    c, admin = api["c"], api["admin"]
    assert c.put("/api/mail/server", json=SERVER, headers=admin).status_code == 200
    plain = {**SERVER, "security": "none", "port": 25, "password": None}
    r = c.put("/api/mail/server", json=plain, headers=admin)
    assert r.status_code == 422 and "平文" in r.json()["detail"]
    r = c.put("/api/mail/server", json={**plain, "accept_insecure": True}, headers=admin)
    assert r.status_code == 200 and any("暗号化なし" in w for w in r.json()["warnings"])
    # 保存済みのものは、確認なしで保存し直せる（ほかの項目の変更）。送信も止めない
    assert c.put("/api/mail/server", json={**plain, "from_name": "別名"}, headers=admin).status_code == 200
    # L1: 送り先のサーバーを変えるのは「新しく保存する」とみなす（保存済みの危険な設定のまま、別のサーバーへ移せない）
    r = c.put("/api/mail/server", json={**plain, "host": "smtp2.example.test"}, headers=admin)
    assert r.status_code == 422 and "平文" in r.json()["detail"]
    assert c.put("/api/mail/server", json={**plain, "port": 2525}, headers=admin).status_code == 422
    assert c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin).json()["ok"] is True
    assert "暗号化なし" in _status(c, admin)["notes"]["summary"]
    assert c.put("/api/mail/server", json=SERVER, headers=admin).status_code == 200


def test_oauth_without_verification_is_rejected_but_saved_one_keeps_sending(api, smtp, monkeypatch):
    c, admin = api["c"], api["admin"]
    ms = {**SERVER, "auth": "microsoft", "host": "smtp.office365.com", "password": None, "ms_tenant_id": "t1",
          "ms_client_id": "cid", "ms_client_secret": "csecret"}
    assert c.put("/api/mail/server", json=ms, headers=admin).status_code == 200
    r = c.put("/api/mail/server", json={**ms, "verify_tls": False, "accept_insecure": True}, headers=admin)
    assert r.status_code == 422 and "証明書を確認する" in r.json()["detail"]
    # 以前の版で保存した（証明書を検証しない＋OAuth）設定: 送信は続け、画面とシステム状態で注意する
    _set_row(verify_tls=False)
    monkeypatch.setattr(mail, "_post_form", lambda url, data: {"access_token": "tok", "expires_in": 3600})
    assert c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin).json()["ok"] is True
    out = c.get("/api/mail/server", headers=admin).json()
    assert any("証明書を検証せずに OAuth" in w for w in out["warnings"])
    assert "証明書を検証せずに OAuth" in _status(c, admin)["notes"]["summary"]
    assert c.put("/api/mail/server", json={**ms, "verify_tls": False, "from_name": "別名"}, headers=admin).status_code == 200
    # L1: プロバイダーを変える（Microsoft → Google）のも新しく保存するとみなす
    r = c.put("/api/mail/server", json={**ms, "verify_tls": False, "auth": "google_user", "google_client_id": "g",
                                        "google_client_secret": "gs"}, headers=admin)
    assert r.status_code == 422 and "証明書を確認する" in r.json()["detail"]
    assert c.put("/api/mail/server", json=SERVER, headers=admin).status_code == 200


def test_unverified_password_is_only_a_warning():
    w = mail.config_warnings(cfg(verify_tls=False, allowed_domains=["example.test"]))
    assert len(w) == 1 and "証明書を検証せずにパスワード" in w[0]
    assert mail.insecure_combo("password", "starttls", False) is None  # 社内の自己署名の証明書は保存できる
    assert mail.insecure_combo("none", "none", True) is None  # 認証なしの社内のリレーは今までどおり
    assert mail.config_warnings(cfg(enabled=False, security="none")) == []


def test_git_http_url_is_flagged(api, monkeypatch):
    from app.core.config import settings
    c, admin = api["c"], api["admin"]
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "http://git.example.test/net/configs.git")
    notes = _status(c, admin)["notes"]
    assert notes["status"] == "warn" and "http://" in notes["summary"]
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://git.example.test/net/configs.git")
    assert "外部 Git" not in _status(c, admin)["notes"]["summary"]


def test_email_does_not_linkify_user_values():
    m = mail.build_message(cfg(), "ops@example.test", "Ping 応答なし: https://evil.example/login",
                           [("名前", "www.evil.example/login"), ("エラー", "see https://evil.example")],
                           body="https://evil.example/x", url="https://ncm.example.test/ping", link_text="画面で確認")
    text = m.get_body(("plain",)).get_content()
    page = m.get_body(("html",)).get_content()
    for part in (text, page, m["Subject"]):
        assert "https://evil" not in part and "www.evil" not in part
    assert 'href="https://ncm.example.test/ping"' in page and "画面で確認: https://ncm.example.test/ping" in text


def test_precheck_failures_do_not_use_the_interval(api, smtp, hooks):
    """L-b: 接続の前の検査で弾かれたテストは、間隔の枠を使わない（設定を直しながら試せる）。実際に送った回は使う"""
    c, admin, viewer = api["c"], api["admin"], api["viewer"]
    assert c.put("/api/mail/server", json=SERVER, headers=admin).status_code == 200
    for _ in range(3):  # 宛先のドメインの制限で弾かれる
        r = c.post("/api/mail/server/test", json={"to": "ops@outside.test"}, headers=admin)
        assert r.status_code == 200 and "送れません" in r.json()["error"]
    assert smtp.sent == []
    assert c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin).json()["ok"] is True
    assert c.post("/api/mail/server/test", json={"to": "ops@example.test"}, headers=admin).status_code == 429
    # 通知のテスト: メールの宛先だけで、メールサーバーを無効にした（送る前に弾かれる）なら枠を使わない
    assert c.put("/api/notifications/me", json={"mode": "custom", "email_to": "me@example.test"},
                 headers=viewer).status_code == 200
    _set_row(enabled=False)
    for _ in range(2):
        r = c.post("/api/notifications/me/test", headers=viewer)
        assert r.status_code == 200 and "無効" in r.json()["results"]["email:me@example.test"]
    _set_row(enabled=True)
    assert c.post("/api/notifications/me/test", headers=viewer).json()["results"]["email:me@example.test"] == "ok"
    assert c.post("/api/notifications/me/test", headers=viewer).status_code == 429
    c.put("/api/notifications/me", json={"mode": "inherit", "email_to": ""}, headers=viewer)


def test_unexpected_errors_do_not_log_secrets(monkeypatch, caplog):
    """想定外の例外のログには、例外の文・トレースバック（Webhook の URL・トークンが入りうる）を出さず、種類だけ"""
    secret_url = "https://discord.com/api/webhooks/1/SECRET-TOKEN-VALUE"

    def boom(*a, **k):
        raise RuntimeError(f"失敗 {secret_url} Bearer tok-SECRET")
    monkeypatch.setattr(notify, "send_webhook", boom)
    monkeypatch.setattr(mail, "build_message", boom)
    with caplog.at_level("DEBUG"):
        assert "RuntimeError" in notify._send("discord", secret_url, {}, None)
        assert "RuntimeError" in mail.send_notification(cfg(), "ops@example.test", {"title": "x"})

        def raising(*a, **k):
            raise ValueError(f"x {secret_url}")
        monkeypatch.setattr(notify, "_send", raising)
        out = asyncio.run(notify.send_all([("discord", secret_url, {})], None))
        assert "ValueError" in out[0]
    text = "\n".join(r.getMessage() + (str(r.exc_info) if r.exc_info else "") + (r.exc_text or "") for r in caplog.records)
    assert "SECRET" not in text and "RuntimeError" in text and "ValueError" in text
    assert all(r.exc_info is None for r in caplog.records if r.name in ("app.services.notify", "app.services.mail"))
