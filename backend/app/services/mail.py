"""メール通知の送信（SMTP。認証は SMTP Auth か OAuth 2.0 の XOAUTH2）

送信の設定は画面（通知設定 → メールサーバー。管理者）で登録し、mail_server テーブルに保存する（models/mail.py）。
通知（services/notify.py）は、宛先ごとに 1 通ずつ送る（ほかの宛先を見せないため）。

OAuth 2.0 のトークン
  microsoft   : client credentials（https://login.microsoftonline.com/<テナント>/oauth2/v2.0/token）。
                スコープ https://outlook.office365.com/.default。Exchange 側でアプリにメールボックスの権限が要る
  google_sa   : サービスアカウントの鍵で署名した JWT を渡す（ドメイン全体の委任で username として振る舞う）
  google_user : 画面で一度 Google に同意して得た更新用トークンから取る（authorize_url / complete_authorization）
取ったトークンは有効期限の少し前まで、プロセスの中で使い回す。トークンを取る先は上の固定のホストだけ（任意の URL に送らない）
トークンの取得（HTTPS）は core/outbound.py を通す（OUTBOUND_PROXY・OUTBOUND_CA_FILE）。SMTP（smtplib）はプロキシを通さない

送信の結果は Redis に残し、画面「システム状態」の「メール送信」に出す（失敗はシステムの異常として通知する）
"""
import base64
import hashlib
import html
import json
import logging
import re
import secrets
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

import jwt
from redis.exceptions import RedisError

from app.core import outbound
from app.core.timeutil import utcnow

logger = logging.getLogger(__name__)

TIMEOUT_SEC = 20
MS_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MS_SCOPE = "https://outlook.office365.com/.default"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_SCOPE = "https://mail.google.com/"
# 個人の Gmail などの同意: Google の「デスクトップ アプリ」の OAuth クライアントで、戻り先を自分の PC（127.0.0.1）にする。
# サーバーのホスト名（社内のドメイン・IP）は Google の戻り先に登録できないため。同意のあとブラウザに表示される
# 「接続できません」のページのアドレスを画面に貼り付けてもらい、そこに含まれる認可コードをトークンに換える
GOOGLE_REDIRECT_URI = "http://127.0.0.1"
LAST_KEY = "netconfig:mail:last"  # 最後の送信の結果（JSON）
AUTHZ_KEY = "netconfig:mail:google_authz:{state}"  # 同意の途中の情報（10 分）
AUTHZ_TTL_SEC = 600

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")  # テナント ID（GUID）かドメイン名
MAX_RECIPIENTS = 10
AUTH_LABELS = {"none": "認証なし", "password": "SMTP Auth（パスワード）", "microsoft": "Microsoft 365（OAuth 2.0）",
               "google_sa": "Google（サービスアカウント）", "google_user": "Google（アカウントの同意）"}


class MailError(Exception):
    """利用者に見せるエラー（日本語。秘密の値は含めない）"""


@dataclass
class MailConfig:
    """送信に使う設定（DB から読み、復号した値）。スレッドへ渡すため ORM のオブジェクトとは分ける"""

    enabled: bool = False
    auth: str = "password"
    host: str = ""
    port: int = 587
    security: str = "starttls"
    verify_tls: bool = True
    username: str = ""
    password: str = ""
    from_address: str = ""
    from_name: str = ""
    subject_prefix: str = ""
    allowed_domains: list[str] = field(default_factory=list)
    ms_tenant_id: str = ""
    ms_client_id: str = ""
    ms_client_secret: str = ""
    google_sa_json: str = ""
    google_client_id: str = ""
    google_client_secret: str = ""
    google_refresh_token: str = ""

    @classmethod
    def from_row(cls, row) -> "MailConfig":
        if row is None:
            return cls()
        return cls(
            enabled=row.enabled, auth=row.auth, host=row.host or "", port=row.port or 587, security=row.security,
            verify_tls=row.verify_tls, username=row.username or "", password=row.password or "",
            from_address=row.from_address or "", from_name=row.from_name or "", subject_prefix=row.subject_prefix or "",
            allowed_domains=parse_domains(row.allowed_domains), ms_tenant_id=row.ms_tenant_id or "",
            ms_client_id=row.ms_client_id or "", ms_client_secret=row.ms_client_secret or "",
            google_sa_json=row.google_sa_json or "", google_client_id=row.google_client_id or "",
            google_client_secret=row.google_client_secret or "", google_refresh_token=row.google_refresh_token or "",
        )


async def load_config(db) -> MailConfig:
    from app.models.mail import MailServer  # 循環 import を避ける

    return MailConfig.from_row(await db.get(MailServer, "default"))


# ---------------------------------------------------------------- 宛先


def parse_domains(value: str | None) -> list[str]:
    return [d.strip().lower().lstrip("@") for d in re.split(r"[,\s]+", value or "") if d.strip()]


def parse_addresses(value: str | list[str] | None) -> list[str]:
    """カンマ・空白・改行区切りの宛先を、重複を除いた一覧にする（大文字小文字は区別しない）"""
    items = value if isinstance(value, list) else re.split(r"[,;\s]+", value or "")
    out: dict[str, str] = {}
    for a in items:
        a = a.strip()
        if a:
            out.setdefault(a.lower(), a)
    return list(out.values())


def check_address(addr: str, allowed_domains: list[str]) -> str | None:
    """宛先として使えなければ理由を返す"""
    if len(addr) > 254 or not EMAIL_RE.match(addr):
        return f"メールアドレスの形式が正しくありません: {addr}"
    domain = addr.rsplit("@", 1)[1].lower()
    if allowed_domains and not any(domain == d or domain.endswith("." + d) for d in allowed_domains):
        return f"{addr} には送れません（宛先に使えるドメイン: {', '.join(allowed_domains)}）"
    return None


# ---------------------------------------------------------------- OAuth 2.0 のトークン

_token_cache: dict[tuple, tuple[str, float]] = {}
_token_lock = threading.Lock()


def _urlopen(req: urllib.request.Request, timeout: float):
    """外向きの HTTPS（core/outbound.py。OUTBOUND_PROXY・OUTBOUND_CA_FILE を使う。テストで差し替える）"""
    return outbound.urlopen(req, timeout=timeout)


def _post_form(url: str, data: dict) -> dict:
    """トークンの取得（固定のホストだけ）。エラーの応答も JSON で読み、説明を返す"""
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "NetConfig-Manager"})
    try:
        with _urlopen(req, timeout=TIMEOUT_SEC) as r:  # 固定のホスト
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read() or b"{}")
        except ValueError:
            err = {}
        desc = (err.get("error_description") or err.get("error") or f"HTTP {e.code}").splitlines()[0][:300]
        raise MailError(f"トークンを取得できません（{desc}）") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # プロキシ・証明書・時間切れは分かる文に。そのほかも、プロキシの認証情報を伏せる。元の例外はつなげない
        # （ログの traceback にプロキシの応答などを残さない）
        raise MailError(f"トークンを取得できません（{outbound.describe(e)}）") from None
    except ValueError as e:
        raise MailError("トークンの応答を読めません") from e


def _google_sa_key(cfg: MailConfig) -> dict:
    try:
        key = json.loads(cfg.google_sa_json)
    except ValueError as e:
        raise MailError("サービスアカウントの鍵（JSON）を読めません") from e
    if not isinstance(key, dict) or not key.get("client_email") or not key.get("private_key"):
        raise MailError("サービスアカウントの鍵（JSON）に client_email・private_key がありません")
    return key


def fetch_token(cfg: MailConfig) -> tuple[str, int]:
    """（アクセストークン, 有効秒数）"""
    if cfg.auth == "microsoft":
        if not (cfg.ms_tenant_id and cfg.ms_client_id and cfg.ms_client_secret):
            raise MailError("Microsoft 365 のテナント ID・クライアント ID・クライアントシークレットを設定してください")
        if not TENANT_RE.match(cfg.ms_tenant_id):
            raise MailError("テナント ID の形式が正しくありません")
        r = _post_form(MS_TOKEN_URL.format(tenant=cfg.ms_tenant_id), {
            "grant_type": "client_credentials", "client_id": cfg.ms_client_id,
            "client_secret": cfg.ms_client_secret, "scope": MS_SCOPE})
    elif cfg.auth == "google_sa":
        key = _google_sa_key(cfg)
        now = int(time.time())
        assertion = jwt.encode({
            "iss": key["client_email"], "sub": cfg.username, "scope": GOOGLE_SCOPE,
            "aud": GOOGLE_TOKEN_URL, "iat": now, "exp": now + 3600,
        }, key["private_key"], algorithm="RS256")
        r = _post_form(GOOGLE_TOKEN_URL, {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
    elif cfg.auth == "google_user":
        if not (cfg.google_client_id and cfg.google_client_secret):
            raise MailError("Google の OAuth クライアント ID・シークレットを設定してください")
        if not cfg.google_refresh_token:
            raise MailError("Google アカウントの同意がまだです（メールサーバーの設定で「Google にサインイン」）")
        r = _post_form(GOOGLE_TOKEN_URL, {
            "grant_type": "refresh_token", "client_id": cfg.google_client_id,
            "client_secret": cfg.google_client_secret, "refresh_token": cfg.google_refresh_token})
    else:
        raise MailError("OAuth 2.0 の認証方式ではありません")
    token = r.get("access_token")
    if not token:
        raise MailError("トークンを取得できません（応答に access_token がありません）")
    return token, int(r.get("expires_in") or 3600)


def get_token(cfg: MailConfig) -> str:
    """有効期限の 2 分前までは、取ったトークンを使い回す"""
    secret = cfg.ms_client_secret or cfg.google_sa_json or cfg.google_refresh_token
    key = (cfg.auth, cfg.ms_tenant_id, cfg.ms_client_id, cfg.google_client_id, cfg.username,
           hashlib.sha256(secret.encode()).hexdigest())
    with _token_lock:
        hit = _token_cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]
    token, ttl = fetch_token(cfg)
    with _token_lock:
        _token_cache[key] = (token, time.time() + max(ttl - 120, 30))
    return token


def clear_token_cache() -> None:
    with _token_lock:
        _token_cache.clear()


# ---------------------------------------------------------------- メッセージ


def build_message(cfg: MailConfig, to: str, title: str, facts: list[tuple[str, str]] | None = None,
                  body: str | None = None, url: str | None = None, link_text: str | None = None) -> EmailMessage:
    """テキストと HTML の両方を入れたメール。件名・本文の値は改行などを取り除いてから入れる"""
    facts = facts or []
    subject = " ".join(f"{cfg.subject_prefix} {title}".split())[:200]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((cfg.from_name or "NetConfig Manager", cfg.from_address))
    msg["To"] = to
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=cfg.from_address.rsplit("@", 1)[-1] or None)
    msg["Auto-Submitted"] = "auto-generated"  # 自動送信（不在の自動応答などを返さないように）

    text = [title, ""]
    if body:
        text += [body, ""]
    text += [f"{k}: {v}" for k, v in facts]
    if url:
        text += ["", f"{link_text or '画面で確認'}: {url}"]
    text += ["", "-- ", "NetConfig Manager からの自動送信です。"]
    msg.set_content("\n".join(text))

    e = html.escape
    rows = "".join(
        f'<tr><th style="text-align:left;padding:4px 12px 4px 0;color:#555;white-space:nowrap;vertical-align:top">'
        f'{e(k)}</th><td style="padding:4px 0;white-space:pre-wrap">{e(v)}</td></tr>' for k, v in facts)
    parts = [f'<h2 style="font-size:16px;margin:0 0 12px">{e(title)}</h2>']
    if body:
        parts.append(f'<p style="white-space:pre-wrap;margin:0 0 12px">{e(body)}</p>')
    if rows:
        parts.append(f'<table style="border-collapse:collapse;font-size:14px">{rows}</table>')
    if url:
        parts.append(f'<p style="margin:16px 0 0"><a href="{e(url, quote=True)}">{e(link_text or "画面で確認")}</a></p>')
    parts.append('<p style="margin:24px 0 0;color:#888;font-size:12px">NetConfig Manager からの自動送信です。</p>')
    msg.add_alternative(
        '<!DOCTYPE html><html><body style="font-family:sans-serif;color:#222">' + "".join(parts) + "</body></html>",
        subtype="html")
    return msg


# ---------------------------------------------------------------- 送信


def check_config(cfg: MailConfig) -> str | None:
    """送信に必要な設定がそろっているか（そろっていなければ理由）"""
    if not cfg.enabled:
        return "メール送信が無効です（通知設定 → メールサーバー）"
    if not cfg.host:
        return "SMTP サーバーが設定されていません"
    if not cfg.from_address or not EMAIL_RE.match(cfg.from_address):
        return "送信元のメールアドレスが設定されていません"
    if cfg.auth == "password" and not (cfg.username and cfg.password):
        return "SMTP Auth のユーザー名・パスワードが設定されていません"
    if cfg.auth in ("microsoft", "google_sa", "google_user") and not cfg.username:
        return "送信に使うメールアドレス（ユーザー名）が設定されていません"
    if cfg.auth in ("microsoft", "google_sa", "google_user") and cfg.security == "none":
        return "OAuth 2.0 では暗号化（STARTTLS か SSL/TLS）が必要です"
    return None


def _tls_context(cfg: MailConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not cfg.verify_tls:  # 社内の自己署名の証明書など（画面で明示的に選んだときだけ）
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _smtp_error(e: Exception) -> str:
    if isinstance(e, smtplib.SMTPAuthenticationError):
        msg = (e.smtp_error or b"").decode(errors="replace").strip()
        hint = ""
        if "5.7.139" in msg or "basic authentication is disabled" in msg.lower():
            hint = "（Microsoft 365 でパスワードの SMTP 送信が無効です。OAuth 2.0 を使ってください）"
        elif "5.7.8" in msg or "Username and Password not accepted" in msg:
            hint = "（Google はアカウントのパスワードでは送れません。アプリパスワードか OAuth 2.0 を使ってください）"
        return f"認証に失敗しました（{e.smtp_code} {msg[:200]}）{hint}"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        (addr, (code, resp)), *_ = e.recipients.items()
        return f"宛先が受け付けられませんでした（{addr}: {code} {resp.decode(errors='replace')[:200]}）"
    if isinstance(e, smtplib.SMTPSenderRefused):
        return f"送信元が受け付けられませんでした（{e.smtp_code} {e.smtp_error.decode(errors='replace')[:200]}）"
    if isinstance(e, smtplib.SMTPNotSupportedError):
        return f"SMTP サーバーが対応していません（{e}）"
    if isinstance(e, smtplib.SMTPResponseException):
        return f"SMTP サーバーのエラー（{e.smtp_code} {e.smtp_error.decode(errors='replace')[:200]}）"
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"サーバーの証明書を確認できません（{e.verify_message}）"
    if isinstance(e, ssl.SSLError):
        return f"暗号化の接続に失敗しました（{e}。ポートと暗号化の方式の組み合わせを確認してください）"
    if isinstance(e, smtplib.SMTPServerDisconnected):
        return f"SMTP サーバーとの接続が切れました（{e}。ポートと暗号化の方式の組み合わせを確認してください）"
    if isinstance(e, (TimeoutError, OSError)):
        return f"SMTP サーバーに接続できません（{e}）"
    return f"送信できません（{e}）"


def send_message(cfg: MailConfig, msg: EmailMessage) -> None:
    """1 通送る。失敗は MailError（日本語の説明）"""
    if problem := check_config(cfg):
        raise MailError(problem)
    token = get_token(cfg) if cfg.auth in ("microsoft", "google_sa", "google_user") else None
    ctx = _tls_context(cfg)
    try:
        if cfg.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=TIMEOUT_SEC, context=ctx)
        else:
            smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=TIMEOUT_SEC)
        with smtp:
            smtp.ehlo()
            if cfg.security == "starttls":
                smtp.starttls(context=ctx)
                smtp.ehlo()
            if cfg.auth == "password":
                smtp.login(cfg.username, cfg.password)
            elif token:
                if not smtp.has_extn("auth") or "XOAUTH2" not in smtp.esmtp_features.get("auth", "").upper():
                    raise MailError("SMTP サーバーが OAuth 2.0（XOAUTH2）に対応していません")
                sasl = f"user={cfg.username}\x01auth=Bearer {token}\x01\x01"
                # 失敗するとサーバーは 334 で理由（JSON）を返し、空の応答を待つ。空を返して 535 を受け取る
                smtp.auth("XOAUTH2", lambda challenge=None: sasl if challenge is None else "")
            smtp.send_message(msg, from_addr=cfg.from_address)
    except MailError:
        raise
    except Exception as e:  # noqa: BLE001 - 種類ごとに日本語の説明にする
        if isinstance(e, smtplib.SMTPAuthenticationError) and token:
            clear_token_cache()  # 期限切れ・取り消しのトークンを次回は取り直す
        raise MailError(_smtp_error(e)) from e


def send_notification(cfg: MailConfig, to: str, payload: dict) -> str | None:
    """通知を 1 通送る（notify.py から。スレッドで実行）。成功なら None、失敗なら説明。結果の記録は呼び出し元（record_last）"""
    try:
        if err := check_address(to, cfg.allowed_domains):
            raise MailError(err)
        send_message(cfg, build_message(cfg, to, payload["title"], payload.get("facts"), payload.get("body"),
                                        payload.get("url"), payload.get("link_text")))
        return None
    except MailError as e:
        return str(e)


# ---------------------------------------------------------------- 結果の記録（システム状態）


async def record_last(errors: list[str | None]) -> None:
    """今回の送信（複数の宛先）の結果を残す。1 つでも失敗があれば失敗として残す"""
    from app.services import login_limit

    if not errors:
        return
    failed = [e for e in errors if e]
    data = {"at": utcnow().isoformat(), "ok": not failed, "error": failed[0] if failed else None,
            "sent": len(errors) - len(failed), "failed": len(failed)}
    try:
        await login_limit.client().set(LAST_KEY, json.dumps(data, ensure_ascii=False))
    except (RedisError, OSError):
        logger.debug("メール送信の結果を記録できませんでした", exc_info=True)


async def last_result() -> dict | None:
    from app.services import login_limit

    raw = await login_limit.client().get(LAST_KEY)
    return json.loads(raw) if raw else None


# ---------------------------------------------------------------- Google アカウントの同意（google_user）


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def authorize_url(cfg: MailConfig, user_id: str) -> str:
    """同意の画面の URL。state と PKCE の検証値は Redis に 10 分残し、同じ管理者の complete だけ受け付ける"""
    from app.services import login_limit

    if not cfg.google_client_id or not cfg.google_client_secret:
        raise MailError("先に Google の OAuth クライアント ID・シークレットを保存してください")
    state = secrets.token_urlsafe(24)
    verifier, challenge = _pkce()
    await login_limit.client().set(AUTHZ_KEY.format(state=state), json.dumps({"user": user_id, "verifier": verifier}),
                                   ex=AUTHZ_TTL_SEC)
    q = {"client_id": cfg.google_client_id, "redirect_uri": GOOGLE_REDIRECT_URI, "response_type": "code",
         "scope": GOOGLE_SCOPE, "access_type": "offline", "prompt": "consent", "state": state,
         "code_challenge": challenge, "code_challenge_method": "S256"}
    if cfg.username:
        q["login_hint"] = cfg.username
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(q)}"


async def complete_authorization(cfg: MailConfig, user_id: str, redirected: str) -> str:
    """同意のあとのアドレス（http://127.0.0.1/?state=…&code=…）から更新用トークンを得る"""
    import asyncio

    from app.services import login_limit

    q = urllib.parse.parse_qs(urllib.parse.urlsplit(redirected.strip()).query)
    if q.get("error"):
        raise MailError(f"同意されませんでした（{q['error'][0][:100]}）")
    state, code = (q.get("state") or [""])[0], (q.get("code") or [""])[0]
    if not state or not code:
        raise MailError("貼り付けたアドレスに認可コードがありません（ブラウザのアドレス欄をそのまま貼り付けてください）")
    r = login_limit.client()
    raw = await r.getdel(AUTHZ_KEY.format(state=state))
    pending = json.loads(raw) if raw else None
    if not pending or pending.get("user") != user_id:
        raise MailError("同意の有効期限（10 分）が切れたか、別の操作のアドレスです。もう一度「Google にサインイン」してください")
    res = await asyncio.to_thread(_post_form, GOOGLE_TOKEN_URL, {
        "grant_type": "authorization_code", "code": code, "redirect_uri": GOOGLE_REDIRECT_URI,
        "client_id": cfg.google_client_id, "client_secret": cfg.google_client_secret,
        "code_verifier": pending["verifier"]})
    token = res.get("refresh_token")
    if not token:
        raise MailError("更新用トークンを受け取れませんでした"
                        "（Google のアカウント設定でこのアプリの許可を外してからやり直してください）")
    if GOOGLE_SCOPE not in (res.get("scope") or GOOGLE_SCOPE).split():
        raise MailError("メールの送信が許可されませんでした（同意の画面ですべての項目にチェックしてください）")
    clear_token_cache()
    return token
