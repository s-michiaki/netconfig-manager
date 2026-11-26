"""外向き（インターネットへ）の HTTP(S) の共通部品: プロキシ・追加で信頼する CA・エラーの文・伏せ字

使う場所: 通知の Webhook（services/notify.py）、メールの OAuth 2.0 のトークンの取得（services/mail.py）、
脆弱性情報の取得（services/vuln_fetch.py。接続は自前で、プロキシと TLS の文脈だけここから取る）、
システム状態の「外部への接続」の確認（check_connectivity）。

設定は .env の 3 つだけ（core/config.py）。**環境変数の HTTP(S)_PROXY・NO_PROXY は見ない**（設定の出どころを 1 か所にする）。
- OUTBOUND_PROXY    : http://[ユーザー:パスワード@]ホスト:ポート。http:// のプロキシだけ（https://・socks は受け付けない）。
                      HTTPS の宛先へは CONNECT のトンネルで通し、認証は Basic の Proxy-Authorization（CONNECT にだけ付ける）。
                      ユーザー名・パスワードは URL デコードして使う
- OUTBOUND_NO_PROXY : プロキシを通さない宛先。localhost・ループバック・コンテナ名（INTERNAL_HOSTS）は常に直接
- OUTBOUND_CA_FILE  : 追加で信頼する CA（PEM）。ssl.create_default_context() の信頼に **足す** だけ（検証は弱めない）

平文（http://）の宛先: プロキシを通す宛先なら接続しない（外向きは HTTPS だけ。平文の宛先へのリクエストに
プロキシの認証情報を付けて送ることはしない）。プロキシを通さない宛先（NO_PROXY・内向き）なら直接つなぐ。

秘密の扱い: プロキシの URL・ユーザー名・パスワード（URL エンコードの前と後）・Proxy-Authorization の値は、
エラーの文・ログ・画面に出さない（scrub）。画面に出すのは「ホスト:ポート」と認証の有無だけ（display）。
プロキシまでの区間は暗号化されない（http:// のプロキシ）ので、認証情報（Basic）はその区間を平文で流れる（README に明記）。
"""
from __future__ import annotations

import base64
import functools
import http.client
import ipaddress
import logging
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# 追加で信頼する CA の置き場所（コンテナの中）。ホストの certs-outbound/ を読み取り専用でマウントする（compose）
CA_DIR = "/etc/netconfig/outbound"
# 常に直接つなぐ宛先（compose のサービス名と localhost）。NO_PROXY に書かなくてよい
INTERNAL_HOSTS = frozenset({"localhost", "db", "redis", "backend", "worker", "beat", "frontend"})
# システム状態の「接続を確かめる」の宛先（固定。利用者は URL を入れられない）。脆弱性情報の取得でも使うホスト。
# HEAD を送り、TLS のハンドシェイクのあと何かしらの HTTP の応答が返れば「成功」（宛先の 4xx・3xx も成功）
CHECK_URL = "https://endoflife.date/"
CHECK_TIMEOUT = 10  # 秒（接続と 1 回の読み取りの待ち）
CHECK_TOTAL = 15  # 秒（全体の期限。少しずつ返し続ける相手でも、ここで打ち切る）
CA_WARN_DAYS = 30

_CA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HOST_ENTRY = re.compile(r"^\.?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_MIN_SECRET = 3  # これより短い認証情報は伏せ字の対象にしない（1 文字を伏せると文が読めなくなるため。README に明記）


def _settings():
    from app.core.config import settings  # config の検査からも呼ぶので、遅く読む

    return settings


# ---------------------------------------------------------------- エラー


class ProxyError(OSError):
    """プロキシ・TLS まわりの失敗。文（str）は利用者に見せてよい日本語で、認証情報・プロキシの URL を含めない

    OSError の仲間にしてあるので、urllib の中で起きれば URLError(reason=ProxyError) に包まれる。kind で種類を見分ける:
    config（設定が不正）/ proxy_unreachable / proxy_auth（407）/ proxy_refused（ほかの HTTP の拒否）/ timeout /
    plain_http（平文の宛先をプロキシ経由で送ろうとした）
    """

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message

    def __str__(self) -> str:
        return self.message


MSG = {
    "proxy_unreachable": "プロキシに接続できません（OUTBOUND_PROXY のホスト・ポートと、プロキシまでの経路を確認してください）",
    "proxy_auth": "プロキシの認証に失敗しました（HTTP 407。OUTBOUND_PROXY のユーザー名・パスワードを確認してください）",
    "cert": "証明書を検証できません（HTTPS を検査するプロキシなら、組織の CA を OUTBOUND_CA_FILE に指定してください）",
    "cert_name": "証明書を検証できません（証明書の名前が宛先と一致しません）",
    "timeout": "時間切れ（相手が応答しません）",
    "proxy_timeout": "プロキシに接続できません（時間切れ。OUTBOUND_PROXY のホスト・ポートを確認してください）",
    "plain_http": "平文（http://）の宛先へはプロキシ経由で接続しません（外部へは https:// だけ）",
    "dns": "名前を解決できません（DNS か OUTBOUND_PROXY の設定を確認してください）",
}


# ---------------------------------------------------------------- プロキシの設定


@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    username: str = ""  # URL デコード済み
    password: str = ""
    raw_userinfo: tuple[str, str] = ("", "")  # URL エンコードのまま（伏せ字に使う）

    @property
    def auth(self) -> bool:
        return bool(self.username or self.password)

    @property
    def display(self) -> str:
        """画面・ログに出してよい形（ホスト:ポート）。認証情報は含めない"""
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}"

    def authorization(self) -> str:
        cred = f"{self.username}:{self.password}".encode()
        return "Basic " + base64.b64encode(cred).decode()

    def connect_headers(self) -> dict[str, str]:
        """CONNECT に付けるヘッダー（認証が要るときだけ Proxy-Authorization）"""
        return {"Proxy-Authorization": self.authorization()} if self.auth else {}

    def secrets(self) -> list[str]:
        """単独でも伏せる値: パスワード（デコード後・設定の表記・別のエンコード）と Basic の値"""
        out: set[str] = set()
        for v in (self.password, self.raw_userinfo[1]):
            out |= _encodings(v)
        if self.auth:
            token = self.authorization()
            out |= {token, token.split(" ", 1)[1]}
        return [s for s in out if s and len(s) >= _MIN_SECRET]

    def user_forms(self) -> list[str]:
        """ユーザー名の表記（デコード後・設定の表記・別のエンコード）。普通の語でありうるので、文脈つきでだけ伏せる"""
        out: set[str] = set()
        for v in (self.username, self.raw_userinfo[0]):
            out |= _encodings(v)
        return [s for s in out if s]


def _encodings(v: str) -> set[str]:
    """同じ値の別の表記（デコード・URL エンコード（記号すべて／既定）・%xx の大文字小文字）"""
    if not v:
        return set()
    dec = urllib.parse.unquote(v)
    forms = {v, dec, urllib.parse.quote(dec, safe=""), urllib.parse.quote(dec), urllib.parse.quote(dec, safe=":@")}
    out = set(forms)
    for f in forms:
        out.add(re.sub(r"%[0-9A-Fa-f]{2}", lambda m: m.group(0).lower(), f))
        out.add(re.sub(r"%[0-9A-Fa-f]{2}", lambda m: m.group(0).upper(), f))
    return out


def parse_proxy(value: str) -> Proxy | None:
    """OUTBOUND_PROXY を解析する。空なら None。不正なら ValueError（文に値・認証情報を入れない）"""
    value = (value or "").strip()
    if not value:
        return None
    if re.search(r"[\x00-\x20\x7f]", value):
        raise ValueError("OUTBOUND_PROXY に空白や制御文字は使えません（値は表示しません）")
    try:
        sp = urllib.parse.urlsplit(value)
        scheme = sp.scheme.lower()
        host = sp.hostname or ""
        port = sp.port
    except ValueError:
        raise ValueError("OUTBOUND_PROXY の形式が正しくありません"
                         "（例: http://proxy.example.test:3128。値は表示しません）") from None
    if scheme == "https":
        raise ValueError("OUTBOUND_PROXY は http:// で指定してください（https:// のプロキシには対応していません。"
                         "プロキシとの間は暗号化されませんが、宛先との通信は CONNECT のトンネルの中の TLS で保護されます）")
    if scheme != "http":
        raise ValueError("OUTBOUND_PROXY は http:// で始まるプロキシの URL で指定してください"
                         "（socks などには対応していません。例: http://proxy.example.test:3128。値は表示しません）")
    if not host or port == 0:
        raise ValueError("OUTBOUND_PROXY にホストとポートを指定してください（例: http://proxy.example.test:3128。値は表示しません）")
    if port is None:  # 既定の 80 とはみなさない（setup.sh 側の検査とそろえる）
        raise ValueError("OUTBOUND_PROXY にはポートを書いてください（例: http://proxy.example.test:3128）")
    if sp.path not in ("", "/") or sp.query or sp.fragment:
        raise ValueError("OUTBOUND_PROXY にはパスを付けないでください（例: http://proxy.example.test:3128。値は表示しません）")
    if sp.username is not None and sp.password is None:
        # ユーザー名だけだと、git などがパスワードを聞き返し、ほかの秘密（Git のトークンなど）を答えてしまうおそれがある
        raise ValueError("OUTBOUND_PROXY にユーザー名を書くときは、パスワードも書いてください"
                         "（空のパスワードなら ユーザー名:@ と書きます。値は表示しません）")
    raw_user = sp.username or ""
    raw_pw = sp.password or ""
    user = urllib.parse.unquote(raw_user)
    pw = urllib.parse.unquote(raw_pw)
    if ":" in user or re.search(r"[\x00-\x1f\x7f]", user + pw):
        raise ValueError("OUTBOUND_PROXY のユーザー名・パスワードに使えない文字があります（値は表示しません）")
    try:
        (user + ":" + pw).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("OUTBOUND_PROXY のユーザー名・パスワードを読めません（値は表示しません）") from None
    return Proxy(host=host.lower(), port=port, username=user, password=pw, raw_userinfo=(raw_user, raw_pw))


def current_proxy() -> Proxy | None:
    """いまの設定のプロキシ（実行中に不正な値へ差し替えられていても、認証情報を送らずに ProxyError）"""
    try:
        return parse_proxy(_settings().OUTBOUND_PROXY)
    except ValueError as e:
        raise ProxyError("config", str(e)) from None


# ---------------------------------------------------------------- NO_PROXY


@dataclass(frozen=True)
class NoProxy:
    all: bool
    hosts: frozenset[str]  # 完全一致・後方一致（先頭の . は外して持つ）
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def parse_no_proxy(value: str) -> NoProxy:
    """カンマ区切り（空白も区切りとみなす）。ホスト名・.ドメイン・IP・CIDR・*。不正な項目は ValueError"""
    hosts: set[str] = set()
    nets: list = []
    every = False
    for item in re.split(r"[,\s]+", (value or "").strip()):
        item = item.strip().lower()
        if not item:
            continue
        if item == "*":
            every = True
            continue
        bare = item[1:-1] if item.startswith("[") and item.endswith("]") else item
        try:
            nets.append(ipaddress.ip_network(bare, strict=False))
            continue
        except ValueError:
            pass
        name = item.rstrip(".")
        if name.startswith("*."):
            name = name[1:]
        if not _HOST_ENTRY.match(name):
            # NO_PROXY は秘密ではないが、長い値を丸ごと出さない
            raise ValueError(f"OUTBOUND_NO_PROXY の項目が正しくありません: {item[:60]}"
                             "（ホスト名・.ドメイン・IP・CIDR をカンマ区切りで書いてください）")
        hosts.add(name.lstrip("."))
    return NoProxy(every, frozenset(hosts), tuple(nets))


def _norm_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    return host.rstrip(".")


def is_internal(host: str) -> bool:
    """localhost・ループバック・コンテナ名（常に直接）"""
    h = _norm_host(host)
    if h in INTERNAL_HOSTS or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def bypass(host: str, rules: NoProxy | None = None) -> bool:
    """プロキシを通さない宛先か（内向き・OUTBOUND_NO_PROXY に当たる）"""
    h = _norm_host(host)
    if is_internal(h):
        return True
    if rules is None:
        try:
            rules = parse_no_proxy(_settings().OUTBOUND_NO_PROXY)
        except ValueError:
            rules = NoProxy(False, frozenset(), ())
    if rules.all:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        return any(ip.version == n.version and ip in n for n in rules.nets) or h in rules.hosts
    return any(h == d or h.endswith("." + d) for d in rules.hosts)


def use_proxy(host: str) -> bool:
    """この宛先へプロキシを通すか（プロキシを設定していて、NO_PROXY・内向きに当たらない）"""
    return current_proxy() is not None and not bypass(host)


def proxy_for(host: str) -> Proxy | None:
    """この宛先に使うプロキシ（通さないなら None）"""
    p = current_proxy()
    return None if p is None or bypass(host) else p


# ---------------------------------------------------------------- 追加で信頼する CA


def resolve_ca_path(value: str) -> str:
    """OUTBOUND_CA_FILE → コンテナの中のパス。名前だけなら CA_DIR の下、/ を含めばそのまま"""
    value = (value or "").strip()
    if "/" in value:
        return value
    if not _CA_NAME.match(value) or value in (".", ".."):
        raise ValueError("OUTBOUND_CA_FILE はファイルの名前（例: outbound-ca.pem）かコンテナの中の絶対パスで指定してください")
    return os.path.join(CA_DIR, value)


def load_ca_file(path: str) -> list:
    """PEM の証明書を読む（cryptography の x509.Certificate の一覧）。読めない・PEM でない・証明書が無ければ ValueError"""
    from cryptography import x509

    if path.startswith(CA_DIR + "/"):
        hint = f"（{path}。ホストの certs-outbound/ に置いたか、名前を確認してください）"
    else:
        hint = f"（{path}）"
    try:
        with open(path, "rb") as f:
            data = f.read(5 * 1024 * 1024 + 1)
    except OSError:
        raise ValueError(f"OUTBOUND_CA_FILE のファイルを読めません{hint}") from None
    if len(data) > 5 * 1024 * 1024:
        raise ValueError(f"OUTBOUND_CA_FILE のファイルが大きすぎます{hint}")
    if b"PRIVATE KEY-----" in data:
        raise ValueError(f"OUTBOUND_CA_FILE に秘密鍵が入っています。CA 証明書だけを置いてください{hint}")
    if b"-----BEGIN CERTIFICATE-----" not in data:
        raise ValueError(f"OUTBOUND_CA_FILE が PEM の証明書ではありません（-----BEGIN CERTIFICATE----- で始まる形式）{hint}")
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        raise ValueError(f"OUTBOUND_CA_FILE の証明書を読めません（PEM の形式を確認してください）{hint}") from None
    if not certs:
        raise ValueError(f"OUTBOUND_CA_FILE に証明書がありません{hint}")
    try:
        ssl.create_default_context().load_verify_locations(cafile=path)
    except (ssl.SSLError, OSError):
        raise ValueError(f"OUTBOUND_CA_FILE の証明書を TLS の信頼に追加できません{hint}") from None
    return certs


def ca_path() -> str | None:
    v = _settings().OUTBOUND_CA_FILE.strip()
    return resolve_ca_path(v) if v else None


_ctx_lock = threading.Lock()
_ctx_cache: dict[tuple, ssl.SSLContext] = {}


def tls_context() -> ssl.SSLContext:
    """外向きの TLS の文脈。OS の既定の信頼（ssl.create_default_context）に OUTBOUND_CA_FILE を **足す**

    証明書の検証（CERT_REQUIRED）とホスト名の確認は既定のまま（弱める設定は作らない）。ファイルが変われば読み直す
    """
    path = ca_path()
    key: tuple = (None,)
    if path:
        try:
            st = os.stat(path)
            key = (path, st.st_mtime_ns, st.st_size)
        except OSError:
            key = (path, None, None)
    with _ctx_lock:
        ctx = _ctx_cache.get(key)
        if ctx is not None:
            return ctx
    ctx = ssl.create_default_context()
    if path:
        try:
            ctx.load_verify_locations(cafile=path)
        except (ssl.SSLError, OSError):
            # 起動時に確かめているので、ここに来るのは実行中にファイルが消えた・壊れたとき。CA を足さずに続ける
            # （検証は弱めない。検査するプロキシなら証明書の検証の失敗として表に出る）
            logger.warning("OUTBOUND_CA_FILE を読めないため、追加の CA なしで接続します")
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:  # 念のため（既定の設定が変わっていないこと）
        raise ssl.SSLError("証明書の検証が無効な TLS の設定は使いません")
    with _ctx_lock:
        _ctx_cache.clear()
        _ctx_cache[key] = ctx
    return ctx


def ca_info(now: datetime | None = None) -> dict | None:
    """画面用: 追加の CA の件数・いちばん近い有効期限（設定していなければ None）"""
    path = ca_path()
    if not path:
        return None
    name = _settings().OUTBOUND_CA_FILE.strip()
    try:
        certs = load_ca_file(path)
    except ValueError as e:
        return {"file": name, "count": 0, "error": str(e)}
    now = now or datetime.now(UTC).replace(tzinfo=None)
    ends = sorted(c.not_valid_after_utc.replace(tzinfo=None) for c in certs)
    nearest = ends[0]
    return {"file": name, "count": len(certs), "nearest_expiry": nearest.isoformat(),
            "days_left": (nearest - now).days, "expired": nearest < now}


# ---------------------------------------------------------------- 伏せ字・エラーの文


def scrub(text: str) -> str:
    """プロキシの URL・ユーザー名・パスワード（エンコードの前と後）・Proxy-Authorization の値を伏せる"""
    if not text:
        return text
    text = str(text)
    try:
        p = parse_proxy(_settings().OUTBOUND_PROXY)
    except ValueError:
        p = None
    raw = (_settings().OUTBOUND_PROXY or "").strip()
    secrets = ([raw] if raw else []) + (p.secrets() if p else [])
    for sec in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(sec, "***")
    # ユーザー名は「user:」「user@」の形のときだけ伏せる（proxy のような普通の語の、ほかの箇所は残す）
    for u in sorted(set(p.user_forms() if p else []), key=len, reverse=True):
        text = re.sub(r"(?<![A-Za-z0-9._%-])" + re.escape(u) + r"(?=[:@])", "***", text)
    text = re.sub(r"(?i)(proxy-authorization\s*[:=]\s*)[^\r\n,;)]*", r"\1***", text)
    text = re.sub(r"(?i)\b(basic|bearer)\s+[A-Za-z0-9+/=._-]{6,}", r"\1 ***", text)
    return re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]*@", r"\1***@", text)  # scheme://user:pass@ の形


def classify(e: BaseException) -> tuple[str, str] | None:
    """よくある失敗の種類と、利用者に見せる文。分からなければ None（呼び出し側の文にする）"""
    reason = getattr(e, "reason", e) if isinstance(e, urllib.error.URLError) else e
    if isinstance(reason, ProxyError):
        return reason.kind, reason.message
    if isinstance(reason, ssl.SSLCertVerificationError):
        if getattr(reason, "verify_code", None) == 62 or "hostname mismatch" in str(reason).lower() \
                or "doesn't match" in str(reason):
            return "cert", MSG["cert_name"]
        return "cert", MSG["cert"]
    text = str(reason)
    if m := re.search(r"Tunnel connection failed: (\d{3})", text):
        code = int(m.group(1))
        if code == 407:
            return "proxy_auth", MSG["proxy_auth"]
        return "proxy_refused", _refused(code)
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text.lower():
        return "cert", MSG["cert"]
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout", MSG["timeout"]
    return None


def _refused(code: int) -> str:
    return f"プロキシが接続を断りました（HTTP {code}。宛先がプロキシで許可されているか確認してください）"


def describe(e: BaseException, fallback: str | None = None) -> str:
    """失敗の説明（伏せ字済み）。分類できなければ fallback か、例外の文を伏せたもの"""
    hit = classify(e)
    if hit:
        return hit[1]
    if fallback is not None:
        return fallback
    reason = getattr(e, "reason", e) if isinstance(e, urllib.error.URLError) else e
    return scrub(str(reason))[:300]


# ---------------------------------------------------------------- 接続（CONNECT のトンネル）


def open_tunnel(conn: http.client.HTTPConnection) -> None:
    """conn（host・port はプロキシ、_tunnel_host は宛先）でプロキシへつなぎ、CONNECT のトンネルを張る

    TCP の接続には conn._create_connection を使う（vuln_fetch の期限の見張りが差し替えている）。失敗は段階ごとに
    ProxyError にする（プロキシに届かない／認証に失敗（407）／ほかの拒否／時間切れ）。プロキシが返した行は文に入れない
    """
    try:
        conn.sock = conn._create_connection((conn.host, conn.port), conn.timeout, conn.source_address)
    except TimeoutError:
        raise ProxyError("proxy_unreachable", MSG["proxy_timeout"]) from None
    except OSError:
        raise ProxyError("proxy_unreachable", MSG["proxy_unreachable"]) from None
    try:
        conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        conn._tunnel()
    except TimeoutError:
        conn.close()
        raise ProxyError("timeout", "時間切れ（プロキシが CONNECT に応答しません）") from None
    except http.client.HTTPException:  # BadStatusLine・RemoteDisconnected・LineTooLong など
        conn.close()
        raise ProxyError("proxy_unreachable",
                         "プロキシに接続できません（プロキシの応答の形式が正しくないか、接続が切れました）") from None
    except OSError as e:
        conn.close()
        m = re.match(r"Tunnel connection failed: (\d{3})", str(e))
        if m and m.group(1) == "407":
            raise ProxyError("proxy_auth", MSG["proxy_auth"]) from None
        if m:
            raise ProxyError("proxy_refused", _refused(int(m.group(1)))) from None
        raise ProxyError("proxy_unreachable", "プロキシに接続できません（プロキシとの接続が切れました）") from None


class Deadline:
    """全体の期限の見張り。開いたソケットを覚えておき、期限が来たら別のスレッドから閉じる

    相手（プロキシ）が少しずつ返し続けると、1 回ごとの読み取りの待ちは毎回間に合って終わらない。そこで全体の期限で、
    ソケットごと閉じて読み取りを止める（vuln_fetch._Guard と同じ考え。接続の確認で使う）
    """

    def __init__(self, seconds: float):
        self.fired = False
        self._socks: list = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(seconds, self.fire)
        self._timer.daemon = True

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, *a):
        self._timer.cancel()

    def add(self, sock):
        with self._lock:
            self._socks.append(sock)
            fired = self.fired
        if fired:
            self._kill(sock)
        return sock

    def fire(self) -> None:
        with self._lock:
            self.fired = True
            socks = list(self._socks)
        for s in socks:
            self._kill(s)

    @staticmethod
    def _kill(sock) -> None:
        for fn in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
            try:
                fn()
            except OSError:
                pass


class _HTTPSConnection(http.client.HTTPSConnection):
    """宛先が https。プロキシがあれば、プロキシへつないで CONNECT（宛先のホスト名で TLS を検証する）"""

    def __init__(self, host, *args, proxy: Proxy | None = None, deadline: Deadline | None = None, **kwargs):
        self._ncm_proxy = proxy
        self._ncm_deadline = deadline
        if proxy is None:
            super().__init__(host, *args, **kwargs)
        else:
            super().__init__(proxy.host, proxy.port, *args, **kwargs)
            dest_host, dest_port = self._get_hostport(host, 443)
            self.set_tunnel(dest_host, dest_port, proxy.connect_headers())
        if deadline is not None:
            create = self._create_connection
            self._create_connection = lambda *a, **kw: deadline.add(create(*a, **kw))

    def connect(self):
        if self._ncm_deadline is None and self._ncm_proxy is None:
            return super().connect()
        if self._ncm_proxy is None:
            http.client.HTTPConnection.connect(self)
        else:
            open_tunnel(self)
        # server_hostname は本来の宛先（プロキシのホスト名ではない）。検証の設定は tls_context() のまま。
        # 期限の見張りがあるときは、包んだソケットを先に登録してからハンドシェイクする（途中で止まる相手でも打ち切れる）
        sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host,
                                         do_handshake_on_connect=False)
        self.sock = sock
        if self._ncm_deadline is not None:
            self._ncm_deadline.add(sock)
        sock.do_handshake()


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, *args, deadline: Deadline | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ncm_deadline = deadline

    def https_open(self, req):
        p = proxy_for(urllib.parse.urlsplit(req.full_url).hostname or req.host)
        return self.do_open(functools.partial(_HTTPSConnection, proxy=p, deadline=self._ncm_deadline), req,
                            context=self._context)


class _HTTPHandler(urllib.request.HTTPHandler):
    """平文の宛先: プロキシを通す宛先なら接続しない。通さない宛先（内向き・NO_PROXY）なら直接"""

    def http_open(self, req):
        if use_proxy(urllib.parse.urlsplit(req.full_url).hostname or req.host):
            raise urllib.error.URLError(ProxyError("plain_http", MSG["plain_http"]))
        return self.do_open(http.client.HTTPConnection, req)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクトをたどらない（3xx は HTTPError として呼び出し側へ）"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(*, redirect: bool | urllib.request.HTTPRedirectHandler = True, handlers=(),
                 deadline: Deadline | None = None) -> urllib.request.OpenerDirector:
    """外向きの opener。環境変数のプロキシは使わない（ProxyHandler({})）。プロキシと CA は .env の設定から

    redirect: True=たどる（urllib の既定）/ False=たどらない / HTTPRedirectHandler のインスタンス=それを使う
    """
    hs: list = [urllib.request.ProxyHandler({}), _HTTPHandler(), _HTTPSHandler(context=tls_context(), deadline=deadline)]
    if redirect is False:
        hs.append(NoRedirect())
    elif isinstance(redirect, urllib.request.BaseHandler):
        hs.append(redirect)
    hs.extend(handlers)
    return urllib.request.build_opener(*hs)


def urlopen(req: urllib.request.Request | str, timeout: float, *, redirect: bool | urllib.request.HTTPRedirectHandler = True):
    """urllib.request.urlopen の代わり（外向き）"""
    return build_opener(redirect=redirect).open(req, timeout=timeout)


# ---------------------------------------------------------------- 画面・起動時のログ


def summary() -> dict:
    """設定の要約（画面用。認証情報は含めない）"""
    try:
        p = current_proxy()
        proxy_error = None
    except ProxyError as e:
        p, proxy_error = None, e.message
    try:
        rules = parse_no_proxy(_settings().OUTBOUND_NO_PROXY)
        no_proxy = sorted(rules.hosts) + [str(n) for n in rules.nets] + (["*"] if rules.all else [])
    except ValueError:
        no_proxy = []
    return {"proxy": p.display if p else None, "proxy_auth": bool(p and p.auth), "proxy_error": proxy_error,
            "no_proxy": no_proxy, "check_url": CHECK_URL}


def startup_log(log: logging.Logger | None = None) -> None:
    """起動時に 1〜2 行（ホスト:ポートと認証の有無・CA の件数だけ）。廃止した VULN_HTTPS_PROXY が残っていれば知らせる"""
    log = log or logger
    s = summary()
    ca = None
    try:
        ca = ca_info()
    except ValueError:
        ca = None
    proxy = f"プロキシ {s['proxy']}（認証{'あり' if s['proxy_auth'] else 'なし'}）" if s["proxy"] else "プロキシなし（直接）"
    extra = f"・追加の CA {ca['count']} 件" if ca else ""
    log.info("外部への接続: %s%s", proxy, extra)
    if _vuln_proxy_left():
        log.warning("VULN_HTTPS_PROXY は廃止しました（無視します）。プロキシは OUTBOUND_PROXY に設定してください")


def _vuln_proxy_left() -> bool:
    if os.environ.get("VULN_HTTPS_PROXY", "").strip():
        return True
    try:
        from dotenv import dotenv_values

        env_file = _settings().model_config.get("env_file") or ".env"
        return bool((dotenv_values(env_file).get("VULN_HTTPS_PROXY") or "").strip())
    except Exception:  # noqa: BLE001 - 確かめられなくても起動は止めない
        return False


# ---------------------------------------------------------------- 接続を確かめる（システム状態）


RESULT_LABELS = {
    "ok": "成功", "proxy_unreachable": "プロキシに接続できません", "proxy_auth": "プロキシの認証に失敗しました",
    "cert": "証明書を検証できません", "timeout": "時間切れ", "proxy_refused": "プロキシが接続を断りました",
    "config": "設定が正しくありません", "error": "接続できません",
}


def check_connectivity() -> dict:
    """CHECK_URL へ HEAD を送る（固定の宛先だけ）。結果: {result, label, message, via, elapsed_ms}。秘密は含めない"""
    host = urllib.parse.urlsplit(CHECK_URL).hostname or ""
    t0 = time.monotonic()
    try:
        via = "proxy" if use_proxy(host) else "direct"
    except ProxyError as e:
        return {"result": "config", "label": RESULT_LABELS["config"], "message": e.message, "via": "-", "elapsed_ms": 0}
    req = urllib.request.Request(CHECK_URL, method="HEAD", headers={"User-Agent": "NetConfig-Manager"})
    result, message, status = "ok", None, None
    deadline = Deadline(CHECK_TOTAL)
    try:
        with deadline, build_opener(redirect=False, deadline=deadline).open(req, timeout=CHECK_TIMEOUT) as r:
            status = getattr(r, "status", None)
    except urllib.error.HTTPError as e:  # 宛先まで届いて、HTTP の応答が返った（3xx・4xx・5xx）
        status = e.code
        e.close()
    except (urllib.error.URLError, OSError, ssl.SSLError, ValueError, http.client.HTTPException) as e:
        hit = ("timeout", f"時間切れ（{CHECK_TOTAL:g} 秒以内に終わりませんでした）") if deadline.fired else classify(e)
        reason = getattr(e, "reason", e) if isinstance(e, urllib.error.URLError) else e
        if hit:
            result, message = hit
        elif isinstance(reason, socket.gaierror):
            result, message = "error", MSG["dns"]
        else:
            result, message = "error", f"接続できません（{type(reason).__name__}）"
        if result not in RESULT_LABELS:
            result = "error"
    elapsed = int((time.monotonic() - t0) * 1000)
    if result == "ok":
        message = f"{host} に接続できました（HTTP {status}）"
    return {"result": result, "label": RESULT_LABELS[result], "message": scrub(message or ""), "via": via,
            "elapsed_ms": elapsed, "target": host}
