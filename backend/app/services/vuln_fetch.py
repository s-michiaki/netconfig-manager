"""脆弱性・サポート終了日の外部からの取得（HTTP の枠組みと、各情報源の応答の解析）

外部へつなぐのはこのファイルだけ。次を守る（新しい種類の通信なので、制限を厳しくしている）。
- 宛先は固定のホストの一覧（ALLOWED_HOSTS）だけ。https のみ。リダイレクトも同じ一覧の中だけたどる（外れたら失敗）
- 接続の待ちは 10 秒、全体で 60 秒（ヘッダーの受信を含む。期限でソケットを閉じて打ち切る）。
  応答は 50MB で打ち切る（超えたら失敗。Fortinet の RSS・CSAF は 1 件 5MB）。応答は JSON と XML（Fortinet の RSS・CVRF）だけで、
  どちらも標準ライブラリで解析する。XML は DTD（<!DOCTYPE・<!ENTITY）を含む入力を読む前に拒否し、要素の数・深さ・文字数に上限
- 条件つき GET（If-None-Match / If-Modified-Since）と 304（変更なし）は Fortinet で使う。Fortinet への要求は 2 秒以上あける
- **機器名・IP・OS バージョンを URL・ヘッダーに入れない**。取得は製品単位（PAN-OS の勧告すべて、など）で行い、
  どの機器が該当するかの照合はサーバーの中（services/vuln_match.py）で行う。ここの関数は機器の情報を引数に取らない
- 失敗の説明（FetchError）には URL・クエリ・プロキシの認証情報・相手の応答の本文を入れない（種類と HTTP のコードだけ）
- プロキシと TLS の文脈は core/outbound.py から取る（OUTBOUND_PROXY・OUTBOUND_NO_PROXY・OUTBOUND_CA_FILE。
  環境変数のプロキシは使わない）。プロキシとの間は平文で、宛先との TLS は CONNECT のトンネルの中で張る
  （証明書とホスト名の検証は ssl.create_default_context のまま弱めない。追加の CA は信頼に「足す」だけ）
- TLS のハンドシェイクも全体の期限の見張り（_Guard）の中で行う（ハンドシェイクの途中で止まる相手でも打ち切れる）
- 外から来た文字列（題・URL）は、長さを切り詰め、URL は https で許可リストのホストのものだけ残す

テストでは _open（urlopen 相当）を差し替える。実際の通信は、有効にしたときの worker だけが行う
"""
import email.utils
import functools
import http.client
import json
import re
import socket
import ssl
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from app.core import outbound
from app.services import vuln_match as vm

ALLOWED_HOSTS = frozenset({
    "security.paloaltonetworks.com",  # Palo Alto の勧告（J-1）
    "www.cisa.gov",  # 悪用確認済み（KEV）（J-1）
    "endoflife.date",  # サポート終了日（J-1）
    "services.nvd.nist.gov",  # NVD（J-2）
    "www.fortiguard.com",  # Fortinet の勧告（J-2）
    "filestore.fortinet.com",  # Fortinet の勧告（J-2）
})
CONNECT_TIMEOUT = 10  # 秒（接続と、1 回の読み取りの待ち）
TOTAL_TIMEOUT = 60  # 秒（1 回の取得の全体）
MAX_BYTES = 50 * 1024 * 1024  # 応答の大きさの上限
MAX_REDIRECTS = 3
CHUNK = 64 * 1024

# 製品単位の取得先（機器の情報を含まない固定の URL）
URL_PALOALTO = "https://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories"
URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_EOL = "https://endoflife.date/api/v1/products/{product}"
# endoflife.date の製品名 → このアプリの platform
EOL_PRODUCTS = {"panos": "paloalto_panos", "fortios": "fortinet", "cisco-ios-xe": "cisco_xe"}
PALOALTO_URL_BASE = "https://security.paloaltonetworks.com/"

TITLE_MAX = 300
MAX_RANGES = 200
MAX_FIXES = 40
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}\Z", re.A)
_PAN_SA = re.compile(r"^PAN-SA-\d{4}-\d{4,}\Z", re.A)
_BRANCH = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.\-]{0,31}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class FetchError(Exception):
    """取得・解析の失敗。文言はそのまま last_error に保存して画面に出す（秘密を含めない）。code は HTTP のコード（分かれば）"""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


_ua: str | None = None


def user_agent() -> str:
    """netconfig-manager/<バージョン>。バージョンは main.py の 1 か所から読む（読めなければ名前だけ）"""
    global _ua
    if _ua is None:
        try:
            from app.main import app  # 遅く読む（worker から呼ぶとき・循環を避ける）

            _ua = f"netconfig-manager/{app.version}"
        except Exception:  # noqa: BLE001
            return "netconfig-manager"
    return _ua


# ---------------------------------------------------------------- 宛先の検査


def check_url(url: str) -> None:
    """許可する宛先か（https・許可リストのホスト・既定のポート・認証情報なし）。外れたら FetchError"""
    sp = urllib.parse.urlsplit(url)
    if sp.scheme != "https":
        raise FetchError("https 以外の宛先へは接続しません")
    if sp.username or sp.password:
        raise FetchError("認証情報つきの宛先へは接続しません")
    try:
        port = sp.port
    except ValueError:
        raise FetchError("宛先の形式が正しくありません") from None
    if port not in (None, 443):
        raise FetchError("許可されていないポートです")
    if (sp.hostname or "").lower() not in ALLOWED_HOSTS:
        raise FetchError("許可リストにない宛先です")


def safe_url(url) -> str | None:
    """保存してよい出典の URL（https・許可リストのホスト・512 文字まで）。それ以外は None"""
    if not isinstance(url, str) or len(url) > 512 or _CTRL.search(url) or " " in url:
        return None
    try:
        check_url(url)
    except FetchError:
        return None
    return url


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクトは、許可リストの中のホストへだけたどる（外れたら FetchError で失敗）"""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------- 全体の期限（ソケットを閉じる見張り）


class _Guard:
    """1 回の取得で開いたソケットを覚えておき、全体の期限が来たら閉じる（読み取り中の recv を止める）

    相手がヘッダーや本文を少しずつ返すと、1 回ごとの待ち（CONNECT_TIMEOUT）は毎回間に合って、終わらない。
    そこで、全体の期限は別のスレッドから、ソケットごと閉じて打ち切る
    """

    def __init__(self) -> None:
        self.fired = False
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()

    def add(self, sock) -> None:
        with self._lock:
            self._socks.append(sock)
            fired = self.fired
        if fired:
            self._kill(sock)

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


_tl = threading.local()  # 取得を行うスレッドの _Guard（_open が接続にひもづける）


class _GuardedMixin:
    """接続のソケットを _Guard に登録する（TCP 接続・プロキシ経由のトンネル・TLS のあとのソケット）"""

    _guard: _Guard | None = None

    def _setup_guard(self, guard: _Guard | None) -> None:
        self._guard = guard
        if guard is not None:
            self._create_connection = self._guarded_create

    def _guarded_create(self, address, timeout=socket.getdefaulttimeout(), source_address=None):
        sock = socket.create_connection(address, timeout, source_address)
        self._guard.add(sock)
        return sock

    def connect(self):
        super().connect()
        if self._guard is not None:
            self._guard.add(self.sock)  # TLS で包んだあとのソケット


class _GuardedHTTP(_GuardedMixin, http.client.HTTPConnection):
    def __init__(self, *args, guard=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_guard(guard)


class _GuardedHTTPS(_GuardedMixin, http.client.HTTPSConnection):
    """https。プロキシ（outbound.proxy_for）があれば、そこへ CONNECT して通す（環境変数のプロキシ・NO_PROXY は見ない）"""

    def __init__(self, host, *args, guard=None, proxy: outbound.Proxy | None = None, **kwargs):
        if proxy is not None:
            super().__init__(proxy.host, proxy.port, *args, **kwargs)
            hostname, port = self._get_hostport(host, 443)
            self.set_tunnel(hostname, port, proxy.connect_headers())
        else:
            super().__init__(host, *args, **kwargs)
        self._setup_guard(guard)

    def connect(self):
        """HTTPSConnection.connect と同じ手順で、ハンドシェイクだけを見張りへの登録のあとに行う

        wrap_socket の既定（do_handshake_on_connect=True）では、包む前の TCP のソケットは detach され、見張りが閉じても
        ハンドシェイクの読み取りは止まらない。そこで包んだソケットを先に見張りに登録してから、ハンドシェイクする。
        証明書とホスト名の検証は、渡された context（outbound.tls_context）と本来の宛先（server_hostname）のまま
        """
        if self._tunnel_host:
            outbound.open_tunnel(self)  # プロキシへの TCP の接続（見張りに登録済み）と CONNECT。失敗は種類の分かる ProxyError
        else:
            http.client.HTTPConnection.connect(self)  # TCP の接続（見張りに登録済み）
        server_hostname = self._tunnel_host or self.host
        sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname, do_handshake_on_connect=False)
        self.sock = sock
        if self._guard is not None:
            self._guard.add(sock)  # 期限が過ぎていれば、ここで閉じる（下のハンドシェイクはすぐ失敗する）
        sock.do_handshake()


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(functools.partial(_GuardedHTTP, guard=getattr(_tl, "guard", None)), req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        proxy = outbound.proxy_for(urllib.parse.urlsplit(req.full_url).hostname or req.host)
        factory = functools.partial(_GuardedHTTPS, guard=getattr(_tl, "guard", None), proxy=proxy)
        kwargs = {"context": self._context} if getattr(self, "_context", None) is not None else {}
        return self.do_open(factory, req, **kwargs)


def _tls_context() -> ssl.SSLContext:
    """宛先との TLS の設定（outbound.tls_context: 既定の検証＋OUTBOUND_CA_FILE を足したもの。弱めない）"""
    return outbound.tls_context()


def _open(req: urllib.request.Request, timeout: float):
    """urlopen 相当（テストで差し替える）。プロキシは OUTBOUND_PROXY だけ（環境変数のものは使わない）"""
    handlers = [urllib.request.ProxyHandler({}), _GuardedHTTPHandler(), _GuardedHTTPSHandler(context=_tls_context()),
                _AllowlistRedirect()]
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def _describe(e: BaseException) -> str:
    """接続の失敗の説明。例外の文言（URL・プロキシの認証情報・相手が返した行が入りうる）は使わず、種類だけにする"""
    reason = getattr(e, "reason", e)
    if hit := outbound.classify(e):  # プロキシに届かない・407・ほかの拒否・証明書・時間切れ（文は秘密を含まない）
        return hit[1]
    if isinstance(reason, ssl.SSLError):
        return "TLS の接続に失敗しました"
    if isinstance(reason, socket.gaierror):
        return "名前を解決できません（DNS・プロキシの設定を確認してください）"
    if isinstance(reason, ConnectionRefusedError):
        return "接続を拒否されました"
    if isinstance(reason, http.client.HTTPException):
        return f"相手の応答の形式が正しくありません（{type(reason).__name__}）"
    return f"接続できません（{type(reason).__name__}）"


def _timeout_error() -> FetchError:
    return FetchError(f"時間切れ（{TOTAL_TIMEOUT:g} 秒以内に受け取れませんでした）")


@dataclass
class Fetched:
    """条件つき GET の結果。status は 200 か 304（変更なし。本文は空）。etag・last_modified は次回の条件（検査済みの形だけ）"""

    status: int
    body: bytes
    etag: str | None = None
    last_modified: str | None = None


_ETAG = re.compile(r'^(?:W/)?"[\x21\x23-\x7e]{1,200}"$')
_LAST_MODIFIED = re.compile(r"^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$")


def _validator(headers, name: str, pattern: re.Pattern) -> str | None:
    """応答の ETag・Last-Modified（形を確かめたものだけ。次の要求のヘッダーにそのまま入れるので、改行などを入れない）"""
    try:
        v = headers.get(name) if headers is not None else None
    except Exception:  # noqa: BLE001
        return None
    return v if isinstance(v, str) and pattern.match(v) else None


def _fetch_inner(url: str, deadline: float, accept: str = "application/json", max_bytes: int | None = None,
                 etag: str | None = None, last_modified: str | None = None) -> Fetched:
    """接続して本文を読む（取得を行うスレッドで動く）。失敗は FetchError

    etag・last_modified を渡したときだけ条件つき GET にし、304 を「変更なし」として返す（それ以外の 3xx は失敗）
    """
    max_bytes = MAX_BYTES if max_bytes is None else min(max_bytes, MAX_BYTES)
    headers = {"User-Agent": user_agent(), "Accept": accept, "Accept-Encoding": "identity"}
    conditional = False
    if etag and _ETAG.match(etag):
        headers["If-None-Match"] = etag
        conditional = True
    if last_modified and _LAST_MODIFIED.match(last_modified):
        headers["If-Modified-Since"] = last_modified
        conditional = True
    limit_label = f"{max_bytes // (1024 * 1024)}MB" if max_bytes >= 1024 * 1024 else f"{max_bytes} バイト"
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        resp = _open(req, CONNECT_TIMEOUT)
    except FetchError:
        raise
    except urllib.error.HTTPError as e:
        e.close()
        if e.code == 304 and conditional:
            return Fetched(304, b"", _validator(e.headers, "ETag", _ETAG) or etag,
                           _validator(e.headers, "Last-Modified", _LAST_MODIFIED) or last_modified)
        if e.code == 429:
            raise FetchError("相手の回数制限に達しました（HTTP 429）。時間をおいて再試行します", 429) from None
        if 300 <= e.code < 400:
            raise FetchError(f"リダイレクトの先を確認できません（HTTP {e.code}）", e.code) from None
        raise FetchError(f"HTTP {e.code}", e.code) from None
    except (urllib.error.URLError, OSError, ssl.SSLError, ValueError, http.client.HTTPException) as e:
        raise FetchError(_describe(e)) from None
    with closing(resp):
        final = getattr(resp, "geturl", lambda: url)()
        check_url(final)  # たどった先も許可リストの中であること
        try:
            declared = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError, AttributeError):
            declared = 0
        if declared > max_bytes:
            raise FetchError(f"応答が大きすぎます（上限 {limit_label}）")
        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                if time.monotonic() > deadline:
                    raise _timeout_error()
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"応答が大きすぎます（上限 {limit_label}）")
                chunks.append(chunk)
        except FetchError:
            raise
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as e:  # TimeoutError・IncompleteRead など
            raise FetchError(_describe(e)) from None
        if declared and total < declared:  # read(n) は途中で切れても例外にしないため、宣言の大きさと比べる
            raise FetchError("相手の応答の形式が正しくありません（途中で切れました）")
        hdrs = getattr(resp, "headers", None)
        return Fetched(200, b"".join(chunks), _validator(hdrs, "ETag", _ETAG),
                       _validator(hdrs, "Last-Modified", _LAST_MODIFIED))


def fetch_bytes(url: str) -> bytes:
    """URL の応答の本文（上限まで）。失敗は FetchError

    ヘッダーの受信を含めて、全体で TOTAL_TIMEOUT 秒を超えない。取得は別のスレッドで行い、期限が来たら
    開いているソケットを閉じて打ち切る（相手が少しずつ返し続けても、ここで必ず終わる）
    """
    return fetch(url).body


def fetch(url: str, *, accept: str = "application/json", max_bytes: int | None = None, etag: str | None = None,
          last_modified: str | None = None) -> Fetched:
    """fetch_bytes の本体（条件つき GET・受け付ける形式・大きさの上限を指定できる）"""
    check_url(url)
    guard = _Guard()
    box: dict[str, Any] = {}
    deadline = time.monotonic() + TOTAL_TIMEOUT

    def work() -> None:
        _tl.guard = guard
        try:
            box["body"] = _fetch_inner(url, deadline, accept, max_bytes, etag, last_modified)
        except BaseException as e:  # noqa: BLE001 - 呼び出し元のスレッドへ渡す
            box["error"] = e

    th = threading.Thread(target=work, name="vuln-fetch", daemon=True)
    th.start()
    th.join(TOTAL_TIMEOUT)
    if th.is_alive() or guard.fired:
        guard.fire()
        th.join(2)
        raise _timeout_error()
    guard.fire()  # 念のため閉じる（読み終えたあとの残り）
    if "error" in box:
        raise box["error"]
    return box["body"]


def fetch_json(url: str) -> Any:
    body = fetch_bytes(url)
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):  # UnicodeDecodeError は ValueError の仲間
        raise FetchError("応答を JSON として読めません（形式が変わった可能性があります）") from None


# ---------------------------------------------------------------- 解析（共通）


def _text(value, limit: int) -> str:
    """外から来た文字列。制御文字を除き、長さを切り詰める"""
    if not isinstance(value, str):
        return ""
    return _CTRL.sub(" ", value).strip()[:limit]


def _dt(value) -> datetime | None:
    """ISO 8601（"2026-11-11T17:00:00.000Z" など）→ UTC の日時（タイムゾーンなし）"""
    if not isinstance(value, str) or not value:
        return None
    try:
        d = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


def _date(value) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def severity_of(score: float | None) -> str:
    if score is None:
        return "none"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


# ---------------------------------------------------------------- Palo Alto
#
# 本物の応答（2026-11 に確認）の affected[] の行の形。どれも versionType は "custom"
#   (a) version "10.2.0", lessThan "10.2.18-h14", changes [10.2.18-h14, 10.2.16-h13, …]（lessThan が修正点の最大）
#   (b) version "12.1.0", lessThan "12.1.4-h7", changes [12.1.4-h7, 12.1.7]（lessThan が修正点の最小）
#   (c) version "10.2.0" だけ（lessThan も changes も無い。勧告の表では「10.2: All」＝修正版の無い系列）
#   (d) version "12.1.0", changes だけ（lessThan なし）/ version が "12.2"（.0 なし）/ version が "12.1.5"（途中から影響）
#   (e) status "unaffected", version "11.1.0" だけ（表では「11.1: None / All」＝その系列は影響なし）
#   (f) 製品名が "PAN-OS 11.1" で version "All", status "unaffected"（その系列すべてが影響なし）
#   (g) status "unknown", version ""（判定できない）
#   (h) platforms ["Panorama"]（Panorama だけ）/ defaultStatus "affected"（記載のない系列も影響あり）
#   (i) 2024 年 10 月ごろより前の古い形: 表の言葉をそのまま version に入れる
#       {"version": "9.0 All", "status": "unaffected"}（9.0 はすべて影響なし）/ "9.1 All" affected と "9.1 None" unaffected の組
#       （9.1 はすべて影響あり。"None" は「この列に当てはまる版は無い」で、判定には使わない）
#   (j) platforms がハードウェアの機種（["PA-3200", "PA-5200", "PA-7000"]）と、先頭に空白のある version " All"


def _version_text(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def _wild(v: str) -> str:
    """"10.2.14*" のようなワイルドカードの記号を除く"""
    return v.rstrip("*.x ").rstrip(".") if v.endswith(("*", ".x")) else v


def _full(v: str) -> str:
    """"10.2" → "10.2.0"（系列だけの書き方を最初の版に直す）"""
    v = _wild(v)
    return v + ".0" if re.fullmatch(r"\d+\.\d+", v) else v


_WILD_END = re.compile(r"^(\d+)\.(\d+)\.\*$")
_PRODUCT = re.compile(r"^pan-os(?:\s+(\d+)\.(\d+))?$", re.I)  # "PAN-OS" と、系列つきの "PAN-OS 11.1"
_ALL_WORDS = ("all", "*", "any")
# x.y を系列として読むのは、版の全体が「x.y」「x.y.z」「x.y.z-hN」「x.y.x」「x.y.*」「x.y*」「x.y All」「x.y None」のときだけ。
# それ以外（"10.1 and earlier"・"10.2 and later"・"10.2.0 - 10.2.5"・"10.2abc" など）は系列なし（どの系列にも関わりうる）
_BRANCH_OF = re.compile(r"^(\d+)\.(\d+)(?:\.\d+(?:-h\d+)?|\.x|\.\*|\*|\s+(?:all|none))?$", re.I)
_OLD_ALL_NONE = re.compile(r"^(\d+)\.(\d+)\s+(all|none)$", re.I)  # 古い形の "9.0 All" / "9.1 None"


def _pv(v: str) -> vm.Parsed | None:
    return vm.parse_scheme("panos", v)


def _is_panos(v: str) -> bool:
    return _pv(v) is not None


def _after_all(text: str) -> tuple[bool, str | None]:
    """上限のワイルドカード。("*" / "all" / "10.2.*") → (True, 系列。"*" は None＝系列を決められない)。違えば (False, None)"""
    t = text.strip().lower()
    if t in ("*", "all", "any"):
        return True, None
    m = _WILD_END.match(t)
    return (True, f"{int(m[1])}.{int(m[2])}") if m else (False, None)


def _src_of(v, product: str, default_status, platforms: list[str] | None) -> dict:
    """行の元の値（判定の理由をあとから追うため。文字列は切り詰める）"""
    def t(x):
        return _text(x, 40) if isinstance(x, str) else None

    src = {"product": t(product), "defaultStatus": t(default_status), "platforms": platforms or None}
    if isinstance(v, dict):
        src.update({"version": t(v.get("version")), "lessThan": t(v.get("lessThan")),
                    "lessThanOrEqual": t(v.get("lessThanOrEqual")), "status": t(v.get("status")),
                    "versionType": t(v.get("versionType"))})
        ch = v.get("changes")
        if isinstance(ch, list):
            src["changes"] = [{"at": t(c.get("at")), "status": t(c.get("status"))} if isinstance(c, dict) else {}
                              for c in ch[:MAX_FIXES + 10]]
    return {k: x for k, x in src.items() if x is not None}


def ranges_from_versions(versions, platforms: list[str] | None = None, *, product: str = "PAN-OS",
                         product_branch: str | None = None, default_status=None, entry: int | None = None,
                         platforms_bad: bool = False) -> list[dict]:
    """CVE 5.0 形式の affected[] の 1 製品（PAN-OS）を、影響範囲の一覧に直す。形は services/vuln_match.py の先頭を参照

    - 行（versions[]）ごとに 1 件。status が affected・unaffected 以外（unknown など）の行・読めない行は捨てずに
      {"unreadable": true, "branch": 系列（分かれば）} として持つ（該当・非該当のどちらにもせず「判定できない」に数える）
    - version だけの行（上限も修正点も無い）は、その系列の version 以上すべて（open）
    - lessThan と changes（status が unaffected の at）は、どちらも修正点として fixes に持つ（昇順。並びは信用しない）
    - defaultStatus が unaffected・無し以外なら、{"kind": "default"} を 1 件足す（記載のない系列の扱い）
    - platforms（Panorama など）は、付いていれば各項目に持つ（判定には全件を使う）。形が違う platforms は
      "platforms_bad" の印を付ける（platforms なしとは扱わない）。元の値は "src" に残す
    - entry は、勧告の affected[] の何番目の製品行か（defaultStatus は同じ製品行に載っている系列だけで判断するため）
    """
    out: list[dict] = []
    rows = versions if isinstance(versions, list) else []
    if versions is not None and not isinstance(versions, list):
        out.append(_unread(product_branch, "", "行の一覧（versions）の形が想定と違います"))
    for v in rows[:MAX_RANGES]:
        item = _range_one(v, product_branch) if isinstance(v, dict) else _unread(product_branch, "", "行の形が想定と違います")
        item["src"] = _src_of(v, product, default_status, platforms)
        out.append(item)
    if len(rows) > MAX_RANGES:
        out.append(_unread(product_branch, "", "行が多すぎます（読み切れません）"))
    if default_status not in (None, "unaffected"):
        ds = default_status if default_status == "affected" else "unknown"
        if product_branch:  # 系列つきの製品の既定の扱い（未確認の形）は、その系列を判定できないにする
            why = f"系列つきの製品の既定の状態（defaultStatus: {_text(str(default_status), 20)}）"
            out.append(_unread(product_branch, "", why))
        else:
            out.append({"kind": "default", "default": ds, "raw": f"記載のない系列（defaultStatus: {ds}）",
                        "src": _src_of(None, product, default_status, platforms)})
    for item in out:
        if platforms:
            item["platforms"] = platforms
        if platforms_bad:
            item["platforms_bad"] = True
        if entry is not None:
            item["entry"] = entry
    return out


def _unread(branch: str | None, start: str, why: str, status=None) -> dict:
    item = {"unreadable": True, "branch": branch, "raw": _text(f"{start or '（版なし）'}: {why}", 120)}
    if isinstance(status, str):
        item["status"] = _text(status, 20)
    return item


def _range_one(v: dict, product_branch: str | None) -> dict:
    status = v.get("status")
    start = _version_text(v.get("version"))
    lt, le = _version_text(v.get("lessThan")), _version_text(v.get("lessThanOrEqual"))
    changes = v.get("changes")
    has_changes = isinstance(changes, list) and len(changes) > 0
    branch = product_branch  # 系列つきの製品（"PAN-OS 11.1"）の行は、その系列のもの
    if (m := _BRANCH_OF.match(start)) and start.lower() not in _ALL_WORDS:
        branch = f"{int(m[1])}.{int(m[2])}"
    elif start and start.lower() not in _ALL_WORDS:
        branch = None  # 系列の形で始まらない・語句つき: どの系列にも関わりうる

    def bad(why: str) -> dict:
        return _unread(branch, start, why, status)

    def bad_all(why: str) -> dict:  # 系列をまたぐ・系列を決められない行: 全系列で判定できない
        return _unread(None, start, why, status)

    if status not in ("affected", "unaffected"):
        return bad("影響の有無（status）が affected・unaffected のどちらでもありません")
    if v.get("versionType") not in (None, "", "custom"):
        return bad("版の種類（versionType）が想定と違います")
    if changes is not None and not isinstance(changes, list):
        return bad("修正点（changes）の形が想定と違います")
    if product_branch and branch != product_branch:
        return bad_all("製品名の系列と版の系列が違います")
    if m := _OLD_ALL_NONE.match(start):  # 古い形（表の言葉）
        if lt or le or has_changes:
            return bad("「x.y All / None」の行に上限・修正点が付いています")
        if m[3].lower() == "none":  # この列に当てはまる版が無い: 判定に使わない
            return {"status": status, "none": True, "branch": branch, "raw": _text(f"{branch} None（判定に使わない）", 80)}
        label = "すべて影響あり" if status == "affected" else "すべて影響なし"
        return {"status": status, "all": True, "branch": branch, "raw": _text(f"{branch} {label}", 80)}
    if start.lower() in _ALL_WORDS:
        if lt or le or has_changes:
            return bad("「すべて」の行に上限・修正点が付いています")
        label = "すべて" if status == "affected" else "すべて影響なし"
        return {"status": status, "all": True, "branch": product_branch,
                "raw": f"{product_branch} の{label}" if product_branch else label}
    lo = _full(start)
    if not start or not _is_panos(lo):
        return bad("版を読み取れません")
    item: dict = {"status": status, "branch": branch, "ge": lo}
    if status == "unaffected":
        if lt or le or has_changes:
            return bad("影響なしの行に上限・修正点が付いています（この形は扱いません）")
        item.update(open=True, raw=_text(f"{lo} 以上は影響なし", 80))
        return item
    fixes: list[str] = []
    for c in changes or []:
        if not isinstance(c, dict):
            return bad("修正点（changes）の形が想定と違います")
        at, cs = _version_text(c.get("at")), c.get("status")
        if cs == "affected":
            return bad("修正のあとにまた影響ありになる記述があります")
        if cs != "unaffected":
            return bad("修正点の状態を読み取れません")
        if not _is_panos(at):
            return bad("修正点の版を読み取れません")
        fixes.append(at)
    if any(_pv(f).branch != branch for f in fixes):
        return bad_all("修正点が別の系列にあります（系列をまたぐ行）")
    if lt and le:
        return bad("lessThan と lessThanOrEqual が両方あります")
    if le:
        if fixes:
            return bad("lessThanOrEqual と修正点が一緒にあります（この形は扱いません）")
        wild, wbranch = _after_all(le)
        hi = _pv(le)
        if wild and wbranch == branch:
            item["open"] = True  # "10.2.*": その系列の version 以上すべて
        elif wild or (hi is not None and hi.branch != branch):
            return bad_all("上限（lessThanOrEqual）が別の系列・系列を決められない形です")
        elif hi is not None and hi.key >= _pv(lo).key:
            item["le"] = le
        else:
            return bad("上限（lessThanOrEqual）を読み取れません")
    elif lt:
        wild, wbranch = _after_all(lt)
        if wild and wbranch != branch:  # "*"（その系列だけか全体か決められない）・別の系列の "x.y.*"
            return bad_all("上限（lessThan）が系列を決められない形・別の系列です")
        if wild:
            if fixes:
                return bad("上限なし（x.y.*）と修正点が一緒にあります")
            item["open"] = True
        elif _is_panos(lt):
            # 本物では lessThan は常に changes の中にある。changes に無く、changes の最大より小さい lessThan は
            # 意味を決められない（その版から上が影響なしなのか）ので読まない
            if fixes and lt not in fixes and _pv(lt).key < max(_pv(f).key for f in fixes):
                return bad("lessThan が修正点（changes）に無く、修正点の最大より前にあります")
            if lt not in fixes:
                item["lt_only"] = [lt]  # changes に無い lessThan（「この版より前が影響あり」だけ。既定より優先しない）
            fixes.append(lt)  # lessThan も修正点の 1 つ（最小のことも最大のこともある）
        else:
            return bad("上限（lessThan）を読み取れません")
    if fixes:
        lo_key = _pv(lo).key
        parsed = {f: _pv(f) for f in fixes}
        uniq = sorted(set(fixes), key=lambda f: parsed[f].key)
        if any(parsed[f].branch != branch for f in uniq):
            return bad_all("修正点・上限が別の系列にあります（系列をまたぐ行）")
        if any(parsed[f].key <= lo_key for f in uniq):
            return bad("修正点が範囲の始まり以前にあります")
        maint = [parsed[f].key[:3] for f in uniq]
        if len(set(maint)) != len(maint):
            return bad("同じ保守版に修正点が 2 つあります")
        if len(uniq) > MAX_FIXES:
            return bad("修正点が多すぎます（読み切れません）")
        item["fixes"] = uniq
        item["raw"] = _text(f"{lo} 以上・修正 {', '.join(uniq)}", 160)
    elif item.get("le"):
        item["raw"] = _text(f"{lo} 〜 {le}", 80)
    else:
        item["open"] = True  # 上限も修正点も無い: その系列の version 以上すべて（修正版が無い）
        item["raw"] = _text(f"{lo} 以上すべて（修正版なし）", 80)
    return item


_OTHER_PRODUCTS = ("prisma access", "cloud ngfw", "prisma sd-wan")
_PANOS_WORDS = ("pan-os", "pa-series", "vm-series", "firewall", "panorama")


def _scenario_text(mt: dict) -> str:
    sc = mt.get("scenarios")
    parts: list[str] = []
    for x in sc if isinstance(sc, list) else []:
        parts.append(x.get("value", "") if isinstance(x, dict) else x)
    return " ".join(p for p in parts if isinstance(p, str)).lower()


def _cvss_of(metrics) -> tuple[float | None, str]:
    """metrics[] の CVSS（cvssV4_0 / cvssV3_1 / cvssV3_0 …）の基本スコアと重大度

    Palo Alto は製品ごと（PA-Series・Prisma Access など）の場面（scenarios）別に複数の点を持つ。
    PAN-OS に結び付く点を採る: 場面の文に Prisma Access・Cloud NGFW だけが出てくる点は除き、残りのうち最も高い点。
    区別できなければ（除いたら 1 つも残らないとき）、勧告の全部の点のうち最も高い点（代表の点）
    """
    scored: list[tuple[float, bool]] = []  # (点, PAN-OS に結び付くか)
    if isinstance(metrics, list):
        for mt in metrics:
            if not isinstance(mt, dict):
                continue
            text = _scenario_text(mt)
            other = any(w in text for w in _OTHER_PRODUCTS) and not any(w in text for w in _PANOS_WORDS)
            for k, val in mt.items():
                if k.startswith("cvssV") and isinstance(val, dict):
                    sc = val.get("baseScore")
                    if isinstance(sc, (int, float)) and not isinstance(sc, bool) and 0 <= sc <= 10:
                        scored.append((float(sc), not other))
    pool = [s for s, ok in scored if ok] or [s for s, _ in scored]
    best = max(pool) if pool else None
    return best, severity_of(best)


def parse_paloalto(data, rejected: list[str] | None = None, broken: list[dict] | None = None,
                   emptied: list[str] | None = None) -> list[dict]:
    """Palo Alto の /api/v1/products/PAN-OS/advisories（{"success": true, "data": [CVE 5.0 の記録…]}）を勧告の一覧に直す

    PAN-OS に影響範囲（affected）のある勧告だけを返す。1 件が壊れていてもほかは読む。読めなかった勧告も消さずに数える:
    - rejected: 取り下げ（state が REJECTED）の勧告の ID
    - broken: 記録として読めなかった勧告（{"ext_id": ID（分からなければ None）, "reason": 理由}）。保存済みの勧告なら、
      古い範囲のまま判定を続けず「範囲を読み取れない」状態に上書きする（vuln_service）
    - emptied: 公開中で読めたが、PAN-OS に影響ありになりうる行が無い勧告の ID（保存済みなら範囲を空に上書きする）
    """
    if not isinstance(data, dict) or not isinstance(data.get("data"), list) or not data["data"]:
        raise FetchError("Palo Alto の応答の形が想定と違います（形式が変わった可能性があります）")
    out: list[dict] = []
    for rec in data["data"]:
        try:
            adv = _paloalto_one(rec, rejected, broken, emptied)
        except (AttributeError, TypeError, KeyError, ValueError) as e:
            if broken is not None:
                broken.append({"ext_id": _record_id(rec), "reason": f"記録を読み取れません（{type(e).__name__}）"})
            continue
        if adv:
            out.append(adv)
    if not out:
        raise FetchError("Palo Alto の応答から PAN-OS の勧告を読み取れませんでした（形式が変わった可能性があります）")
    return out


def _record_id(rec) -> str | None:
    """記録の勧告の ID（CVE-… / PAN-SA-… の形のときだけ）"""
    meta = rec.get("cveMetadata") if isinstance(rec, dict) else None
    ext_id = meta.get("cveId") if isinstance(meta, dict) else None
    return ext_id if isinstance(ext_id, str) and (_CVE.match(ext_id) or _PAN_SA.match(ext_id)) else None


MAX_PLATFORMS = 100


def _platforms_of(raw) -> tuple[list[str] | None, bool]:
    """affected[].platforms → (判定に使う全件, 形が違うか)。無い・空の配列は (None, False)（機種の絞り込みなし）

    文字列・配列でない・中身が文字列でない・空の文字列・多すぎる、は「形が違う」（platforms なしとは扱わず、候補にする）
    """
    if raw is None or raw == []:
        return None, False
    if not isinstance(raw, list) or len(raw) > MAX_PLATFORMS:
        return [_text(str(raw), 40) or "?"], True
    plats = [_text(x, 40) if isinstance(x, str) else "" for x in raw]
    if any(not t for t in plats):
        return [t or "?" for t in plats], True
    return plats, False


def _paloalto_one(rec, rejected: list[str] | None = None, broken: list[dict] | None = None,
                  emptied: list[str] | None = None) -> dict | None:
    ext_id = _record_id(rec)

    def broke(reason: str) -> None:
        if broken is not None:
            broken.append({"ext_id": ext_id, "reason": reason})

    if ext_id is None:
        return broke("勧告の ID を読み取れません")
    meta = rec["cveMetadata"]
    state = meta.get("state")
    if state == "REJECTED":  # 取り下げ: 保存済みなら、その勧告の照合結果を解消する（vuln_service）
        if rejected is not None:
            rejected.append(ext_id)
        return None
    if state not in (None, "PUBLISHED"):
        return broke("勧告の状態（state）が想定と違います")
    cna = rec.get("containers", {}).get("cna") if isinstance(rec.get("containers"), dict) else None
    if not isinstance(cna, dict):
        return broke("記録に containers.cna がありません")
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return broke("影響範囲（affected）が配列ではありません")
    ranges: list[dict] = []
    for i, a in enumerate(affected):
        product = a.get("product") if isinstance(a, dict) else None
        name = product.strip() if isinstance(product, str) else ""
        if not isinstance(a, dict):
            ranges.append({**_unread(None, "", "製品行の形が想定と違います"), "entry": i})
            continue
        if not (m := _PRODUCT.match(name)):
            if "pan-os" in name.lower():  # "PAN-OS®"・"PAN-OS 11.1.x"・"PAN-OS (Panorama)" など: 捨てずに全系列で判定できない
                ranges.append({**_unread(None, "", "製品名の形が想定と違います"), "entry": i,
                               "src": _src_of(None, name, a.get("defaultStatus"), None)})
            continue  # Prisma Access・Cloud NGFW など、PAN-OS 以外の製品は見ない
        plats, plats_bad = _platforms_of(a.get("platforms"))
        ranges += ranges_from_versions(a.get("versions"), plats, product=str(a.get("product")).strip(),
                                       product_branch=f"{int(m[1])}.{int(m[2])}" if m[1] else None,
                                       default_status=a.get("defaultStatus"), entry=i, platforms_bad=plats_bad)
    if len(ranges) > MAX_RANGES:
        ranges = [*ranges[:MAX_RANGES - 1], _unread(None, "", "行が多すぎます（読み切れません）")]
    # 該当・候補・判定できないになりうる行（affected・読めない行・既定・"x.y None" の影響なし）が 1 つも無い勧告は
    # 保存しない（根拠: 影響なしの行だけの勧告は、どの版も該当にならない）
    if not any(r.get("status") == "affected" or r.get("unreadable") or r.get("kind") == "default"
               or (r.get("none") and r.get("status") == "unaffected") for r in ranges):
        if emptied is not None:
            emptied.append(ext_id)  # 保存済みなら範囲を空に上書きする（改訂で影響なしだけになった）
        return None
    score, severity = _cvss_of(cna.get("metrics"))
    times = [t for t in [_dt(cna.get("datePublic")), _dt(meta.get("dateUpdated"))]
             + [_dt(x.get("time")) for x in cna.get("timeline") or [] if isinstance(x, dict)] if t]
    url = None
    for ref in cna.get("references") or []:
        if isinstance(ref, dict) and (u := safe_url(ref.get("url"))):
            url = u
            break
    return {
        "source": "paloalto", "ext_id": ext_id, "cve_ids": [ext_id] if _CVE.match(ext_id) else [],
        "title": _text(cna.get("title"), TITLE_MAX) or ext_id, "severity": severity, "cvss": score,
        "published_at": _dt(cna.get("datePublic")) or (min(times) if times else None),
        "modified_at": max(times) if times else None,
        # 勧告の公式の画面（ID から組み立てる）。参照の中に許可リストのホストの URL があればそれを使う
        "url": url or PALOALTO_URL_BASE + ext_id,
        "products": ["paloalto_panos"], "affected": ranges,
        "unreadable": sum(1 for r in ranges if r.get("unreadable")),  # 保存はしない（取得の記録の数え上げ用）
    }


# ---------------------------------------------------------------- CISA KEV


def parse_kev(data) -> dict[str, str]:
    """CISA の known_exploited_vulnerabilities.json → {CVE ID: 対応の期限（YYYY-MM-DD。なければ空）}"""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise FetchError("CISA の応答の形が想定と違います（形式が変わった可能性があります）")
    out: dict[str, str] = {}
    for v in data["vulnerabilities"]:
        if not isinstance(v, dict) or not isinstance(v.get("cveID"), str) or not _CVE.match(v["cveID"]):
            continue
        d = _date(v.get("dueDate"))
        out[v["cveID"]] = d.isoformat() if d else ""
    if not out:
        raise FetchError("CISA の応答に悪用確認済みの脆弱性が 1 件もありませんでした（形式が変わった可能性があります）")
    return out


# ---------------------------------------------------------------- endoflife.date


def parse_eol(product: str, data) -> list[dict]:
    """endoflife.date の /api/v1/products/{名前}（{"result": {"releases": [{"name": "10.2", "eolFrom": "2025-08-27"…}]}}）

    リリース系列ごとのサポート終了日。eolFrom が無い（まだ決まっていない）系列は含めない
    """
    releases = data.get("result", {}).get("releases") if isinstance(data, dict) and isinstance(data.get("result"), dict) else None
    if not isinstance(releases, list) or not releases:
        raise FetchError(f"endoflife.date（{product}）の応答の形が想定と違います（形式が変わった可能性があります）")
    out = []
    for r in releases:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) or not _BRANCH.match(r["name"]):
            continue
        d = _date(r.get("eolFrom"))
        if d:
            out.append({"platform": EOL_PRODUCTS[product], "branch": r["name"], "eol_date": d,
                        "url": f"https://endoflife.date/{product}"})
    if not out:
        raise FetchError(f"endoflife.date（{product}）の応答からサポート終了日を読み取れませんでした")
    return out


# ---------------------------------------------------------------- XML（Fortinet の RSS・CVRF）

MAX_XML_BYTES = 5 * 1024 * 1024  # XML の応答の上限（RSS は約 51KB、CVRF は約 40KB）
MAX_XML_ELEMENTS = 20_000
MAX_XML_DEPTH = 32
MAX_XML_TEXT = 4 * 1024 * 1024  # 要素の文字の合計
_XML_DECL_ENC = re.compile(r"""^\s*<\?xml[^>]*?\bencoding\s*=\s*["']([A-Za-z0-9._\-]+)["']""")
_XML_DTD = re.compile(r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)", re.I)


def parse_xml(body: bytes) -> ET.Element:
    """XML を標準ライブラリで読む（失敗は FetchError）

    - DTD（<!DOCTYPE・<!ENTITY など）を含む入力は、読む前に拒否する（実体の展開・外部実体を一切させない。defusedxml は使わない）
    - UTF-8 だけ（宣言が別の文字コードなら拒否。UTF-16 などで DTD の検査をすり抜けさせない）
    - 要素の数・深さ・文字の合計に上限
    """
    if len(body) > MAX_XML_BYTES:
        raise FetchError("XML の応答が大きすぎます（上限 5MB）")
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise FetchError("XML を UTF-8 として読めません（形式が変わった可能性があります）") from None
    if (m := _XML_DECL_ENC.match(text)) and m[1].lower().replace("_", "-") not in ("utf-8", "utf8"):
        raise FetchError("XML の文字コードが UTF-8 ではありません（読みません）")
    if _XML_DTD.search(text):
        raise FetchError("DTD（<!DOCTYPE・<!ENTITY）を含む XML は読みません")
    parser = ET.XMLPullParser(events=("start", "end"))
    root: ET.Element | None = None
    depth = count = chars = 0
    raw = text.encode("utf-8")
    try:
        for i in range(0, len(raw), CHUNK):
            parser.feed(raw[i:i + CHUNK])
            for ev, el in parser.read_events():
                if ev == "start":
                    depth += 1
                    count += 1
                    if root is None:
                        root = el
                    if depth > MAX_XML_DEPTH or count > MAX_XML_ELEMENTS:
                        raise FetchError("XML の要素が深すぎる・多すぎます（読みません）")
                else:
                    depth -= 1
                    chars += len(el.text or "") + len(el.tail or "")
                    if chars > MAX_XML_TEXT:
                        raise FetchError("XML の文字が多すぎます（読みません）")
        parser.close()
        for _ev, _el in parser.read_events():
            pass
    except ET.ParseError:
        raise FetchError("応答を XML として読めません（形式が変わった可能性があります）") from None
    if root is None:
        raise FetchError("応答を XML として読めません（形式が変わった可能性があります）")
    return root


# ---------------------------------------------------------------- 要求の間隔


_sleep = time.sleep  # テストで差し替える


class Pacer:
    """同じ相手への要求の間隔を interval 秒以上あける（Fortinet は robots.txt の Crawl-delay: 2 に合わせて 2 秒）"""

    def __init__(self, interval: float):
        self.interval = interval
        self._last: float | None = None

    def wait(self) -> None:
        if self._last is not None:
            rest = self.interval - (time.monotonic() - self._last)
            if rest > 0:
                _sleep(rest)
        self._last = time.monotonic()


# ---------------------------------------------------------------- Fortinet（FortiOS）
#
# 情報源（2026-11 に本物で確認。research の記録は README の「情報源」）
#   RSS  https://filestore.fortinet.com/fortiguard/rss/ir.xml   最新 50 件。<link>（…/psirt/FG-IR-26-279）と、
#        <csaf:link>（https://filestore.fortinet.com/fortiguard/psirt/csaf_<題名のスラッグ>_fg-ir-26-279.json）。ETag あり
#   CSAF 上の csaf:link。1 件 1〜22KB。ETag あり（304 を返す）
#   CVRF https://www.fortiguard.com/psirt/cvrf/<ID>（ID だけで引ける XML。過去の勧告の取り込みで、題名を得るためだけに使う。
#        存在しない ID も 200 で、題名が空の文書を返す）
#   CSAF のファイル名は題名から作る: 小文字にして、英数字以外の並びを "-" 1 つにし、前後の "-" を除く
#   （RSS の 50 件中 49 件で一致。1 件は題名が後から変わって不一致）。
#   勧告のページ（HTML）は取得しない。出典のリンクだけ ID から組み立てる
#
# CSAF の vulnerabilities[]（CVE × 製品ごとに 1 件）の product_status の FortiOS の文字列（本物の形。空白・スラッシュ・
# ハイフンの有無で意味が変わる）:
#   known_affected     "FortiOS >=7.4.0|<=7.4.2"  範囲（両端を含む）          "FortiOS 7.6.0"  単独の版
#                      "FortiOS 7.0 all versions"  その系列すべて（修正版なし）
#   known_not_affected "FortiOS-7.4.3"  修正版（以上は影響なし）            "FortiOS/ 8.0 all versions"  その系列は影響なし
#                      "FortiOS-upcoming  7.2.14"  修正版が未公開（空白 2 つ）
#   別の製品: "FortiOS-6K7K …"（FortiGate 6000 / 7000 系）・FortiProxy など。"FortiOS" で始まるかだけで見分けない
#   上のどれでもない FortiOS の文字列・ほかのキー（fixed など）にある FortiOS の文字列は「読めない行」（判定できない）

URL_FORTINET_RSS = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
URL_FORTINET_CVRF = "https://www.fortiguard.com/psirt/cvrf/{ext_id}"
URL_FORTINET_CSAF = "https://filestore.fortinet.com/fortiguard/psirt/csaf_{slug}_{lower_id}.json"
FORTINET_PAGE = "https://www.fortiguard.com/psirt/{ext_id}"
FORTINET_INTERVAL_SEC = 2.0
FORTINET_MAX_BYTES = 5 * 1024 * 1024
_FG_IR = re.compile(r"^FG-IR-\d{2}-\d{3,4}\Z", re.A)
_CSAF_PATH = re.compile(r"^/fortiguard/psirt/csaf_[a-z0-9]+(?:-[a-z0-9]+)*_(fg-ir-\d{2}-\d{3,4})\.json\Z", re.A)
_NS_CSAF = "{https://fortiguard.fortinet.com/rss/ns/csaf}"
_NS_CVRF = "{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf}"
ACCEPT_XML = "application/rss+xml, application/xml, text/xml"


def valid_fortinet_id(text) -> bool:
    return isinstance(text, str) and bool(_FG_IR.match(text))


def fortinet_page_url(ext_id: str) -> str:
    """出典（勧告のページ）の URL。ID から組み立てる（取得はしない）"""
    return FORTINET_PAGE.format(ext_id=ext_id)


def fortinet_csaf_url(url, ext_id: str) -> str | None:
    """CSAF の URL として使ってよいか（https・filestore.fortinet.com・決まったパスの形・パスの ID が ext_id）。よければその URL"""
    u = safe_url(url)
    if u is None or not valid_fortinet_id(ext_id):
        return None
    sp = urllib.parse.urlsplit(u)
    if sp.hostname != "filestore.fortinet.com" or sp.query or sp.fragment or sp.port is not None:
        return None
    m = _CSAF_PATH.match(sp.path)
    return u if m and m[1] == ext_id.lower() else None


def csaf_url_from_title(ext_id: str, title: str) -> str | None:
    """題名から CSAF の URL を組み立てる（過去の勧告の取り込み用。規則は上の節）"""
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") if isinstance(title, str) else ""
    if not slug or len(slug) > 200 or not valid_fortinet_id(ext_id):
        return None
    return fortinet_csaf_url(URL_FORTINET_CSAF.format(slug=slug, lower_id=ext_id.lower()), ext_id)


FORTINET_PAGE_MAX_BYTES = 1024 * 1024  # 勧告のページ（HTML。本物は約 100KB）
ACCEPT_HTML = "text/html"
_PAGE_CSAF = re.compile(r"csaf_url=([^\s\"'<>&]{1,600})", re.A)


def csaf_url_from_page(body: bytes, ext_id: str) -> str | None:
    """勧告のページ（HTML）に書かれた CSAF の URL（"…/psirt/csaf/FG-IR-…?csaf_url=https://filestore…json" の形。本物で確認）

    HTML は解析せず、正規表現で csaf_url= の値を拾うだけ。拾った値は URL のデコードのあと fortinet_csaf_url の検査
    （https・filestore.fortinet.com・決まったパスの形・パスの ID が ext_id）に通し、通ったものが 1 つに決まるときだけ使う
    """
    if len(body) > FORTINET_PAGE_MAX_BYTES:
        return None
    text = body.decode("utf-8", errors="replace")
    found = {u for raw in _PAGE_CSAF.findall(text) if (u := fortinet_csaf_url(urllib.parse.unquote(raw), ext_id))}
    return found.pop() if len(found) == 1 else None


def _rss_date(text) -> datetime | None:
    try:
        d = email.utils.parsedate_to_datetime(text.strip()) if isinstance(text, str) else None
    except (TypeError, ValueError, IndexError):
        return None
    if d is None:
        return None
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


def parse_fortinet_rss(body: bytes) -> tuple[list[dict], int]:
    """RSS → ([{ext_id, csaf_url, published}], 使わなかった項目の数)。外れた項目（ID・CSAF の URL が形に合わない）は使わない"""
    root = parse_xml(body)
    channel = root.find("channel") if root.tag == "rss" else None
    if channel is None:
        raise FetchError("Fortinet の RSS の形が想定と違います（形式が変わった可能性があります）")
    items: list[dict] = []
    skipped = 0
    seen: set[str] = set()
    for it in channel.findall("item")[:500]:
        link = (it.findtext("link") or it.findtext("guid") or "").strip()
        ext_id = link.rstrip("/").rsplit("/", 1)[-1] if link else ""
        csaf = fortinet_csaf_url((it.findtext(f"{_NS_CSAF}link") or "").strip(), ext_id)
        if not valid_fortinet_id(ext_id) or csaf is None or ext_id in seen:
            skipped += 1
            continue
        seen.add(ext_id)
        items.append({"ext_id": ext_id, "csaf_url": csaf, "published": _rss_date(it.findtext("pubDate"))})
    if not items and not skipped:
        raise FetchError("Fortinet の RSS に勧告が 1 件もありませんでした（形式が変わった可能性があります）")
    return items, skipped


def parse_cvrf_title(body: bytes, ext_id: str) -> str | None:
    """CVRF（ID で引ける XML）の題名。存在しない ID（題名が空・ID が無い）は None。ID が違えば FetchError"""
    root = parse_xml(body)
    if root.tag != f"{_NS_CVRF}cvrfdoc":
        raise FetchError("Fortinet の CVRF の形が想定と違います（形式が変わった可能性があります）")
    title = (root.findtext(f"{_NS_CVRF}DocumentTitle") or "").strip()
    doc_id = (root.findtext(f"{_NS_CVRF}DocumentTracking/{_NS_CVRF}Identification/{_NS_CVRF}ID") or "").strip()
    if not title or not doc_id:
        return None
    if doc_id != ext_id:
        raise FetchError("Fortinet の CVRF の勧告の ID が、指定した ID と違います")
    return _text(title, TITLE_MAX)


_FOS_ANY = re.compile(r"^FortiOS(?:$|[ /]|-(?!6K7K))")  # FortiOS の文字列（FortiOS-6K7K は別の製品）
_FA_RANGE = re.compile(r"^FortiOS >=(\d{1,3})\.(\d{1,3})\.(\d{1,3})\|<=(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z", re.A)
_FA_ONE = re.compile(r"^FortiOS (\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z", re.A)
_FA_ALL = re.compile(r"^FortiOS (\d{1,3})\.(\d{1,3}) all versions\Z", re.A)
_FN_FIX = re.compile(r"^FortiOS-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z", re.A)
_FN_ALL = re.compile(r"^FortiOS/ (\d{1,3})\.(\d{1,3}) all versions\Z", re.A)
# 修正版が未公開。本物は空白 2 つ。この行は「判定できない」か「何も決めない」にしか使わない（非該当の根拠にしない）ので、
# 空白の数は問わない
_FN_UPCOMING = re.compile(r"^FortiOS-upcoming\s+(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z", re.A)


def _v3(m, i: int = 1) -> str:
    return f"{int(m[i])}.{int(m[i + 1])}.{int(m[i + 2])}"


def fortios_row(key: str, text: str, v: int) -> dict:
    """product_status の FortiOS の文字列 1 つ → 影響範囲の 1 行（形は services/vuln_match.py の FortiOS の節）"""
    base = {"fmt": "fortios", "v": v, "raw": _text(text, 80)}

    def bad(why: str) -> dict:
        # 系列を読み取れる形（"FortiOS 6.0 …"・"FortiOS >=7.4.5|<=7.4.2" など、版の数字が 1 つの系列だけ）なら、
        # その系列だけを判定できないにする（PAN-OS と同じ考え方）。系列を読み取れないもの・系列をまたぐものは全系列
        return {**base, "unreadable": True, "branch": _branch_of_text(text), "raw": _text(f"{text}: {why}", 120)}

    if key == "known_affected":
        # 末尾に括弧の注記が付いた行（本物の FG-IR-23-001: "FortiOS 6.0 all versions (special note …)"）は、
        # 影響ありの欄に限って、注記を除いた読める形として持つ（"note" に注記）。注記は限定（"except 7.0.5"・"FortiGate-60F only"
        # など）のことがあるので、その行に入る版は「該当」ではなく「候補」（理由 note）にし、非該当の根拠にも使わない
        # （services/vuln_match.py）。影響なしの欄の注記つきは読めない行のまま
        if (m := _NOTE.match(text)) and any(r.match(m[1]) for r in (_FA_RANGE, _FA_ONE, _FA_ALL)):
            row = fortios_row(key, m[1], v)
            if not row.get("unreadable"):
                return {**row, "raw": _text(text, 160), "note": _text(m[2], 120)}
        if m := _FA_RANGE.match(text):
            lo, hi = _v3(m, 1), _v3(m, 4)
            if (int(m[1]), int(m[2])) != (int(m[4]), int(m[5])):
                return bad("範囲が系列をまたいでいます")
            if tuple(map(int, lo.split("."))) > tuple(map(int, hi.split("."))):
                return bad("範囲の始まりが終わりより後です")
            return {**base, "status": "affected", "branch": f"{int(m[1])}.{int(m[2])}", "ge": lo, "le": hi}
        if m := _FA_ONE.match(text):
            return {**base, "status": "affected", "branch": f"{int(m[1])}.{int(m[2])}", "eq": _v3(m)}
        if m := _FA_ALL.match(text):
            return {**base, "status": "affected", "branch": f"{int(m[1])}.{int(m[2])}", "all": True}
        return bad("影響ありの行の形を読み取れません")
    if key == "known_not_affected":
        if m := _FN_FIX.match(text):
            return {**base, "status": "unaffected", "branch": f"{int(m[1])}.{int(m[2])}", "fix": _v3(m)}
        if m := _FN_ALL.match(text):
            return {**base, "status": "unaffected", "branch": f"{int(m[1])}.{int(m[2])}", "all": True}
        if m := _FN_UPCOMING.match(text):
            return {**base, "branch": f"{int(m[1])}.{int(m[2])}", "upcoming": _v3(m)}
        return bad("影響なしの行の形を読み取れません")
    return bad(f"想定していない状態（{_text(key, 30)}）の行です")


_NOTE = re.compile(r"^(.+?) \(([^()]{1,200})\)\Z", re.A)
_6K7K_EXACT = re.compile(r"^FortiOS-6K7K(?:$|[ /\-])")  # 別の製品（FortiGate 6000 / 7000 系）。厳密に一致するものだけ
_INVISIBLE = re.compile(r"[\s\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]+")


# 系列を限ってよい読めない行の骨格（読める 6 形のうち 5 つと同じ形。欄が違う・範囲の向きが逆・注記つき、で読めなかったもの）
_SKELETONS = (
    re.compile(r"^FortiOS (\d{1,3})\.(\d{1,3})\.\d{1,3}\Z", re.A),
    re.compile(r"^FortiOS (\d{1,3})\.(\d{1,3}) all versions\Z", re.A),
    re.compile(r"^FortiOS-(\d{1,3})\.(\d{1,3})\.\d{1,3}\Z", re.A),
    re.compile(r"^FortiOS/ (\d{1,3})\.(\d{1,3}) all versions\Z", re.A),
)
_SKELETON_RANGE = re.compile(r"^FortiOS >=(\d{1,3})\.(\d{1,3})\.\d{1,3}\|<=(\d{1,3})\.(\d{1,3})\.\d{1,3}\Z", re.A)


def _branch_of_text(text: str) -> str | None:
    """読めない FortiOS の文字列のうち、その系列だけを判定できないにしてよいものの系列（それ以外は None＝全系列）

    許可した骨格だけ: 末尾の括弧の注記を除いた本体が、読める形と同じ骨格（"FortiOS A.B.C"・"FortiOS A.B all versions"・
    "FortiOS-A.B.C"・"FortiOS/ A.B all versions"・両端がそろって同じ系列の "FortiOS >=A.B.C|<=A.B.D"）に当たるもの。
    片側だけの範囲（<・>・+）や語つき（later・earlier・and・to など）・形が違うものは、ほかの系列にまたがりうるので全系列
    （語の一覧で弾くのではなく、許可した骨格に当たらなければ全系列）
    """
    body = m[1] if (m := _NOTE.match(text)) else text
    for rx in _SKELETONS:
        if m := rx.match(body):
            return f"{int(m[1])}.{int(m[2])}"
    if (m := _SKELETON_RANGE.match(body)) and (int(m[1]), int(m[2])) == (int(m[3]), int(m[4])):
        return f"{int(m[1])}.{int(m[2])}"
    return None


def product_kind(name) -> str | None:
    """文字列の製品の種類: "fortios"（FortiOS の行として読む）/ "other"（別の製品）/ None（文字列でない）

    1. 先頭が厳密に "FortiOS" で、続きが空白・"/"・"-"（"-6K7K" を除く）・終わり → "fortios"（形が違えば読めない行になる）
    2. 先頭が厳密に "FortiOS-6K7K" で、続きが区切り・終わり → "other"（FortiOS-6K7K は既知の別の製品）
    3. それ以外で、NFKC・大文字小文字・空白（BOM・ゼロ幅の文字を含む）を正規化すると "fortios" を含むもの
       （"fortios 7.2.4"・"FORTIOS"・"FortiOSxxx"・全角・先頭の空白や BOM・NBSP など）→ "fortios"（読めない行。黙って無視しない）
    4. それ以外（FortiProxy など）→ "other"
    """
    if not isinstance(name, str):
        return None
    if _FOS_ANY.match(name):
        return "fortios"
    if _6K7K_EXACT.match(name):
        return "other"
    norm = _INVISIBLE.sub("", unicodedata.normalize("NFKC", name)).casefold()
    return "fortios" if "fortios" in norm else "other"


def _is_fortios_name(name) -> bool:
    return product_kind(name) == "fortios"


def _tree_mentions_fortios(tree) -> bool:
    """product_tree に FortiOS の製品・版の行があるか（壊れた形なら True＝あるかもしれない）"""
    if tree is None:
        return False
    if not isinstance(tree, dict):
        return True
    stack = list(tree.get("branches") or []) if isinstance(tree.get("branches"), list) else [None]
    seen = 0
    while stack:
        b = stack.pop()
        seen += 1
        if not isinstance(b, dict) or seen > 5000:
            return True
        if _is_fortios_name(b.get("name")):
            return True
        kids = b.get("branches")
        if kids is not None:
            if not isinstance(kids, list):
                return True
            stack += kids
    return False


def _doc_mentions_fortios(doc: dict) -> bool:
    """文書の全体（product_tree の branches・full_product_names・relationships、document.notes・title）に、
    M1 と同じ正規化で "fortios" が出てくるか（出てくれば、製品の記載が無くても告知にはしない）"""
    d = doc.get("document") if isinstance(doc.get("document"), dict) else {}
    try:
        text = json.dumps([doc.get("product_tree"), d.get("notes"), d.get("title")], ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        return True
    return "fortios" in _INVISIBLE.sub("", unicodedata.normalize("NFKC", text)).casefold()


def _cvss_of_scores(scores, product: str | None) -> float | None:
    """vulnerabilities[].scores の CVSS（cvss_v3・cvss_v4 の baseScore）の最大。product を指定したら、その製品の点だけ"""
    best = None
    for sc in scores if isinstance(scores, list) else []:
        if not isinstance(sc, dict):
            continue
        prods = sc.get("products")
        if product is not None and isinstance(prods, list) and product not in prods:
            continue
        for k, val in sc.items():
            if k.startswith("cvss_v") and isinstance(val, dict):
                x = val.get("baseScore")
                if isinstance(x, (int, float)) and not isinstance(x, bool) and 0 <= x <= 10:
                    best = float(x) if best is None else max(best, float(x))
    return best


def _status_strings(v: dict) -> tuple[list[tuple[str, str]], bool]:
    """product_status の (キー, 文字列) の一覧と、形が壊れているか"""
    ps = v.get("product_status")
    if ps is None:
        return [], False
    if not isinstance(ps, dict):
        return [], True
    out: list[tuple[str, str]] = []
    broken = False
    for k, arr in ps.items():
        if not isinstance(arr, list):
            broken = True
            continue
        for x in arr:
            if isinstance(x, str):
                out.append((str(k), x))
            else:
                broken = True
    return out, broken


def _vuln_names_product(v: dict, product: str) -> bool:
    title = v.get("title")
    if isinstance(title, str) and title.startswith(f"{product} - "):
        return True
    for sc in v.get("scores") or [] if isinstance(v.get("scores"), list) else []:
        if isinstance(sc, dict) and isinstance(sc.get("products"), list) and product in sc["products"]:
            return True
    for r in v.get("remediations") or [] if isinstance(v.get("remediations"), list) else []:
        if isinstance(r, dict) and isinstance(r.get("product_ids"), list) and product in r["product_ids"]:
            return True
    return False


_TITLE_SEV = re.compile(r"^FortiOS - (CRITICAL|HIGH|MEDIUM|LOW) - ", re.A)
_SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_fortinet_csaf(doc, expected_id: str | None = None) -> dict:
    """Fortinet の CSAF 1 件 → 勧告（products が ["fortinet"] なら FortiOS の勧告。[] なら FortiOS 以外の製品だけの勧告）

    文書として読めない（JSON が dict でない・ID が無い・ID が違う）ときは FetchError（呼び出し側で「記録を読めない」扱い）。
    FortiOS の勧告かどうか:
      - vulnerabilities[] のうち、FortiOS の文字列（product_status）を持つか、題の接頭辞「FortiOS - 」・scores.products・
        remediations.product_ids に厳密に "FortiOS" があるものを、FortiOS の脆弱性とする（"FortiOS-6K7K" は別の製品）
      - FortiOS の脆弱性が無くても、vulnerabilities が無い・空・製品を決められない脆弱性がある・product_tree に FortiOS の行が
        ある・状態（tracking.status）が final でない、のどれかなら、読めない勧告として保存する（判定できない）
      - それ以外（読めた脆弱性がすべて FortiOS 以外の製品のもの）だけが「FortiOS 以外の勧告」（products []）
      - ただし vulnerabilities が無い・空で、product_tree に FortiOS が無い文書（NGINX・Java などの PSIRT の告知）は
        「要確認の告知」（"notice": True。products []・影響範囲は告知の印だけ）。機器ごとの照合には使わず、画面の上部に別に出す
    重大度は、FortiOS の脆弱性の題の接頭辞（"FortiOS - CRITICAL - …"）と CVSS の点の区分のうち高いほう
    （CSAF の baseScore には時間で変わる点が入り、勧告のページの値と違うことがあるため。点数は CSAF の値のまま）
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        raise FetchError("Fortinet の CSAF の形が想定と違います（形式が変わった可能性があります）")
    d = doc["document"]
    tracking = d.get("tracking") if isinstance(d.get("tracking"), dict) else {}
    ext_id = tracking.get("id")
    if not valid_fortinet_id(ext_id):
        raise FetchError("Fortinet の CSAF の勧告の ID を読み取れません")
    if expected_id is not None and ext_id != expected_id:
        raise FetchError("Fortinet の CSAF の勧告の ID が、指定した ID と違います")
    vulns = doc.get("vulnerabilities")
    rows: list[dict] = []
    cves: list[str] = []
    scores: list[float] = []
    title_sev: list[str] = []
    fos_seen = False
    whole: list[str] = []  # 勧告の全体を読めない理由
    provisional = tracking.get("status") != "final"
    if provisional:
        whole.append("勧告の状態（tracking.status）が final ではありません（暫定の勧告）")
    no_vulns = not isinstance(vulns, list) or not vulns
    if no_vulns:
        whole.append("勧告に脆弱性（vulnerabilities）の記載がありません")
        vulns = vulns if isinstance(vulns, list) else []
    for i, v in enumerate(vulns[:MAX_RANGES]):
        if not isinstance(v, dict):
            whole.append("脆弱性の記載の形が想定と違います")
            continue
        strings, broken = _status_strings(v)
        fos = [(k, t) for k, t in strings if _is_fortios_name(t)]
        if not (fos or _vuln_names_product(v, "FortiOS")):
            if broken or not (strings or isinstance(v.get("title"), str)):
                whole.append("製品を決められない脆弱性の記載があります")
            continue  # FortiOS 以外の製品（FortiProxy・FortiOS-6K7K など）の脆弱性
        fos_seen = True
        cve = v.get("cve")
        if isinstance(cve, str) and _CVE.match(cve) and cve not in cves:
            cves.append(cve)
        if (sc := _cvss_of_scores(v.get("scores"), "FortiOS")) is not None:
            scores.append(sc)
        if isinstance(v.get("title"), str) and (m := _TITLE_SEV.match(v["title"])):
            title_sev.append(m[1].lower())
        rows.append({"fmt": "fortios", "kind": "vuln", "v": i, "cve": cve if isinstance(cve, str) and _CVE.match(cve) else None})
        if broken:
            rows.append({"fmt": "fortios", "v": i, "unreadable": True, "raw": "product_status の形が想定と違います"})
        if not fos:
            rows.append({"fmt": "fortios", "v": i, "unreadable": True, "raw": "FortiOS の脆弱性に、FortiOS の行がありません"})
        for k, t in fos[:MAX_RANGES]:
            rows.append(fortios_row(k, t, i))
        if len(fos) > MAX_RANGES:
            rows.append({"fmt": "fortios", "v": i, "unreadable": True, "raw": "行が多すぎます（読み切れません）"})
    if len(vulns) > MAX_RANGES:
        whole.append("脆弱性の記載が多すぎます（読み切れません）")
    tree_fos = _tree_mentions_fortios(doc.get("product_tree"))
    if not fos_seen and tree_fos:
        whole.append("製品の一覧に FortiOS がありますが、FortiOS の脆弱性の記載がありません")
    if no_vulns and not tree_fos and not _doc_mentions_fortios(doc):
        # 要確認の告知: 製品の記載が無く、機器を特定できない。機器ごとの「判定できない」には数えない
        score = max((x for v in vulns if isinstance(v, dict) and (x := _cvss_of_scores(v.get("scores"), None)) is not None),
                    default=None)
        return {
            "source": "fortinet", "ext_id": ext_id, "cve_ids": [], "title": _text(d.get("title"), TITLE_MAX) or ext_id,
            "severity": severity_of(score), "cvss": score,
            "published_at": _dt(tracking.get("initial_release_date")), "modified_at": _dt(tracking.get("current_release_date")),
            "url": fortinet_page_url(ext_id), "products": [],
            "affected": [{"fmt": "fortios", "v": None, "notice": True, "raw": "製品の記載が無い告知（機器を特定できません）"}],
            "unreadable": 0, "notice": True,
        }
    for why in dict.fromkeys(whole):
        row = {"fmt": "fortios", "v": None, "unreadable": True, "raw": _text(why, 120)}
        if why.startswith("勧告の状態"):
            row["provisional"] = True
        rows.append(row)
    is_fortios = fos_seen or bool(whole)
    if not cves and whole:
        for v in vulns:
            c = v.get("cve") if isinstance(v, dict) else None
            if isinstance(c, str) and _CVE.match(c) and c not in cves:
                cves.append(c)
    score = max(scores) if scores else None
    if score is None and whole:
        score = max((x for v in vulns if isinstance(v, dict) and (x := _cvss_of_scores(v.get("scores"), None)) is not None),
                    default=None)
    severity = severity_of(score)
    for t in title_sev:
        if _SEV_RANK.get(t, -1) > _SEV_RANK.get(severity, -1):
            severity = t
    return {
        "source": "fortinet", "ext_id": ext_id, "cve_ids": cves[:50],
        "title": _text(d.get("title"), TITLE_MAX) or ext_id, "severity": severity, "cvss": score,
        "published_at": _dt(tracking.get("initial_release_date")), "modified_at": _dt(tracking.get("current_release_date")),
        "url": fortinet_page_url(ext_id),
        "products": ["fortinet"] if is_fortios else [], "affected": rows if is_fortios else [],
        "unreadable": sum(1 for r in rows if r.get("unreadable")) if is_fortios else 0,
    }
