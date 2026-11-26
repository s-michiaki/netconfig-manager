"""脆弱性・サポート終了日の外部からの取得（HTTP の枠組みと、各情報源の応答の解析）

外部へつなぐのはこのファイルだけ。次を守る（新しい種類の通信なので、制限を厳しくしている）。
- 宛先は固定のホストの一覧（ALLOWED_HOSTS）だけ。https のみ。リダイレクトも同じ一覧の中だけたどる（外れたら失敗）
- 接続の待ちは 10 秒、全体で 60 秒（ヘッダーの受信を含む。期限でソケットを閉じて打ち切る）。
  応答は 50MB で打ち切る（超えたら失敗）。応答は JSON だけ（標準ライブラリで解析）
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
import functools
import http.client
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
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
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_PAN_SA = re.compile(r"^PAN-SA-\d{4}-\d{4,}$")
_BRANCH = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.\-]{0,31}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class FetchError(Exception):
    """取得・解析の失敗。文言はそのまま last_error に保存して画面に出す（秘密を含めない）"""


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


def _fetch_inner(url: str, deadline: float) -> bytes:
    """接続して本文を読む（取得を行うスレッドで動く）。失敗は FetchError"""
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": user_agent(), "Accept": "application/json", "Accept-Encoding": "identity",
    })
    try:
        resp = _open(req, CONNECT_TIMEOUT)
    except FetchError:
        raise
    except urllib.error.HTTPError as e:
        e.close()
        if e.code == 429:
            raise FetchError("相手の回数制限に達しました（HTTP 429）。時間をおいて再試行します") from None
        if 300 <= e.code < 400:
            raise FetchError(f"リダイレクトの先を確認できません（HTTP {e.code}）") from None
        raise FetchError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ssl.SSLError, ValueError, http.client.HTTPException) as e:
        raise FetchError(_describe(e)) from None
    with closing(resp):
        final = getattr(resp, "geturl", lambda: url)()
        check_url(final)  # たどった先も許可リストの中であること
        try:
            declared = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError, AttributeError):
            declared = 0
        if declared > MAX_BYTES:
            raise FetchError("応答が大きすぎます（上限 50MB）")
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
                if total > MAX_BYTES:
                    raise FetchError("応答が大きすぎます（上限 50MB）")
                chunks.append(chunk)
        except FetchError:
            raise
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as e:  # TimeoutError・IncompleteRead など
            raise FetchError(_describe(e)) from None
        if declared and total < declared:  # read(n) は途中で切れても例外にしないため、宣言の大きさと比べる
            raise FetchError("相手の応答の形式が正しくありません（途中で切れました）")
    return b"".join(chunks)


def fetch_bytes(url: str) -> bytes:
    """URL の応答の本文（上限まで）。失敗は FetchError

    ヘッダーの受信を含めて、全体で TOTAL_TIMEOUT 秒を超えない。取得は別のスレッドで行い、期限が来たら
    開いているソケットを閉じて打ち切る（相手が少しずつ返し続けても、ここで必ず終わる）
    """
    check_url(url)
    guard = _Guard()
    box: dict[str, Any] = {}
    deadline = time.monotonic() + TOTAL_TIMEOUT

    def work() -> None:
        _tl.guard = guard
        try:
            box["body"] = _fetch_inner(url, deadline)
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
