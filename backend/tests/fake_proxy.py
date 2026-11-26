"""テスト用の偽の HTTP プロキシ（スレッドで動く socket サーバー）と、テストの中で作る CA・サーバー証明書

外部へは実際につながない。CONNECT を受けると、宛先へは中継せず、プロキシ自身が「宛先のふり」をして TLS で応答する
（HTTPS を検査するプロキシと同じ動き。証明書は渡した CA で、CONNECT の宛先の名前（または cert_name）に発行する）。

mode:
  mitm  : CONNECT に 200 を返し、TLS で応答する（auth を渡すと、Proxy-Authorization が合わなければ 407）
  407   : CONNECT にいつも 407 を返す
  hang  : CONNECT を受けたまま何も返さない（時間切れの確かめ）
  drip  : CONNECT の応答を少しずつ返し続ける（全体の期限の確かめ）
記録: connects（CONNECT の要求の生の文字列）、inner（トンネルの中の要求）、plain（CONNECT 以外の要求＝平文の宛先）
"""
import base64
import ipaddress
import socket
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path


class TestCA:
    """テスト用の CA（cryptography で作る）。issue でサーバー証明書と鍵のファイルを作る"""

    __test__ = False  # pytest に集めさせない

    def __init__(self, cn: str = "Example Corp CA", days: int = 365):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509, self._hashes, self._ser, self._ec, self._oid = x509, hashes, serialization, ec, NameOID
        now = datetime.now(UTC)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        self.cert = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                  content_commitment=False, key_encipherment=False, data_encipherment=False,
                                                  key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
                     .sign(self.key, hashes.SHA256()))
        self.dir = Path(tempfile.mkdtemp(prefix="fake-proxy-ca-"))
        self._issued: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

    def pem(self) -> bytes:
        return self.cert.public_bytes(self._ser.Encoding.PEM)

    def write_pem(self, path: Path) -> Path:
        path.write_bytes(self.pem())
        return path

    def issue(self, name: str) -> tuple[str, str]:
        """name（DNS 名か IP）のサーバー証明書と鍵のファイル（パス）"""
        with self._lock:
            if name in self._issued:
                return self._issued[name]
            x509, ec = self._x509, self._ec
            now = datetime.now(UTC)
            key = ec.generate_private_key(ec.SECP256R1())
            try:
                san = x509.IPAddress(ipaddress.ip_address(name))
            except ValueError:
                san = x509.DNSName(name)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(self._oid.COMMON_NAME, name)]))
                    .issuer_name(self.name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
                    .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                    .sign(self.key, self._hashes.SHA256()))
            safe = name.replace(":", "_")
            cp, kp = self.dir / f"{safe}.crt", self.dir / f"{safe}.key"
            cp.write_bytes(cert.public_bytes(self._ser.Encoding.PEM))
            kp.write_bytes(key.private_bytes(self._ser.Encoding.PEM, self._ser.PrivateFormat.PKCS8,
                                             self._ser.NoEncryption()))
            self._issued[name] = (str(cp), str(kp))
            return self._issued[name]


def default_respond(method, path, headers, body):
    return 200, {"Content-Type": "application/json"}, b'{"ok": true}'


def _read_head(conn) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def _headers(head: bytes) -> dict[str, str]:
    out = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            out[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return out


class FakeProxy:
    def __init__(self, ca: TestCA | None = None, *, mode: str = "mitm", auth: tuple[str, str] | None = None,
                 cert_name: str | None = None, respond=default_respond):
        self.ca, self.mode, self.auth, self.cert_name, self.respond = ca, mode, auth, cert_name, respond
        self.connects: list[str] = []
        self.inner: list[dict] = []
        self.plain: list[str] = []
        self.stop = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def url(self, user: str = "", password: str = "") -> str:
        """プロキシの URL（user・password は URL エンコード済みの文字列を渡す）"""
        cred = f"{user}:{password}@" if user or password else ""
        return f"http://{cred}127.0.0.1:{self.port}"

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

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
            head = _read_head(conn)
            if not head:
                return
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            if not first.startswith("CONNECT "):
                self.plain.append(head.decode("latin-1"))
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                return
            self.connects.append(head.decode("latin-1"))
            if self.mode == "hang":
                self.stop.wait(10)
                return
            if self.mode == "drip":  # CONNECT の応答を 1 文字ずつ、終わらないヘッダーで返し続ける
                for b in b"HTTP/1.1 200 Connection established\r\nX-Pad: " + b"a" * 100000:
                    if self.stop.is_set():
                        return
                    conn.sendall(bytes([b]))
                    self.stop.wait(0.2)
                return
            if self.mode == "407" or (self.auth and _headers(head).get("proxy-authorization") != "Basic " + base64.b64encode(
                    f"{self.auth[0]}:{self.auth[1]}".encode()).decode()):
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n"
                             b"Content-Length: 0\r\n\r\n")
                return
            target = first.split()[1]
            host = target.rsplit(":", 1)[0].strip("[]")
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            cert, key = self.ca.issue(self.cert_name or host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                return  # 相手（テストの側）が証明書を拒否した
            with tls:
                req = _read_head(tls)
                if not req:
                    return
                head_part, _, rest = req.partition(b"\r\n\r\n")
                hs = _headers(head_part + b"\r\n")
                length = int(hs.get("content-length") or 0)
                while len(rest) < length:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                line = head_part.split(b"\r\n", 1)[0].decode("latin-1").split()
                method, path = line[0], line[1]
                self.inner.append({"host": host, "method": method, "path": path, "headers": hs, "body": rest,
                                   "raw": head_part.decode("latin-1")})
                status, extra, body = self.respond(method, path, hs, rest)
                lines = [f"HTTP/1.1 {status} X"] + [f"{k}: {v}" for k, v in extra.items()]
                lines += [f"Content-Length: {len(body)}", "Connection: close"]
                tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (b"" if method == "HEAD" else body))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def closed_port() -> int:
    """つながらないポート（いったん bind して閉じる）"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
