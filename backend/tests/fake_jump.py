"""テスト用の踏み台SSHサーバ（パスワード / 公開鍵認証、direct-tcpip 転送）"""
import socket
import threading

import paramiko


class JumpServer(paramiko.ServerInterface):
    def __init__(self, cfg):
        self.cfg = cfg
        self.targets: dict[int, socket.socket] = {}

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        ok = username == self.cfg["username"] and self.cfg.get("password") and password == self.cfg["password"]
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        pub = self.cfg.get("pubkey")
        ok = username == self.cfg["username"] and pub is not None and key.get_base64() == pub.get_base64()
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.cfg.get("allow_forward", True):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        try:
            self.targets[chanid] = socket.create_connection(destination, timeout=3)
        except OSError:
            return paramiko.OPEN_FAILED_CONNECT_FAILED
        self.cfg.setdefault("forwarded", []).append(destination)
        return paramiko.OPEN_SUCCEEDED


def _pump(src_recv, dst_send, closers):
    try:
        while True:
            data = src_recv(32768)
            if not data:
                break
            dst_send(data)
    except Exception:  # noqa: BLE001
        pass
    finally:
        for c in closers:
            try:
                c()
            except Exception:  # noqa: BLE001
                pass


def _handle(sock, host_key, cfg):
    t = paramiko.Transport(sock)
    t.add_server_key(host_key)
    srv = JumpServer(cfg)
    try:
        t.start_server(server=srv)
    except Exception:  # noqa: BLE001
        return
    while t.is_active():
        ch = t.accept(1)
        if ch is None:
            continue
        target = srv.targets.pop(ch.get_id())
        closers = [ch.close, target.close]
        threading.Thread(target=_pump, args=(ch.recv, target.sendall, closers), daemon=True).start()
        threading.Thread(target=_pump, args=(target.recv, ch.sendall, closers), daemon=True).start()


def start(username="jumpuser", password=None, pubkey=None, allow_forward=True):
    """起動してポート番号と設定 dict（転送先の記録 forwarded を含む）を返す"""
    cfg = {"username": username, "password": password, "pubkey": pubkey, "allow_forward": allow_forward}
    host_key = paramiko.RSAKey.generate(2048)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(5)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(c, host_key, cfg), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1], cfg
