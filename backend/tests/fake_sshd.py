"""テスト用の簡易SSHサーバー（Cisco風 / PAN-OS風プロンプト）

start(pubkey=..., password=..., mode="cisco"|"panos") で起動
- パスワード認証・キーボード対話認証・公開鍵認証に対応
"""
import socket
import threading

import paramiko

CONFIG = "Building configuration...\r\n\r\nCurrent configuration : 99 bytes\r\n! Last configuration change at 12:00:00 JST\r\nhostname R1\r\ninterface Gi0/1\r\n description 日本語の説明\r\nend"

PANOS_SET_CONFIG = (
    "set deviceconfig system hostname PA-VM\r\n"
    "set deviceconfig system timezone Asia/Tokyo\r\n"
    "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\r\n"
    "set rulebase security rules allow-web from trust to untrust application web-browsing action allow\r\n"
    'set address web01 description "日本語の説明"'
)


class Server(paramiko.ServerInterface):
    def __init__(self, cfg):
        self.cfg = cfg
        self.auth_method = None

    def get_allowed_auths(self, u):
        return "password,publickey,keyboard-interactive"

    def check_auth_password(self, u, p):
        if self.cfg["password"] and (u, p) == ("admin", self.cfg["password"]):
            self.auth_method = "password"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, u, key):
        pub = self.cfg.get("pubkey")
        if u == "admin" and pub is not None and key.get_base64() == pub.get_base64():
            self.auth_method = "publickey"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, u, submethods):
        q = paramiko.server.InteractiveQuery("", "")
        q.add_prompt("Password: ", False)
        return q

    def check_auth_interactive_response(self, responses):
        if self.cfg["password"] and responses and responses[0] == self.cfg["password"]:
            self.auth_method = "keyboard-interactive"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, cid): return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *a): return True
    def check_channel_shell_request(self, ch): return True

    def check_channel_window_change_request(self, ch, w, h, *a):
        self.size = (w, h)
        return True


def _lines(ch):
    buf = b""
    while True:
        d = ch.recv(1024)
        if not d:
            return
        buf += d
        while b"\n" in buf or b"\r" in buf:
            i = min(x for x in (buf.find(b"\n"), buf.find(b"\r")) if x >= 0)
            line, buf = buf[:i].decode(), buf[i + 1:].lstrip(b"\n")
            yield line


def _cisco(ch):
    ch.send("R1#")
    for line in _lines(ch):
        out = ""
        if line.strip() == "show running-config":
            out = CONFIG
        elif line.strip() == "exit":
            ch.send(line + "\r\n")
            ch.close()
            return
        elif line.strip() == "utf8":
            out = "あいうえお" * 2000
        ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "R1#")


def _panos(ch, state):
    op, conf = "admin@PA-VM> ", "admin@PA-VM# "
    ch.send("Last login: Thu Oct 29 10:00:00 2026\r\n\r\n" + op)
    in_conf = False
    for line in _lines(ch):
        cmd = line.strip()
        state.setdefault("commands", []).append(cmd)
        prompt = conf if in_conf else op
        out = ""
        if not in_conf:
            if cmd == "show admins":
                out = "Admin  From          Client Session-start\r\n-----------------------------------------\r\nadmin  192.0.2.10    CLI    10/29 10:00:00"
            elif cmd == "configure":
                in_conf = True
                ch.send(line + "\r\nEntering configuration mode\r\n[edit]\r\n" + conf)
                continue
            elif cmd == "exit":
                ch.send(line + "\r\n")
                ch.close()
                return
            ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "\r\n" + op)
        else:
            if cmd == "show":
                fmt = state.get("format_set")
                out = PANOS_SET_CONFIG if fmt else "deviceconfig {\r\n  system {\r\n    hostname PA-VM;\r\n  }\r\n}"
            elif cmd == "exit":
                in_conf = False
                ch.send(line + "\r\nExiting configuration mode\r\n" + op)
                continue
            ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "\r\n[edit]\r\n" + prompt)
        if cmd == "set cli config-output-format set":
            state["format_set"] = True


def handle(sock, key, state, cfg=None):
    cfg = cfg or {"password": "pw", "pubkey": None, "mode": "cisco"}
    t = paramiko.Transport(sock)
    t.add_server_key(key)
    srv = Server(cfg)
    try:
        t.start_server(server=srv)
    except Exception:  # noqa: BLE001
        return
    ch = t.accept(20)
    if ch is None:
        return
    state["server"] = srv
    state["auth_method"] = srv.auth_method
    try:
        if cfg["mode"] == "panos":
            _panos(ch, state)
        else:
            _cisco(ch)
    except Exception:  # noqa: BLE001
        pass


def start(key=None, password="pw", pubkey=None, mode="cisco"):
    key = key or paramiko.RSAKey.generate(2048)
    cfg = {"password": password, "pubkey": pubkey, "mode": mode}
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    state = {}

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c, key, state, cfg), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1], state, s
