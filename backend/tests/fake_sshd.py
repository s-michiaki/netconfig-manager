"""テスト用の簡易SSHサーバー（Cisco風プロンプト）"""
import socket, threading, paramiko

CONFIG = "Building configuration...\r\n\r\nCurrent configuration : 99 bytes\r\n! Last configuration change at 12:00:00 JST\r\nhostname R1\r\ninterface Gi0/1\r\n description 日本語の説明\r\nend"

class Server(paramiko.ServerInterface):
    def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u, p) == ("admin", "pw") else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, kind, cid): return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *a): return True
    def check_channel_shell_request(self, ch): return True
    def check_channel_window_change_request(self, ch, w, h, *a):
        self.size = (w, h); return True

def handle(sock, key, state):
    t = paramiko.Transport(sock); t.add_server_key(key); srv = Server(); t.start_server(server=srv)
    ch = t.accept(20)
    if ch is None: return
    state["server"] = srv
    ch.send("R1#")
    buf = b""
    while True:
        d = ch.recv(1024)
        if not d: break
        buf += d
        while b"\n" in buf or b"\r" in buf:
            i = min(x for x in (buf.find(b"\n"), buf.find(b"\r")) if x >= 0)
            line, buf = buf[:i].decode(), buf[i+1:].lstrip(b"\n")
            out = ""
            if line.strip() == "show running-config": out = CONFIG
            elif line.strip() == "exit": ch.send(line + "\r\n"); ch.close(); return
            elif line.strip() == "utf8": out = "あいうえお" * 2000
            ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "R1#")

def start(key=None):
    key = key or paramiko.RSAKey.generate(2048)
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0)); s.listen(5)
    state = {}
    def loop():
        while True:
            c, _ = s.accept(); threading.Thread(target=handle, args=(c, key, state), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1], state, s
