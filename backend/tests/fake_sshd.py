"""テスト用の簡易SSHサーバー（Cisco風 / PAN-OS風 / FortiGate風 / AlliedWare Plus風 / 汎用プロンプト）

start(pubkey=..., password=..., mode="cisco"|"panos"|"fortinet"|"awplus"|"generic") で起動
- パスワード認証・キーボード対話認証・公開鍵認証に対応
"""
import socket
import threading
import time

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


def _cisco(ch, pager=None):
    ch.send("R1#")
    for line in _lines(ch):
        out = ""
        if line.strip() == "show running-config" and pager:
            # ページングが無効化されていない機器: 途中でページャーが出て止まる
            ch.send(line + "\r\n" + "\r\n".join(CONFIG.split("\r\n")[:4]) + "\r\n" + pager)
            continue
        if line.strip() == "show running-config":
            out = CONFIG
        elif line.strip() == "exit":
            ch.send(line + "\r\n")
            ch.close()
            return
        elif line.strip() == "utf8":
            out = "あいうえお" * 2000
        ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "R1#")


def _panos(ch, state, login_delay=0.0):
    op, conf = "admin@PA-VM> ", "admin@PA-VM# "
    if login_delay:
        time.sleep(login_delay)  # ログイン後プロンプトが出るまで時間のかかる機器を再現
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


# ---------------------------------------------------------------- FortiGate（FortiOS 7）
def _forti_config(state):
    """show の出力。暗号化された値（ENC）と秘密鍵は実機と同じく取得のたびに変わる"""
    import secrets
    n = state["show_count"] = state.get("show_count", 0) + 1
    console = "config system console\r\n    set output standard\r\nend\r\n" if state["output"] == "standard" else ""
    return (
        "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\r\n"
        f"#conf_file_ver={1000 + n}\r\n#buildno=1517\r\n#global_vdom=1\r\n"
        'config system global\r\n    set hostname "FGT60F"\r\n    set admintimeout 480\r\nend\r\n'
        + console
        + 'config system admin\r\n    edit "admin"\r\n        set password ENC SH2stablehashvalue=\r\n'
        "    next\r\nend\r\n"
        'config system interface\r\n    edit "port1"\r\n        set allowaccess ping https ssh http\r\n'
        '        set description "日本語の説明"\r\n    next\r\nend\r\n'
        'config vpn ipsec phase1-interface\r\n    edit "vpn1"\r\n'
        f"        set psksecret ENC {secrets.token_urlsafe(24)}\r\n    next\r\nend\r\n"
        'config vpn certificate local\r\n    edit "cert1"\r\n        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n'
        f"{secrets.token_urlsafe(40)}\r\n-----END ENCRYPTED PRIVATE KEY-----\"\r\n    next\r\nend"
    )


def _fortinet(ch, state):
    state.setdefault("output", "more")
    ctx = []
    host = "FGT60F"

    def prompt():
        return f"{host} ({ctx[-1]}) # " if ctx else f"{host} # "

    ch.send(prompt())
    for line in _lines(ch):
        cmd = line.strip()
        state.setdefault("commands", []).append(cmd)
        out = ""
        if cmd == "get system status | grep Virtual":
            out = "Virtual domain configuration: disable"
        elif cmd == "get system status | grep Version":
            out = "Version: FortiGate-60F v7.2.5,build1517,230606 (GA.F)"
        elif cmd == "get system console":
            out = f"output              : {state['output']}\r\nlogin               : enable"
        elif cmd.startswith("config "):
            ctx.append(cmd.split()[-1])
        elif cmd == "set output standard" and ctx == ["console"]:
            state["output"] = "standard"
        elif cmd == "set output more" and ctx == ["console"]:
            state["output"] = "more"
        elif cmd in ("end", "next"):
            if ctx:
                ctx.pop()
        elif cmd == "show":
            text = _forti_config(state)
            if state["output"] == "more":
                ch.send(line + "\r\n" + "\r\n".join(text.split("\r\n")[:6]) + "\r\n--More-- ")
                continue
            out = text
        elif cmd == "exit":
            ch.send(line + "\r\n")
            ch.close()
            return
        ch.send(line + "\r\n" + (out + "\r\n" if out else "") + "\r\n" + prompt())


# ---------------------------------------------------------------- AlliedWare Plus
AWPLUS_CONFIG = (
    "!\r\nservice password-encryption\r\n!\r\nhostname awplus\r\n!\r\nno service telnet\r\n!\r\n"
    "snmp-server community public\r\n!\r\ninterface port1.0.1\r\n description 日本語の説明\r\n"
    " switchport mode access\r\n!\r\nntp server 192.0.2.123\r\n!\r\nend"
)


def _awplus(ch, state, enable_password=None):
    priv = False
    paging = True
    ch.send("\r\nAlliedWare Plus (TM) 5.5.2 11/01/22 12:00:00\r\n\r\nawplus>")
    waiting_password = False
    for line in _lines(ch):
        cmd = line.strip()
        state.setdefault("commands", []).append(cmd if not waiting_password else "<password>")
        prompt = lambda: "awplus#" if priv else "awplus>"  # noqa: E731
        if waiting_password:
            waiting_password = False
            if cmd == (enable_password or ""):
                priv = True
                ch.send("\r\n" + prompt())
            else:
                ch.send("\r\n% Bad passwords\r\n" + prompt())
            continue
        out = ""
        if cmd == "terminal length 0":
            paging = False
        elif cmd == "enable":
            if enable_password:
                waiting_password = True
                ch.send(line + "\r\nPassword: ")
                continue
            priv = True
        elif cmd == "show running-config":
            if not priv:
                out = "% Invalid input detected at '^' marker."
            elif paging:
                ch.send(line + "\r\n" + "\r\n".join(AWPLUS_CONFIG.split("\r\n")[:5]) + "\r\n--More--")
                continue
            else:
                out = AWPLUS_CONFIG
        elif cmd in ("exit", "logout"):
            ch.send(line + "\r\n")
            ch.close()
            return
        ch.send(line + "\r\n" + (out + "\r\n" if out else "") + prompt())


# ---------------------------------------------------------------- 汎用（どのコマンドにも応答する）
GENERIC_CONFIG = "hostname sw1\r\ninterface eth1\r\n description 日本語の説明\r\n!"


def _generic(ch, state, prompt="sw1#", config_commands=()):
    """プロンプトを返し続けるだけの機器。config_commands のコマンドにはコンフィグを返す"""
    ch.send("\r\n" + prompt)
    for line in _lines(ch):
        cmd = line.strip()
        state.setdefault("commands", []).append(cmd)
        if cmd in ("exit", "logout", "quit", "/quit"):
            ch.send(line + "\r\n")
            ch.close()
            return
        out = GENERIC_CONFIG if cmd in config_commands else ""
        ch.send(line + "\r\n" + (out + "\r\n" if out else "") + prompt)


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
            _panos(ch, state, cfg.get("login_delay", 0.0))
        elif cfg["mode"] == "fortinet":
            _fortinet(ch, state)
        elif cfg["mode"] == "awplus":
            _awplus(ch, state, cfg.get("enable_password"))
        elif cfg["mode"] == "generic":
            _generic(ch, state, cfg.get("prompt", "sw1#"), cfg.get("config_commands", ()))
        else:
            _cisco(ch, cfg.get("pager"))
    except Exception:  # noqa: BLE001
        pass


def start(key=None, password="pw", pubkey=None, mode="cisco", login_delay=0.0, pager=None, **extra):
    key = key or paramiko.RSAKey.generate(2048)
    cfg = {"password": password, "pubkey": pubkey, "mode": mode, "login_delay": login_delay, "pager": pager, **extra}
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
