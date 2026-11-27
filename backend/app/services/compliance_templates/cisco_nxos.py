"""Cisco NX-OS のひな形（書式は show running-config）。共通のもの（NTP・SNMP・説明）は common.py"""
from ._base import REF_OPS, REF_VENDOR, tpl

NXOS = ["cisco_nxos"]

TEMPLATES = [
    tpl(
        "NX-OS: Telnet 機能を有効にしない", "high", NXOS, "管理アクセス",
        "暗号化されない Telnet（feature telnet）を有効にしない",
        "regex", "absent", r"^feature telnet\b",
        remediation="""
# 変更前に、別のセッションで SSH ログインできることを確かめてください（Telnet の接続は切れます）
no feature telnet
""",
        good="feature ssh\nfeature tacacs+\n", bad="feature telnet\nfeature ssh\n",
    ),
    tpl(
        "NX-OS: SSH 機能を無効にしない", "medium", NXOS, "管理アクセス",
        "遠隔の管理に使う SSH を無効（no feature ssh）にしない",
        "regex", "absent", r"^no feature ssh\b",
        remediation="""
# SSH を無効にしている機器で有効に戻す操作です。SSH 以外の管理手段（コンソールなど）が使える状態で行ってください
feature ssh
""",
        good="feature ssh\n", bad="no feature ssh\nfeature telnet\n",
    ),
    tpl(
        "NX-OS: VTY のアイドルタイムアウトを設定する", "medium", NXOS, "管理アクセス",
        "line vty に exec-timeout（分）を設定する。NX-OS は VTY のタイムアウトが既定で無効（無制限）なので、"
        "行があることを求める。"
        "running-config に line vty の見出しが出ない機器は、検出できません",
        "regex", "present", r"^\s+exec-timeout [1-9]\d*\s*$", scope="section", section_pattern=r"^line vty",
        remediation="""
line vty
  exec-timeout 10
""",
        good="line vty\n  exec-timeout 10\n!\n", bad="line vty\n  session-limit 5\n!\n",
    ),
    tpl(
        "NX-OS: Syslog の転送先", "low", NXOS, "ログ",
        "ログを Syslog サーバーへ転送する",
        "regex", "present", r"^logging server \S+",
        remediation="""
# 管理用の VRF を使う環境では use-vrf <VRF名> を付けます
logging server <syslog サーバーの IP> 5
""",
        good="logging server 192.0.2.5 5 use-vrf management\n", bad="hostname Core-SW01\n",
    ),
    tpl(
        "NX-OS: ログイン認証に AAA を使う", "low", NXOS, "認証",
        "ログインの認証方式（aaa authentication login）を設定する。ローカルだけで運用する環境では違反になる",
        "regex", "present", r"^aaa authentication login (?:default|console) (?:group|local)\b", reference=REF_VENDOR,
        remediation="""
# 先にサーバーのグループを作り、別のセッションを開いたまま確かめてください
feature tacacs+
aaa authentication login default group <サーバーグループ名>
""",
        good="aaa authentication login default group TAC-GRP\n", bad="hostname Core-SW01\n",
    ),
    tpl(
        "NX-OS: ログインバナーを設定する", "low", NXOS, "バナー",
        "無断利用への警告などを示すバナー（banner motd）を設定する",
        "regex", "present", r"^banner (?:motd|exec) \S", reference=REF_OPS,
        remediation="""
# % はバナーの区切り文字です（本文に % を含めないでください）
banner motd %
<許可された利用者以外の利用を禁止する旨の警告文>
%
""",
        good="banner motd #Authorized use only#\n", bad="hostname Core-SW01\n",
    ),
]
