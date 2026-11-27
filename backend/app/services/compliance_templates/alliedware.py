"""AlliedWare Plus のひな形（書式は show running-config）。共通のもの（NTP・SNMP）は common.py"""
from ._base import REF_OPS, REF_VENDOR, tpl

AW = ["allied_telesis_awplus"]

TEMPLATES = [
    tpl(
        "AW+: Telnet サーバーを無効化", "high", AW, "管理アクセス",
        "Telnet での管理アクセスを無効にする（no service telnet）",
        "regex", "present", r"^no service telnet",
        remediation="""
# 変更前に、別のセッションで SSH ログインできることを確かめてください（Telnet の接続は切れます）
no service telnet
""",
        good="no service telnet\nservice ssh\n", bad="service telnet\nservice ssh\n",
    ),
    tpl(
        "AW+: HTTP サーバーを無効化", "medium", AW, "管理アクセス",
        "Web 管理画面（service http）を使わない場合は無効にする",
        "regex", "present", r"^no service http\b",
        remediation="no service http",
        good="no service http\n", bad="service http\n",
    ),
    tpl(
        "AW+: SSH サーバーを有効にする", "medium", AW, "管理アクセス",
        "暗号化された管理のため SSH サーバー（service ssh）を有効にする",
        "regex", "present", r"^service ssh\b",
        remediation="service ssh",
        good="service ssh\n", bad="no service telnet\n",
    ),
    tpl(
        "AW+: SSH はバージョン 2 のみ", "medium", AW, "暗号",
        "SSH サーバーをバージョン 2 のみに限る（ssh server v2only。既定は v1 も許可）",
        "regex", "present", r"^ssh server v2only\b",
        remediation="ssh server v2only",
        good="service ssh\nssh server v2only\n", bad="service ssh\n",
    ),
    tpl(
        "AW+: パスワードの暗号化表示", "medium", AW, "認証",
        "コンフィグ上のパスワードを暗号化して表示する（service password-encryption）",
        "regex", "present", r"^service password-encryption\b",
        remediation="service password-encryption",
        good="service password-encryption\n", bad="no service telnet\n",
    ),
    tpl(
        "AW+: 既定のユーザー manager を使わない", "medium", AW, "認証",
        "初期設定のユーザー manager（既定のパスワードが広く知られている）を使い続けない",
        "regex", "absent", r"^username manager\b",
        remediation="""
# 新しい管理者でログインできることを確かめてから、manager を削除します
username <ユーザー名> privilege 15 password <パスワード>
no username manager
""",
        good="username netadmin privilege 15 password 8 $1$abcdef\n",
        bad="username manager privilege 15 password 8 $1$abcdef\n",
    ),
    tpl(
        "AW+: VTY のアイドルタイムアウトを無制限にしない", "medium", AW, "管理アクセス",
        "line vty の exec-timeout を 0（無制限）にしない",
        "regex", "absent", r"^\s+(?:exec-timeout 0(?: 0)?|no exec-timeout)\s*$", scope="section",
        section_pattern=r"^line vty",
        remediation="""
line vty 0 4
 exec-timeout 10
""",
        good="line vty 0 4\n exec-timeout 10\n!\n", bad="line vty 0 4\n exec-timeout 0\n!\n",
    ),
    tpl(
        "AW+: ログイン認証に AAA を使う", "low", AW, "認証",
        "ログインの認証方式（aaa authentication login default）を設定する。ローカルだけで運用する環境では違反になる",
        "regex", "present", r"^aaa authentication login default\b", reference=REF_VENDOR,
        remediation="""
# 先にサーバー（RADIUS / TACACS+）を登録し、別のセッションを開いたまま確かめてください
aaa authentication login default group <radius または tacacs+> local
""",
        good="aaa authentication login default group radius local\n", bad="no service telnet\n",
    ),
    tpl(
        "AW+: Syslog の転送先", "low", AW, "ログ",
        "ログを Syslog サーバーへ転送する（log host）",
        "regex", "present", r"^log host \S+",
        remediation="log host <syslog サーバーの IP>",
        good="log host 192.0.2.5\n", bad="no service telnet\n",
    ),
    tpl(
        "AW+: ログインバナーを設定する", "low", AW, "バナー",
        "無断利用への警告などを示すバナー（banner motd / login）を設定する",
        "regex", "present", r"^banner (?:motd|login)\b", reference=REF_OPS,
        remediation="""
banner motd <許可された利用者以外の利用を禁止する旨の警告文>
""",
        good="banner motd Authorized use only\n", bad="no service telnet\n",
    ),
]
