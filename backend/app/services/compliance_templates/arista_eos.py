"""Arista EOS のひな形（書式は show running-config。字下げは 3 文字）。共通のもの（NTP・SNMP・説明）は common.py"""
from ._base import REF_OPS, REF_VENDOR, tpl

EOS = ["arista_eos"]

TEMPLATES = [
    tpl(
        "EOS: Telnet サーバーを有効にしない", "high", EOS, "管理アクセス",
        "management telnet を有効（no shutdown）にしない",
        "regex", "absent", r"^\s+no shutdown\b", scope="section", section_pattern=r"^management telnet\s*$",
        remediation="""
# 変更前に、別のセッションで SSH ログインできることを確かめてください（Telnet の接続は切れます）
management telnet
   shutdown
""",
        good="management telnet\n   shutdown\n!\n", bad="management telnet\n   no shutdown\n!\n",
    ),
    tpl(
        "EOS: eAPI を HTTP（暗号化なし）で使わない", "high", EOS, "管理アクセス",
        "management api http-commands で protocol http（暗号化されない）を使わない。HTTPS を使う",
        "regex", "absent", r"^\s+protocol http\s*$", scope="section",
        section_pattern=r"^management api http-commands\s*$",
        remediation="""
management api http-commands
   no protocol http
   protocol https
""",
        good="management api http-commands\n   protocol https\n   no shutdown\n!\n",
        bad="management api http-commands\n   protocol http\n   no shutdown\n!\n",
    ),
    tpl(
        "EOS: SSH のアイドルタイムアウトを設定する", "low", EOS, "管理アクセス",
        "management ssh の idle-timeout（分）を設定して、放置したセッションを切る。"
        "コンフィグ全体で探すため、management console など別のまとまりの idle-timeout でも合格になります。"
        "management ssh の既定の機器は、行が出ないので違反になります",
        "regex", "present", r"^\s+idle-timeout [1-9]\d*\s*$",
        remediation="""
management ssh
   idle-timeout 15
""",
        good="management ssh\n   idle-timeout 15\n!\n", bad="management ssh\n   server-port 22\n!\n",
    ),
    tpl(
        "EOS: 管理の SSH を ACL で制限する", "medium", EOS, "管理アクセス",
        "management ssh に ip access-group（in）を付け、管理用のネットワークからだけ接続できるようにする。"
        "management ssh のまとまりが無い機器は、検出できません",
        "regex", "present", r"^\s+ip access-group \S+(?: vrf \S+)? in\b", scope="section",
        section_pattern=r"^management ssh\s*$", reference=REF_VENDOR,
        remediation="""
# 管理ネットワークを誤ると、管理接続できなくなります。コンソールから戻せる状態で行ってください
ip access-list <ACL 名>
   permit ip <管理ネットワーク/プレフィックス長> any
management ssh
   ip access-group <ACL 名> in
""",
        good="management ssh\n   ip access-group MGMT in\n!\n", bad="management ssh\n   idle-timeout 15\n!\n",
    ),
    tpl(
        "EOS: パスワードなしのユーザーを作らない", "high", EOS, "認証",
        "username に nopassword（パスワードなしでログインできる）を指定しない",
        "regex", "absent", r"^username \S+ .*\bnopassword\b",
        remediation="""
username <ユーザー名> privilege 15 role network-admin secret <パスワード>
""",
        good="username admin privilege 15 role network-admin secret sha512 $6$abcdef\n",
        bad="username admin privilege 15 role network-admin nopassword\n",
    ),
    tpl(
        "EOS: ログイン認証に AAA を使う", "low", EOS, "認証",
        "ログインの認証方式（aaa authentication login）を設定する。ローカルだけで運用する環境では違反になる",
        "regex", "present", r"^aaa authentication login ", reference=REF_VENDOR,
        remediation="""
# 先にサーバーグループを作り、別のセッションを開いたまま確かめてください
aaa authentication login default group <サーバーグループ名> local
""",
        good="aaa authentication login default group tacacs+ local\n", bad="hostname sw1\n",
    ),
    tpl(
        "EOS: Syslog の転送先", "low", EOS, "ログ",
        "ログを Syslog サーバーへ転送する",
        "regex", "present", r"^logging (?:vrf \S+ )?host \S+",
        remediation="""
# 管理用の VRF を使う環境では logging vrf <VRF名> host ... とします
logging host <syslog サーバーの IP>
""",
        good="logging host 192.0.2.5\n", bad="hostname sw1\n",
    ),
    tpl(
        "EOS: SNMPv3 を使う", "low", EOS, "SNMP",
        "SNMP は認証・暗号化のある v3 のグループを設定する。v1 / v2c だけで運用している機器が違反になる",
        "regex", "present", r"^snmp-server group \S+ v3 (?:auth|priv)\b", reference=REF_VENDOR,
        remediation="""
# 認証・暗号化に使うパスワードは機器へ直接入力します（この画面には書きません）
snmp-server group <グループ名> v3 priv
snmp-server user <ユーザー名> <グループ名> v3 auth sha <認証パスワード> priv aes <暗号化パスワード>
""",
        good="snmp-server group MON-GRP v3 priv\n", bad="snmp-server community Example-Mon ro\n",
    ),
    tpl(
        "EOS: ログインバナーを設定する", "low", EOS, "バナー",
        "無断利用への警告などを示すバナー（banner login / motd）を設定する",
        "regex", "present", r"^banner (?:login|motd)\b", reference=REF_OPS,
        remediation="""
# 入力は EOF だけの行で終わります
banner login
<許可された利用者以外の利用を禁止する旨の警告文>
EOF
""",
        good="banner login\nAuthorized use only\nEOF\n", bad="hostname sw1\n",
    ),
]
