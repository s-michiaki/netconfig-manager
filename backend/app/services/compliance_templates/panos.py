"""Palo Alto PAN-OS のひな形（書式は set 形式。収集は set cli config-output-format set のうえ、設定モードの show で行う）"""
from ._base import REF_GENERAL, REF_OPS, REF_VENDOR, tpl

PAN = ["paloalto_panos"]

TEMPLATES = [
    tpl(
        "PAN-OS: Telnet 管理を無効化", "high", PAN, "管理アクセス",
        "管理インターフェースの Telnet を無効にする",
        "contains", "present", "deviceconfig system service disable-telnet yes",
        remediation="""
set deviceconfig system service disable-telnet yes
commit
""",
        good="set deviceconfig system service disable-telnet yes\n", bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: HTTP 管理を無効化", "high", PAN, "管理アクセス",
        "管理インターフェースの HTTP（暗号化されない Web 管理）を無効にする。HTTPS で管理する",
        "contains", "present", "deviceconfig system service disable-http yes",
        remediation="""
set deviceconfig system service disable-http yes
commit
""",
        good="set deviceconfig system service disable-http yes\n", bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: 管理インターフェースの接続元を制限する", "medium", PAN, "管理アクセス",
        "管理インターフェースへ接続できる IP アドレス（permitted-ip）を指定する",
        "regex", "present", r"^set deviceconfig system permitted-ip \S+",
        reference=REF_VENDOR,
        remediation="""
# 管理ネットワークを誤ると、管理接続できなくなります。コンソールから戻せる状態で行ってください
set deviceconfig system permitted-ip <管理ネットワーク/プレフィックス長>
commit
""",
        good="set deviceconfig system permitted-ip 192.0.2.0/24\n", bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: インターフェース管理プロファイルで Telnet / HTTP を許可しない", "high", PAN, "管理アクセス",
        "データ用のインターフェースの管理プロファイル（interface-management-profile）で、telnet・http を許可しない",
        "regex", "absent", r"^set network profiles interface-management-profile \S+ (?:telnet|http) yes\s*$",
        remediation="""
# プロファイルを使っているインターフェースからの管理接続が切れることがあります
delete network profiles interface-management-profile <プロファイル名> telnet
delete network profiles interface-management-profile <プロファイル名> http
set network profiles interface-management-profile <プロファイル名> https yes
commit
""",
        good="set network profiles interface-management-profile mgmt https yes\n",
        bad="set network profiles interface-management-profile mgmt telnet yes\n",
    ),
    tpl(
        "PAN-OS: 管理画面のアイドルタイムアウト", "low", PAN, "管理アクセス",
        "管理画面・CLI の無操作時の自動ログアウトを 30 分以内に設定する。既定は 60 分で行が出ないため、行があることを求める",
        "regex", "present",
        r"^set deviceconfig setting management idle-timeout (?:[1-9]|[12]\d|30)\s*$",
        remediation="""
set deviceconfig setting management idle-timeout 10
commit
""",
        good="set deviceconfig setting management idle-timeout 10\n",
        bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: 管理者のパスワードの強度を設定する", "medium", PAN, "認証",
        "パスワードの長さ・文字種の条件（password-complexity）を有効にする",
        "regex", "present", r"^set mgt-config password-complexity enabled yes",
        remediation="""
set mgt-config password-complexity enabled yes
set mgt-config password-complexity minimum-length 12
commit
""",
        good="set mgt-config password-complexity enabled yes\nset mgt-config password-complexity minimum-length 12\n",
        bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: ログイン失敗の回数を制限する", "low", PAN, "認証",
        "認証プロファイル（または管理設定）のロックアウトで、続けて失敗したログインを制限する",
        "regex", "present",
        r"^set (?:deviceconfig setting management admin-lockout"
        r"|shared authentication-profile \S+ lockout) failed-attempts [1-9]\d*",
        reference=REF_GENERAL,
        remediation="""
# ファイアウォールでは認証プロファイルのロックアウトで設定します
set shared authentication-profile <プロファイル名> lockout failed-attempts 5
set shared authentication-profile <プロファイル名> lockout lockout-time 30
commit
""",
        good="set shared authentication-profile local-auth lockout failed-attempts 5\n",
        bad="set shared authentication-profile local-auth method local-database\n",
    ),
    tpl(
        "PAN-OS: 既定の SNMP コミュニティを使わない", "high", PAN, "SNMP",
        "SNMP v2c のコミュニティ名に public / private を使わない",
        "regex", "absent",
        r"^set deviceconfig system snmp-setting .*\bsnmp-community-string (?:public|private)\b",
        remediation="""
# 先に別のコミュニティ（または SNMPv3）へ監視システムの設定を切り替えてから、置き換えます
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string <新しいコミュニティ名>
commit
""",
        good="set deviceconfig system snmp-setting access-setting version v2c snmp-community-string Example-Mon\n",
        bad="set deviceconfig system snmp-setting access-setting version v2c snmp-community-string public\n",
    ),
    tpl(
        "PAN-OS: NTP サーバーの設定", "low", PAN, "時刻",
        "時刻同期のため NTP サーバー（primary）を設定する",
        "regex", "present",
        r"^set deviceconfig system ntp-servers primary-ntp-server ntp-server-address \S+",
        remediation="""
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <NTP サーバーのホスト名または IP>
commit
""",
        good="set deviceconfig system ntp-servers primary-ntp-server ntp-server-address ntp.example.test\n",
        bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: Syslog サーバープロファイルの設定", "low", PAN, "ログ",
        "ログの転送先として Syslog サーバープロファイルを設定する（ログ転送の設定で使う）",
        "regex", "present", r"^set shared log-settings syslog \S+",
        remediation="""
set shared log-settings syslog <プロファイル名> server <サーバー名> server <syslog サーバーの IP>
commit
""",
        good="set shared log-settings syslog SYSLOG-PROF server S1 server 192.0.2.5\n",
        bad="set deviceconfig system hostname fw1\n",
    ),
    tpl(
        "PAN-OS: ログインバナーを設定する", "low", PAN, "バナー",
        "無断利用への警告などを示すバナー（login-banner / motd-and-banner）を設定する",
        "regex", "present", r"^set deviceconfig system (?:login-banner|motd-and-banner)\b", reference=REF_OPS,
        remediation="""
set deviceconfig system login-banner "<許可された利用者以外の利用を禁止する旨の警告文>"
commit
""",
        good='set deviceconfig system login-banner "Authorized use only"\n',
        bad="set deviceconfig system hostname fw1\n",
    ),
]
