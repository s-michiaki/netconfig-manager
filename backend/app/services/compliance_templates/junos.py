"""Juniper JunOS のひな形（書式は show configuration | display set）

設定を反映するには commit が必要。管理接続に関わる変更は commit confirmed で確認つきにする
"""
from ._base import REF_GENERAL, REF_OPS, REF_VENDOR, tpl

JUNOS = ["juniper_junos"]

TEMPLATES = [
    tpl(
        "JunOS: root の SSH ログイン禁止", "high", JUNOS, "管理アクセス",
        "root ユーザーで SSH ログインできないようにする",
        "contains", "present", "set system services ssh root-login deny",
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
set system services ssh root-login deny
commit confirmed 5
""",
        good="set system services ssh root-login deny\n", bad="set system services ssh\n",
    ),
    tpl(
        "JunOS: Telnet サービスを有効にしない", "high", JUNOS, "管理アクセス",
        "暗号化されない Telnet（system services telnet）を有効にしない",
        "regex", "absent", r"^set system services telnet\b",
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
# 変更前に、別のセッションで SSH ログインできることを確かめてください（Telnet の接続は切れます）
delete system services telnet
commit confirmed 5
""",
        good="set system services ssh\n", bad="set system services telnet\n",
    ),
    tpl(
        "JunOS: FTP・rlogin・rsh・finger・平文の XML API を有効にしない", "high", JUNOS, "サービス",
        "暗号化されない、または古い管理用サービスを有効にしない（SSH 上の SFTP・NETCONF で代える）",
        "regex", "absent", r"^set system services (?:ftp|rlogin|rsh|finger|xnm-clear-text)\b",
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
# 使っているものだけ消します（自動化の仕組みが xnm-clear-text に頼っていないか確かめてください）
delete system services ftp
delete system services xnm-clear-text
commit confirmed 5
""",
        good="set system services ssh\nset system services netconf ssh\n",
        bad="set system services ssh\nset system services ftp\n",
    ),
    tpl(
        "JunOS: Web 管理を HTTP（暗号化なし）で使わない", "high", JUNOS, "管理アクセス",
        "web-management の http（暗号化されない）を有効にしない。使うなら https にする",
        "regex", "absent", r"^set system services web-management http\b",
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
delete system services web-management http
set system services web-management https system-generated-certificate
commit confirmed 5
""",
        good="set system services web-management https system-generated-certificate\n",
        bad="set system services web-management http interface ge-0/0/0.0\n",
    ),
    tpl(
        "JunOS: SSH プロトコルバージョン 1 を使わない", "high", JUNOS, "暗号",
        "SSH のプロトコルバージョンに v1 を指定しない",
        "regex", "absent", r"^set system services ssh protocol-version .*\bv1\b",
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
delete system services ssh protocol-version
set system services ssh protocol-version v2
commit confirmed 5
""",
        good="set system services ssh protocol-version v2\n", bad="set system services ssh protocol-version v1\n",
    ),
    tpl(
        "JunOS: SSH で弱い暗号方式を使わない", "medium", JUNOS, "暗号",
        "SSH の ciphers に CBC モード（3des-cbc・blowfish128-cbc・cast128-cbc・aes*-cbc）・arcfour を指定しない。"
        "古いクライアントは接続できなくなることがある",
        "regex", "absent", r"^set system services ssh ciphers (?:\S+-cbc|arcfour\S*)\s*$",
        reference=REF_VENDOR,
        remediation="""
# 接続を確かめたあとに commit で確定しないと、5 分後に元に戻ります
# 管理に使うクライアントが対応していることを確かめてから行います
delete system services ssh ciphers 3des-cbc
set system services ssh ciphers aes256-ctr
commit confirmed 5
""",
        good="set system services ssh ciphers aes256-ctr\n", bad="set system services ssh ciphers 3des-cbc\n",
    ),
    tpl(
        "JunOS: 既定の SNMP コミュニティを使わない", "high", JUNOS, "SNMP",
        "public / private のコミュニティ名は使わない",
        "regex", "absent", r"^set snmp community (?:public|private)\b",
        remediation="""
# 先に別のコミュニティ（または SNMPv3）へ監視システムの設定を切り替えてから削除します
delete snmp community <削除するコミュニティ名>
""",
        good="set snmp community Example-Mon authorization read-only\n",
        bad="set snmp community public authorization read-only\n",
    ),
    tpl(
        "JunOS: SNMP の書き込み可コミュニティを使わない", "high", JUNOS, "SNMP",
        "authorization read-write のコミュニティは、機器の設定を書き換えられてしまうため使わない",
        "regex", "absent", r"^set snmp community \S+ authorization read-write\b",
        remediation="""
set snmp community <コミュニティ名> authorization read-only
""",
        good="set snmp community Example-Mon authorization read-only\n",
        bad="set snmp community Example-Mon authorization read-write\n",
    ),
    tpl(
        "JunOS: SNMPv3 を使う", "low", JUNOS, "SNMP",
        "SNMP は認証・暗号化のある v3（usm / vacm）を設定する。v1 / v2c だけで運用している機器が違反になる",
        "regex", "present", r"^set snmp v3 (?:usm|vacm)\b", reference=REF_VENDOR,
        remediation="""
# 認証・暗号化に使うパスワードは機器へ直接入力します（この画面には書きません）。アクセス権（vacm）の設定も要ります
set snmp v3 usm local-engine user <ユーザー名> authentication-sha authentication-password <認証パスワード>
set snmp v3 usm local-engine user <ユーザー名> privacy-aes128 privacy-password <暗号化パスワード>
""",
        good="set snmp v3 usm local-engine user mon authentication-sha authentication-key \"$9$abc\"\n",
        bad="set snmp community Example-Mon authorization read-only\n",
    ),
    tpl(
        "JunOS: Syslog の転送先", "low", JUNOS, "ログ",
        "ログを Syslog サーバーへ転送する",
        "regex", "present", r"^set system syslog host \S+",
        remediation="set system syslog host <syslog サーバーの IP> any notice",
        good="set system syslog host 192.0.2.5 any notice\n", bad="set system host-name R1\n",
    ),
    tpl(
        "JunOS: NTP サーバーの設定", "low", JUNOS, "時刻",
        "時刻同期のため NTP サーバーを設定する",
        "regex", "present", r"^set system ntp server \S+",
        remediation="set system ntp server <NTP サーバーの IP>",
        good="set system ntp server 192.0.2.1\n", bad="set system host-name R1\n",
    ),
    tpl(
        "JunOS: NTP の認証を設定する", "low", JUNOS, "時刻",
        "なりすましの NTP サーバーで時刻を狂わされないよう、NTP の認証鍵を設定する。"
        "認証に対応していない NTP サーバーを使う環境では違反になる",
        "regex", "present", r"^set system ntp authentication-key \d+", reference=REF_VENDOR,
        remediation="""
# 鍵はサーバーと同じ値を機器へ直接入力します（この画面には書きません）
# type（md5 / sha1 / sha256）は機種・版によって使える範囲が違います
set system ntp authentication-key <鍵番号> type <認証の種類> value <鍵>
set system ntp trusted-key <鍵番号>
set system ntp server <NTP サーバーの IP> key <鍵番号>
""",
        good="set system ntp authentication-key 1 type sha256 value \"$9$abc\"\n",
        bad="set system ntp server 192.0.2.1\n",
    ),
    tpl(
        "JunOS: ログインバナーを設定する", "low", JUNOS, "バナー",
        "無断利用への警告などを示すメッセージ（system login message）を設定する",
        "regex", "present", r"^set system login message ", reference=REF_OPS,
        remediation="""
set system login message "<許可された利用者以外の利用を禁止する旨の警告文>"
""",
        good="set system login message \"Authorized use only\"\n", bad="set system host-name R1\n",
    ),
    tpl(
        "JunOS: ログイン失敗の回数を制限する", "low", JUNOS, "認証",
        "ログインに続けて失敗したら切断する（system login retry-options）",
        "regex", "present", r"^set system login retry-options tries-before-disconnect \d+", reference=REF_GENERAL,
        remediation="""
set system login retry-options tries-before-disconnect 3
set system login retry-options lockout-period 5
""",
        good="set system login retry-options tries-before-disconnect 3\n", bad="set system host-name R1\n",
    ),
    tpl(
        "JunOS: ログインクラスにアイドルタイムアウトを設定する", "low", JUNOS, "管理アクセス",
        "独自のログインクラスに idle-timeout（分）を設定して、放置したセッションを切る。"
        "組み込みのクラス（super-user など）だけを使う環境では違反になる",
        "regex", "present", r"^set system login class \S+ idle-timeout \d+",
        remediation="""
set system login class <クラス名> idle-timeout 15
""",
        good="set system login class ops idle-timeout 15\n", bad="set system login user admin class super-user\n",
    ),
]
