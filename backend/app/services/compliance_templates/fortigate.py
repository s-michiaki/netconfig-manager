"""FortiGate（FortiOS）のひな形（書式は show）

show は既定値と同じ設定を出力しないので、既定値を前提にした判定は「違反する設定がある」形にしている

字下げは 4 文字。config ... end のまとまりを 1 つのセクション（行頭に空白の無い行が見出し）として扱う
"""
from ._base import REF_GENERAL, REF_OPS, REF_VENDOR, tpl

FGT = ["fortinet"]

TEMPLATES = [
    tpl(
        "FortiGate: 管理アクセスに Telnet / HTTP を許可しない", "high", FGT, "管理アクセス",
        "インターフェースの allowaccess に telnet・http（暗号化されない管理アクセス）を含めない",
        "regex", "absent", r"^\s*set allowaccess .*\b(telnet|http)\b",
        remediation="""
# allowaccess は一覧ごと置き換わります。必要なものだけを指定してください（接続が切れることがあります）
config system interface
    edit "<インターフェース名>"
        set allowaccess ping https ssh
    next
end
""",
        good='config system interface\n    edit "port1"\n        set allowaccess ping https ssh\n    next\nend\n',
        bad='config system interface\n    edit "port1"\n        set allowaccess ping https http telnet\n    next\nend\n',
    ),
    tpl(
        "FortiGate: 管理者のアイドルタイムアウト", "low", FGT, "管理アクセス",
        "管理画面・CLI の無操作時の自動ログアウトを長くしすぎない（30 分以上を違反とする。既定は 5 分）",
        "regex", "absent", r"^\s*set admintimeout (\d{3,}|[3-9]\d)$",
        remediation="""
config system global
    set admintimeout 10
end
""",
        good="config system global\n    set admintimeout 10\nend\n",
        bad="config system global\n    set admintimeout 60\nend\n",
    ),
    tpl(
        "FortiGate: 既定の admin 名を使わない", "low", FGT, "認証",
        "管理者に既定の名前「admin」を使わない。名前の変更・削除ができない版では違反が残るため、例外として扱う",
        "regex", "absent", r'^\s+edit "admin"\s*$', scope="section", section_pattern=r"^config system admin\s*$",
        reference=REF_GENERAL,
        remediation="""
# 別の管理者でログインできることを確かめてから、admin を削除（または名前を変更）します
config system admin
    edit "<管理者名>"
        set accprofile "super_admin"
        set password <パスワード>
    next
    delete "admin"
end
""",
        good='config system admin\n    edit "netadmin"\n        set accprofile "super_admin"\n    next\nend\n',
        bad='config system admin\n    edit "admin"\n        set accprofile "super_admin"\n    next\nend\n',
    ),
    tpl(
        "FortiGate: 管理者に接続元の制限（trusthost）を付ける", "medium", FGT, "管理アクセス",
        "管理者に trusthost を設定して、管理用のネットワークからだけログインできるようにする。"
        "管理者が複数いるときは、1 人でも設定があれば合格になる",
        "regex", "present", r"^\s*set trusthost1 \S+ \S+", reference=REF_VENDOR,
        remediation="""
# 管理ネットワークを誤ると、その管理者でログインできなくなります。別の管理者でも確認してください
config system admin
    edit "<管理者名>"
        set trusthost1 <管理ネットワーク> <サブネットマスク>
    next
end
""",
        good='config system admin\n    edit "netadmin"\n        set trusthost1 192.0.2.0 255.255.255.0\n    next\nend\n',
        bad='config system admin\n    edit "netadmin"\n        set accprofile "super_admin"\n    next\nend\n',
    ),
    tpl(
        "FortiGate: ログイン失敗の回数を増やしすぎない", "low", FGT, "認証",
        "管理者のロックアウトまでの失敗回数（admin-lockout-threshold）を 6 回以上にしない（既定は 3 回）",
        "regex", "absent", r"^\s*set admin-lockout-threshold (?:[6-9]|\d\d+)\s*$",
        remediation="""
config system global
    set admin-lockout-threshold 3
    set admin-lockout-duration 60
end
""",
        good="config system global\n    set admin-lockout-threshold 3\nend\n",
        bad="config system global\n    set admin-lockout-threshold 10\nend\n",
    ),
    tpl(
        "FortiGate: パスワードポリシーの設定がある", "medium", FGT, "認証",
        "管理者のパスワードの条件（system password-policy）の設定があること。次の「パスワードポリシーを有効にする」と組で使う。"
        "この件は、設定の見出しが出ない（既定のままの）機器を違反にする。見出しはあるが status が無効の機器は、"
        "次の件が違反にする（既定のままの機器が見出しを空のまとまりとして出す版では次の件が、出さない版ではこの件が違反を出す）",
        "regex", "present", r"^config system password-policy\s*$",
        remediation="""
config system password-policy
    set status enable
    set minimum-length 12
end
""",
        good="config system password-policy\n    set status disable\nend\n", bad="config system global\nend\n",
        extra_good=["config system password-policy\nend\n"],
    ),
    tpl(
        "FortiGate: パスワードポリシーを有効にする", "medium", FGT, "認証",
        "system password-policy のまとまりの中に status enable があること（status の既定は無効）。"
        "前の「パスワードポリシーの設定がある」と組で使う。"
        "この件は、見出しはあるが status が無効・無い（空のまとまりを含む）機器を違反にする。見出しが出ない機器は検出できない",
        "regex", "present", r"^\s+set status enable\b", scope="section", section_pattern=r"^config system password-policy\s*$",
        remediation="""
config system password-policy
    set status enable
    set minimum-length 12
end
""",
        good="config system password-policy\n    set status enable\nend\n",
        bad="config system password-policy\n    set status disable\nend\n",
        extra_good=["config system global\nend\n"],
        extra_bad=["config system password-policy\nend\n",
                   "config system password-policy\n    set minimum-length 12\nend\n"],
    ),
    tpl(
        "FortiGate: 強い暗号化を無効にしない", "medium", FGT, "暗号",
        "strong-crypto（弱い暗号方式・TLS の古い版を使わない）を無効（disable）にしない",
        "regex", "absent", r"^\s*set strong-crypto disable\b",
        remediation="""
config system global
    set strong-crypto enable
end
""",
        good="config system global\n    set strong-crypto enable\nend\n",
        bad="config system global\n    set strong-crypto disable\nend\n",
    ),
    tpl(
        "FortiGate: 古い SSH（v1）を許可しない", "high", FGT, "暗号",
        "管理用の SSH で v1（admin-ssh-v1）を有効にしない",
        "regex", "absent", r"^\s*set admin-ssh-v1 enable\b",
        remediation="""
config system global
    set admin-ssh-v1 disable
end
""",
        good="config system global\n    set admintimeout 10\nend\n",
        bad="config system global\n    set admin-ssh-v1 enable\nend\n",
    ),
    tpl(
        "FortiGate: 管理画面で古い TLS を使わない", "medium", FGT, "暗号",
        "admin-https-ssl-versions に sslv3・tlsv1-0・tlsv1-1 を含めない",
        "regex", "absent", r"^\s*set admin-https-ssl-versions .*\b(?:sslv3|tlsv1-0|tlsv1-1)\b",
        remediation="""
# 古いブラウザや管理ツールから接続できなくなることがあります
config system global
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
end
""",
        good="config system global\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend\n",
        bad="config system global\n    set admin-https-ssl-versions tlsv1-1 tlsv1-2\nend\n",
    ),
    tpl(
        "FortiGate: HTTP から HTTPS へのリダイレクトを切らない", "low", FGT, "管理アクセス",
        "管理画面で HTTP から HTTPS へのリダイレクト（admin-https-redirect）を無効にしない",
        "regex", "absent", r"^\s*set admin-https-redirect disable\b",
        remediation="""
config system global
    set admin-https-redirect enable
end
""",
        good="config system global\n    set admin-https-redirect enable\nend\n",
        bad="config system global\n    set admin-https-redirect disable\nend\n",
    ),
    tpl(
        "FortiGate: ログイン前のバナーを設定する", "low", FGT, "バナー",
        "管理画面のログイン前に警告文を表示する（pre-login-banner）",
        "regex", "present", r"^\s*set pre-login-banner enable\b", reference=REF_OPS,
        remediation="""
config system global
    set pre-login-banner enable
end
""",
        good="config system global\n    set pre-login-banner enable\nend\n", bad="config system global\nend\n",
    ),
    tpl(
        "FortiGate: 既定の SNMP コミュニティを使わない", "high", FGT, "SNMP",
        "SNMP のコミュニティ名に public / private を使わない",
        "regex", "absent", r'^\s+set name "(?:public|private)"\s*$', scope="section",
        section_pattern=r"^config system snmp community\s*$",
        remediation="""
# 先に別のコミュニティ（または SNMPv3）へ監視システムの設定を切り替えてから、置き換えます
config system snmp community
    edit <ID>
        set name "<新しいコミュニティ名>"
    next
end
""",
        good='config system snmp community\n    edit 1\n        set name "Example-Mon"\n    next\nend\n',
        bad='config system snmp community\n    edit 1\n        set name "public"\n    next\nend\n',
    ),
    tpl(
        "FortiGate: NTP サーバーを指定する", "low", FGT, "時刻",
        "時刻同期の NTP サーバーを指定する（config ntpserver）。既定の FortiGuard の NTP を使う環境では違反になる",
        "regex", "present", r"^\s+config ntpserver\b",
        remediation="""
config system ntp
    set type custom
    config ntpserver
        edit 1
            set server "<NTP サーバーのホスト名または IP>"
        next
    end
end
""",
        good=("config system ntp\n    set type custom\n    config ntpserver\n        edit 1\n"
              '            set server "ntp.example.test"\n        next\n    end\nend\n'),
        bad="config system ntp\n    set ntpsync enable\nend\n",
    ),
    tpl(
        "FortiGate: ログの転送先の設定がある（Syslog / FortiAnalyzer）", "low", FGT, "ログ",
        "ログの転送先（syslogd・fortianalyzer の設定）があること。次の「ログの転送を有効にする」と組で使う。"
        "この件は、設定の見出しが出ない（既定のままの）機器を違反にする。見出しはあるが status が無効の機器は、"
        "次の件が違反にする（既定のままの機器が見出しを空のまとまりとして出す版では次の件が、出さない版ではこの件が違反を出す）",
        "regex", "present", r"^config log (?:syslogd[2-4]?|fortianalyzer[2-3]?) setting\s*$",
        remediation="""
config log syslogd setting
    set status enable
    set server "<syslog サーバーのホスト名または IP>"
end
""",
        good='config log syslogd setting\n    set status disable\nend\n', bad="config system global\nend\n",
        extra_good=["config log fortianalyzer setting\nend\n"],
    ),
    tpl(
        "FortiGate: ログの転送を有効にする（Syslog / FortiAnalyzer）", "low", FGT, "ログ",
        "ログの転送先のまとまりの中に status enable があること。前の「ログの転送先の設定がある」と組で使う。"
        "この件は、見出しはあるが status が無効・無い機器を違反にする。見出しが出ない機器は検出できない。"
        "syslogd と fortianalyzer など複数のまとまりがあるときは、すべてのまとまりに status enable を求める"
        "（片方だけ有効な機器も、無効なまとまりが違反になる。「どれか 1 つが有効なら合格」にはできない）。"
        "使わない転送先を残している場合は、そのまとまりを例外にするか、設定を消す",
        "regex", "present", r"^\s+set status enable\b", scope="section",
        section_pattern=r"^config log (?:syslogd[2-4]?|fortianalyzer[2-3]?) setting\s*$",
        remediation="""
config log syslogd setting
    set status enable
    set server "<syslog サーバーのホスト名または IP>"
end
""",
        good='config log syslogd setting\n    set status enable\n    set server "192.0.2.5"\nend\n',
        bad='config log syslogd setting\n    set status disable\nend\n',
        extra_good=["config system global\nend\n"],
        extra_bad=[
            "config log syslogd setting\n    set status enable\nend\n"
            "config log fortianalyzer setting\n    set status disable\nend\n",
            "config log syslogd setting\nend\n",
        ],
    ),
]
