"""Cisco ASA のひな形（書式は show running-config。SNMP のコミュニティ名は伏せ字で出るので判定しない）"""
from ._base import REF_GENERAL, REF_OPS, REF_VENDOR, tpl

ASA = ["cisco_asa"]

TEMPLATES = [
    tpl(
        "ASA: SSH はバージョン 2 のみ", "medium", ASA, "管理アクセス",
        "SSH はバージョン 2 のみを許可する（ssh version 2）。新しい版（9.16 以降）では既定の扱いが変わり、"
        "行が出ず違反と出ることがあります（running-config への表示は公式ドキュメントでは確かめられていません）",
        "regex", "present", r"^ssh version 2\b",
        remediation="ssh version 2",
        good="ssh version 2\n", bad="hostname fw1\n",
    ),
    tpl(
        "ASA: Telnet で管理させない", "high", ASA, "管理アクセス",
        "暗号化されない Telnet（telnet <ネットワーク> <インターフェース>）の接続元を設定しない",
        "regex", "absent", r"^telnet (?!timeout\b)\S+ \S+ \S+",
        remediation="""
# 変更前に、別のセッションで SSH ログインできることを確かめてください
clear configure telnet
ssh <管理ネットワーク> <サブネットマスク> <インターフェース名>
""",
        good="telnet timeout 5\nssh 192.0.2.0 255.255.255.0 inside\n",
        bad="telnet 192.0.2.0 255.255.255.0 inside\ntelnet timeout 5\n",
    ),
    tpl(
        "ASA: SSH の接続元を any にしない", "high", ASA, "管理アクセス",
        "ssh 0.0.0.0 0.0.0.0 <インターフェース>（どこからでも）を許可しない。管理用のネットワークに絞る",
        "regex", "absent", r"^ssh 0\.0\.0\.0 0\.0\.0\.0 \S+", reference=REF_VENDOR,
        remediation="""
# 先に管理ネットワークからの設定を入れてから、any の行を消してください（接続が切れることがあります）
ssh <管理ネットワーク> <サブネットマスク> <インターフェース名>
no ssh 0.0.0.0 0.0.0.0 <インターフェース名>
""",
        good="ssh 192.0.2.0 255.255.255.0 inside\n", bad="ssh 0.0.0.0 0.0.0.0 outside\n",
    ),
    tpl(
        "ASA: ASDM（HTTPS）の接続元を any にしない", "high", ASA, "管理アクセス",
        "http 0.0.0.0 0.0.0.0 <インターフェース>（どこからでも ASDM に接続）を許可しない",
        "regex", "absent", r"^http 0\.0\.0\.0 0\.0\.0\.0 \S+", reference=REF_VENDOR,
        remediation="""
# 先に管理ネットワークからの設定を入れてから、any の行を消してください（接続が切れることがあります）
http <管理ネットワーク> <サブネットマスク> <インターフェース名>
no http 0.0.0.0 0.0.0.0 <インターフェース名>
""",
        good="http server enable\nhttp 192.0.2.0 255.255.255.0 inside\n", bad="http 0.0.0.0 0.0.0.0 inside\n",
    ),
    tpl(
        "ASA: SSH のタイムアウトを長くしない", "low", ASA, "管理アクセス",
        "ssh timeout（分）を 30 分以上にしない（既定は 5 分）",
        "regex", "absent", r"^ssh timeout (?:[3-5]\d|60)\s*$",
        remediation="ssh timeout 10",
        good="ssh timeout 10\n", bad="ssh timeout 60\n",
    ),
    tpl(
        "ASA: 管理ログインに AAA を使う", "low", ASA, "認証",
        "SSH でのログインの認証方式（aaa authentication ssh console）を設定する",
        "regex", "present", r"^aaa authentication ssh console \S+",
        remediation="""
# LOCAL のときはローカルユーザー（username <ユーザー名> password <パスワード> privilege 15）を先に作ります
aaa authentication ssh console <サーバーグループ名 または LOCAL>
""",
        good="aaa authentication ssh console LOCAL\n", bad="hostname fw1\n",
    ),
    tpl(
        "ASA: ログを有効にする", "medium", ASA, "ログ",
        "ログの記録（logging enable）を有効にする",
        "regex", "present", r"^logging enable\b",
        remediation="logging enable",
        good="logging enable\n", bad="hostname fw1\n",
    ),
    tpl(
        "ASA: Syslog の転送先", "low", ASA, "ログ",
        "ログを Syslog サーバーへ転送する（logging host）",
        "regex", "present", r"^logging host \S+ \S+",
        remediation="""
logging host <インターフェース名> <syslog サーバーの IP>
logging trap informational
""",
        good="logging host inside 192.0.2.5\n", bad="logging enable\n",
    ),
    tpl(
        "ASA: ログに日時を付ける", "low", ASA, "ログ",
        "ログの各行に日時を付ける（logging timestamp）",
        "regex", "present", r"^logging timestamp\b",
        remediation="logging timestamp",
        good="logging timestamp\n", bad="logging enable\n",
    ),
    tpl(
        "ASA: NTP サーバーの設定", "low", ASA, "時刻",
        "時刻同期のため NTP サーバーを設定する",
        "regex", "present", r"^ntp server \S+",
        remediation="ntp server <NTP サーバーの IP> source <インターフェース名>",
        good="ntp server 192.0.2.1 source inside\n", bad="hostname fw1\n",
    ),
    tpl(
        "ASA: ログインバナーを設定する", "low", ASA, "バナー",
        "無断利用への警告などを示すバナー（banner login / motd / exec）を設定する",
        "regex", "present", r"^banner (?:login|motd|exec) \S", reference=REF_OPS,
        remediation="""
banner login <許可された利用者以外の利用を禁止する旨の警告文>
""",
        good="banner login Authorized use only\n", bad="hostname fw1\n",
    ),
    tpl(
        "ASA: 逆方向の経路検査（uRPF）を有効にする", "low", ASA, "サービス",
        "外部に面したインターフェースで送信元の偽装を防ぐ（ip verify reverse-path）。"
        "非対称な経路のある環境では通信が落ちることがあるため、導入前に確かめる",
        "regex", "present", r"^ip verify reverse-path interface \S+", reference=REF_GENERAL,
        remediation="""
# 非対称な経路があると、正当な通信も破棄されます
ip verify reverse-path interface <外部インターフェース名>
""",
        good="ip verify reverse-path interface outside\n", bad="hostname fw1\n",
    ),
]
