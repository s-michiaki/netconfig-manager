"""Yamaha RTX / NVR のひな形（書式は show config。パスワードは * で出る）

プラットフォーム yamaha には SWX シリーズも含まれるが、SWX は CLI が異なるため、このひな形の対象外

SNMP・UPnP などは、書式を確かめきれていないため入れていない
"""
from ._base import ADJUST, REF_GENERAL, REF_VENDOR, tpl

YAMAHA = ["yamaha"]

TEMPLATES = [
    tpl(
        "Yamaha: ログイン用パスワードを設定する", "high", YAMAHA, "認証",
        "一般ユーザーのログインパスワード（login password）を設定する",
        "regex", "present", r"^login password\b",
        remediation="""
# パスワードは対話形式で入力します（この画面には書きません）
login password
""",
        good="login password *\n", bad="ip route default gateway pp 1\n",
    ),
    tpl(
        "Yamaha: 管理パスワードを設定する", "high", YAMAHA, "認証",
        "管理者のパスワード（administrator password）を設定する",
        "regex", "present", r"^administrator password\b",
        remediation="""
# パスワードは対話形式で入力します（この画面には書きません）
administrator password
""",
        good="administrator password *\n", bad="ip route default gateway pp 1\n",
    ),
    tpl(
        "Yamaha: Telnet サーバーを停止する", "medium", YAMAHA, "管理アクセス",
        "暗号化されない Telnet（telnetd）を停止する。SSH（sshd）で管理する",
        "regex", "present", r"^telnetd service off\b",
        remediation="""
# パスワード認証の SSH は、名前のある利用者（login user）を登録しないとログインできません（締め出しに注意）
# 先に SSH でログインできることを確かめてから、最後の行で Telnet を止めてください
login user <ユーザー名> <パスワード>
sshd service on
sshd host key generate
telnetd service off
""",
        good="telnetd service off\nsshd service on\n", bad="telnetd host lan\n",
    ),
    tpl(
        "Yamaha: SSH サーバーを有効にする", "low", YAMAHA, "管理アクセス",
        "暗号化された管理のため SSH サーバー（sshd service on）を有効にする",
        "regex", "present", r"^sshd service on\b",
        remediation="""
# パスワード認証の SSH は、名前のある利用者（login user）を登録しないとログインできません
login user <ユーザー名> <パスワード>
sshd service on
sshd host key generate
""",
        good="sshd service on\nsshd host key generate *\n", bad="telnetd service off\n",
    ),
    tpl(
        "Yamaha: 管理サービスの接続元を any にしない", "medium", YAMAHA, "管理アクセス",
        "telnetd・sshd の host を any（どこからでも）にしない。LAN など管理用のネットワークに絞る"
        "（httpd は書式を確かめていないため対象外）",
        "regex", "absent", r"^(?:telnetd|sshd) host any\s*$", reference=REF_VENDOR,
        remediation="""
# 管理ネットワークを誤ると、管理接続できなくなります。コンソールから戻せる状態で行ってください
sshd host <接続を許可する IP の範囲 または lan>
telnetd host <接続を許可する IP の範囲 または lan>
""",
        good="sshd host lan\ntelnetd host lan\n", bad="sshd host any\n",
    ),
    tpl(
        "Yamaha: Syslog の転送先", "low", YAMAHA, "ログ",
        "ログを Syslog サーバーへ転送する（syslog host）",
        "regex", "present", r"^syslog host \S+",
        remediation="syslog host <syslog サーバーの IP>",
        good="syslog host 192.0.2.5\n", bad="ip route default gateway pp 1\n",
    ),
    tpl(
        "Yamaha: 時刻を NTP で合わせる", "low", YAMAHA, "時刻",
        "スケジュール（schedule）から ntpdate を実行して、時刻を NTP サーバーに合わせる",
        "regex", "present", r"^schedule at \d+ .*\bntpdate \S+", reference=REF_GENERAL,
        remediation="""
# 毎時 0 分に時刻を合わせる例です（schedule の書式は機種のコマンドリファレンスで確かめてください）
schedule at 1 */* *:00 * ntpdate <NTP サーバーのホスト名または IP>
""",
        good="schedule at 1 */* *:00 * ntpdate ntp.example.test\n", bad="ip route default gateway pp 1\n",
    ),
]

# プラットフォーム yamaha には SWX シリーズも含まれるが、書式は RTX / NVR のもの
for _t in TEMPLATES:
    _t["description"] = _t["description"].replace(
        ADJUST, f"RTX / NVR 向けです（SWX シリーズは CLI が異なるため対象外）。{ADJUST}")
