"""Cisco IOS / IOS-XE のひな形（書式は show running-config）"""
from ._base import REF_GENERAL, REF_OPS, REF_VENDOR, tpl
from .common import IOS

TEMPLATES = [
    tpl(
        "パスワードの暗号化表示", "medium", IOS, "認証",
        "コンフィグ上のパスワードを暗号化して表示する（service password-encryption）。"
        "表示の暗号化は可逆（タイプ 7）なので、コンフィグを見られても困らないようにする補助の位置づけ",
        "regex", "present", r"^service password-encryption",
        remediation="service password-encryption",
        good="service password-encryption\n", bad="hostname R1\n",
    ),
    tpl(
        "enable secret を使う", "high", IOS, "認証",
        "enable password（弱いハッシュ）ではなく enable secret を使う",
        "regex", "absent", r"^enable password ",
        remediation="""
# 機種・バージョンによっては algorithm-type scrypt（タイプ 9）が使えます
enable secret <特権モードのパスワード>
no enable password
""",
        good="enable secret 9 $9$abcdef\n", bad="enable password Example-Pass\n",
    ),
    tpl(
        "HTTP サーバーの無効化", "medium", IOS, "管理アクセス",
        "Web 管理画面（ip http server）を無効にする",
        "regex", "absent", r"^ip http server",
        remediation="""
# Web 画面を使っている管理者は接続できなくなります。使うなら HTTPS（ip http secure-server）に限ります
no ip http server
""",
        good="ip http secure-server\n", bad="ip http server\n",
    ),
    tpl(
        "SSH バージョン2", "high", IOS, "管理アクセス",
        "SSH はバージョン2のみ許可する",
        "regex", "present", r"^ip ssh version 2",
        remediation="""
# 鍵が無いときは、ホスト名とドメイン名を設定してから作ります（既存の鍵があると置き換わります）
ip domain name <ドメイン名>
crypto key generate rsa modulus 2048
ip ssh version 2
""",
        good="ip ssh version 2\n", bad="hostname R1\n",
    ),
    tpl(
        "VTY で Telnet を許可しない", "high", IOS, "管理アクセス",
        "line vty の transport input に telnet を含めない",
        "regex", "absent", r"transport input .*(telnet|all)", scope="section", section_pattern=r"^line vty",
        remediation="""
# 変更前に、別のセッションで SSH ログインできることを確かめてください（Telnet の接続は切れます）
line vty 0 15
 transport input ssh
""",
        good="line vty 0 4\n transport input ssh\n!\n", bad="line vty 0 4\n transport input ssh telnet\n!\n",
    ),
    tpl(
        "Syslog の転送先", "low", IOS, "ログ",
        "ログを Syslog サーバーへ転送する",
        "regex", "present", r"^logging (host )?\d",
        remediation="""
logging host <syslog サーバーの IP>
logging trap informational
""",
        good="logging host 192.0.2.5\n", bad="hostname R1\n",
    ),
    # ---- ここから追加分
    tpl(
        "AAA を有効にする（aaa new-model）", "medium", IOS, "認証",
        "ログインの認証を AAA（ローカル・RADIUS・TACACS+）で扱えるようにする。使わない運用では違反になる",
        "regex", "present", r"^aaa new-model\b", reference=REF_VENDOR,
        remediation="""
# 有効にするとログインの方式が変わります。先にローカルユーザーを作り、別のセッションを開いたまま確かめてください
username <ユーザー名> privilege 15 secret <パスワード>
aaa new-model
aaa authentication login default local
""",
        good="aaa new-model\n", bad="hostname R1\n",
    ),
    tpl(
        "VTY のアイドルタイムアウトを無制限にしない", "medium", IOS, "管理アクセス",
        "line vty の exec-timeout を 0（無制限）にしない。放置したセッションが残り続けるのを防ぐ",
        "regex", "absent", r"^\s+(?:exec-timeout 0(?: 0)?|no exec-timeout)\s*$", scope="section",
        section_pattern=r"^line vty",
        remediation="""
line vty 0 15
 exec-timeout 10 0
""",
        good="line vty 0 4\n exec-timeout 10 0\n!\n", bad="line vty 0 4\n exec-timeout 0 0\n!\n",
    ),
    tpl(
        "VTY の接続元を ACL で制限する", "medium", IOS, "管理アクセス",
        "line vty に access-class（in）を付け、管理用の端末・ネットワークからだけ接続できるようにする。"
        "管理の接続元を別の仕組み（コントロールプレーンの保護など）で制限している環境では違反になる",
        "regex", "present", r"^\s+access-class \S+ in\b", scope="section", section_pattern=r"^line vty",
        reference=REF_VENDOR,
        remediation="""
# 管理端末のネットワークを誤ると、管理接続できなくなります。コンソールから戻せる状態で行ってください
ip access-list standard <ACL 名>
 permit <管理ネットワーク> <ワイルドカードマスク>
line vty 0 15
 access-class <ACL 名> in
""",
        good="line vty 0 4\n access-class MGMT in\n transport input ssh\n!\n",
        bad="line vty 0 4\n transport input ssh\n!\n",
    ),
    tpl(
        "ログイン失敗の制限（login block-for）", "low", IOS, "認証",
        "ログインに続けて失敗したら、一定時間ログインを受け付けなくする（総当たり攻撃の対策）。"
        "管理用のホストからの接続は quiet-mode access-class で除けます",
        "regex", "present", r"^login block-for \d+ attempts \d+ within \d+",
        remediation="""
# 管理者自身が締め出されることがあります。許可する接続元を quiet-mode access-class で指定できます
login block-for <待ち時間(秒)> attempts <失敗の回数> within <数える期間(秒)>
""",
        good="login block-for 120 attempts 5 within 60\n", bad="hostname R1\n",
    ),
    tpl(
        "ローカルユーザーを password（弱い保存）で作らない", "medium", IOS, "認証",
        "username に password を使うと、タイプ 0 / 7 のように復元できる形で保存される。secret を使う",
        "regex", "absent", r"^username \S+ (?:privilege \d+ )?password\b",
        remediation="""
# 変更後に、新しいパスワードでログインできることを別のセッションで確かめてください
username <ユーザー名> privilege <レベル> secret <パスワード>
""",
        good="username admin privilege 15 secret 9 $9$abcdef\n",
        bad="username admin privilege 15 password 7 0822455D0A16\n",
    ),
    tpl(
        "CDP を使わない（no cdp run）", "low", IOS, "サービス",
        "CDP は隣の機器に機種・バージョン・アドレスを知らせる。使わないなら止める。"
        "IP 電話や管理ツールが CDP に頼っている環境では違反になる",
        "regex", "present", r"^no cdp run\b", reference=REF_GENERAL,
        remediation="""
# 機器全体で止めます。外向きのポートだけ止めるときは、インターフェースで no cdp enable
no cdp run
""",
        good="no cdp run\n", bad="hostname R1\n",
    ),
    tpl(
        "ソースルーティングを無効にする", "low", IOS, "サービス",
        "送信元が経路を指定できる IP ソースルーティングを無効にする（no ip source-route）。"
        "新しい版では既定で無効のため、行が出ず違反と出ることがあります（既定値の変更は公式ドキュメントでは確かめられていません）",
        "regex", "present", r"^no ip source-route\b",
        remediation="no ip source-route",
        good="no ip source-route\n", bad="hostname R1\n",
    ),
    tpl(
        "ログインバナーを設定する", "low", IOS, "バナー",
        "無断利用への警告などを示すバナー（banner login / motd / exec）を設定する",
        "regex", "present", r"^banner (?:login|motd|exec) \S", reference=REF_OPS,
        remediation="""
# % はバナーの区切り文字です（本文に % を含めないでください）
banner login %
<許可された利用者以外の利用を禁止する旨の警告文>
%
""",
        good="banner login ^CAuthorized use only^C\n", bad="hostname R1\n",
    ),
    tpl(
        "ログに日時を付ける", "low", IOS, "ログ",
        "ログの各行に日時を付ける（service timestamps log datetime）。原因の調査で時刻が分からなくなるのを防ぐ",
        "regex", "present", r"^service timestamps log datetime\b",
        remediation="service timestamps log datetime msec",
        good="service timestamps log datetime msec\n", bad="hostname R1\n",
    ),
    tpl(
        "Smart Install を無効にする（no vstack）", "low", IOS, "サービス",
        "スイッチの Smart Install（TCP 4786）は、不正な設定の書き換えに悪用されたことがあるため無効にする。"
        "スイッチ向けです。この機能の無い機種（ルーターなど）では必ず違反になるので、対象から外してください",
        "regex", "present", r"^no vstack\b", reference=REF_VENDOR,
        remediation="no vstack",
        good="no vstack\n", bad="hostname Core-SW01\n",
    ),
]
