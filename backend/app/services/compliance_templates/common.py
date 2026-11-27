"""複数の機種に共通するひな形（Cisco IOS / IOS-XE・NX-OS・Arista EOS・AlliedWare Plus で書式が同じもの）

既存の 3 件（NTP・既定の SNMP コミュニティ・インターフェースの説明）の名前・条件は、
すでにこのひな形から作られたルールの「同じ名前」の判定に使われるので変えない
"""
from ._base import REF_VENDOR, tpl

IOS = ["cisco_ios", "cisco_xe"]
AWPLUS = ["allied_telesis_awplus"]

TEMPLATES = [
    tpl(
        "NTP サーバーの設定", "low", [*IOS, "cisco_nxos", "arista_eos", *AWPLUS], "時刻",
        "時刻同期のため NTP サーバーを設定する",
        "regex", "present", r"^ntp server ",
        remediation="""
# NX-OS では VRF の指定（use-vrf <VRF名>）が要ることがあります
ntp server <NTP サーバーの IP またはホスト名>
""",
        good="hostname R1\nntp server 192.0.2.1\n", bad="hostname R1\n",
    ),
    tpl(
        "既定の SNMP コミュニティを使わない", "high", [*IOS, "cisco_nxos", "arista_eos", *AWPLUS], "SNMP",
        "public / private のコミュニティ名は使わない",
        "regex", "absent", r"^snmp-server community (public|private)\b",
        remediation="""
# 先に別のコミュニティ（または SNMPv3）へ監視システムの設定を切り替えてから削除します
no snmp-server community <削除するコミュニティ名>
""",
        good="snmp-server community Example-Mon ro\n", bad="snmp-server community public ro\n",
    ),
    tpl(
        "物理インターフェースに説明を付ける", "low", [*IOS, "cisco_nxos", "arista_eos"], "そのほか",
        "各物理インターフェースに description を設定する",
        "regex", "present", r"^\s+description ", scope="section",
        section_pattern=r"^interface (GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet)",
        remediation="""
interface <インターフェース名>
 description <接続先の説明>
""",
        good="interface GigabitEthernet0/1\n description uplink\n!\n",
        bad="interface GigabitEthernet0/1\n shutdown\n!\n",
    ),
    tpl(
        "SNMP: 書き込み可（RW）のコミュニティを使わない", "high", [*IOS, "cisco_nxos", "arista_eos", *AWPLUS], "SNMP",
        "SNMP の書き込み（rw）を許すコミュニティは、機器の設定を書き換えられてしまうため使わない。"
        "NX-OS で group を指定する形式（権限が group で決まるもの）は判定できません",
        "regex", "absent", r"^snmp-server community \S+ (?:view \S+ )?(?i:rw)\b",
        remediation="""
# 読み取り専用で足りるかを確かめてから切り替えます
no snmp-server community <削除するコミュニティ名>
snmp-server community <新しいコミュニティ名> ro
""",
        good="snmp-server community Example-Mon ro\n", bad="snmp-server community Example-Mon RW\n",
    ),
    tpl(
        "SNMPv3 を使う", "low", IOS, "SNMP",
        "SNMP は認証・暗号化のある v3 のグループを設定する。v1 / v2c だけで運用している機器が違反になる",
        "regex", "present", r"^snmp-server group \S+ v3 (?:auth|priv)\b", reference=REF_VENDOR,
        remediation="""
# 認証・暗号化に使うパスワードは機器へ直接入力します（この画面には書きません）
snmp-server group <グループ名> v3 priv
snmp-server user <ユーザー名> <グループ名> v3 auth sha <認証パスワード> priv aes 128 <暗号化パスワード>
""",
        good="snmp-server group MON-GRP v3 priv\n", bad="snmp-server community Example-Mon ro\n",
    ),
    tpl(
        "NTP の認証を有効にする", "low", [*IOS, "cisco_nxos", "arista_eos"], "時刻",
        "なりすましの NTP サーバーで時刻を狂わされないよう、NTP の認証を有効にする。"
        "認証に対応していない NTP サーバーを使う環境では違反になる",
        "regex", "present", r"^ntp authenticate\b", reference=REF_VENDOR,
        remediation="""
# 認証用の鍵はサーバーと同じ値を機器へ直接入力します（この画面には書きません）
ntp authenticate
ntp authentication-key <鍵番号> md5 <鍵>
ntp trusted-key <鍵番号>
ntp server <NTP サーバーの IP> key <鍵番号>
""",
        good="ntp authenticate\nntp server 192.0.2.1 key 1\n", bad="ntp server 192.0.2.1\n",
    ),
]
