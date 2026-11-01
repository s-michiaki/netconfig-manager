"""
コンフィグ収集サービス
Netmiko でSSH接続してコンフィグを取得し、GitPython で世代管理を行う

Gitリポジトリは機器ごとに GIT_REPO_PATH/<device_id>/ に作成する。
（以前は機器名で作っていたが、名前変更で履歴が切れる・パス操作の危険があるため device_id に変更）
"""
import difflib
import logging
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import git
from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from paramiko import BadHostKeyException

from app.core.config import settings
from app.core.ssh_hostkeys import HostKeyPolicy, UnknownHostKeyError, describe_ssh_error
from app.core.ssh_jump import JumpHostError, JumpHostInfo, connect_jump, open_tunnel
from app.core.ssh_keys import PrivateKeyError, load_private_key

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "running-config.txt"
COMMIT_HASH_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
DEVICE_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")

# 取得のたびに変わる行（タイムスタンプ等）。これらを除外しないと毎回差分が出てコミットが増え続ける
_CISCO_IOS_IGNORE = [
    r"^Building configuration\.\.\.",
    r"^Current configuration\s*:\s*\d+ bytes",
    r"^! Last configuration change at ",
    r"^! NVRAM config last updated at ",
    r"^! No configuration change since last restart",
    r"^ntp clock-period \d+",
]


@dataclass(frozen=True)
class PlatformSpec:
    label: str  # 画面に表示する名前
    vendor: str  # 画面でまとめて表示するメーカー名
    commands: list[str] = field(default_factory=list)
    supports_enable: bool = False
    # Enable パスワードが未設定でも特権モードに入る（ログイン直後は一般モードで、取得コマンドに特権が必要な機種）
    auto_enable: bool = False
    ignore_patterns: list[str] = field(default_factory=list)
    # 取得前に実行する設定コマンド（出力は保存しない）
    prep_commands: list[str] = field(default_factory=list)
    # 設定モードに入って実行するコマンド（PAN-OS の "configure" → "show" など）
    config_mode_commands: list[str] = field(default_factory=list)
    # 応答の遅い機器。True ならログイン後のプロンプト待ちなどにも応答待ち時間を適用する
    slow_device: bool = False
    # 取得のたびに値が変わる部分の置き換え（パターン, 置換後）。行単位の除外では足りないもの
    # （FortiOS の暗号化パスワードのように、行は残して値だけ伏せたいもの）に使う
    replace_patterns: list[tuple[str, str]] = field(default_factory=list)
    # 構成図での既定のアイコン（switch / l3switch / router / firewall / wireless）
    icon: str = "switch"
    # 機器登録画面に表示する注意事項
    note: str | None = None
    # Netmiko の device_type（省略時はプラットフォームのキーと同じ）
    driver: str | None = None

    @property
    def device_type(self) -> str:
        return self.driver or ""


def _spec(label: str, vendor: str, commands: list[str], **kw) -> PlatformSpec:
    return PlatformSpec(label=label, vendor=vendor, commands=commands, **kw)


# FASTPATH 系（Ubiquiti EdgeSwitch・NETGEAR・Broadcom ICOS・Dell PowerConnect）の running-config の先頭にある、
# 稼働時間・現在時刻の行
_FASTPATH_IGNORE = [
    r"^!Current Configuration:",
    r"^!System Up ?Time",
    r"^!Up Time",
    r"^!Current SNTP Synchronized Time",
]
# 先頭に出る「曜日 月 日 時刻」の行（IOS-XR など）
_TIMESTAMP_LINE = r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+ \d{2}:\d{2}:\d{2}"

_FW_NOTE_ENABLE = "特権モードのパスワードが必要な場合は Enable パスワードを設定してください"

PLATFORMS: dict[str, PlatformSpec] = {
    # ---------------------------------------------------------------- Cisco
    "cisco_ios": _spec("Cisco IOS", "Cisco", ["show running-config"], supports_enable=True,
                       ignore_patterns=_CISCO_IOS_IGNORE),
    "cisco_xe": _spec("Cisco IOS-XE", "Cisco", ["show running-config"], supports_enable=True,
                      ignore_patterns=_CISCO_IOS_IGNORE),
    "cisco_nxos": _spec(
        "Cisco NX-OS", "Cisco", ["show running-config"],
        ignore_patterns=[r"^!Time: ", r"^!Running configuration last done at: ", r"^!Command: show running-config"],
        icon="l3switch",
    ),
    "cisco_xr": _spec(
        "Cisco IOS-XR", "Cisco", ["show running-config"],
        ignore_patterns=[r"^Building configuration\.\.\.", r"^!! Last configuration change at ", _TIMESTAMP_LINE],
        icon="router",
    ),
    "cisco_asa": _spec(
        "Cisco ASA", "Cisco", ["show running-config"], supports_enable=True,
        ignore_patterns=[r"^: Saved", r"^: Written by ", r"^Cryptochecksum:"],
        icon="firewall", note=_FW_NOTE_ENABLE,
    ),
    "cisco_s300": _spec("Cisco Small Business（Sx300 / Sx350 など）", "Cisco", ["show running-config"],
                        supports_enable=True),
    "cisco_s200": _spec("Cisco Small Business（Sx200 など）", "Cisco", ["show running-config"], supports_enable=True),
    "cisco_wlc": _spec("Cisco WLC（AireOS）", "Cisco", ["show run-config commands"], icon="wireless"),
    "cisco_viptela": _spec("Cisco SD-WAN（Viptela）", "Cisco", ["show running-config"], icon="router"),
    # ---------------------------------------------------------------- Juniper
    "juniper_junos": _spec("Juniper JunOS", "Juniper", ["show configuration | display set"],
                           ignore_patterns=[r"^## Last (commit|changed): "], icon="router"),
    "juniper_screenos": _spec("Juniper ScreenOS", "Juniper", ["get config"], icon="firewall"),
    # ---------------------------------------------------------------- Arista
    "arista_eos": _spec("Arista EOS", "Arista", ["show running-config"], supports_enable=True,
                        ignore_patterns=[r"^! Command: show running-config"]),
    # ---------------------------------------------------------------- Fortinet
    # show は既定値以外の設定だけを出す（full-configuration は既定値も含み膨大になる）。
    # Netmiko はページング無効化のため、収集中だけ config system console の output を standard にし、
    # 終了時に元に戻す（そのため収集用アカウントにはシステム設定の書き込み権限が必要）
    "fortinet": _spec(
        "Fortinet FortiGate（FortiOS）", "Fortinet", ["show"],
        ignore_patterns=[r"^#conf_file_ver="],
        replace_patterns=[
            # 可逆暗号化された値（ENC xxx）は取得のたびに変わる。管理者パスワードのハッシュ（SH2 / PB2）は変わらないので残す
            (r"^(\s*set \S+ ENC) (?!SH2|PB2)\S+$", r"\1 <暗号化された値（取得のたびに変わるため省略）>"),
            # 秘密鍵も取得のたびに暗号化し直される（複数行）
            (r'^(\s*set private-key ")[^"]*(")', r"\1<秘密鍵（取得のたびに変わるため省略）>\2"),
        ],
        icon="firewall",
        note="収集用の管理者アカウントにはシステム設定の書き込み権限が必要です（ページング無効化のため、"
             "収集中だけ config system console の output を standard にし、終了時に戻します。"
             "常に standard にしておけば設定は変わりません）。暗号化されたパスワード等の値は取得のたびに変わるため、"
             "差分の対象から外しています",
    ),
    # ---------------------------------------------------------------- Palo Alto
    # 差分を見やすくするため set 形式で出力させ、設定モードの show で全体を取得
    "paloalto_panos": PlatformSpec(
        label="Palo Alto PAN-OS", vendor="Palo Alto Networks",
        prep_commands=["set cli config-output-format set"],
        config_mode_commands=["show"],
        ignore_patterns=[r"^\[edit\]$", r"^Entering configuration mode$"],
        # ログイン後プロンプトが出るまで数十秒かかることがある（Netmiko 既定の待ちは 20 秒固定）
        slow_device=True,
        icon="firewall",
    ),
    # ---------------------------------------------------------------- Allied Telesis
    "allied_telesis_awplus": _spec(
        "Allied Telesis AlliedWare Plus", "Allied Telesis", ["show running-config"], supports_enable=True,
        auto_enable=True,
        note="AlliedWare Plus（x シリーズ・AR シリーズ・GS900 / SH シリーズなど）に対応。"
             "ログイン後に自動で enable します（パスワードを設定している場合は Enable パスワード欄に入力）。"
             "旧 CentreCOM（AlliedWare、Manager > のプロンプト）には未対応です",
    ),
    # ---------------------------------------------------------------- 国内メーカー
    "yamaha": _spec(
        "Yamaha RTX / NVR / SWX", "Yamaha", ["show config"], supports_enable=True,
        ignore_patterns=[r"^# Reporting Date: "],
        icon="router",
        note="show config は管理者モードが必要な機種があるため、Enable パスワード欄に administrator のパスワードを"
             "設定してください。console character が sjis の場合、日本語の部分は正しく取得できません",
    ),
    "apresia_aeos": _spec("APRESIA AEOS", "APRESIA Systems", ["show running-config"], supports_enable=True),
    # ---------------------------------------------------------------- HPE / Aruba
    "hp_comware": _spec("HPE Comware", "HPE / Aruba", ["display current-configuration"]),
    "hp_procurve": _spec("HPE ProCurve", "HPE / Aruba", ["show running-config"], supports_enable=True,
                         ignore_patterns=[r"^Running configuration:"]),
    "aruba_osswitch": _spec("Aruba OS-Switch", "HPE / Aruba", ["show running-config"], supports_enable=True,
                            ignore_patterns=[r"^Running configuration:"]),
    "aruba_aoscx": _spec("Aruba AOS-CX", "HPE / Aruba", ["show running-config"]),
    "aruba_os": _spec("Aruba OS（コントローラー）", "HPE / Aruba", ["show running-config"], supports_enable=True,
                      ignore_patterns=[r"^Building Configuration\.\.\."], icon="wireless"),
    # ---------------------------------------------------------------- Huawei
    "huawei": _spec("Huawei VRP", "Huawei", ["display current-configuration"],
                    ignore_patterns=[r"^!Last configuration was (updated|saved) at "]),
    "huawei_vrpv8": _spec("Huawei VRP V8", "Huawei", ["display current-configuration"],
                          ignore_patterns=[r"^!Last configuration was (updated|saved) at "], icon="router"),
    # ---------------------------------------------------------------- Dell
    "dell_os10": _spec("Dell OS10", "Dell", ["show running-configuration"],
                       ignore_patterns=[r"^! Version ", r"^! Last configuration change at "]),
    "dell_os9": _spec("Dell OS9（Force10）", "Dell", ["show running-config"], supports_enable=True,
                      ignore_patterns=[r"^Current Configuration \.\.\.", r"^! Version ",
                                       r"^! Last configuration change at ", r"^! Startup-config last updated at "]),
    "dell_os6": _spec("Dell OS6 / PowerConnect", "Dell", ["show running-config"], supports_enable=True,
                      ignore_patterns=_FASTPATH_IGNORE),
    # ---------------------------------------------------------------- Extreme / Avaya / Brocade / Ruckus
    "extreme_exos": _spec("Extreme EXOS", "Extreme / Brocade / Ruckus", ["show configuration"]),
    "extreme_vsp": _spec(
        "Extreme VOSS（VSP）", "Extreme / Brocade / Ruckus", ["show running-config"], supports_enable=True,
        ignore_patterns=[r"(?i)^#\s*(mon|tue|wed|thu|fri|sat|sun)\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}"],
    ),
    "extreme_ers": _spec("Extreme ERS（Avaya）", "Extreme / Brocade / Ruckus", ["show running-config"],
                         supports_enable=True),
    "extreme_slx": _spec("Extreme SLX", "Extreme / Brocade / Ruckus", ["show running-config"]),
    "extreme_nos": _spec("Extreme NOS（Brocade VDX）", "Extreme / Brocade / Ruckus", ["show running-config"]),
    "extreme_netiron": _spec("Extreme NetIron（Brocade MLX）", "Extreme / Brocade / Ruckus", ["show running-config"],
                             supports_enable=True, ignore_patterns=[r"^Current configuration:"], icon="router"),
    "ruckus_fastiron": _spec("Ruckus / Brocade FastIron（ICX）", "Extreme / Brocade / Ruckus",
                             ["show running-config"], supports_enable=True,
                             ignore_patterns=[r"^Current configuration:"]),
    # ---------------------------------------------------------------- ルーター・その他
    "mikrotik_routeros": _spec("MikroTik RouterOS", "MikroTik", ["/export"],
                               ignore_patterns=[r"^# .* by RouterOS "], icon="router"),
    "vyos": _spec("VyOS", "VyOS", ["show configuration commands"], icon="router"),
    "ubiquiti_edgerouter": _spec("Ubiquiti EdgeRouter", "Ubiquiti", ["show configuration commands"], icon="router"),
    "ubiquiti_edgeswitch": _spec("Ubiquiti EdgeSwitch", "Ubiquiti", ["show running-config"], supports_enable=True,
                                 ignore_patterns=_FASTPATH_IGNORE),
    "nokia_sros": _spec("Nokia SR OS", "Nokia", ["admin show configuration"],
                        ignore_patterns=[r"^# (Generated|Finished) "], icon="router"),
    "checkpoint_gaia": _spec("Check Point Gaia", "Check Point", ["show configuration"],
                             ignore_patterns=[r"^# Exported by \S+ on "], icon="firewall"),
    "hillstone_stoneos": _spec("Hillstone StoneOS", "Hillstone", ["show configuration"], icon="firewall"),
    "alcatel_aos": _spec("Alcatel-Lucent OmniSwitch（AOS）", "Alcatel-Lucent", ["show configuration snapshot"]),
    "a10": _spec("A10 ACOS", "A10 Networks", ["show running-config"], supports_enable=True,
                 ignore_patterns=[r"^!Configuration last (updated|saved) at "], icon="server"),
    "netscaler": _spec("Citrix NetScaler（ADC）", "Citrix", ["show ns runningConfig"],
                       ignore_patterns=[r"^# Last modified "], icon="server"),
    "mellanox_mlnxos": _spec("NVIDIA / Mellanox Onyx", "NVIDIA / Mellanox", ["show running-config"],
                             supports_enable=True, ignore_patterns=[r"^## Generated at "]),
    "ruijie_os": _spec("Ruijie", "その他", ["show running-config"], supports_enable=True,
                       ignore_patterns=[r"^Building configuration\.\.\.", r"^Current configuration\s*:\s*\d+ bytes"]),
    "zte_zxros": _spec("ZTE ZXROS", "その他", ["show running-config"], supports_enable=True,
                       ignore_patterns=[r"^Building configuration\.\.\."]),
    "tplink_jetstream": _spec("TP-Link JetStream", "その他", ["show running-config"], supports_enable=True),
    "netgear_prosafe": _spec("NETGEAR ProSAFE", "その他", ["show running-config"], supports_enable=True,
                             ignore_patterns=_FASTPATH_IGNORE),
    "broadcom_icos": _spec("Broadcom ICOS", "その他", ["show running-config"], supports_enable=True,
                           ignore_patterns=_FASTPATH_IGNORE),
    "dlink_ds": _spec("D-Link DGS / DES", "その他", ["show config current_config"]),
    "zyxel_os": _spec("Zyxel", "その他", ["show running-config"]),
    "ipinfusion_ocnos": _spec("IP Infusion OcNOS", "その他", ["show running-config"], supports_enable=True,
                              ignore_patterns=[r"^!Last configuration change at "]),
    "centec_os": _spec("Centec", "その他", ["show running-config"], supports_enable=True),
    "fiberstore_fsos": _spec("FS（FiberStore）", "その他", ["show running-config"], supports_enable=True),
    "eltex": _spec("Eltex", "その他", ["show running-config"]),
}
# Netmiko の device_type を埋める（driver 省略時はキーと同じ）
PLATFORMS = {k: (v if v.driver else replace(v, driver=k)) for k, v in PLATFORMS.items()}

SUPPORTED_PLATFORMS = tuple(PLATFORMS.keys())

# ページャー表示（ページング無効化に失敗したときに出る）
#   Cisco / Arista / NX-OS / FortiOS / AW+: --More--   Huawei / Comware: ---- More ----
#   JunOS: ---(more 45%)---   PAN-OS（less）: lines 1-40   Yamaha: ---つづく---   MikroTik: -- [Q quit|...
PAGER_RE = re.compile(
    r"(?im)(?:^|\s)-{2,}\s*\(?\s*(?:more|つづく)(?:\s+\d+%)?\s*\)?\s*-{2,}|^lines \d+-\d+|-- \[Q quit\|"
)


class PagingNotDisabledError(Exception):
    """ページング（--More--）が無効化されておらず、出力が途中で止まった"""

    def __init__(self, command: str):
        self.command = command
        super().__init__(command)


def _send(conn, command: str, read_timeout: int) -> str:
    """プロンプトに加えてページャー表示も待ち、ページャーが出たら応答待ちを待たずに即エラーにする
    （そのままだとプロンプトが出ないまま応答待ち時間いっぱい待ってタイムアウトする）"""
    prompt = conn.find_prompt()
    # send_command はフラグを渡せないため、ページャー部分はスコープ付きフラグ (?im:...) で埋め込む
    pattern = rf"{re.escape(prompt.strip())}|(?im:{PAGER_RE.pattern.removeprefix('(?im)')})"
    output = conn.send_command(command, expect_string=pattern, read_timeout=read_timeout)
    if PAGER_RE.search(output):
        raise PagingNotDisabledError(command)
    return output


@dataclass
class DeviceConnectionInfo:
    """ORMオブジェクトをセッション外に持ち出さないための接続情報"""

    id: str
    name: str
    hostname: str
    platform: str
    port: int
    username: str
    password: str | None
    enable_secret: str | None
    jump: JumpHostInfo | None = None  # 踏み台経由の場合のみ
    private_key: str | None = None  # SSH 鍵認証（パスワードと併用可）
    key_passphrase: str | None = None
    read_timeout: int | None = None  # 応答待ち時間（秒）。None なら既定値


def effective_read_timeout(device: DeviceConnectionInfo) -> int:
    return device.read_timeout or settings.SSH_READ_TIMEOUT


@dataclass
class CollectResult:
    success: bool
    commit_hash: str | None = None
    added: int = 0
    removed: int = 0
    error: str | None = None
    retryable: bool = False

    def as_dict(self) -> dict:
        return {
            "success": self.success,
            "commit_hash": self.commit_hash,
            "added": self.added,
            "removed": self.removed,
            "error": self.error,
        }


# ---------------------------------------------------------------- Git helpers


def repo_path(device_id: str) -> Path:
    if not DEVICE_ID_RE.match(device_id):
        raise ValueError("invalid device id")
    return Path(settings.GIT_REPO_PATH) / device_id


def _open_repo(device_id: str) -> git.Repo | None:
    path = repo_path(device_id)
    if not (path / ".git").exists():
        return None
    return git.Repo(path)


def _get_or_init_repo(device_id: str) -> tuple[git.Repo, Path]:
    path = repo_path(device_id)
    path.mkdir(parents=True, exist_ok=True)
    if (path / ".git").exists():
        repo = git.Repo(path)
    else:
        repo = git.Repo.init(path)
    with repo.config_writer() as cw:
        cw.set_value("user", "name", "NetConfig System")
        cw.set_value("user", "email", "netconfig@system.local")
    return repo, path / CONFIG_FILENAME


def migrate_legacy_repo(device_id: str, device_name: str) -> bool:
    """機器名ディレクトリで作られた旧リポジトリを device_id ディレクトリへ移動する"""
    base = Path(settings.GIT_REPO_PATH)
    if not device_name or Path(device_name).name != device_name or device_name in (".", ".."):
        return False
    legacy = base / device_name
    new = repo_path(device_id)
    if (legacy / ".git").exists() and not new.exists():
        legacy.rename(new)
        logger.info("Gitリポジトリを移行しました: %s -> %s", legacy, new)
        return True
    return False


def normalize_config(text: str, platform: str) -> str:
    spec = PLATFORMS.get(platform)
    patterns = [re.compile(p) for p in (spec.ignore_patterns if spec else [])]
    text = text.replace("\r\n", "\n")
    for pat, repl in (spec.replace_patterns if spec else []):
        text = re.sub(pat, repl, text, flags=re.M)
    lines = [
        line.rstrip()
        for line in text.replace("\r\n", "\n").split("\n")
        if not any(p.match(line) for p in patterns)
    ]
    return "\n".join(lines).strip("\n") + "\n"


def count_changes(old: str, new: str) -> tuple[int, int]:
    """unified diff ベースで追加・削除行数を数える（重複行も正しく数える）"""
    added = removed = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


def save_config(device_id: str, config_text: str, triggered_by: str) -> CollectResult:
    repo, config_file = _get_or_init_repo(device_id)
    current = config_file.read_text(encoding="utf-8") if config_file.exists() else ""
    if current == config_text:
        return CollectResult(success=True)

    added, removed = count_changes(current, config_text)
    config_file.write_text(config_text, encoding="utf-8")
    repo.index.add([CONFIG_FILENAME])
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = repo.index.commit(f"Collect ({triggered_by}) {ts}  +{added} -{removed}")
    return CollectResult(success=True, commit_hash=commit.hexsha, added=added, removed=removed)


# ---------------------------------------------------------------- Collect


def fetch_config(device: DeviceConnectionInfo) -> str:
    spec = PLATFORMS.get(device.platform)
    if spec is None:
        raise ValueError(f"未対応のプラットフォームです: {device.platform}")

    read_timeout = effective_read_timeout(device)
    params = {
        "device_type": spec.device_type,
        "host": device.hostname,
        "port": device.port,
        "username": device.username,
        "password": device.password or "",
        "conn_timeout": settings.SSH_TIMEOUT,  # TCP 接続
        "banner_timeout": settings.SSH_TIMEOUT,  # SSH バナー受信
        "auth_timeout": settings.SSH_AUTH_TIMEOUT,
        "alt_host_keys": True,
        "alt_key_file": settings.SSH_KNOWN_HOSTS,
        "auto_connect": False,
    }
    if spec.slow_device or device.read_timeout:
        # Netmiko はログイン直後のプロンプト待ちなどを 10〜20 秒固定で待つため、応答の遅い機器では
        # タイムアウトする。すべての読み取り待ちを応答待ち時間で上書きし、高速モードも無効にする
        # （待ち時間は上限であり、応答が来ればすぐ次へ進む）
        params["read_timeout_override"] = read_timeout
        params["fast_cli"] = False
    if device.enable_secret:
        params["secret"] = device.enable_secret
    if device.private_key:
        # 鍵とパスワードの両方がある場合、Paramiko は鍵 → パスワードの順に試す
        params["pkey"] = load_private_key(device.private_key, device.key_passphrase)
        params["allow_agent"] = False

    jump_client = None
    if device.jump:
        # 踏み台へ接続し、機器宛てのチャネルを Netmiko のソケットとして使う
        jump_client = connect_jump(device.jump)
        try:
            params["sock"] = open_tunnel(jump_client, device.jump.name, device.hostname, device.port)
        except Exception:
            jump_client.close()
            raise

    conn = ConnectHandler(**params)
    # Netmiko 既定の AutoAddPolicy を known_hosts 検証ポリシーに差し替えてから接続する
    conn.key_policy = HostKeyPolicy()
    if device.private_key and device.platform.startswith("paloalto"):
        # PAN-OS ドライバは use_keys=False だとキーボード対話認証（パスワード）専用のクライアントを使い、
        # 鍵を無視する。生成時に use_keys=True を渡すと鍵ファイルの存在を要求されるため（秘密鍵は
        # ディスクに書き出さない）、生成後に切り替えて標準の SSHClient（pkey を使う）にする
        conn.use_keys = True
    try:
        conn._open()
        if spec.supports_enable and (device.enable_secret or spec.auto_enable):
            conn.enable()
        for cmd in spec.prep_commands:
            _send(conn, cmd, read_timeout)
        output = []
        for cmd in spec.commands:
            output.append(_send(conn, cmd, read_timeout))
        if spec.config_mode_commands:
            conn.config_mode()
            try:
                for cmd in spec.config_mode_commands:
                    output.append(_send(conn, cmd, read_timeout))
            finally:
                conn.exit_config_mode()
        return "\n".join(output)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001 - 切断失敗は無視してよい
            pass
        if jump_client is not None:
            jump_client.close()


def _host_key_error(e: BaseException) -> BaseException | None:
    """Netmiko は Paramiko のホスト鍵エラーを NetmikoTimeoutException で包むため、原因を辿る"""
    seen = set()
    while e is not None and id(e) not in seen:
        if isinstance(e, (BadHostKeyException, UnknownHostKeyError)):
            return e
        seen.add(id(e))
        e = e.__cause__ or e.__context__
    return None


def collect_config_sync(device: DeviceConnectionInfo, triggered_by: str = "manual") -> CollectResult:
    """同期的にコンフィグを収集する（Celeryワーカーから呼び出す）"""
    try:
        raw = fetch_config(device)
    except JumpHostError as e:
        return CollectResult(success=False, error=str(e), retryable=e.retryable)
    except PrivateKeyError as e:
        return CollectResult(success=False, error=f"機器の秘密鍵: {e}")
    except PagingNotDisabledError as e:
        # 権限不足などでページング無効化コマンドが効いていない。リトライしても解決しない
        return CollectResult(
            success=False,
            error=f"「{e.command}」の出力が --More-- 等で止まりました。ページングを無効化できていません"
            "（ログインユーザーの権限で terminal length 0 / screen-length 等が実行できるか確認してください）",
        )
    except NetmikoAuthenticationException:
        return CollectResult(success=False, error="認証失敗" + ("（機器）" if device.jump else ""))
    except Exception as e:  # noqa: BLE001
        hk = _host_key_error(e)
        if hk is not None:
            # 鍵不一致・未登録はリトライしても解決しない
            return CollectResult(success=False, error=describe_ssh_error(hk))
        if isinstance(e, ReadTimeout):
            spec = PLATFORMS.get(device.platform)
            if device.read_timeout or (spec and spec.slow_device):
                msg = f"機器の応答待ちがタイムアウトしました（{effective_read_timeout(device)}秒）。" \
                    "応答が遅い機器の場合はデバイス設定の「応答待ち時間」を延ばしてください"
            else:
                msg = "機器の応答待ちがタイムアウトしました。応答が遅い機器の場合はデバイス設定の「応答待ち時間」を指定してください"
            return CollectResult(success=False, error=msg, retryable=True)
        if isinstance(e, NetmikoTimeoutException):
            return CollectResult(success=False, error="タイムアウトまたは接続不可", retryable=True)
        if isinstance(e, ValueError):
            return CollectResult(success=False, error=str(e))
        logger.exception("コンフィグ取得に失敗: %s", device.name)
        return CollectResult(success=False, error=describe_ssh_error(e), retryable=True)

    config_text = normalize_config(raw, device.platform)
    if not config_text.strip():
        return CollectResult(success=False, error="取得したコンフィグが空でした")

    try:
        return save_config(device.id, config_text, triggered_by)
    except Exception as e:  # noqa: BLE001
        logger.exception("Gitへの保存に失敗: %s", device.name)
        return CollectResult(success=False, error=f"保存に失敗しました: {type(e).__name__}")


# ---------------------------------------------------------------- Read


def get_config_history(device_id: str, limit: int = 50) -> list[dict]:
    repo = _open_repo(device_id)
    if repo is None:
        return []
    try:
        commits = list(repo.iter_commits(max_count=limit))
    except (ValueError, git.GitCommandError):  # コミットが1件も無いリポジトリ
        return []
    return [
        {
            "hash": c.hexsha[:8],
            "full_hash": c.hexsha,
            "message": c.message.strip(),
            # タイムゾーン付きで返す（ブラウザ側でローカル時刻に正しく変換される）
            "date": datetime.fromtimestamp(c.committed_date, tz=timezone.utc).isoformat(),
            "author": c.author.name,
        }
        for c in commits
    ]


def _check_hash(h: str) -> None:
    # "--output=..." 等をgitのオプションとして解釈させないため、16進文字列のみ許可
    if not COMMIT_HASH_RE.match(h):
        raise ValueError("invalid commit hash")


def get_config_diff(device_id: str, hash_a: str, hash_b: str) -> str | None:
    """差分を返す。リポジトリやコミットが無い場合は None"""
    _check_hash(hash_a)
    _check_hash(hash_b)
    repo = _open_repo(device_id)
    if repo is None:
        return None
    try:
        return repo.git.diff(hash_a, hash_b, "--", CONFIG_FILENAME)
    except git.GitCommandError:
        return None


def get_config_content(device_id: str, commit_hash: str) -> str | None:
    """指定コミット時点のコンフィグ。存在しない場合は None（空ファイルは "" を返す）"""
    _check_hash(commit_hash)
    repo = _open_repo(device_id)
    if repo is None:
        return None
    try:
        blob = repo.commit(commit_hash).tree[CONFIG_FILENAME]
    except (KeyError, ValueError, git.BadName, git.GitCommandError):
        return None
    return blob.data_stream.read().decode("utf-8", errors="replace")
