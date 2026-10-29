"""
コンフィグ収集サービス
Netmiko でSSH接続してコンフィグを取得し、GitPython で世代管理を行う

Gitリポジトリは機器ごとに GIT_REPO_PATH/<device_id>/ に作成する。
（以前は機器名で作っていたが、名前変更で履歴が切れる・パス操作の危険があるため device_id に変更）
"""
import difflib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import git
from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from paramiko import BadHostKeyException

from app.core.config import settings
from app.core.ssh_hostkeys import HostKeyPolicy, UnknownHostKeyError, describe_ssh_error
from app.core.ssh_jump import JumpHostError, JumpHostInfo, connect_jump, open_tunnel

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
    commands: list[str]
    supports_enable: bool = False
    ignore_patterns: list[str] = field(default_factory=list)


PLATFORMS: dict[str, PlatformSpec] = {
    "cisco_ios": PlatformSpec(["show running-config"], True, _CISCO_IOS_IGNORE),
    "cisco_xe": PlatformSpec(["show running-config"], True, _CISCO_IOS_IGNORE),
    "cisco_nxos": PlatformSpec(
        ["show running-config"],
        False,
        [r"^!Time: ", r"^!Running configuration last done at: ", r"^!Command: show running-config"],
    ),
    "juniper_junos": PlatformSpec(
        ["show configuration | display set"], False, [r"^## Last (commit|changed): "]
    ),
    "arista_eos": PlatformSpec(["show running-config"], True, [r"^! Command: show running-config"]),
    "hp_comware": PlatformSpec(["display current-configuration"], False, []),
    "huawei": PlatformSpec(
        ["display current-configuration"], False, [r"^!Last configuration was (updated|saved) at "]
    ),
}

SUPPORTED_PLATFORMS = tuple(PLATFORMS.keys())


@dataclass
class DeviceConnectionInfo:
    """ORMオブジェクトをセッション外に持ち出さないための接続情報"""

    id: str
    name: str
    hostname: str
    platform: str
    port: int
    username: str
    password: str
    enable_secret: str | None
    jump: JumpHostInfo | None = None  # 踏み台経由の場合のみ


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

    params = {
        "device_type": device.platform,
        "host": device.hostname,
        "port": device.port,
        "username": device.username,
        "password": device.password,
        "timeout": settings.SSH_TIMEOUT,
        "auth_timeout": settings.SSH_AUTH_TIMEOUT,
        "alt_host_keys": True,
        "alt_key_file": settings.SSH_KNOWN_HOSTS,
        "auto_connect": False,
    }
    if device.enable_secret:
        params["secret"] = device.enable_secret

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
    try:
        conn._open()
        if device.enable_secret and spec.supports_enable:
            conn.enable()
        output = []
        for cmd in spec.commands:
            output.append(conn.send_command(cmd, read_timeout=settings.SSH_READ_TIMEOUT))
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
    except NetmikoAuthenticationException:
        return CollectResult(success=False, error="認証失敗" + ("（機器）" if device.jump else ""))
    except Exception as e:  # noqa: BLE001
        hk = _host_key_error(e)
        if hk is not None:
            # 鍵不一致・未登録はリトライしても解決しない
            return CollectResult(success=False, error=describe_ssh_error(hk))
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
