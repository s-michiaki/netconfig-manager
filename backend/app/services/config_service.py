"""
コンフィグ収集サービス
Netmiko でSSH接続してコンフィグを取得し、GitPython で世代管理を行う
"""
import os
from datetime import datetime
from pathlib import Path

import git
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import CollectLog, ConfigSnapshot, Device


# プラットフォームごとのコンフィグ取得コマンド
PLATFORM_COMMANDS: dict[str, list[str]] = {
    "cisco_ios": ["show running-config"],
    "cisco_xe": ["show running-config"],
    "cisco_nxos": ["show running-config"],
    "juniper_junos": ["show configuration | display set"],
    "arista_eos": ["show running-config"],
    "hp_comware": ["display current-configuration"],
    "huawei": ["display current-configuration"],
}


def _get_or_init_repo(device_name: str) -> tuple[git.Repo, Path]:
    """デバイスごとのGitリポジトリを取得または初期化"""
    device_path = Path(settings.GIT_REPO_PATH) / device_name
    device_path.mkdir(parents=True, exist_ok=True)

    config_file = device_path / "running-config.txt"
    config_file.touch(exist_ok=True)

    if not (device_path / ".git").exists():
        repo = git.Repo.init(device_path)
        repo.index.add(["running-config.txt"])
        repo.index.commit("Initial commit")
    else:
        repo = git.Repo(device_path)

    return repo, config_file


def collect_config_sync(device: Device) -> dict:
    """
    同期的にコンフィグを収集する（Celeryワーカーから呼び出す）
    戻り値: {"success": bool, "commit_hash": str | None, "added": int, "removed": int, "error": str | None}
    """
    commands = PLATFORM_COMMANDS.get(device.platform, ["show running-config"])

    connect_params = {
        "device_type": device.platform,
        "host": device.hostname,
        "port": device.port,
        "username": device.username,
        "password": device.password,
        "timeout": settings.SSH_TIMEOUT,
        "auth_timeout": settings.SSH_AUTH_TIMEOUT,
    }
    if device.enable_secret:
        connect_params["secret"] = device.enable_secret

    try:
        conn = ConnectHandler(**connect_params)
        if device.enable_secret:
            conn.enable()

        config_text = ""
        for cmd in commands:
            config_text += conn.send_command(cmd) + "\n"
        conn.disconnect()

        repo, config_file = _get_or_init_repo(device.name)

        current = config_file.read_text(encoding="utf-8")
        if current == config_text:
            return {"success": True, "commit_hash": None, "added": 0, "removed": 0, "error": None}

        # 差分計算
        old_lines = set(current.splitlines())
        new_lines = set(config_text.splitlines())
        added = len(new_lines - old_lines)
        removed = len(old_lines - new_lines)

        config_file.write_text(config_text, encoding="utf-8")
        repo.index.add(["running-config.txt"])
        commit = repo.index.commit(
            f"Auto-collect {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return {
            "success": True,
            "commit_hash": commit.hexsha,
            "added": added,
            "removed": removed,
            "error": None,
        }

    except NetmikoAuthenticationException as e:
        return {"success": False, "commit_hash": None, "added": 0, "removed": 0, "error": f"認証失敗: {e}"}
    except NetmikoTimeoutException as e:
        return {"success": False, "commit_hash": None, "added": 0, "removed": 0, "error": f"タイムアウト: {e}"}
    except Exception as e:
        return {"success": False, "commit_hash": None, "added": 0, "removed": 0, "error": str(e)}


def get_config_history(device_name: str, limit: int = 50) -> list[dict]:
    """Gitコミット履歴を取得"""
    device_path = Path(settings.GIT_REPO_PATH) / device_name
    if not (device_path / ".git").exists():
        return []

    repo = git.Repo(device_path)
    history = []
    for commit in list(repo.iter_commits(max_count=limit)):
        history.append({
            "hash": commit.hexsha[:8],
            "full_hash": commit.hexsha,
            "message": commit.message.strip(),
            "date": datetime.fromtimestamp(commit.committed_date).isoformat(),
            "author": commit.author.name,
        })
    return history


def get_config_diff(device_name: str, hash_a: str, hash_b: str) -> str:
    """2つのコミット間の差分をunified diff形式で返す"""
    device_path = Path(settings.GIT_REPO_PATH) / device_name
    if not (device_path / ".git").exists():
        return ""

    repo = git.Repo(device_path)
    try:
        diff = repo.git.diff(hash_a, hash_b, "--", "running-config.txt")
        return diff
    except git.GitCommandError:
        return ""


def get_config_content(device_name: str, commit_hash: str) -> str:
    """指定コミット時点のコンフィグ内容を返す"""
    device_path = Path(settings.GIT_REPO_PATH) / device_name
    if not (device_path / ".git").exists():
        return ""

    repo = git.Repo(device_path)
    try:
        blob = repo.commit(commit_hash).tree["running-config.txt"]
        return blob.data_stream.read().decode("utf-8")
    except Exception:
        return ""
