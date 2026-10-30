"""テスト用設定: SQLite + 一時ディレクトリで動かす（PostgreSQL / Redis 不要）

実行方法（backend ディレクトリで）:
    pip install -r requirements.txt -r requirements-dev.txt
    pytest
"""
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

TMP = tempfile.mkdtemp(prefix="netconfig-test-")
os.environ.update(
    SECRET_KEY="test-secret-key-" + "x" * 32,
    DEVICE_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    DATABASE_URL=f"sqlite+aiosqlite:///{TMP}/t.db",
    GIT_REPO_PATH=f"{TMP}/configs",
    SSH_KNOWN_HOSTS=f"{TMP}/ssh/known_hosts",
    TERMINAL_LOG_PATH=f"{TMP}/terminal-logs",
    ADMIN_USERNAME="admin",
    ADMIN_PASSWORD="initial-pass-123",
    ALLOWED_ORIGINS="",
)
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
