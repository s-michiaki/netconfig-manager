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
    SYSTEM_WATCHDOG_ENABLED="false",  # テストでは定期確認を動かさない（必要なテストが直接呼ぶ）
    NOTIFY_FAILURE_BATCH_SEC="0",  # 収集失敗の通知はすぐ送る（まとめる動きは test_failure_batch.py で確かめる）
    SYSTEM_CERT_ENDPOINT="",
)
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import fakeredis  # noqa: E402
import pytest  # noqa: E402

from app.services import login_limit  # noqa: E402


def _fake_redis():
    return fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer())


# ログインの失敗回数は Redis で数える。テストでは偽の Redis を使い、テストごとに空にする
login_limit._client = _fake_redis()


@pytest.fixture(autouse=True)
def _login_limit_redis(monkeypatch):
    monkeypatch.setattr(login_limit, "_client", _fake_redis())
    # ログアウトの確認（services/sessions.py）が、前のテストで Redis を止めたときの「しばらく確かめない」を引き継がない
    from app.services import sessions
    monkeypatch.setattr(sessions, "_skip_until", 0.0)
    monkeypatch.setattr(sessions, "_warned", False)
    # 無操作の確認（services/idle.py）も同じ
    from app.services import idle
    monkeypatch.setattr(idle, "_skip_until", 0.0)
    monkeypatch.setattr(idle, "_warned", False)
    monkeypatch.setattr(idle, "_error_logged", -1e9)
