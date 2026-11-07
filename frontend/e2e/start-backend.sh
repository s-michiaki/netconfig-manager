#!/usr/bin/env bash
# 画面テスト用の backend を起動する（Playwright の webServer から呼ばれる）
#   一時ディレクトリに SQLite・コンフィグ履歴を作り、seed.py で初期データを入れてから uvicorn を起動する
#   PostgreSQL / Redis / 実機は使わない
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$HERE/../../backend"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ncm-e2e-XXXXXX")"

export SECRET_KEY="e2e-secret-key-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DEVICE_ENCRYPTION_KEY="$("$PYTHON" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export DEVICE_ENCRYPTION_KEY
export DATABASE_URL="sqlite+aiosqlite:///$WORK/e2e.db"
export GIT_REPO_PATH="$WORK/configs"
export SSH_KNOWN_HOSTS="$WORK/ssh/known_hosts"
export TERMINAL_LOG_PATH="$WORK/terminal-logs"
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-initial-pass-123}"
export ALLOWED_ORIGINS=""
export REDIS_URL="redis://127.0.0.1:1/0"  # 使わない（収集などのタスクは投入しない画面だけを確認する）

cd "$BACKEND"
"$PYTHON" "$HERE/seed.py"
exec "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "${E2E_API_PORT:-8000}" --log-level warning
