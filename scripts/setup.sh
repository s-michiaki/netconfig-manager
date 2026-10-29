#!/bin/bash
# =============================================================================
# NetConfig Manager 自動セットアップ（AlmaLinux / RHEL 10 系・Podman）
#
# 使い方（一般ユーザー + sudo、または root で実行）:
#   bash setup.sh                 # 対話形式でセットアップ（[ ] 内は Enter でそのまま採用）
#
# 2回目以降に実行すると「更新」として動作する:
#   - ソースを git pull し、コンテナを再ビルドして再起動
#   - 既存の .env（暗号化キー等）はそのまま使う（再生成しない）
# =============================================================================
set -euo pipefail

# ===========================
# sudo Password Enter Please
# ===========================
echo "=== EXECUTE sudo -v ==="
sudo -v

# =========================
# Get IP Address
# =========================
IPADD=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1]}' || true)
[ -n "$IPADD" ] || IPADD=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
IPADD="${IPADD:-localhost}"

# =========================
# Random PASSWORD Generated
# =========================
gen_secret() { # $1 = 文字数（英数字のみ）
  head -c 300 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | cut -c 1-"$1"
}
gen_fernet_key() { # Fernet 鍵 = 32バイト乱数の URL-safe Base64
  head -c 32 /dev/urandom | base64 | tr '+/' '-_'
}
ADMIN_PASSWORD=$(gen_secret 20)

echo "=== NetConfig Manager Setup Start ==="
# =========================
# 設定
# =========================
# このスクリプトがリポジトリ内（scripts/）にあれば、そのリポジトリを使う
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../docker-compose.prod.yml" ]; then
  INSTALL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  INSTALL_DIR="/opt/netconfig-manager"
fi
REPO_URL="https://github.com/s-michiaki/netconfig-manager.git"
BRANCH="master"
HTTP_PORT="80"
ADMIN_USERNAME="admin"
SSH_HOST_KEY_POLICY="tofu"
COMPOSE_FILE="docker-compose.prod.yml"

# =========================
# 設定値入力
# =========================
read -r -p "INSTALL_DIR Please Enter [${INSTALL_DIR}]: " Red_INSTALL_DIR
if [ -n "${Red_INSTALL_DIR}" ]; then INSTALL_DIR="${Red_INSTALL_DIR}" ; fi

if [ ! -d "$INSTALL_DIR/.git" ]; then
  read -r -p "REPO_URL Please Enter [${REPO_URL}]: " Red_REPO_URL
  if [ -n "${Red_REPO_URL}" ]; then REPO_URL="${Red_REPO_URL}" ; fi

  read -r -p "BRANCH Please Enter [${BRANCH}]: " Red_BRANCH
  if [ -n "${Red_BRANCH}" ]; then BRANCH="${Red_BRANCH}" ; fi
fi

read -r -p "IP Address Please Enter [${IPADD}]: " Red_IPADD
if [ -n "${Red_IPADD}" ]; then IPADD="${Red_IPADD}" ; fi

read -r -p "HTTP_PORT Please Enter [${HTTP_PORT}]: " Red_HTTP_PORT
if [ -n "${Red_HTTP_PORT}" ]; then HTTP_PORT="${Red_HTTP_PORT}" ; fi
[[ "$HTTP_PORT" =~ ^[0-9]+$ ]] && [ "$HTTP_PORT" -ge 1 ] && [ "$HTTP_PORT" -le 65535 ] \
  || { echo "HTTP_PORT が不正です: $HTTP_PORT"; exit 1; }

FIRST_INSTALL=1
[ -f "$INSTALL_DIR/.env" ] && FIRST_INSTALL=0
if [ "$FIRST_INSTALL" -eq 1 ]; then
  read -r -p "ADMIN_USERNAME Please Enter [${ADMIN_USERNAME}]: " Red_ADMIN_USERNAME
  if [ -n "${Red_ADMIN_USERNAME}" ]; then ADMIN_USERNAME="${Red_ADMIN_USERNAME}" ; fi

  read -r -p "ADMIN_PASSWORD Please Enter [${ADMIN_PASSWORD}]: " Red_ADMIN_PASSWORD
  if [ -n "${Red_ADMIN_PASSWORD}" ]; then ADMIN_PASSWORD="${Red_ADMIN_PASSWORD}" ; fi
  [ "${#ADMIN_PASSWORD}" -ge 10 ] || { echo "ADMIN_PASSWORD は10文字以上にしてください"; exit 1; }

  read -r -p "SSH_HOST_KEY_POLICY Please Enter (tofu/strict) [${SSH_HOST_KEY_POLICY}]: " Red_POLICY
  if [ -n "${Red_POLICY}" ]; then SSH_HOST_KEY_POLICY="${Red_POLICY}" ; fi
  case "$SSH_HOST_KEY_POLICY" in tofu|strict) ;; *) echo "tofu か strict を指定してください"; exit 1 ;; esac
else
  echo "[INFO] 既存の $INSTALL_DIR/.env を使用します（暗号化キー・パスワードは変更しません）"
fi

ENV_BACKUP_DIR="/root/netconfig-manager-backup"
TS=$(date +%Y%m%d-%H%M%S)

# =========================
# 依存チェック
# =========================
command -v sudo >/dev/null || { echo "sudo required"; exit 1; }
command -v dnf  >/dev/null || { echo "dnf required (AlmaLinux / RHEL 10 系で実行してください)"; exit 1; }

# =========================
# 必要パッケージのインストール（git / podman / podman-compose）
# =========================
echo "[INFO] Checking packages..."
PKGS=()
command -v git            >/dev/null || PKGS+=(git)
command -v podman         >/dev/null || PKGS+=(podman)
command -v podman-compose >/dev/null || PKGS+=(podman-compose)
command -v curl           >/dev/null || PKGS+=(curl)
if [ ${#PKGS[@]} -gt 0 ]; then
  if [[ " ${PKGS[*]} " == *" podman-compose "* ]] && ! rpm -q epel-release >/dev/null 2>&1; then
    echo "[INFO] Installing epel-release (podman-compose is provided by EPEL)..."
    sudo dnf install -y epel-release
  fi
  echo "[INFO] Installing ${PKGS[*]}..."
  sudo dnf install -y "${PKGS[@]}"
else
  echo "[INFO] git / podman / podman-compose are already installed"
fi

# =========================
# ソース取得（初回: clone / 2回目以降: pull）
# =========================
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "[INFO] Updating source ($INSTALL_DIR)..."
  # リポジトリの所有者として git を実行する（root 以外が所有するリポジトリを sudo git で
  # 操作すると "dubious ownership" エラーになるため）
  REPO_OWNER=$(stat -c %U "$INSTALL_DIR")
  if [ "$REPO_OWNER" = "$(id -un)" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
  else
    sudo -u "$REPO_OWNER" git -C "$INSTALL_DIR" pull --ff-only
  fi
else
  echo "[INFO] Cloning $REPO_URL ($BRANCH) into $INSTALL_DIR..."
  echo "       （プライベートリポジトリの場合、Password には GitHub の Personal Access Token を入力）"
  sudo mkdir -p "$(dirname "$INSTALL_DIR")"
  sudo git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"
[ -f "$COMPOSE_FILE" ] || { echo "$INSTALL_DIR/$COMPOSE_FILE が見つかりません"; exit 1; }

# =========================
# 導入前チェック（check_env.sh があれば実行）
# =========================
# 更新時は自分のコンテナがポートを使用中で NG と誤判定されるため、初回のみ実行する
if [ "$FIRST_INSTALL" -eq 0 ]; then
  echo "[INFO] Update mode: skipping pre-install check"
elif [ -f scripts/check_env.sh ]; then
  echo "[INFO] Running pre-install check..."
  if ! sudo bash scripts/check_env.sh -m prod | sed 's/^/       /'; then
    read -r -p "チェックで NG がありました。続行しますか？ [y/N]: " Red_CONT
    [ "${Red_CONT}" = "y" ] || [ "${Red_CONT}" = "Y" ] || { echo "中止しました"; exit 1; }
  fi
fi

# =========================
# .env 作成（初回のみ。既存の .env は絶対に上書きしない）
# =========================
# .env が無いのに DB データ（ボリューム）が残っている場合、新しいパスワードでは
# 既存DBに接続できず、機器パスワードも復号できないため、ここで止める
PROJECT_NAME=$(basename "$INSTALL_DIR")
if [ "$FIRST_INSTALL" -eq 1 ] && sudo podman volume exists "${PROJECT_NAME}_postgres_data" 2>/dev/null; then
  echo ""
  echo "⚠ .env がありませんが、既存のデータベース（ボリューム ${PROJECT_NAME}_postgres_data）が残っています。"
  echo "  バックアップした .env があれば $INSTALL_DIR/.env に戻してから再実行してください。"
  echo "  （バックアップ: $ENV_BACKUP_DIR/ ）"
  echo "  データを捨てて作り直す場合: sudo podman-compose -f $COMPOSE_FILE down -v を実行してから再実行"
  exit 1
fi
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo "[INFO] Creating .env..."
  POSTGRES_PASSWORD=$(gen_secret 32)
  SECRET_KEY=$(gen_secret 64)
  DEVICE_ENCRYPTION_KEY=$(gen_fernet_key)

  TMP_ENV=$(mktemp)
  chmod 600 "$TMP_ENV"
  cat > "$TMP_ENV" <<EOF
# NetConfig Manager 設定（setup.sh が $TS に生成）
# ※ DEVICE_ENCRYPTION_KEY を失うと登録済みの機器・踏み台のパスワードを復号できなくなります
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
SECRET_KEY=${SECRET_KEY}
DEVICE_ENCRYPTION_KEY=${DEVICE_ENCRYPTION_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
SSH_HOST_KEY_POLICY=${SSH_HOST_KEY_POLICY}
ALLOWED_ORIGINS=
HTTP_PORT=${HTTP_PORT}
EOF
  sudo install -m 600 -o root -g root "$TMP_ENV" "$INSTALL_DIR/.env"
  rm -f "$TMP_ENV"
else
  # HTTP_PORT だけは入力値を反映する
  if sudo grep -q '^HTTP_PORT=' .env; then
    sudo sed -i "s/^HTTP_PORT=.*/HTTP_PORT=${HTTP_PORT}/" .env
  else
    echo "HTTP_PORT=${HTTP_PORT}" | sudo tee -a .env >/dev/null
  fi
fi

# =========================
# .env バックアップ（root のみ読める場所へ）
# =========================
echo "[INFO] Backing up .env..."
sudo mkdir -p "$ENV_BACKUP_DIR"
sudo chmod 700 "$ENV_BACKUP_DIR"
sudo install -m 600 "$INSTALL_DIR/.env" "$ENV_BACKUP_DIR/env-$TS"

# =========================
# firewalld ポート開放
# =========================
echo "[INFO] Configuring firewall..."
if systemctl is-active --quiet firewalld; then
  if [ "$HTTP_PORT" = "80" ]; then
    sudo firewall-cmd --permanent --add-service=http
  else
    sudo firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp"
  fi
  sudo firewall-cmd --reload
  echo "[INFO] Port ${HTTP_PORT}/tcp opened in firewalld"
else
  echo "[INFO] firewalld is not running, skipping"
fi

# =========================
# コンテナのビルド・起動
# =========================
echo "[INFO] Building and starting containers (初回は数分かかります)..."
# podman-compose は compose ファイルが変わらない限り既存コンテナを作り直さない
# （イメージだけ更新しても古いコンテナが動き続ける）ため、ビルド後に必ず再作成する。
# ボリューム（DB・コンフィグ履歴）は保持される
sudo podman-compose -f "$COMPOSE_FILE" build
sudo podman-compose -f "$COMPOSE_FILE" up -d --force-recreate

# =========================
# 再起動後の自動起動（Podman にはデーモンが無いため）
# =========================
echo "[INFO] Enabling auto start on boot..."
sudo systemctl enable --now podman-restart.service

# =========================
# 起動確認（ヘルスチェック）
# =========================
echo "[INFO] Waiting for NetConfig Manager to become ready..."
HEALTH_URL="http://localhost:${HTTP_PORT}/api/health"
READY=0
for _ in $(seq 1 60); do
  if curl -fsS -m 3 "$HEALTH_URL" 2>/dev/null | grep -q '"ok"'; then READY=1; break; fi
  sleep 3
done

if [ "$READY" -ne 1 ]; then
  echo ""
  echo "❌ 起動を確認できませんでした（3分待機）"
  echo ""
  echo "■ コンテナ状態"
  sudo podman ps -a --format '{{.Names}}\t{{.Status}}' | sed 's/^/  /'
  echo ""
  echo "■ backend のログ（末尾）"
  sudo podman-compose -f "$COMPOSE_FILE" logs --tail 30 backend 2>/dev/null | sed 's/^/  /' || true
  exit 1
fi

# =========================
# 完了
# =========================
echo ""
echo "✅ 完了"
echo ""
echo "■ アクセスURL"
if [ "$HTTP_PORT" = "80" ]; then echo "http://${IPADD}/"; else echo "http://${IPADD}:${HTTP_PORT}/"; fi
echo ""
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo "■ 初期管理者（ログイン後「パスワード変更」で変更してください）"
  echo "ユーザー名: ${ADMIN_USERNAME}"
  echo "パスワード: ${ADMIN_PASSWORD}"
  echo ""
else
  echo "■ 更新しました（ログイン情報は変更していません）"
  echo ""
fi
echo "■ 設定ファイル（暗号化キーを含むため、サーバー外にも必ずバックアップ）"
echo "$INSTALL_DIR/.env"
echo "$ENV_BACKUP_DIR/env-$TS"
echo ""
echo "■ コンテナ状態"
echo "sudo podman ps"
echo ""
echo "■ ログ確認"
echo "cd $INSTALL_DIR && sudo podman-compose -f $COMPOSE_FILE logs -f backend"
echo ""
echo "■ 更新（最新ソースで再ビルド）"
echo "bash $INSTALL_DIR/scripts/setup.sh"
echo ""
echo "■ 停止"
echo "cd $INSTALL_DIR && sudo podman-compose -f $COMPOSE_FILE down"
echo ""
echo "■ 動作確認"
echo "curl $HEALTH_URL"
