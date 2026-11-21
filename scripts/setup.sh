#!/bin/bash
# =============================================================================
# NetConfig Manager 自動セットアップ（AlmaLinux / RHEL 10 系・Podman）
#
# 使い方（一般ユーザー + sudo、または root で実行）:
#   bash setup.sh                 # 初回: 対話形式でセットアップ（[ ] 内は Enter でそのまま採用）
#                                 # 2回目以降: 何も聞かずに更新する
#   bash setup.sh --reconfigure   # 2回目以降でも設定（ポート・IP アドレスなど）を聞き直す
#
# 2回目以降に実行すると「更新」として動作する:
#   - ソースを git pull し、コンテナを再ビルドして再起動
#   - 既存の .env（暗号化キー等）はそのまま使う（再生成しない）。ポートも .env の値を使う
#   - git pull でこのスクリプト自身が変わったときは、新しい内容で最初からやり直す
# =============================================================================
set -euo pipefail

# 全体を関数に入れてあるのは、bash がスクリプトを最後まで読み込んでから実行するようにするため
# （実行中に git pull でこのファイルが書き換わっても、読み込み済みの内容で動く）。
# 行数の差分を増やさないよう、中は字下げしていない
main() {
RECONFIGURE=0
for arg in "$@"; do
  case "$arg" in
    --reconfigure|-r) RECONFIGURE=1 ;;
    -h|--help)
      echo "使い方: bash setup.sh [--reconfigure]"
      echo "  初回は対話形式でセットアップし、2回目以降は .env の設定のまま更新します。"
      echo "  --reconfigure  2回目以降でも設定（ポート・IP アドレスなど）を聞き直す"
      exit 0 ;;
    *) echo "不明なオプションです: $arg（--help で使い方を表示）"; exit 1 ;;
  esac
done

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
HTTPS_PORT="443"
ADMIN_USERNAME="admin"
SSH_HOST_KEY_POLICY="tofu"
COMPOSE_FILE="docker-compose.prod.yml"

# リポジトリの所有者として git pull する（root 以外が所有するリポジトリを sudo git で
# 操作すると "dubious ownership" エラーになるため）
PULLED_DIR=""
pull_source() { # $1 = リポジトリ
  local owner
  owner=$(stat -c %U "$1")
  # 「pull_source ... || 対処」の形で呼ぶと関数の中では set -e が効かないため、失敗は明示的に返す
  if [ "$owner" = "$(id -un)" ]; then
    git -C "$1" pull --ff-only || return 1
  else
    sudo -u "$owner" git -C "$1" pull --ff-only || return 1
  fi
  PULLED_DIR="$1"
}
file_hash() { sha256sum "$1" 2>/dev/null | cut -d" " -f1 || true; }

# =========================
# 更新時: 先にソースを更新し、このスクリプトが変わっていたら新しい内容でやり直す
# =========================
# .env があれば導入済み（更新）。更新では質問をせず、.env の設定をそのまま使う
ASK=1
if [ -f "$INSTALL_DIR/.env" ] && [ -d "$INSTALL_DIR/.git" ] && [ "$RECONFIGURE" -eq 0 ]; then ASK=0; fi

REPO_SCRIPT="$INSTALL_DIR/scripts/setup.sh"
if [ -d "$INSTALL_DIR/.git" ] && [ -f "$INSTALL_DIR/.env" ] && [ "${NETCONFIG_SETUP_REEXEC:-0}" != "1" ]; then
  command -v git >/dev/null || { echo "git が見つかりません"; exit 1; }
  SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
  BEFORE=$(file_hash "$SELF")
  echo "[INFO] Updating source ($INSTALL_DIR)..."
  pull_source "$INSTALL_DIR" || {
    echo ""
    echo "❌ ソースを更新できませんでした（git pull に失敗）。ネットワークと、$INSTALL_DIR に手で変更したファイルが無いかを確認してください"
    exit 1
  }
  # 実行中のスクリプトと、更新後のリポジトリのスクリプトが違えば、新しいほうで最初からやり直す
  # （リポジトリの外に置いた setup.sh から実行した場合も、リポジトリのものに切り替わる）
  if [ -f "$REPO_SCRIPT" ] && [ "$BEFORE" != "$(file_hash "$REPO_SCRIPT")" ]; then
    echo "[INFO] setup.sh が更新されました。新しい内容でやり直します"
    echo ""
    NETCONFIG_SETUP_REEXEC=1 exec bash "$REPO_SCRIPT" "$@"
  fi
elif [ "${NETCONFIG_SETUP_REEXEC:-0}" = "1" ]; then
  PULLED_DIR="$INSTALL_DIR"  # やり直す前に更新済み
fi

# =========================
# 設定値入力（初回と --reconfigure のときだけ）
# =========================
# ASK=0 のときは read の代わりに既定値をそのまま採用する
ask() { # $1 = 表示する文言, $2 = 結果を入れる変数名
  if [ "$ASK" -eq 1 ]; then
    read -r -p "$1" "$2"
  else
    printf -v "$2" '%s' ""
  fi
}

ask "INSTALL_DIR Please Enter [${INSTALL_DIR}]: " Red_INSTALL_DIR
if [ -n "${Red_INSTALL_DIR}" ]; then INSTALL_DIR="${Red_INSTALL_DIR}" ; fi

if [ ! -d "$INSTALL_DIR/.git" ]; then
  read -r -p "REPO_URL Please Enter [${REPO_URL}]: " Red_REPO_URL
  if [ -n "${Red_REPO_URL}" ]; then REPO_URL="${Red_REPO_URL}" ; fi

  read -r -p "BRANCH Please Enter [${BRANCH}]: " Red_BRANCH
  if [ -n "${Red_BRANCH}" ]; then BRANCH="${Red_BRANCH}" ; fi
fi

ask "IP Address Please Enter [${IPADD}]: " Red_IPADD
if [ -n "${Red_IPADD}" ]; then IPADD="${Red_IPADD}" ; fi

# 2回目以降は .env の値を既定にする（Enter だけで今のポートを維持）
if [ -f "$INSTALL_DIR/.env" ]; then
  v=$(sudo sed -n 's/^HTTP_PORT=//p' "$INSTALL_DIR/.env" | tail -1); [ -n "$v" ] && HTTP_PORT="$v"
  v=$(sudo sed -n 's/^HTTPS_PORT=//p' "$INSTALL_DIR/.env" | tail -1); [ -n "$v" ] && HTTPS_PORT="$v"
fi

ask "HTTP_PORT Please Enter [${HTTP_PORT}]: " Red_HTTP_PORT
if [ -n "${Red_HTTP_PORT}" ]; then HTTP_PORT="${Red_HTTP_PORT}" ; fi
[[ "$HTTP_PORT" =~ ^[0-9]+$ ]] && [ "$HTTP_PORT" -ge 1 ] && [ "$HTTP_PORT" -le 65535 ] \
  || { echo "HTTP_PORT が不正です: $HTTP_PORT"; exit 1; }

# HTTPS は certs/ に証明書を置いたときだけ有効（scripts/import_cert.sh）。ポートは先に決めておく
ask "HTTPS_PORT Please Enter [${HTTPS_PORT}]: " Red_HTTPS_PORT
if [ -n "${Red_HTTPS_PORT}" ]; then HTTPS_PORT="${Red_HTTPS_PORT}" ; fi
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && [ "$HTTPS_PORT" -ge 1 ] && [ "$HTTPS_PORT" -le 65535 ] \
  || { echo "HTTPS_PORT が不正です: $HTTPS_PORT"; exit 1; }
[ "$HTTPS_PORT" != "$HTTP_PORT" ] || { echo "HTTPS_PORT と HTTP_PORT が同じです"; exit 1; }

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
  if [ "$ASK" -eq 0 ]; then
    echo "[INFO] 更新モード: HTTP_PORT=${HTTP_PORT} / HTTPS_PORT=${HTTPS_PORT}（.env の設定のまま更新します）"
    echo "       ポートなどを変えるときは: bash $INSTALL_DIR/scripts/setup.sh --reconfigure"
  fi
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
if [ "$PULLED_DIR" = "$INSTALL_DIR" ]; then
  echo "[INFO] Source is up to date ($(git -C "$INSTALL_DIR" log -1 --format='%h %s' 2>/dev/null || sudo git -C "$INSTALL_DIR" log -1 --format='%h %s' 2>/dev/null || echo "$INSTALL_DIR"))"
elif [ -d "$INSTALL_DIR/.git" ]; then
  echo "[INFO] Updating source ($INSTALL_DIR)..."
  pull_source "$INSTALL_DIR"
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
# ※ DEVICE_ENCRYPTION_KEY を失うと登録済みの機器・踏み台・認証情報プロファイルのパスワードを復号できなくなります
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
SECRET_KEY=${SECRET_KEY}
DEVICE_ENCRYPTION_KEY=${DEVICE_ENCRYPTION_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
SSH_HOST_KEY_POLICY=${SSH_HOST_KEY_POLICY}
ALLOWED_ORIGINS=
HTTP_PORT=${HTTP_PORT}
HTTPS_PORT=${HTTPS_PORT}
PUBLIC_URL=
EOF
  sudo install -m 600 -o root -g root "$TMP_ENV" "$INSTALL_DIR/.env"
  rm -f "$TMP_ENV"
else
  # HTTP_PORT・HTTPS_PORT だけは入力値を反映する
  for kv in "HTTP_PORT=${HTTP_PORT}" "HTTPS_PORT=${HTTPS_PORT}"; do
    k="${kv%%=*}"
    if sudo grep -q "^${k}=" .env; then
      sudo sed -i "s/^${k}=.*/${kv}/" .env
    else
      echo "$kv" | sudo tee -a .env >/dev/null
    fi
  done
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
  if [ "$HTTPS_PORT" = "443" ]; then
    sudo firewall-cmd --permanent --add-service=https
  else
    sudo firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp"
  fi
  sudo firewall-cmd --reload
  echo "[INFO] Port ${HTTP_PORT}/tcp, ${HTTPS_PORT}/tcp opened in firewalld"
else
  echo "[INFO] firewalld is not running, skipping"
fi

# =========================
# コンテナのビルド・起動
# =========================
# HTTPS の証明書置き場（コンテナにマウントするため、無ければ作る）
sudo install -d -m 755 "$INSTALL_DIR/certs"
HTTPS_ENABLED=0
sudo test -s "$INSTALL_DIR/certs/server.crt" && sudo test -s "$INSTALL_DIR/certs/server.key" && HTTPS_ENABLED=1

# 通知に付ける画面へのリンク（PUBLIC_URL）。未設定のときだけ、IP アドレスとポートから設定する
if [ "$HTTPS_ENABLED" -eq 1 ]; then
  if [ "$HTTPS_PORT" = "443" ]; then AUTO_URL="https://${IPADD}"; else AUTO_URL="https://${IPADD}:${HTTPS_PORT}"; fi
else
  if [ "$HTTP_PORT" = "80" ]; then AUTO_URL="http://${IPADD}"; else AUTO_URL="http://${IPADD}:${HTTP_PORT}"; fi
fi
CUR_URL=$(sudo sed -n 's/^PUBLIC_URL=//p' "$INSTALL_DIR/.env" | tail -1)
if [ -z "$CUR_URL" ]; then
  if sudo grep -q '^PUBLIC_URL=' "$INSTALL_DIR/.env"; then
    sudo sed -i "s|^PUBLIC_URL=.*|PUBLIC_URL=${AUTO_URL}|" "$INSTALL_DIR/.env"
  else
    echo "PUBLIC_URL=${AUTO_URL}" | sudo tee -a "$INSTALL_DIR/.env" >/dev/null
  fi
  echo "[INFO] PUBLIC_URL=${AUTO_URL}（通知のリンク先。変更する場合は .env を編集）"
fi

echo "[INFO] Building and starting containers (初回は数分かかります)..."
# podman-compose は compose ファイルが変わらない限り既存コンテナを作り直さない
# （イメージだけ更新しても古いコンテナが動き続ける）ため、ビルド後に必ず再作成する。
# ボリューム（DB・コンフィグ履歴）は保持される
#
# イメージを取り直す（#18）: 一度ダウンロードしたイメージは、タグ（postgres:16-alpine など）の中身が新しくなっても
# 自動では取り直されない。DB・Redis のイメージと、ビルドの土台（python・node・nginx）を毎回取り直し、
# セキュリティ修正を取り込む。取り直せなくても（インターネットに出られない等）手元のイメージで続ける
IMAGES=$( { sed -n 's#^[[:space:]]*image:[[:space:]]*\([^[:space:]]*\).*#\1#p' "$INSTALL_DIR/$COMPOSE_FILE"
            sed -n 's#^FROM[[:space:]]\{1,\}\([^[:space:]]*\).*#\1#p' "$INSTALL_DIR/backend/Dockerfile" "$INSTALL_DIR/frontend/Dockerfile"
          } | grep '/' | sort -u )
PULL_FAILED=()
for img in $IMAGES; do
  echo "[INFO] Pulling $img ..."
  if ! sudo podman pull -q "$img" >/dev/null; then
    echo "[WARN] $img を取り直せませんでした（手元のイメージで続けます）"
    PULL_FAILED+=("$img")
  fi
done
sudo podman-compose -f "$COMPOSE_FILE" build
sudo podman-compose -f "$COMPOSE_FILE" up -d --force-recreate
# 取り直し・作り直しで使われなくなった古いイメージ（名前の無いもの）を消す（ディスクの圧迫を防ぐ）
sudo podman image prune -f >/dev/null 2>&1 || true

# =========================
# 再起動後の自動起動（Podman にはデーモンが無いため）
# =========================
echo "[INFO] Enabling auto start on boot..."
sudo systemctl enable --now podman-restart.service

# =========================
# 定期バックアップ（DB・コンフィグ履歴・.env など。scripts/backup.sh を systemd タイマーで実行）
# =========================
# 実行時刻は .env の BACKUP_ON_CALENDAR（systemd の OnCalendar 形式、既定 毎日 03:15）。off で無効
BACKUP_ON_CALENDAR=$( (grep -E '^BACKUP_ON_CALENDAR=' "$INSTALL_DIR/.env" 2>/dev/null || true) | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//')
BACKUP_ON_CALENDAR="${BACKUP_ON_CALENDAR:-*-*-* 03:15:00}"
BACKUP_TIMER=""  # on / off（最後にアプリへ伝える。画面「システム状態」で、登録したのに動いていないことに気づけるように）
if [ "$BACKUP_ON_CALENDAR" = "off" ]; then
  echo "[INFO] 定期バックアップは無効です（BACKUP_ON_CALENDAR=off）"
  sudo systemctl disable --now netconfig-backup.timer 2>/dev/null || true
  BACKUP_TIMER="off"
elif ! systemd-analyze calendar "$BACKUP_ON_CALENDAR" >/dev/null 2>&1; then
  echo "[WARN] BACKUP_ON_CALENDAR の形式が正しくありません（$BACKUP_ON_CALENDAR）。定期バックアップの設定をスキップします"
else
  BACKUP_TIMER="on"
  echo "[INFO] Enabling scheduled backup ($BACKUP_ON_CALENDAR)..."
  sudo tee /etc/systemd/system/netconfig-backup.service >/dev/null <<UNIT
[Unit]
Description=NetConfig Manager backup (DB / config history / .env)
After=podman-restart.service

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_DIR/scripts/backup.sh
UNIT
  sudo tee /etc/systemd/system/netconfig-backup.timer >/dev/null <<UNIT
[Unit]
Description=NetConfig Manager scheduled backup

[Timer]
OnCalendar=$BACKUP_ON_CALENDAR
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now netconfig-backup.timer
fi

# =========================
# 起動確認（ヘルスチェック）
# =========================
echo "[INFO] Waiting for NetConfig Manager to become ready..."
# HTTPS 有効時は HTTP が HTTPS へ転送されるため -L で追う（自分自身への確認なので証明書の検証は省く）
HEALTH_URL="http://localhost:${HTTP_PORT}/api/health"
READY=0
for _ in $(seq 1 60); do
  if curl -fsSkL -m 3 "$HEALTH_URL" 2>/dev/null | grep -q '"ok"'; then READY=1; break; fi
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
  echo ""
  echo "調査用のログをまとめるには: bash $INSTALL_DIR/scripts/collect_logs.sh"
  exit 1
fi

# =========================
# 動作確認（収集などのバックグラウンド処理が実際に動くか）
# =========================
# API が応答していても、worker が Redis に接続できない・スケジューラーが起動していない状態では収集が動かない
# （依存パッケージの更新で実際に起きた）。タスクを登録して worker が実行するか、スケジューラーからの
# 定期実行が届くかまで確かめる。
echo "[INFO] Checking background workers (worker / scheduler)..."
# compose のサービス名のラベルでコンテナを探す（scripts/backup.sh と同じ方法）
BACKEND_CT=$(sudo podman ps -q --filter "label=com.docker.compose.service=backend" | head -1 || true)
if [ -z "$BACKEND_CT" ]; then
  echo "[WARN] backend のコンテナが見つからないため、動作確認を省略しました"
elif ! sudo podman exec "$BACKEND_CT" python -m app.tools.selfcheck 2>&1 | sed 's/^/  /'; then
  echo ""
  echo "❌ 画面は起動しましたが、コンフィグ収集などのバックグラウンド処理が動いていません"
  echo ""
  echo "■ コンテナ状態"
  sudo podman ps -a --format '{{.Names}}\t{{.Status}}' | sed 's/^/  /'
  for svc in worker beat; do
    echo ""
    echo "■ $svc のログ（末尾）"
    sudo podman-compose -f "$COMPOSE_FILE" logs --tail 20 "$svc" 2>/dev/null | sed 's/^/  /' || true
  done
  echo ""
  echo "画面の「システム状態」でも確認できます。原因が分からない場合は、上のログを開発者に伝えてください。"
  echo "調査用のログをまとめるには: bash $INSTALL_DIR/scripts/collect_logs.sh"
  exit 1
fi

# 定期バックアップの登録状況をアプリへ伝える（失敗しても更新は続ける）
if [ -n "$BACKEND_CT" ] && [ -n "$BACKUP_TIMER" ]; then
  sudo podman exec "$BACKEND_CT" python -m app.tools.backup_report schedule "$BACKUP_TIMER" --calendar "$BACKUP_ON_CALENDAR" \
    >/dev/null 2>&1 || echo "[WARN] 定期バックアップの登録状況を画面に伝えられませんでした（バックアップ自体は動きます）"
fi

# 使っているイメージの作成日時をアプリへ伝える（画面「システム状態」で、古いイメージのまま動いていることに気づけるように）
if [ -n "$BACKEND_CT" ]; then
  IMG_ARGS=()
  for img in $IMAGES; do
    created=$(sudo podman image inspect --format '{{.Created}}' "$img" 2>/dev/null | head -1 || true)
    [ -n "$created" ] && IMG_ARGS+=(--image "$img=$created")
  done
  for img in "${PULL_FAILED[@]}"; do IMG_ARGS+=(--pull-failed "$img"); done
  sudo podman exec "$BACKEND_CT" python -m app.tools.image_report "${IMG_ARGS[@]}" >/dev/null 2>&1 \
    || echo "[WARN] イメージの情報を画面に伝えられませんでした"
fi

# =========================
# 完了
# =========================
echo ""
echo "✅ 完了"
echo ""
echo "■ アクセスURL"
SHOW_URL=$(sudo sed -n 's/^PUBLIC_URL=//p' "$INSTALL_DIR/.env" | tail -1)
if [ "$ASK" -eq 0 ] && [ -n "$SHOW_URL" ]; then
  # 更新では IP アドレスを聞かないので、.env の PUBLIC_URL（通知のリンク先）を表示する
  echo "${SHOW_URL%/}/"
elif [ "$HTTPS_ENABLED" -eq 1 ]; then
  if [ "$HTTPS_PORT" = "443" ]; then echo "https://${IPADD}/"; else echo "https://${IPADD}:${HTTPS_PORT}/"; fi
  echo "（HTTP は HTTPS へ転送されます）"
else
  if [ "$HTTP_PORT" = "80" ]; then echo "http://${IPADD}/"; else echo "http://${IPADD}:${HTTP_PORT}/"; fi
  echo "（HTTPS 化: bash $INSTALL_DIR/scripts/import_cert.sh で証明書を取り込む）"
fi
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
echo "■ バックアップ（毎日自動。保存先は .env の BACKUP_DIR、既定 /var/backups/netconfig-manager）"
echo "今すぐ実行: sudo bash $INSTALL_DIR/scripts/backup.sh  / 一覧: sudo bash $INSTALL_DIR/scripts/backup.sh --list"
echo "次回の実行: systemctl list-timers netconfig-backup.timer"
echo "復元: sudo bash $INSTALL_DIR/scripts/restore.sh <バックアップファイル>"
echo "サーバー外への保管: .env の BACKUP_COPY_DIR（NAS などをマウントした場所）・BACKUP_POST_COMMAND（README「バックアップと復元」）"
echo "結果: 画面の「システム状態」（失敗したときは「システムの異常」の通知先へ送ります）"
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
echo "curl -kL $HEALTH_URL"
}

main "$@"
