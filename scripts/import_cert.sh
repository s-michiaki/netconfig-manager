#!/bin/bash
# =============================================================================
# NetConfig Manager HTTPS 化（証明書の取り込み）
#
# step-ca などで発行済みのサーバー証明書・秘密鍵を NetConfig Manager に取り込み、HTTPS を有効にする。
#   - 証明書と秘密鍵の組み合わせ・有効期限・ルート CA での検証をチェックしてから配置する
#   - 配置先: <INSTALL_DIR>/certs/server.crt, server.key, ca.crt（Git 管理外）
#   - nginx（frontend コンテナ）を再起動して HTTPS を有効にし、HTTP は HTTPS へ転送する
#
# 使い方（一般ユーザー + sudo、または root で実行）:
#   bash scripts/import_cert.sh        # [ ] 内は Enter でそのまま採用
#
# 既定値は setup_step-ca.sh の出力に合わせている:
#   証明書   ~/certs/<COMMON_NAME>.crt（中間 CA を含むチェーン）
#   秘密鍵   ~/certs/<COMMON_NAME>.key
#   ルート CA /etc/step-ca/certs/root_ca.crt
# 証明書を更新（再発行）したときも、このスクリプトをもう一度実行すればよい。
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

echo "=== NetConfig Manager HTTPS Setup Start ==="
# =========================
# 設定
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../docker-compose.prod.yml" ]; then
  INSTALL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  INSTALL_DIR="/opt/netconfig-manager"
fi
COMPOSE_FILE="docker-compose.prod.yml"
LOGIN_USER="$(logname 2>/dev/null || id -un)"
USER_HOME=$(eval echo ~"$LOGIN_USER")
ENV_BACKUP_DIR="/root/netconfig-manager-backup"
TS=$(date +%Y%m%d-%H%M%S)

# 証明書: ~/certs の .crt のうち一番新しいもの（setup_step-ca.sh が作る短期の server.crt は除く）
CERT_FILE=$(ls -t "$USER_HOME"/certs/*.crt 2>/dev/null | grep -v '/server\.crt$' | head -1 || true)
CERT_FILE="${CERT_FILE:-$USER_HOME/certs/server.crt}"
# ルート CA: step-ca の CA ディレクトリ → step CLI の bootstrap 先 の順に探す
CA_FILE="-"
for f in /etc/step-ca/certs/root_ca.crt "$USER_HOME/.step/certs/root_ca.crt"; do
  if sudo test -f "$f"; then CA_FILE="$f"; break; fi
done

# =========================
# 設定値入力
# =========================
read -r -p "INSTALL_DIR Please Enter [${INSTALL_DIR}]: " Red_INSTALL_DIR
if [ -n "${Red_INSTALL_DIR}" ]; then INSTALL_DIR="${Red_INSTALL_DIR}" ; fi
[ -f "$INSTALL_DIR/$COMPOSE_FILE" ] || { echo "$INSTALL_DIR/$COMPOSE_FILE が見つかりません（先に setup.sh で導入してください）"; exit 1; }

HTTPS_PORT="443"
HTTP_PORT="80"
if sudo test -f "$INSTALL_DIR/.env"; then
  v=$(sudo sed -n 's/^HTTPS_PORT=//p' "$INSTALL_DIR/.env" | tail -1); [ -n "$v" ] && HTTPS_PORT="$v"
  v=$(sudo sed -n 's/^HTTP_PORT=//p' "$INSTALL_DIR/.env" | tail -1); [ -n "$v" ] && HTTP_PORT="$v"
fi

read -r -p "CERT_FILE (サーバー証明書) Please Enter [${CERT_FILE}]: " Red_CERT_FILE
if [ -n "${Red_CERT_FILE}" ]; then CERT_FILE="${Red_CERT_FILE}" ; fi

KEY_FILE="${CERT_FILE%.crt}.key"
read -r -p "KEY_FILE (秘密鍵) Please Enter [${KEY_FILE}]: " Red_KEY_FILE
if [ -n "${Red_KEY_FILE}" ]; then KEY_FILE="${Red_KEY_FILE}" ; fi

read -r -p "CA_FILE (ルート CA 証明書。無しは -) Please Enter [${CA_FILE}]: " Red_CA_FILE
if [ -n "${Red_CA_FILE}" ]; then CA_FILE="${Red_CA_FILE}" ; fi

read -r -p "IP Address Please Enter [${IPADD}]: " Red_IPADD
if [ -n "${Red_IPADD}" ]; then IPADD="${Red_IPADD}" ; fi

read -r -p "HTTPS_PORT Please Enter [${HTTPS_PORT}]: " Red_HTTPS_PORT
if [ -n "${Red_HTTPS_PORT}" ]; then HTTPS_PORT="${Red_HTTPS_PORT}" ; fi
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] && [ "$HTTPS_PORT" -ge 1 ] && [ "$HTTPS_PORT" -le 65535 ] \
  || { echo "HTTPS_PORT が不正です: $HTTPS_PORT"; exit 1; }
[ "$HTTPS_PORT" != "$HTTP_PORT" ] || { echo "HTTPS_PORT と HTTP_PORT（$HTTP_PORT）が同じです"; exit 1; }

# =========================
# 依存チェック
# =========================
command -v sudo >/dev/null || { echo "sudo required"; exit 1; }
if ! command -v openssl >/dev/null; then
  echo "[INFO] Installing openssl..."
  sudo dnf install -y openssl
fi
command -v podman >/dev/null || { echo "podman が見つかりません（先に setup.sh で導入してください）"; exit 1; }

# =========================
# 証明書の読み込み（root 所有のファイルでも読めるよう sudo で一時ディレクトリへコピー）
# =========================
WORK=$(mktemp -d)
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

copy_in() { # $1=元ファイル $2=コピー先 $3=表示名
  sudo test -f "$1" || { echo "❌ $3 が見つかりません: $1"; exit 1; }
  sudo cat "$1" > "$2"
}
copy_in "$CERT_FILE" "$WORK/server.crt" "証明書"
copy_in "$KEY_FILE"  "$WORK/server.key" "秘密鍵"
HAS_CA=0
if [ "$CA_FILE" != "-" ] && [ -n "$CA_FILE" ]; then
  copy_in "$CA_FILE" "$WORK/ca.crt" "ルート CA 証明書"
  HAS_CA=1
fi

WARNINGS=0
warn() { echo "⚠ $*"; WARNINGS=$((WARNINGS + 1)); }

# =========================
# 証明書のチェック
# =========================
echo "[INFO] Checking certificate..."
openssl x509 -in "$WORK/server.crt" -noout 2>/dev/null \
  || { echo "❌ 証明書を読み込めません（PEM 形式の証明書ファイルを指定してください）: $CERT_FILE"; exit 1; }
if grep -q "ENCRYPTED" "$WORK/server.key"; then
  echo "❌ 秘密鍵がパスワードで暗号化されています。nginx は暗号化された鍵を読み込めません"
  echo "   復号してから指定してください: openssl pkey -in 暗号化された鍵 -out 復号した鍵"
  exit 1
fi
openssl pkey -in "$WORK/server.key" -noout 2>/dev/null \
  || { echo "❌ 秘密鍵を読み込めません（PEM 形式の秘密鍵を指定してください）: $KEY_FILE"; exit 1; }

# 証明書と秘密鍵の組み合わせ（公開鍵が一致するか）
CERT_PUB=$(openssl x509 -in "$WORK/server.crt" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)
KEY_PUB=$(openssl pkey -in "$WORK/server.key" -pubout -outform DER 2>/dev/null | sha256sum)
[ "$CERT_PUB" = "$KEY_PUB" ] \
  || { echo "❌ 証明書と秘密鍵の組み合わせが一致しません（別の証明書の鍵を指定していないか確認してください）"; exit 1; }

# 有効期限
openssl x509 -in "$WORK/server.crt" -noout -checkend 0 >/dev/null \
  || { echo "❌ 証明書の有効期限が切れています（$(openssl x509 -in "$WORK/server.crt" -noout -enddate | cut -d= -f2)）"; exit 1; }
openssl x509 -in "$WORK/server.crt" -noout -checkend $((30 * 86400)) >/dev/null \
  || warn "証明書の有効期限が30日以内です（setup_step-ca.sh が作る server.crt は既定24時間です。長期の証明書を指定してください）"

SUBJECT=$(openssl x509 -in "$WORK/server.crt" -noout -subject | sed 's/^subject= *//')
ISSUER=$(openssl x509 -in "$WORK/server.crt" -noout -issuer | sed 's/^issuer= *//')
NOT_AFTER=$(openssl x509 -in "$WORK/server.crt" -noout -enddate | cut -d= -f2)
SAN=$(openssl x509 -in "$WORK/server.crt" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | sed 's/^ *//' || true)
CHAIN=$(grep -c "BEGIN CERTIFICATE" "$WORK/server.crt")

echo "       サブジェクト : $SUBJECT"
echo "       発行者       : $ISSUER"
echo "       有効期限     : $NOT_AFTER"
echo "       SAN          : ${SAN:-（なし）}"
echo "       チェーン     : ${CHAIN} 枚（サーバー証明書＋中間 CA）"

# アクセスするアドレスが SAN に含まれるか（含まれないとブラウザが警告を出す）
if [[ "$IPADD" =~ ^[0-9.]+$ ]]; then
  echo "$SAN" | grep -qE "IP Address:${IPADD//./\\.}(,|$)" \
    || warn "SAN に IP アドレス $IPADD が含まれていません（https://$IPADD/ で開くと証明書エラーになります。ホスト名で開く場合は問題ありません）"
else
  echo "$SAN" | grep -qE "DNS:${IPADD//./\\.}(,|$)" \
    || warn "SAN に $IPADD が含まれていません（https://$IPADD/ で開くと証明書エラーになります）"
fi

# ルート CA で検証できるか（チェーンに中間 CA が含まれているか）
if [ "$HAS_CA" -eq 1 ]; then
  openssl x509 -in "$WORK/ca.crt" -noout 2>/dev/null \
    || { echo "❌ ルート CA 証明書を読み込めません: $CA_FILE"; exit 1; }
  if openssl verify -CAfile "$WORK/ca.crt" -untrusted "$WORK/server.crt" "$WORK/server.crt" >/dev/null 2>&1; then
    echo "       ルート CA    : 検証 OK（$(openssl x509 -in "$WORK/ca.crt" -noout -subject | sed 's/^subject= *//')）"
  else
    warn "ルート CA で証明書を検証できません（別の CA の証明書か、中間 CA がチェーンに含まれていない可能性があります）"
  fi
  CA_FP=$(openssl x509 -in "$WORK/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)
fi

if [ "$WARNINGS" -gt 0 ]; then
  read -r -p "警告があります。このまま取り込みますか？ [y/N]: " Red_CONT
  [ "${Red_CONT}" = "y" ] || [ "${Red_CONT}" = "Y" ] || { echo "中止しました"; exit 1; }
fi

# =========================
# 既存の証明書をバックアップ（root のみ読める場所へ）
# =========================
CERT_DIR="$INSTALL_DIR/certs"
sudo install -d -m 755 "$CERT_DIR"
if sudo test -f "$CERT_DIR/server.crt" || sudo test -f "$CERT_DIR/server.key"; then
  echo "[INFO] Backing up current certificate..."
  sudo install -d -m 700 "$ENV_BACKUP_DIR" "$ENV_BACKUP_DIR/certs-$TS"
  for f in server.crt server.key ca.crt; do
    if sudo test -f "$CERT_DIR/$f"; then sudo cp -p "$CERT_DIR/$f" "$ENV_BACKUP_DIR/certs-$TS/"; fi
  done
  echo "       → $ENV_BACKUP_DIR/certs-$TS/"
fi

# =========================
# 証明書の配置
# =========================
echo "[INFO] Installing certificate into $CERT_DIR ..."
sudo install -m 644 -o root -g root "$WORK/server.crt" "$CERT_DIR/server.crt"
sudo install -m 600 -o root -g root "$WORK/server.key" "$CERT_DIR/server.key"
if [ "$HAS_CA" -eq 1 ]; then
  sudo install -m 644 -o root -g root "$WORK/ca.crt" "$CERT_DIR/ca.crt"
else
  sudo rm -f "$CERT_DIR/ca.crt"   # 古い CA を配布し続けないように
fi

# =========================
# .env に HTTPS_PORT を反映
# =========================
if sudo test -f "$INSTALL_DIR/.env"; then
  if sudo grep -q '^HTTPS_PORT=' "$INSTALL_DIR/.env"; then
    sudo sed -i "s/^HTTPS_PORT=.*/HTTPS_PORT=${HTTPS_PORT}/" "$INSTALL_DIR/.env"
  else
    echo "HTTPS_PORT=${HTTPS_PORT}" | sudo tee -a "$INSTALL_DIR/.env" >/dev/null
  fi
fi

# =========================
# firewalld ポート開放
# =========================
echo "[INFO] Configuring firewall..."
if systemctl is-active --quiet firewalld; then
  if [ "$HTTPS_PORT" = "443" ]; then
    sudo firewall-cmd --permanent --add-service=https
  else
    sudo firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp"
  fi
  sudo firewall-cmd --reload
  echo "[INFO] Port ${HTTPS_PORT}/tcp opened in firewalld"
else
  echo "[INFO] firewalld is not running, skipping"
fi

# =========================
# nginx（frontend コンテナ）へ反映
# =========================
PROJECT_NAME=$(basename "$INSTALL_DIR")
FRONT=$(sudo podman ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
          --filter "label=com.docker.compose.service=frontend" --format '{{.Names}}' 2>/dev/null | head -1 || true)
CAN_RESTART=0
if [ -n "$FRONT" ]; then
  MOUNTS=$(sudo podman inspect "$FRONT" --format '{{range .Mounts}}{{.Destination}} {{end}}' 2>/dev/null || true)
  PORTS=$(sudo podman port "$FRONT" 2>/dev/null || true)
  if [[ "$MOUNTS" == *"/etc/nginx/certs"* ]] && echo "$PORTS" | grep -q "^443/tcp -> .*:${HTTPS_PORT}$"; then
    CAN_RESTART=1
  fi
fi

if [ "$CAN_RESTART" -eq 1 ]; then
  echo "[INFO] Restarting $FRONT ..."
  sudo podman restart "$FRONT" >/dev/null
else
  # HTTPS 対応前の構成で動いている・ポートを変えた場合は、コンテナを作り直す必要がある
  echo "[INFO] コンテナの作り直しが必要です（HTTPS 対応前の構成、または HTTPS_PORT の変更）"
  echo "[INFO] Recreating containers..."
  # setup.sh と同じ手順（ボリューム＝DB・コンフィグ履歴は保持される）
  (cd "$INSTALL_DIR" && sudo podman-compose -f "$COMPOSE_FILE" build \
     && sudo podman-compose -f "$COMPOSE_FILE" up -d --force-recreate)
  FRONT=$(sudo podman ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
            --filter "label=com.docker.compose.service=frontend" --format '{{.Names}}' 2>/dev/null | head -1 || true)
fi

# =========================
# 起動確認
# =========================
echo "[INFO] Waiting for HTTPS to become ready..."
if [ "$HTTPS_PORT" = "443" ]; then BASE="https://${IPADD}"; else BASE="https://${IPADD}:${HTTPS_PORT}"; fi
if [ "$HTTP_PORT" = "80" ]; then HTTP_BASE="http://${IPADD}"; else HTTP_BASE="http://${IPADD}:${HTTP_PORT}"; fi
CURL_TRUST=()
[ "$HAS_CA" -eq 1 ] && CURL_TRUST=(--cacert "$WORK/ca.crt")
READY=0
for _ in $(seq 1 40); do
  if curl -fsS -m 3 -k "https://localhost:${HTTPS_PORT}/api/health" 2>/dev/null | grep -q '"ok"'; then READY=1; break; fi
  sleep 3
done

if [ "$READY" -ne 1 ]; then
  echo ""
  echo "❌ HTTPS で応答がありません（2分待機）"
  echo ""
  echo "■ nginx のログ（末尾）"
  [ -n "$FRONT" ] && sudo podman logs --tail 20 "$FRONT" 2>&1 | sed 's/^/  /'
  exit 1
fi

VERIFIED=0
if curl -fsS -m 5 "${CURL_TRUST[@]}" "${BASE}/api/health" 2>/dev/null | grep -q '"ok"'; then VERIFIED=1; fi

# =========================
# 完了
# =========================
echo ""
echo "✅ 完了"
echo ""
echo "■ アクセスURL"
echo "${BASE}/"
echo "（${HTTP_BASE}/ は HTTPS へ転送されます）"
echo ""
if [ "$VERIFIED" -eq 1 ]; then
  echo "■ 証明書の検証: OK（${BASE} で信頼できる証明書が返っています）"
else
  echo "■ 証明書の検証: ⚠ ${BASE} では検証できませんでした（SAN にこのアドレスが無い、またはルート CA 未指定）"
fi
echo ""
if [ "$HAS_CA" -eq 1 ]; then
  echo "■ 利用者の PC にルート CA を登録（初回のみ。登録しないとブラウザが警告を出します）"
  echo "  ダウンロード: ${HTTP_BASE}/ca.crt"
  echo "  SHA256 指紋 : ${CA_FP}"
  echo "  Windows（管理者の PowerShell）:"
  echo "    Import-Certificate -FilePath .\\netconfig-root-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root"
  echo "  （またはファイルをダブルクリック →「証明書のインストール」→ ローカルコンピューター →"
  echo "    「信頼されたルート証明機関」に配置）"
  echo ""
fi
echo "■ 配置した証明書"
echo "$CERT_DIR/server.crt"
echo "$CERT_DIR/server.key"
[ "$HAS_CA" -eq 1 ] && echo "$CERT_DIR/ca.crt"
echo ""
echo "■ 証明書を更新したとき"
echo "bash $INSTALL_DIR/scripts/import_cert.sh"
echo ""
echo "■ HTTP に戻す"
echo "sudo rm $CERT_DIR/server.crt $CERT_DIR/server.key && sudo podman restart $FRONT"
