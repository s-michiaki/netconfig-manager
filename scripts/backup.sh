#!/usr/bin/env bash
# NetConfig Manager のバックアップ
#
#   DB（pg_dump）・コンフィグ履歴（Git リポジトリ）・SSH の known_hosts・ターミナルの記録・.env・証明書を
#   1つのファイル（netconfig-backup-YYYYmmdd-HHMMSS.tar.gz）にまとめ、古いものを削除する。
#   setup.sh が systemd タイマー（netconfig-backup.timer）として毎日実行するよう登録する。
#
# 使い方（root で実行）:
#   bash scripts/backup.sh                 # 今すぐバックアップ
#   bash scripts/backup.sh --list          # バックアップの一覧
#
# 設定（.env に書けば上書きできる）:
#   BACKUP_DIR=/var/backups/netconfig-manager   保存先（別ディスク・NFS などを推奨）
#   BACKUP_KEEP_DAYS=14                         保存日数（これより古いものを削除）
#   BACKUP_TERMINAL_LOGS=true                   ターミナルの記録も含める
#
# ※ .env（DEVICE_ENCRYPTION_KEY）を含むため、バックアップは root だけが読めるようにしている。
#   バックアップを持ち出すときは取り扱いに注意すること（機器のパスワードを復号できる）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROJECT_NAME="${PROJECT_NAME:-$(basename "$INSTALL_DIR")}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"   # 動作確認用に docker も指定できる

# .env の値（無ければ既定値）
env_value() {
  local v=""
  [ -f "$INSTALL_DIR/.env" ] && v=$( (grep -E "^$1=" "$INSTALL_DIR/.env" || true) | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//')
  echo "${v:-$2}"
}
BACKUP_DIR="${BACKUP_DIR:-$(env_value BACKUP_DIR /var/backups/netconfig-manager)}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-$(env_value BACKUP_KEEP_DAYS 14)}"
BACKUP_TERMINAL_LOGS="${BACKUP_TERMINAL_LOGS:-$(env_value BACKUP_TERMINAL_LOGS true)}"

log() { echo "$(date '+%F %T') $*"; }

if [ "${1:-}" = "--list" ]; then
  ls -lh "$BACKUP_DIR"/netconfig-backup-*.tar.gz 2>/dev/null || echo "バックアップはありません（$BACKUP_DIR）"
  exit 0
fi

[[ "$BACKUP_KEEP_DAYS" =~ ^[0-9]+$ ]] || { echo "BACKUP_KEEP_DAYS は日数（整数）で指定してください: $BACKUP_KEEP_DAYS"; exit 1; }

# compose のサービス名からコンテナを探す（podman-compose・docker compose のどちらもこのラベルを付ける）
container_of() {
  local id
  id=$($CONTAINER_CMD ps -q --filter "label=com.docker.compose.project=$PROJECT_NAME" \
        --filter "label=com.docker.compose.service=$1" | head -1)
  [ -n "$id" ] || { log "[ERROR] コンテナ（$1）が起動していません。バックアップを中止します"; exit 1; }
  echo "$id"
}
DB=$(container_of db)
BACKEND=$(container_of backend)

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
TS=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d "$BACKUP_DIR/.work-$TS-XXXX")
trap 'rm -rf "$WORK"' EXIT

log "[INFO] バックアップ開始 → $BACKUP_DIR/netconfig-backup-$TS.tar.gz"

# DB（カスタム形式。復元は pg_restore）
$CONTAINER_CMD exec "$DB" pg_dump -U netconfig -d netconfig -Fc --no-owner > "$WORK/db.dump"
[ -s "$WORK/db.dump" ] || { log "[ERROR] DB のダンプが空です"; exit 1; }

# コンフィグ履歴（機器ごとの Git リポジトリ）・known_hosts・ターミナルの記録
$CONTAINER_CMD exec "$BACKEND" tar -C /app/configs -cf - . > "$WORK/configs.tar"
$CONTAINER_CMD exec "$BACKEND" tar -C /data/ssh -cf - . > "$WORK/ssh.tar"
if [ "$BACKUP_TERMINAL_LOGS" = "true" ]; then
  $CONTAINER_CMD exec "$BACKEND" tar -C /data/terminal-logs -cf - . > "$WORK/terminal-logs.tar"
fi

# 設定（.env・証明書）
[ -f "$INSTALL_DIR/.env" ] && cp -p "$INSTALL_DIR/.env" "$WORK/env"
if compgen -G "$INSTALL_DIR/certs/*" >/dev/null; then
  tar -C "$INSTALL_DIR" -cf "$WORK/certs.tar" certs
fi

VERSION=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
cat > "$WORK/manifest.txt" <<EOF
NetConfig Manager バックアップ
作成日時: $(date '+%F %T %z')
ホスト: $(hostname)
コミット: $VERSION
内容: $(cd "$WORK" && ls | tr '\n' ' ')
復元: bash scripts/restore.sh <このファイル>
EOF

OUT="$BACKUP_DIR/netconfig-backup-$TS.tar.gz"
tar -C "$WORK" -czf "$OUT.part" .
mv "$OUT.part" "$OUT"
log "[INFO] 作成しました: $OUT（$(du -h "$OUT" | cut -f1)）"

# 古いバックアップの削除（最新の1つは必ず残す）
LATEST=$(ls -1t "$BACKUP_DIR"/netconfig-backup-*.tar.gz | head -1)
find "$BACKUP_DIR" -maxdepth 1 -name 'netconfig-backup-*.tar.gz' -mtime +"$BACKUP_KEEP_DAYS" ! -path "$LATEST" -print -delete \
  | sed "s/^/$(date '+%F %T') [INFO] 削除: /"
