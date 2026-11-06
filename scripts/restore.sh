#!/usr/bin/env bash
# NetConfig Manager の復元（scripts/backup.sh で作ったファイルから）
#
# 使い方（root で実行）:
#   bash scripts/restore.sh /var/backups/netconfig-manager/netconfig-backup-YYYYmmdd-HHMMSS.tar.gz
#
# 処理の流れ:
#   1. アプリのコンテナ（backend / worker / beat / frontend）を止める（db と redis は動かしたまま）
#   2. DB を作り直してダンプを流し込む
#   3. コンフィグ履歴・known_hosts・ターミナルの記録のボリュームを中身ごと入れ替える
#   4. .env の DEVICE_ENCRYPTION_KEY がバックアップと違えば、.env をバックアップのものに戻す
#      （違う鍵では機器のパスワードを復号できないため。今の .env は /root/netconfig-manager-backup/ に退避）
#   5. コンテナを起動する（起動時にマイグレーションが適用される）
#
# ※ 現在のデータはすべてバックアップの時点に置き換わります。
# ※ 新しいバージョンで作ったバックアップを古いバージョンに戻すことはできません（先に git pull と setup.sh を）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROJECT_NAME="${PROJECT_NAME:-$(basename "$INSTALL_DIR")}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_BACKUP_DIR="${ENV_BACKUP_DIR:-/root/netconfig-manager-backup}"
APP_SERVICES=(frontend beat worker backend)

FILE="${1:-}"
[ -n "$FILE" ] && [ -f "$FILE" ] || { echo "使い方: bash scripts/restore.sh <バックアップファイル>"; exit 1; }

log() { echo "$(date '+%F %T') $*"; }
container_of() {
  $CONTAINER_CMD ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$1" | head -1
}
env_value() { (grep -E "^$2=" "$1" 2>/dev/null || true) | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'; }

umask 077
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$FILE"
[ -f "$WORK/manifest.txt" ] && [ -f "$WORK/db.dump" ] || { echo "NetConfig Manager のバックアップではありません: $FILE"; exit 1; }
echo "----------------------------------------"
cat "$WORK/manifest.txt"
echo "----------------------------------------"
echo "現在のデータ（DB・コンフィグ履歴など）をすべてこのバックアップの内容に置き換えます。"
if [ "${RESTORE_YES:-}" != "1" ]; then
  read -r -p "続けるには yes と入力してください: " ans
  [ "$ans" = "yes" ] || { echo "中止しました"; exit 1; }
fi

DB=$(container_of db)
[ -n "$DB" ] || { echo "db コンテナが見つかりません。先に setup.sh で起動してください"; exit 1; }
$CONTAINER_CMD start "$DB" >/dev/null
for _ in $(seq 1 30); do
  $CONTAINER_CMD exec "$DB" pg_isready -U netconfig >/dev/null 2>&1 && break
  sleep 2
done

# 1. アプリを止める
STOPPED=()
for s in "${APP_SERVICES[@]}"; do
  c=$(container_of "$s")
  [ -n "$c" ] || continue
  log "[INFO] 停止: $s"
  $CONTAINER_CMD stop "$c" >/dev/null
  STOPPED+=("$c")
done

# 2. .env（暗号鍵が違うときだけ戻す）
ENV_CHANGED=0
if [ -f "$WORK/env" ]; then
  if [ "$(env_value "$WORK/env" DEVICE_ENCRYPTION_KEY)" != "$(env_value "$INSTALL_DIR/.env" DEVICE_ENCRYPTION_KEY)" ]; then
    mkdir -p "$ENV_BACKUP_DIR" && chmod 700 "$ENV_BACKUP_DIR"
    TS=$(date +%Y%m%d-%H%M%S)
    [ -f "$INSTALL_DIR/.env" ] && install -m 600 "$INSTALL_DIR/.env" "$ENV_BACKUP_DIR/env-before-restore-$TS"
    install -m 600 "$WORK/env" "$INSTALL_DIR/.env"
    ENV_CHANGED=1
    log "[INFO] .env をバックアップのものに戻しました（今までの .env: $ENV_BACKUP_DIR/env-before-restore-$TS）"
  fi
fi

# 3. DB を作り直して流し込む
log "[INFO] DB を復元しています..."
$CONTAINER_CMD exec "$DB" psql -q -U netconfig -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'netconfig' AND pid <> pg_backend_pid();" \
  -c "DROP DATABASE IF EXISTS netconfig;" -c "CREATE DATABASE netconfig OWNER netconfig;" >/dev/null
$CONTAINER_CMD exec -i "$DB" pg_restore -U netconfig -d netconfig --no-owner --exit-on-error < "$WORK/db.dump"
# DB ユーザーのパスワードを（戻した）.env に合わせる（別サーバーへ復元したときに接続できるように）
PGPW=$(env_value "$INSTALL_DIR/.env" POSTGRES_PASSWORD)
if [ -n "$PGPW" ]; then
  printf "ALTER USER netconfig PASSWORD '%s';\n" "${PGPW//\'/\'\'}" \
    | $CONTAINER_CMD exec -i "$DB" psql -q -U netconfig -d postgres -v ON_ERROR_STOP=1 >/dev/null
fi

# 4. ボリュームの中身を入れ替える
restore_volume() {  # $1=ボリューム名の後半 $2=tar
  [ -f "$WORK/$2" ] || return 0
  local vol="${PROJECT_NAME}_$1" mp
  mp=$($CONTAINER_CMD volume inspect -f '{{.Mountpoint}}' "$vol" 2>/dev/null) || { log "[WARN] ボリューム $vol がありません（スキップ）"; return 0; }
  log "[INFO] 復元: $vol"
  find "$mp" -mindepth 1 -delete
  tar -C "$mp" --numeric-owner -xf "$WORK/$2"
}
restore_volume config_repo configs.tar
restore_volume ssh_data ssh.tar
restore_volume terminal_logs terminal-logs.tar

# 証明書（今の certs は退避）
if [ -f "$WORK/certs.tar" ]; then
  if [ -d "$INSTALL_DIR/certs" ] && compgen -G "$INSTALL_DIR/certs/*.crt" >/dev/null; then
    cp -a "$INSTALL_DIR/certs" "$ENV_BACKUP_DIR/certs-before-restore-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  fi
  tar -C "$INSTALL_DIR" -xf "$WORK/certs.tar"
fi

# 5. 起動
if [ "$ENV_CHANGED" -eq 1 ]; then
  # .env の変更はコンテナを作り直さないと反映されない
  log "[INFO] .env を反映するためコンテナを作り直します..."
  if [ "$CONTAINER_CMD" = "podman" ]; then
    (cd "$INSTALL_DIR" && podman-compose -f "$COMPOSE_FILE" up -d --force-recreate)
  else
    (cd "$INSTALL_DIR" && docker compose -f "$COMPOSE_FILE" up -d --force-recreate)
  fi
else
  for ((i = ${#STOPPED[@]} - 1; i >= 0; i--)); do $CONTAINER_CMD start "${STOPPED[$i]}" >/dev/null; done
fi
log "[INFO] 復元が完了しました。画面で機器・コンフィグ履歴を確認してください"
