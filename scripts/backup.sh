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
# 設定（.env に書けば上書きできる。どれもホストのこのスクリプトだけが読む）:
#   BACKUP_DIR=/var/backups/netconfig-manager   保存先（サーバー内）
#   BACKUP_KEEP_DAYS=14                         保存日数（これより古いものを削除）
#   BACKUP_TERMINAL_LOGS=true                   ターミナルの記録も含める
#   BACKUP_COPY_DIR=                            サーバー外への保管先（NAS などをマウントした場所）。空ならコピーしない
#   BACKUP_COPY_REQUIRE_MOUNT=true              コピー先が BACKUP_DIR・/ と別のディスク（マウントしたもの）であることを確かめる
#   BACKUP_COPY_KEEP_DAYS=                      コピー先の保存日数（空なら BACKUP_KEEP_DAYS と同じ）
#   BACKUP_POST_COMMAND=                        作成後に実行するコマンド（rsync・scp など。ファイルは $BACKUP_FILE）
#
# 結果は backend コンテナの app.tools.backup_report でアプリに伝える（画面「システム状態」・異常の通知）。
# 終了コード: 0 = 成功、1 = 失敗（バックアップを作れなかった）、2 = サーバー内には作れたが、外部への保管に失敗
#
# ※ .env（DEVICE_ENCRYPTION_KEY）と証明書の秘密鍵を含むため、バックアップは root だけが読めるようにしている。
#   バックアップを持ち出す・外部にコピーするときは取り扱いに注意すること（機器のパスワードを復号できる）。
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
BACKUP_COPY_DIR="${BACKUP_COPY_DIR:-$(env_value BACKUP_COPY_DIR "")}"
BACKUP_COPY_REQUIRE_MOUNT="${BACKUP_COPY_REQUIRE_MOUNT:-$(env_value BACKUP_COPY_REQUIRE_MOUNT true)}"
BACKUP_COPY_KEEP_DAYS="${BACKUP_COPY_KEEP_DAYS:-$(env_value BACKUP_COPY_KEEP_DAYS "$BACKUP_KEEP_DAYS")}"
BACKUP_POST_COMMAND="${BACKUP_POST_COMMAND:-$(env_value BACKUP_POST_COMMAND "")}"
POST_TIMEOUT=3600  # BACKUP_POST_COMMAND の制限時間（秒）
RESULT_FILE="$BACKUP_DIR/last-result.json"  # 最後の結果（アプリに伝えられなかったときの確認用）

log() { echo "$(date '+%F %T') $*"; }

if [ "${1:-}" = "--list" ]; then
  ls -lh "$BACKUP_DIR"/netconfig-backup-*.tar.gz 2>/dev/null || echo "バックアップはありません（$BACKUP_DIR）"
  if [ -n "$BACKUP_COPY_DIR" ]; then
    echo "■ コピー先（$BACKUP_COPY_DIR）"
    ls -lh "$BACKUP_COPY_DIR"/netconfig-backup-*.tar.gz 2>/dev/null || echo "コピーはありません（マウントされているか確認してください）"
  fi
  [ -f "$RESULT_FILE" ] && { echo "■ 最後の結果"; cat "$RESULT_FILE"; echo; }
  exit 0
fi

for v in BACKUP_KEEP_DAYS BACKUP_COPY_KEEP_DAYS; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || { echo "$v は日数（整数）で指定してください: ${!v}"; exit 1; }
done

# ---- 結果をアプリへ伝える（失敗してもバックアップの成否は変えない）
DB=""
BACKEND=""
WORK=""
OUT=""
STAGE="開始"          # 失敗したときに、どこで止まったかを伝える
START=$(date +%s)
COPY_STATUS="none"     # none（設定なし）/ ok / failed
POST_STATUS="none"
OFFSITE_MSG=""
REPORTED=0

json_str() { # JSON の文字列にする（\ と " と改行を逃がす）
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "${s//$'\n'/ }"
}

report() { # $1 = ok / failed, $2 = 文
  local status="$1" msg="$2" file="" size=0 secs
  REPORTED=1
  secs=$(( $(date +%s) - START ))
  if [ "$status" = "ok" ] && [ -n "$OUT" ] && [ -f "$OUT" ]; then
    file=$(basename "$OUT")
    size=$(stat -c %s "$OUT" 2>/dev/null || echo 0)
  fi
  if [ -d "$BACKUP_DIR" ]; then
    {
      printf '{"at": %s, "status": %s, "file": %s, "size": %s, "seconds": %s, ' \
        "$(json_str "$(date '+%F %T %z')")" "$(json_str "$status")" "$(json_str "$file")" "$size" "$secs"
      printf '"copy": %s, "copy_dir": %s, "post": %s, "message": %s}\n' \
        "$(json_str "$COPY_STATUS")" "$(json_str "$BACKUP_COPY_DIR")" "$(json_str "$POST_STATUS")" "$(json_str "$msg")"
    } > "$RESULT_FILE" 2>/dev/null || true
  fi
  if [ -z "$BACKEND" ]; then
    log "[WARN] backend のコンテナが無いため、結果を画面に伝えられません（$RESULT_FILE に記録しました）"
    return 0
  fi
  # 標準入力は渡さない（-i なし）。止まったままにならないよう時間を区切る
  if ! timeout 60 "$CONTAINER_CMD" exec "$BACKEND" python -m app.tools.backup_report result --status "$status" \
      --file "$file" --size "$size" --seconds "$secs" --dir "$BACKUP_DIR" --copy "$COPY_STATUS" \
      --copy-dir "$BACKUP_COPY_DIR" --post "$POST_STATUS" --message "$msg" >/dev/null 2>&1; then
    log "[WARN] 結果を画面に伝えられませんでした（$RESULT_FILE に記録しました）"
  fi
}

on_exit() {
  local rc=$?
  [ -n "$WORK" ] && rm -rf "$WORK"
  [ -n "$OUT" ] && rm -f "$OUT.part"
  if [ "$rc" -ne 0 ] && [ "$REPORTED" -eq 0 ]; then
    log "[ERROR] バックアップに失敗しました（「$STAGE」で失敗。終了コード $rc）"
    report failed "「$STAGE」で失敗しました（終了コード $rc）。サーバーの journalctl -u netconfig-backup.service を確認してください"
  fi
}
trap on_exit EXIT

# compose のサービス名からコンテナを探す（podman-compose・docker compose のどちらもこのラベルを付ける）
container_of() {
  local id
  id=$($CONTAINER_CMD ps -q --filter "label=com.docker.compose.project=$PROJECT_NAME" \
        --filter "label=com.docker.compose.service=$1" | head -1)
  [ -n "$id" ] || { log "[ERROR] コンテナ（$1）が起動していません。バックアップを中止します" >&2; exit 1; }
  echo "$id"
}
STAGE="コンテナの確認"
# backend を先に探す（DB だけが止まっているときも、失敗を画面に伝えられるように）
BACKEND=$(container_of backend)
DB=$(container_of db)

STAGE="保存先の準備"
umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
TS=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d "$BACKUP_DIR/.work-$TS-XXXX")

log "[INFO] バックアップ開始 → $BACKUP_DIR/netconfig-backup-$TS.tar.gz"

# DB（カスタム形式。復元は pg_restore）
STAGE="DB のダンプ"
$CONTAINER_CMD exec "$DB" pg_dump -U netconfig -d netconfig -Fc --no-owner > "$WORK/db.dump"
[ -s "$WORK/db.dump" ] || { log "[ERROR] DB のダンプが空です"; exit 1; }

# コンフィグ履歴（機器ごとの Git リポジトリ）・known_hosts・ターミナルの記録
STAGE="コンフィグ履歴などの取り出し"
$CONTAINER_CMD exec "$BACKEND" tar -C /app/configs -cf - . > "$WORK/configs.tar"
$CONTAINER_CMD exec "$BACKEND" tar -C /data/ssh -cf - . > "$WORK/ssh.tar"
if [ "$BACKUP_TERMINAL_LOGS" = "true" ]; then
  $CONTAINER_CMD exec "$BACKEND" tar -C /data/terminal-logs -cf - . > "$WORK/terminal-logs.tar"
fi

# 設定（.env・証明書）
STAGE=".env・証明書の取り出し"
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

STAGE="アーカイブの作成"
OUT="$BACKUP_DIR/netconfig-backup-$TS.tar.gz"
tar -C "$WORK" -czf "$OUT.part" .
mv "$OUT.part" "$OUT"
log "[INFO] 作成しました: $OUT（$(du -h "$OUT" | cut -f1)）"
# ここから先の失敗では、作ったバックアップを消さない（成功として扱い、外部への保管の失敗は別に伝える）
STAGE="後片付け"

# 古いバックアップの削除（最新の1つは必ず残す）。$1 = ディレクトリ, $2 = 保存日数
prune() {
  local latest
  latest=$(find "$1" -maxdepth 1 -name 'netconfig-backup-*.tar.gz' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
  [ -n "$latest" ] || return 0
  find "$1" -maxdepth 1 -name 'netconfig-backup-*.tar.gz' -mtime +"$2" ! -path "$latest" -print -delete \
    | sed "s/^/$(date '+%F %T') [INFO] 削除: /"
}
prune "$BACKUP_DIR" "$BACKUP_KEEP_DAYS" || log "[WARN] 古いバックアップの削除に失敗しました（$BACKUP_DIR）"

# ---- サーバー外への保管 1: マウントした場所（NAS など）へのコピー
# コピー先の失敗は return 1 で返し、理由を OFFSITE_MSG に入れる（set -e では止めない）
copy_offsite() {
  local dir="$BACKUP_COPY_DIR" name part need avail
  if [ ! -d "$dir" ]; then
    OFFSITE_MSG="コピー先 $dir がありません（マウントされているか確認してください）"
    return 1
  fi
  if [ "$BACKUP_COPY_REQUIRE_MOUNT" = "true" ]; then
    # マウントが外れていると、マウント先のはずのディレクトリ（サーバーのディスク）へ書いてしまう。
    # サーバー内の保存先・ルートと同じディスクなら、外れているとみなしてコピーしない
    if [ "$(stat -c %d "$dir")" = "$(stat -c %d "$BACKUP_DIR")" ] || [ "$(stat -c %d "$dir")" = "$(stat -c %d /)" ]; then
      OFFSITE_MSG="コピー先 $dir がサーバーのディスク上にあります（NAS などのマウントが外れている可能性。意図した構成なら BACKUP_COPY_REQUIRE_MOUNT=false）"
      return 1
    fi
  fi
  name=$(basename "$OUT")
  need=$(stat -c %s "$OUT")
  avail=$(df -P -B1 "$dir" 2>/dev/null | awk 'NR == 2 { print $4 }')
  if [[ "$avail" =~ ^[0-9]+$ ]] && [ "$avail" -lt "$need" ]; then
    OFFSITE_MSG="コピー先 $dir の空きが足りません（必要 $need バイト、空き $avail バイト）"
    return 1
  fi
  part="$dir/.$name.part"
  # -p で日時と権限（root だけが読める 600）を保つ（世代の削除は日時で判断する）
  if ! cp -p "$OUT" "$part" || ! mv -f "$part" "$dir/$name"; then
    rm -f "$part" 2>/dev/null || true
    OFFSITE_MSG="コピー先 $dir へのコピーに失敗しました（書き込みの権限・空きを確認してください）"
    return 1
  fi
  log "[INFO] コピーしました: $dir/$name"
  prune "$dir" "$BACKUP_COPY_KEEP_DAYS" || log "[WARN] コピー先の古いバックアップの削除に失敗しました（$dir）"
  return 0
}

if [ -n "$BACKUP_COPY_DIR" ]; then
  log "[INFO] サーバー外へコピーします → $BACKUP_COPY_DIR（.env と証明書の秘密鍵を含むため、root 相当の人だけが読める場所にしてください）"
  if copy_offsite; then
    COPY_STATUS="ok"
  else
    COPY_STATUS="failed"
    log "[ERROR] $OFFSITE_MSG"
  fi
fi

# ---- サーバー外への保管 2: 任意のコマンド（rsync・scp など）。作ったファイルは $BACKUP_FILE で渡す
if [ -n "$BACKUP_POST_COMMAND" ]; then
  log "[INFO] BACKUP_POST_COMMAND を実行します"
  post_rc=0
  BACKUP_FILE="$OUT" timeout "$POST_TIMEOUT" bash -c "$BACKUP_POST_COMMAND" </dev/null || post_rc=$?
  if [ "$post_rc" -eq 0 ]; then
    POST_STATUS="ok"
  else
    POST_STATUS="failed"
    msg="BACKUP_POST_COMMAND が失敗しました（終了コード $post_rc）"
    [ "$post_rc" -ne 124 ] || msg="BACKUP_POST_COMMAND が $POST_TIMEOUT 秒で終わらなかったため打ち切りました"
    log "[ERROR] $msg"
    OFFSITE_MSG="${OFFSITE_MSG:+$OFFSITE_MSG / }$msg"
  fi
fi

report ok "$OFFSITE_MSG"
if [ "$COPY_STATUS" = "failed" ] || [ "$POST_STATUS" = "failed" ]; then
  log "[WARN] サーバー内のバックアップは作成しましたが、外部への保管に失敗しました"
  exit 2
fi
log "[INFO] 完了しました"
