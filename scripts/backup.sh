#!/usr/bin/env bash
# NetConfig Manager のバックアップ
#
#   DB（pg_dump）・コンフィグ履歴（Git リポジトリ）・SSH の known_hosts・ターミナルの記録・.env・証明書を
#   1つのファイル（netconfig-backup-YYYYmmdd-HHMMSS.tar.gz）にまとめ、古いものを削除する。
#   BACKUP_ENCRYPT_PASSPHRASE_FILE を設定すると、gpg（AES256）で暗号化した .tar.gz.gpg にする。
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
#   BACKUP_ENCRYPT_PASSPHRASE_FILE=             暗号化のパスフレーズを書いたファイル（例 /root/netconfig-backup.pass）。
#                                               空なら暗号化しない。**バックアップと別の場所にも保管すること**（無いと復元できない）
#                                               root だけが読める（所有者 root・600 か 400）ことを確かめ、違えば警告する
#   BACKUP_WORK_DIR=/var/tmp                    作業用のディレクトリ（DB のダンプなどを平文で一時的に置く）を作る場所。
#                                               BACKUP_DIR の外に、root だけが読める（700）ディレクトリを作り、アーカイブができたらすぐ消す。
#                                               DB のダンプとコンフィグ履歴が入るだけの空きが要る（/tmp が tmpfs の環境で溢れないよう /var/tmp）
#
# 結果は backend コンテナの app.tools.backup_report でアプリに伝える（画面「システム状態」・異常の通知）。
# 終了コード: 0 = 成功、1 = 失敗（バックアップを作れなかった）、2 = サーバー内には作れたが、外部への保管に失敗
#
# ※ .env（DEVICE_ENCRYPTION_KEY）と証明書の秘密鍵を含むため、バックアップは root だけが読めるようにしている。
#   暗号化しない場合、バックアップを持ち出す・外部にコピーするときは取り扱いに注意すること（機器のパスワードを復号できる）。
#   外部へコピーする（BACKUP_COPY_DIR・BACKUP_POST_COMMAND）なら暗号化を推奨（しないと「システム状態」で注意を出す）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
# OS ごとの案内文（パッケージ名など）。lib が無くても動く
# shellcheck source=lib/os.sh
[ -f "$SCRIPT_DIR/lib/os.sh" ] && . "$SCRIPT_DIR/lib/os.sh"
gpg_hint() { if declare -F ncm_install_hint >/dev/null; then ncm_install_hint gpg; else echo "dnf install gnupg2"; fi; }
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
BACKUP_ENCRYPT_PASSPHRASE_FILE="${BACKUP_ENCRYPT_PASSPHRASE_FILE:-$(env_value BACKUP_ENCRYPT_PASSPHRASE_FILE "")}"
BACKUP_WORK_DIR="${BACKUP_WORK_DIR:-$(env_value BACKUP_WORK_DIR /var/tmp)}"
ENCRYPTED="no"
[ -n "$BACKUP_ENCRYPT_PASSPHRASE_FILE" ] && ENCRYPTED="yes"
POST_TIMEOUT=3600  # BACKUP_POST_COMMAND の制限時間（秒）
RESULT_FILE="$BACKUP_DIR/last-result.json"  # 最後の結果（アプリに伝えられなかったときの確認用）

log() { echo "$(date '+%F %T') $*"; }

if [ "${1:-}" = "--list" ]; then
  ls -lh "$BACKUP_DIR"/netconfig-backup-*.tar.gz{,.gpg} 2>/dev/null || echo "バックアップはありません（$BACKUP_DIR）"
  if [ -n "$BACKUP_COPY_DIR" ]; then
    echo "■ コピー先（$BACKUP_COPY_DIR）"
    ls -lh "$BACKUP_COPY_DIR"/netconfig-backup-*.tar.gz{,.gpg} 2>/dev/null || echo "コピーはありません（マウントされているか確認してください）"
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
GNUPG_TMP=""
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
      printf '"copy": %s, "copy_dir": %s, "post": %s, "encrypted": %s, "message": %s}\n' \
        "$(json_str "$COPY_STATUS")" "$(json_str "$BACKUP_COPY_DIR")" "$(json_str "$POST_STATUS")" \
        "$([ "$ENCRYPTED" = yes ] && echo true || echo false)" "$(json_str "$msg")"
    } > "$RESULT_FILE" 2>/dev/null || true
  fi
  if [ -z "$BACKEND" ]; then
    log "[WARN] backend のコンテナが無いため、結果を画面に伝えられません（$RESULT_FILE に記録しました）"
    return 0
  fi
  # 標準入力は渡さない（-i なし）。止まったままにならないよう時間を区切る
  if ! timeout 60 "$CONTAINER_CMD" exec "$BACKEND" python -m app.tools.backup_report result --status "$status" \
      --file "$file" --size "$size" --seconds "$secs" --dir "$BACKUP_DIR" --copy "$COPY_STATUS" \
      --copy-dir "$BACKUP_COPY_DIR" --post "$POST_STATUS" --encrypted "$ENCRYPTED" --message "$msg" >/dev/null 2>&1; then
    log "[WARN] 結果を画面に伝えられませんでした（$RESULT_FILE に記録しました）"
  fi
}

# 作業用のディレクトリ（平文の DB のダンプ・.env・証明書の秘密鍵が入る）を消す。アーカイブができた直後と、終了時に呼ぶ
remove_work() {
  if [ -n "$WORK" ]; then rm -rf --one-file-system -- "$WORK"; WORK=""; fi
}

# 前に途中で止まった（SIGKILL・メモリ不足・電源断）バックアップの作業用ディレクトリを消す
#   消すのは、このスクリプトが作る名前の形のディレクトリだけ（シンボリックリンク・ほかのファイルには触れない）:
#     BACKUP_WORK_DIR の netconfig-backup-work.<PID>.<8 文字>（その PID が動いていないもの。動いていても 1 日より古いもの）
#     BACKUP_DIR の .work-YYYYmmdd-HHMMSS-<4 文字>（以前の版が BACKUP_DIR の中に作っていたもの。1 時間より古いもの）
remove_stale_work() {
  local d name pid
  if [ -d "$BACKUP_WORK_DIR" ]; then
    while IFS= read -r -d '' d; do
      name=$(basename "$d")
      [[ "$name" =~ ^netconfig-backup-work\.([0-9]+)\.[A-Za-z0-9]{8}$ ]] || continue
      pid="${BASH_REMATCH[1]}"
      if kill -0 "$pid" 2>/dev/null && [ -z "$(find "$d" -maxdepth 0 -mmin +1440 2>/dev/null)" ]; then continue; fi
      log "[INFO] 前に途中で止まったバックアップの作業用ディレクトリを消します: $d"
      rm -rf --one-file-system -- "$d" || log "[WARN] 消せませんでした: $d"
    done < <(find "$BACKUP_WORK_DIR" -mindepth 1 -maxdepth 1 -type d -user "$(id -u)" -name 'netconfig-backup-work.*' -print0 2>/dev/null)
  fi
  if [ -d "$BACKUP_DIR" ]; then
    while IFS= read -r -d '' d; do
      name=$(basename "$d")
      [[ "$name" =~ ^\.work-[0-9]{8}-[0-9]{6}-[A-Za-z0-9]{4}$ ]] || continue
      log "[INFO] 以前の版が保存先に残した作業用ディレクトリ（平文）を消します: $d"
      rm -rf --one-file-system -- "$d" || log "[WARN] 消せませんでした: $d"
    done < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -user "$(id -u)" -name '.work-*' -mmin +60 -print0 2>/dev/null)
  fi
  return 0
}

# 空きの表示（MB。分からなければ ?）
free_mb() { local a; a=$(df -P -k "$1" 2>/dev/null | awk 'NR == 2 { print $4 }'); [[ "$a" =~ ^[0-9]+$ ]] && echo "$((a / 1024))" || echo "?"; }

on_exit() {
  local rc=$?
  local space_hint=""
  # 作業場所・保存先の空きが足りないと、ダンプ・取り出し・アーカイブの書き込みで失敗する。分かるように空きを添える
  case "$STAGE" in
    "DB のダンプ"|"コンフィグ履歴などの取り出し"|".env・証明書の取り出し"|"アーカイブの作成"*)
      space_hint="作業場所 $BACKUP_WORK_DIR の空き $(free_mb "$BACKUP_WORK_DIR") MB・保存先 $BACKUP_DIR の空き $(free_mb "$BACKUP_DIR") MB。空きが足りなければ BACKUP_WORK_DIR・BACKUP_DIR を空きのある場所に" ;;
  esac
  remove_work
  if [ -n "$GNUPG_TMP" ]; then
    GNUPGHOME="$GNUPG_TMP" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf "$GNUPG_TMP"
  fi
  [ -n "$OUT" ] && rm -f "$OUT.part"
  if [ "$rc" -ne 0 ] && [ "$REPORTED" -eq 0 ]; then
    log "[ERROR] バックアップに失敗しました（「$STAGE」で失敗。終了コード $rc）${space_hint:+。$space_hint}"
    report failed "「$STAGE」で失敗しました（終了コード $rc）。${space_hint:+$space_hint。}サーバーの journalctl -u netconfig-backup.service を確認してください"
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

STAGE="暗号化の準備"
if [ "$ENCRYPTED" = "yes" ]; then
  # 鍵が読めないまま暗号化しないで作る、ということはしない（失敗として伝え、設定を直してもらう）
  command -v gpg >/dev/null || { log "[ERROR] 暗号化に gpg が必要です（$(gpg_hint)）"; exit 1; }
  if [ ! -s "$BACKUP_ENCRYPT_PASSPHRASE_FILE" ]; then
    log "[ERROR] BACKUP_ENCRYPT_PASSPHRASE_FILE（$BACKUP_ENCRYPT_PASSPHRASE_FILE）が無いか空です"
    report failed "暗号化のパスフレーズのファイル（$BACKUP_ENCRYPT_PASSPHRASE_FILE）が無いか空です"
    exit 1
  fi
  # パスフレーズのファイルは root（実行している人）だけが読めること。違っても止めない（今までのバックアップを止めないため）が、知らせる
  pass_st=$(stat -L -c '%u %a' "$BACKUP_ENCRYPT_PASSPHRASE_FILE" 2>/dev/null || true)
  read -r pass_uid pass_mode <<<"$pass_st"
  if [ "${pass_uid:-}" != "$(id -u)" ] || ! [[ "${pass_mode:-}" =~ ^[0-7]+$ ]] || [ $(( 8#$pass_mode & 8#077 )) -ne 0 ]; then
    log "[WARN] パスフレーズのファイル（$BACKUP_ENCRYPT_PASSPHRASE_FILE）が root だけが読める形ではありません（所有者 uid ${pass_uid:-?}・権限 ${pass_mode:-?}）。"
    log "       ほかの人が読めると暗号化の意味がありません: sudo chown root:root $BACKUP_ENCRYPT_PASSPHRASE_FILE && sudo chmod 600 $BACKUP_ENCRYPT_PASSPHRASE_FILE"
  fi
fi

STAGE="保存先の準備"
umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
TS=$(date +%Y%m%d-%H%M%S)
# 作業用のディレクトリは BACKUP_DIR の外に作る（BACKUP_DIR をディレクトリごと同期する BACKUP_POST_COMMAND で、
# 平文の作業用のファイルまで外へ送らないように）。mktemp -d は 700 で作る
remove_stale_work
mkdir -p "$BACKUP_WORK_DIR"
case "$(cd "$BACKUP_WORK_DIR" && pwd -P)/" in
  "$(cd "$BACKUP_DIR" && pwd -P)/"*)
    log "[WARN] BACKUP_WORK_DIR（$BACKUP_WORK_DIR）が BACKUP_DIR の中にあります。保存先を同期すると、作業中の平文のファイルも送られる可能性があります" ;;
esac
WORK=$(mktemp -d "$BACKUP_WORK_DIR/netconfig-backup-work.$$.XXXXXXXX")

OUT_NAME="netconfig-backup-$TS.tar.gz"
[ "$ENCRYPTED" = "yes" ] && OUT_NAME="$OUT_NAME.gpg"
log "[INFO] バックアップ開始 → $BACKUP_DIR/$OUT_NAME"

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
暗号化: $([ "$ENCRYPTED" = yes ] && echo "gpg（AES256）" || echo "なし")
復元: bash scripts/restore.sh <このファイル>
EOF

STAGE="アーカイブの作成"
OUT="$BACKUP_DIR/$OUT_NAME"
if [ "$ENCRYPTED" = "yes" ]; then
  # 平文のアーカイブをディスクに置かずに暗号化する。gpg の設定は一時ディレクトリに作る（root の ~/.gnupg を使わない。
  # gpg-agent のソケットのパスが長すぎないよう /tmp の短い名前にする）
  STAGE="アーカイブの作成と暗号化"
  GNUPG_TMP=$(mktemp -d)
  tar -C "$WORK" -czf - . \
    | GNUPGHOME="$GNUPG_TMP" gpg --batch --yes --quiet --pinentry-mode loopback \
        --passphrase-file "$BACKUP_ENCRYPT_PASSPHRASE_FILE" --symmetric --cipher-algo AES256 -o "$OUT.part"
else
  tar -C "$WORK" -czf "$OUT.part" .
fi
mv "$OUT.part" "$OUT"
# 平文の作業用のファイルはすぐに消す（外部への保管・BACKUP_POST_COMMAND の最大 1 時間のあいだ残さない）
remove_work
log "[INFO] 作成しました: $OUT（$(du -h "$OUT" | cut -f1)）"
# ここから先の失敗では、作ったバックアップを消さない（成功として扱い、外部への保管の失敗は別に伝える）
STAGE="後片付け"

# 古いバックアップの削除（最新の1つは必ず残す）。$1 = ディレクトリ, $2 = 保存日数
prune() {
  local latest
  local names=( \( -name 'netconfig-backup-*.tar.gz' -o -name 'netconfig-backup-*.tar.gz.gpg' \) )
  latest=$(find "$1" -maxdepth 1 "${names[@]}" -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
  [ -n "$latest" ] || return 0
  find "$1" -maxdepth 1 "${names[@]}" -mtime +"$2" ! -path "$latest" -print -delete \
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
  if [ "$ENCRYPTED" = "yes" ]; then
    log "[INFO] サーバー外へコピーします → $BACKUP_COPY_DIR（暗号化済み）"
  else
    log "[WARN] サーバー外へコピーします → $BACKUP_COPY_DIR（暗号化していません。.env と証明書の秘密鍵を含むため、root 相当の人だけが読める場所にするか、BACKUP_ENCRYPT_PASSPHRASE_FILE で暗号化してください）"
  fi
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
