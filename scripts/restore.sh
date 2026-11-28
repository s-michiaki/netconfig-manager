#!/usr/bin/env bash
# NetConfig Manager の復元（scripts/backup.sh で作ったファイルから）
#
# 使い方（root で実行）:
#   bash scripts/restore.sh /var/backups/netconfig-manager/netconfig-backup-YYYYmmdd-HHMMSS.tar.gz
#   bash scripts/restore.sh .../netconfig-backup-YYYYmmdd-HHMMSS.tar.gz.gpg   # 暗号化したもの
#
# 暗号化したバックアップ（.gpg）は、パスフレーズのファイルで復号する。ファイルは次の順に探す:
#   環境変数 BACKUP_ENCRYPT_PASSPHRASE_FILE → .env の BACKUP_ENCRYPT_PASSPHRASE_FILE。どちらも無ければ入力を求める
#   （別のサーバーへ復元するときは、別に保管しておいたパスフレーズが要る）
#   .gpg は、パスフレーズで暗号化されたもの（OpenPGP の対称鍵の暗号化と改ざんの検出つき）であることを確かめる。
#   暗号化されていない OpenPGP のデータ（gpg --store で包んだだけのもの）は、復号できても受け付けない
#
# 環境変数（どれも省略できる）:
#   RESTORE_YES=1                 確認（yes の入力・.env の扱いの選択）を省く（自動で実行するとき）
#   RESTORE_ENV=all|keys          .env の扱い（下の 5.）。指定が無ければ、違いを表示して聞く
#                                 （RESTORE_YES=1 のときは、注意が要るキーが変わらなければ all、変わるなら止める）
#   RESTORE_ALLOW_UNENCRYPTED=1   暗号化を使っている環境（BACKUP_ENCRYPT_PASSPHRASE_FILE あり）で、暗号化していない
#                                 バックアップを RESTORE_YES=1 で戻すとき（対話なら、注意を表示して yes で確かめる）
#   RESTORE_WORK_DIR=/var/tmp     バックアップを展開する作業用のディレクトリを作る場所（root だけが読める 700。終了時に消す）
#
# 処理の流れ（途中で失敗したら、どこまで進んだか・いまの状態・戻し方を表示する）:
#   1. バックアップを確かめる（ここまでは何も変えない）: 復号と暗号化の確認、中身の一覧の検査（想定の名前・普通のファイルだけ。
#      絶対パス・..・デバイスなどを含むものは止める）、.env の違いの表示と確認、DB のダンプを pg_restore -l で読めるか
#   2. 今の .env と証明書の控えを /root/netconfig-manager-backup/ に取る（取れなければここで止める）
#   3. アプリのコンテナ（backend / worker / beat / frontend）を止める（db と redis は動かしたまま）
#   4. DB を作り直してダンプを流し込む
#   5. コンフィグ履歴・known_hosts・ターミナルの記録のボリュームを中身ごと入れ替える
#   6. 証明書（certs/ の server.crt・server.key・ca.crt だけ）を戻す
#   7. .env の DEVICE_ENCRYPTION_KEY がバックアップと違えば、.env を戻す（違う鍵では機器のパスワードを復号できないため）
#        all : .env を丸ごとバックアップのものにする（別のサーバーへ移すとき。以前からの動き）
#        keys: 今の .env のまま、DEVICE_ENCRYPTION_KEY と SECRET_KEY だけをバックアップの値にする
#      DB ユーザーのパスワードを（戻した）.env に合わせる
#   8. コンテナを起動する（.env を変えたときは作り直す。起動時にマイグレーションが適用される）
#
# ※ 現在のデータはすべてバックアップの時点に置き換わります。
# ※ 新しいバージョンで作ったバックアップを古いバージョンに戻すことはできません（先に git pull と setup.sh を）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
# OS ごとの案内文（パッケージ名など）・コンテナの作り直し・出力の伏せ字。lib が無くても動く
# shellcheck source=lib/os.sh
[ -f "$SCRIPT_DIR/lib/os.sh" ] && . "$SCRIPT_DIR/lib/os.sh"
# shellcheck source=lib/proxy.sh
[ -f "$SCRIPT_DIR/lib/proxy.sh" ] && . "$SCRIPT_DIR/lib/proxy.sh"
# shellcheck source=lib/compose.sh
[ -f "$SCRIPT_DIR/lib/compose.sh" ] && . "$SCRIPT_DIR/lib/compose.sh"
gpg_hint() { if declare -F ncm_install_hint >/dev/null; then ncm_install_hint gpg; else echo "dnf install gnupg2"; fi; }
PROJECT_NAME="${PROJECT_NAME:-$(basename "$INSTALL_DIR")}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_BACKUP_DIR="${ENV_BACKUP_DIR:-/root/netconfig-manager-backup}"
RESTORE_WORK_DIR="${RESTORE_WORK_DIR:-/var/tmp}"
APP_SERVICES=(frontend beat worker backend)
# バックアップ（backup.sh が作るもの。以前の版も同じ）に入っているファイル
KNOWN_FILES="manifest.txt db.dump configs.tar ssh.tar terminal-logs.tar env certs.tar"
# 証明書の書庫から戻すもの（import_cert.sh が置くもの）と、そのファイルの権限
CERT_FILES="server.crt server.key ca.crt"
# .env のうち、変わるときに特に注意が要るキー。種類ごと（重ならないようにまとめている）:
#   コマンドを実行する・データの送り先・暗号化: BACKUP_*（BACKUP_POST_COMMAND・COPY_DIR・ENCRYPT_PASSPHRASE_FILE。KEEP_DAYS・
#     COPY_KEEP_DAYS を 0 にすると次の定期バックアップで世代が消える。ON_CALENDAR・COPY_REQUIRE_MOUNT・TERMINAL_LOGS・STALE_HOURS も）、
#     ENV_BACKUP_KEEP、GIT_EXPORT_*（コンフィグを外部の Git へ送る）
#   外への口・接続先: OUTBOUND_*、PUBLIC_URL、ALLOWED_ORIGINS、HTTP_PORT・HTTPS_PORT、VULN_ENABLED・VULN_SOURCES（外部へ取りに行く）
#   守りを弱める: SSH_HOST_KEY_POLICY、TERMINAL_LOG_ENCRYPT・TERMINAL_LOG_TEXT、LOGIN_*（ログインの制限）、
#     IDLE_TIMEOUT_MIN（無操作でのログアウト）、SYSTEM_*（監視・通知）、ADMIN_*（ユーザーがいないときに作る管理者）
#   できることを広げる: API_TOKEN*、COMMAND_RUN_ENABLED
#   データを消す: *_RETENTION_DAYS、PING_HISTORY_DAYS（記録を残す日数）
#   podman・podman-compose の動き: PODMAN_*、COMPOSE_*
DANGER_KEYS_RE='^(BACKUP_[A-Z0-9_]+|ENV_BACKUP_KEEP|GIT_EXPORT_[A-Z0-9_]+|OUTBOUND_[A-Z0-9_]+|PUBLIC_URL|ALLOWED_ORIGINS|HTTPS?_PORT|VULN_ENABLED|VULN_SOURCES|SSH_HOST_KEY_POLICY|TERMINAL_LOG_(ENCRYPT|TEXT)|LOGIN_[A-Z0-9_]+|IDLE_TIMEOUT_MIN|SYSTEM_[A-Z0-9_]+|ADMIN_[A-Z0-9_]+|API_TOKEN[A-Z0-9_]*|COMMAND_RUN_ENABLED|[A-Z0-9_]+_RETENTION_DAYS|PING_HISTORY_DAYS|PODMAN_[A-Z0-9_]+|COMPOSE_[A-Z0-9_]+)$'
# keys のときにバックアップから戻すキー（DEVICE_ENCRYPTION_KEY: 機器のパスワードの復号。SECRET_KEY: ログインの署名）
SECRET_KEYS="DEVICE_ENCRYPTION_KEY SECRET_KEY"

FILE="${1:-}"
[ -n "$FILE" ] && [ -f "$FILE" ] || { echo "使い方: bash scripts/restore.sh <バックアップファイル>"; exit 1; }

log() { echo "$(date '+%F %T') $*"; }
die() { echo "❌ $*"; exit 1; }
container_of() {
  $CONTAINER_CMD ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$1" | head -1
}
# .env の値（同じキーが複数あれば最後の行。前後の " と CR を除く）
env_value() { (grep -E "^$2=" "$1" 2>/dev/null || true) | tail -1 | cut -d= -f2- | tr -d '\r' | sed -e 's/^"//' -e 's/"$//'; }
# .env を、podman-compose（python-dotenv の dotenv_values）と同じ読み方で読む（引数: ファイル 連想配列 連想配列 配列）
#   コンテナへ渡る値は podman-compose が python-dotenv で読んだもの、backup.sh・setup.sh が読むのは「KEY=」で始まる行。
#   違いの検査はこの両方を見る（片方だけを見ると、書き方を変えるだけで注意が要るキーの変化を隠せるため）
#   $2（dotenv）: python-dotenv と同じ解釈の値。export の接頭辞・キーの前後と = の前後の空白・引用符（' と "）・行末のコメント
#                （引用符の外の「空白 #」以降。引用符の後ろは空白なしの # も）・CRLF・同じキーの重複（後勝ち）を扱う
#   $3（host）  : 「KEY=」で始まる最後の行の = の後ろ（CR だけを除き、そのまま。backup.sh の BACKUP_POST_COMMAND などはこれを使う）
#   $4          : bash では python-dotenv と同じに読めると言い切れない行（「n 行目（キー）: 理由」。値は入れない）:
#                 KEY=値 の形でない行（= の無い行・キーに . などがある行・引用符の後ろに文字が続く行）、${…}（python-dotenv が
#                 変数として展開する）、引用符の中の \（python-dotenv が逃がしを解く）、閉じていない引用符（複数行の値）、行の途中の CR
#                 （python-dotenv は改行として扱う）
parse_env() {
  local -n _dot="$2" _host="$3" _amb="$4"
  local line n=0 k rest v q inq=""
  local re_bind='^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$'
  local re_host='^([A-Za-z_][A-Za-z0-9_]*)=(.*)$'
  # bash の read は NUL（0 の文字）を落とすので、先に有無を調べる。あれば、その行を読めない行として扱う
  #   （NUL を 0xFF に置き換えて行の番号を探す。0xFF は UTF-8 に現れないので、多めに見つかっても止める向きにしかならない）
  if [ "$(wc -c < "$1")" != "$(tr -d '\000' < "$1" | wc -c)" ]; then
    while IFS= read -r k; do _amb+=("$k 行目（NUL）: NUL（0 の文字）があります（bash では読めません）"); done \
      < <(LC_ALL=C tr '\000' '\377' < "$1" | LC_ALL=C grep -an $'\377' | cut -d: -f1)
  fi
  local re_sq="^'([^'\\\\]*)'[[:space:]]*(#.*)?\$" re_dq='^"([^"\\]*)"[[:space:]]*(#.*)?$'
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%$'\r'}"
    if [[ "$line" =~ $re_host ]]; then _host[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"; fi
    if [ -n "$inq" ]; then   # 閉じていない引用符の続き（python-dotenv では前の行の値の一部）
      [[ "$line" != *"$inq"* ]] || inq=""
      continue
    fi
    case "$line" in *$'\r'*) _amb+=("$n 行目: 行の途中に CR があります（python-dotenv は改行として扱います）"); continue ;; esac
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    if ! [[ "$line" =~ $re_bind ]]; then _amb+=("$n 行目: KEY=値 の形として読めません"); continue; fi
    k="${BASH_REMATCH[2]}"; rest="${BASH_REMATCH[3]}"
    case "$rest" in *'${'*) _amb+=("$n 行目（$k）: 値に \${…} があります（python-dotenv は変数として展開します）"); continue ;; esac
    q="${rest:0:1}"
    if [ "$q" = "'" ] || [ "$q" = '"' ]; then
      if [ "$q" = "'" ] && [[ "$rest" =~ $re_sq ]]; then v="${BASH_REMATCH[1]}"
      elif [ "$q" = '"' ] && [[ "$rest" =~ $re_dq ]]; then v="${BASH_REMATCH[1]}"
      elif [[ "${rest:1}" != *"$q"* ]]; then _amb+=("$n 行目（$k）: 引用符が閉じていません（複数行の値）"); inq="$q"; continue
      else _amb+=("$n 行目（$k）: 引用符で囲んだ値を解釈できません（\\ を含む・引用符の後ろに文字が続く）"); continue; fi
    else
      v="${rest%%[[:space:]]#*}"            # 「空白 #」から後ろはコメント
      v="${v%"${v##*[![:space:]]}"}"        # 末尾の空白
    fi
    _dot[$k]="$v"
  done < "$1"
}

# 今の .env の値（.env が無ければ空。set -e で止まらないよう、必ず 0 で終わる）
cur_env_value() { [ -f "$INSTALL_DIR/.env" ] || return 0; env_value "$INSTALL_DIR/.env" "$1"; }

umask 077
[ -d "$RESTORE_WORK_DIR" ] || mkdir -p "$RESTORE_WORK_DIR"
WORK=$(mktemp -d "$RESTORE_WORK_DIR/netconfig-restore.XXXXXXXX")
GNUPG_TMP=""
STAGE="バックアップの確認"
CHANGED=0          # 1 = 何かを変え始めた（失敗したときに、状態と戻し方を表示する）
APP_STOPPED=0; DB_STATE="変えていません"; VOL_STATE="変えていません"; CERT_STATE="変えていません"; ENV_STATE="変えていません"
ENV_SAVED=""; CERTS_SAVED=""
PHASE="stopped"   # 失敗したときの案内の出し分け: stopped（アプリを止めただけ）/ data（DB などを変えた）/ env（DB のパスワード・.env）/ start

on_exit() {
  local rc=$?
  if [ -n "$GNUPG_TMP" ]; then
    GNUPGHOME="$GNUPG_TMP" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf "$GNUPG_TMP"
  fi
  rm -rf --one-file-system -- "$WORK"
  [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ] || return 0
  echo ""
  echo "❌ 復元は「$STAGE」で失敗しました（終了コード $rc）。上に出たエラーを確かめてください"
  echo "■ いまの状態"
  if [ "$APP_STOPPED" -eq 1 ]; then echo "  - アプリ（backend・worker・beat・frontend）: 止まっています"; else echo "  - アプリ: 止めていません"; fi
  echo "  - DB: $DB_STATE"
  echo "  - コンフィグ履歴・known_hosts・ターミナルの記録: $VOL_STATE"
  echo "  - 証明書（certs/）: $CERT_STATE"
  echo "  - .env: $ENV_STATE"
  [ -z "$ENV_SAVED" ] || echo "  - 復元の前の .env の控え: $ENV_SAVED"
  [ -z "$CERTS_SAVED" ] || echo "  - 復元の前の証明書の控え: $CERTS_SAVED/"
  UP_CMD="cd $INSTALL_DIR && sudo podman-compose -f $COMPOSE_FILE up -d --force-recreate"
  echo "■ 戻し方"
  case "$PHASE" in
    stopped)
      echo "  データ（DB・ボリューム・証明書・.env）はまだ変えていません。アプリを起動するだけで元に戻ります:"
      echo "     $UP_CMD   （または bash $SCRIPT_DIR/setup.sh）"
      echo "  原因を直してから、もう一度復元できます: sudo bash $SCRIPT_DIR/restore.sh $FILE" ;;
    data)
      echo "  DB・ボリュームを変えた後です（.env はまだ変えていません）。このまま起動しないでください（空・途中のデータで動きます）。"
      echo "  1. 原因を直して、もう一度同じバックアップで復元する: sudo bash $SCRIPT_DIR/restore.sh $FILE"
      echo "  2. 別のバックアップで復元する: sudo bash $SCRIPT_DIR/backup.sh --list で選んで、sudo bash $SCRIPT_DIR/restore.sh <ファイル>"
      echo "  （復元が終われば、アプリは作り直して起動されます）" ;;
    env)
      echo "  データの復元は済み、DB のパスワードをこれから使う .env に合わせている途中です（.env はまだ書き換えていません）。"
      echo "  このまま起動しないでください（DB のパスワードが今の .env と合わない可能性があります）。"
      echo "  1. 原因を直して、もう一度同じバックアップで復元する: sudo bash $SCRIPT_DIR/restore.sh $FILE"
      echo "  2. 別のバックアップで復元する: sudo bash $SCRIPT_DIR/backup.sh --list で選んで、sudo bash $SCRIPT_DIR/restore.sh <ファイル>" ;;
    *)
      echo "  データの復元は済み、DB のパスワード・.env をこれから使うものに合わせた後です（起動の段階で止まりました）。"
      echo "  1. 作り直して起動する: bash $SCRIPT_DIR/setup.sh（更新も行います）、または $UP_CMD"
      echo "  2. うまくいかなければ、もう一度同じバックアップで復元する（最後に作り直して起動します）: sudo bash $SCRIPT_DIR/restore.sh $FILE"
      [ -z "$ENV_SAVED" ] || [ "$ENV_STATE" = "変えていません" ] \
        || echo "  ※ 復元の前の .env（$ENV_SAVED）に戻すのは、DB も別のバックアップで戻すときだけにしてください（今の DB の暗号化の鍵と DB のパスワードは、今の .env に合っています）" ;;
  esac
  echo "  調査用のログ: bash $SCRIPT_DIR/collect_logs.sh"
}
trap on_exit EXIT

# ---------------------------------------------------------------- 1. バックアップを確かめる（何も変えない）
# 暗号化を使っている環境か（暗号化していないバックアップを戻すときに注意を出す）
ENC_CONFIGURED="${BACKUP_ENCRYPT_PASSPHRASE_FILE:-$(cur_env_value BACKUP_ENCRYPT_PASSPHRASE_FILE)}"
X="$WORK/x"   # バックアップの展開先
mkdir "$X"
# 展開の大きさの上限（バイト）: RESTORE_MAX_BYTES、無ければ作業場所の空きの 9 割。gzip -l は 4GB を超えると正しくないので、
# 展開しながら数え、上限を超えたら止める（圧縮した小さなファイルが、展開すると空きを使い切る、を防ぐ）
WORK_AVAIL=$(df -P -B1 "$WORK" 2>/dev/null | awk 'NR == 2 { print $4 }')
if [[ "${RESTORE_MAX_BYTES:-}" =~ ^[0-9]+$ ]]; then LIMIT=$((10#$RESTORE_MAX_BYTES))
elif [[ "$WORK_AVAIL" =~ ^[0-9]+$ ]]; then LIMIT=$((WORK_AVAIL / 10 * 9))
else LIMIT=$((1 << 62)); fi
# 上限まで流し、まだ続きがあれば印のファイルを作る（head -c は上限より先を読まない。続きの 1 バイトだけを読んで確かめる）
limit_stream() { head -c "$LIMIT"; if IFS= read -r -d '' -n 1 _; then : > "$WORK/too-large"; fi; }
human() { awk -v b="$1" 'BEGIN { if (b >= 1073741824) printf "%.1f GB", b / 1073741824; else printf "%.1f MB", b / 1048576 }'; }
too_large() {
  local avail="${WORK_AVAIL:-?}" same="" mp
  # ボリュームが作業場所と同じファイルシステムなら、ボリュームへの展開にも同じくらいの空きが要る
  mp=$($CONTAINER_CMD volume inspect -f '{{.Mountpoint}}' "${PROJECT_NAME}_config_repo" 2>/dev/null || true)
  if [ -n "$mp" ] && [ -d "$mp" ] && [ "$(stat -c %d "$mp" 2>/dev/null)" = "$(stat -c %d "$WORK" 2>/dev/null)" ]; then
    same="作業場所とボリューム（$mp）は同じファイルシステムなので、ボリュームへの展開にも同じくらいの空きが要ります（合わせて上限の 2 倍ほど）。"
  fi
  echo "❌ 展開した大きさが上限を超えます（何も変えていません）"
  echo "   上限: $LIMIT バイト（$(human "$LIMIT")。作業場所の空きの 9 割、または RESTORE_MAX_BYTES）"
  if [[ "$avail" =~ ^[0-9]+$ ]]; then echo "   作業場所 $RESTORE_WORK_DIR の今の空き: $avail バイト（$(human "$avail")）"; fi
  echo "   必要な大きさの目安: $LIMIT バイト（$(human "$LIMIT")）より大きい（展開しきるまで分からないため、少なくともこれ以上）"
  [ -z "$same" ] || echo "   $same"
  echo "   空きのある場所を RESTORE_WORK_DIR に指定するか、上限を上げてください（空きが足りることを確かめたうえで）:"
  echo "     RESTORE_MAX_BYTES=$((LIMIT * 2)) RESTORE_WORK_DIR=/空きのある場所 bash $SCRIPT_DIR/restore.sh $FILE   （上限はバイトで書く）"
  exit 1
}

# gpg の状態の出力（--status-fd）で、パスフレーズで暗号化されたデータを復号したことを確かめる（引数: 状態のファイル）
#   gpg の版で --list-packets の表示は変わるが、--status-fd の行（doc/DETAILS）は 2.2 / 2.4 で同じ。次をすべて満たすこと:
#     BEGIN_DECRYPTION・END_DECRYPTION がある（暗号化されたパケットを復号した）。--store で包んだだけのものには無い
#     PLAINTEXT（中身）は 1 つだけで、BEGIN_DECRYPTION と END_DECRYPTION のあいだにある（暗号化されていない中身を前後に足したものを弾く）
#     DECRYPTION_FAILED・BADMDC（改ざんの検出）が無い
#   DECRYPTION_OKAY（改ざんの検出も通った印）が無いときは、ほかがそろっていれば警告して続ける（正しいバックアップを弾かないため）
#   一時の GNUPGHOME には秘密鍵が無いので、公開鍵で暗号化されたものは復号できない（＝ここに来るのはパスフレーズのものだけ）
check_gpg_status() {
  local f="$1" line state=before plain=0 okay=0 began=0 ended=0
  while IFS= read -r line; do
    case "$line" in
      "[GNUPG:] BEGIN_DECRYPTION"*) [ "$state" = before ] || return 1; state=inside; began=1 ;;
      "[GNUPG:] END_DECRYPTION"*) [ "$state" = inside ] || return 1; state=after; ended=1 ;;
      "[GNUPG:] PLAINTEXT "*) [ "$state" = inside ] || return 1; plain=$((plain + 1)) ;;
      "[GNUPG:] DECRYPTION_OKAY"*) okay=1 ;;
      "[GNUPG:] DECRYPTION_FAILED"*|"[GNUPG:] BADMDC"*) return 1 ;;
    esac
  done < "$f"
  [ "$began" -eq 1 ] && [ "$ended" -eq 1 ] && [ "$plain" -le 1 ] || return 1
  [ "$okay" -eq 1 ] || echo "[WARN] gpg の出力に DECRYPTION_OKAY がありません（gpg の版の違いの可能性）。暗号化されたデータの復号はできたので続けます"
  return 0
}

if [[ "$FILE" == *.gpg ]]; then
  command -v gpg >/dev/null || die "暗号化したバックアップの復号に gpg が必要です（$(gpg_hint)）"
  PASS_FILE="${BACKUP_ENCRYPT_PASSPHRASE_FILE:-$(cur_env_value BACKUP_ENCRYPT_PASSPHRASE_FILE)}"
  if [ -z "$PASS_FILE" ] || [ ! -s "$PASS_FILE" ]; then
    [ -t 0 ] || die "パスフレーズのファイルが見つかりません（BACKUP_ENCRYPT_PASSPHRASE_FILE を指定してください）"
    IFS= read -r -s -p "バックアップのパスフレーズ: " pass; echo   # 前後の空白も落とさない（ファイルの 1 行目と同じ扱い）
    PASS_FILE="$WORK/.pass"
    printf '%s' "$pass" > "$PASS_FILE"
    unset pass
  fi
  GNUPG_TMP=$(mktemp -d)
  set +e
  GNUPGHOME="$GNUPG_TMP" gpg --batch --quiet --pinentry-mode loopback --passphrase-file "$PASS_FILE" \
      --status-fd 3 -d "$FILE" 3>"$WORK/gpg.status" | gzip -dc | limit_stream | tar -C "$X" --no-same-owner -xf -
  rcs=("${PIPESTATUS[@]}")
  set -e
  [ ! -e "$WORK/too-large" ] || too_large
  [ "${rcs[*]}" = "0 0 0 0" ] || die "復号できませんでした（パスフレーズが違うか、ファイルが壊れています）: $FILE"
  rm -f "$WORK/.pass"
  check_gpg_status "$WORK/gpg.status" \
    || die "パスフレーズで暗号化されたバックアップではありません（暗号化されていない OpenPGP のデータ・暗号化されていない部分を含むもの・改ざんされたものは受け付けません）: $FILE"
  echo "[INFO] 暗号化されたバックアップです（パスフレーズで復号し、改ざんが無いことを確かめました）"
else
  set +e
  gzip -dc < "$FILE" | limit_stream | tar -C "$X" --no-same-owner -xf -
  rcs=("${PIPESTATUS[@]}")
  set -e
  [ ! -e "$WORK/too-large" ] || too_large
  [ "${rcs[*]}" = "0 0 0" ] || die "バックアップを展開できません（壊れているか、形式が違います）: $FILE"
  echo "[WARN] 暗号化されていないバックアップです（出どころの確かめは、ファイルを置いた場所の管理に頼ります）"
  if [ -n "$ENC_CONFIGURED" ]; then
    echo "[WARN] この環境はバックアップを暗号化しています（BACKUP_ENCRYPT_PASSPHRASE_FILE）が、このファイルは暗号化されていません。"
    echo "       暗号化の設定より前に作ったものか、別の人が置いたものでないか、作成日時（下の manifest）と置き場所を確かめてください"
    if [ "${RESTORE_YES:-}" = "1" ] && [ "${RESTORE_ALLOW_UNENCRYPTED:-}" != "1" ]; then
      die "RESTORE_YES=1 では、暗号化していないバックアップは戻しません（確かめたうえで戻すなら RESTORE_ALLOW_UNENCRYPTED=1 を付けてください）"
    fi
  fi
fi

# 中身の一覧: 一番上に、想定の名前の普通のファイルだけがあること（シンボリックリンク・ディレクトリ・デバイスなどは止める。
#   知らない名前の普通のファイルは使わずに無視する）
while IFS= read -r -d '' p; do
  name="${p#"$X"/}"
  if [ -L "$p" ] || [ ! -f "$p" ] || [[ "$name" == */* ]]; then
    die "バックアップに想定外のもの（普通のファイル以外・下の階層）があります: $(printf '%q' "$name")。復元を中止します（何も変えていません）"
  fi
  case " $KNOWN_FILES " in
    *" $name "*) ;;
    *) echo "[WARN] 知らないファイルは使いません: $(printf '%q' "$name")" ;;
  esac
done < <(find "$X" -mindepth 1 -print0)
[ -f "$X/manifest.txt" ] && [ -f "$X/db.dump" ] || die "NetConfig Manager のバックアップではありません: $FILE"
# DB のダンプ（pg_dump -Fc）の形式か（中身は下で pg_restore -l でも確かめる）
[ "$(head -c 5 "$X/db.dump")" = "PGDMP" ] || die "DB のダンプの形式が違います（pg_dump のカスタム形式ではありません）: db.dump"

# ホストに展開する書庫の一覧の検査（引数: 書庫 表示名）。止めるもの: 絶対パス・.. を含む名前・リンク先、
#   デバイス・FIFO などの特殊なファイル、setuid / setgid のファイル。リンクは、リンク先が書庫の中（相対で .. を含まない）なら通す
#   名前は GNU tar の --quoting-style=c（"…" で囲み、" と \ と表示できない文字を \ で逃がす。/ と . は逃がさない）で読む
check_tar() {
  local tarf="$1" label="$2" line mode rest name tail target comp list="$WORK/tar-list.txt"
  local qre='^((\\.|[^"\\])*)"(.*)$'
  local -A regular=()
  # 一覧は作業用のファイルに書き出し、tar の終了コードを確かめる（途中で切れた・壊れた書庫を、変える前に見つける）。
  # 表示の文言（" link to " など）が翻訳されないよう LC_ALL=C
  if ! LC_ALL=C tar --quoting-style=c --numeric-owner -tvf "$tarf" > "$list" 2>"$WORK/tar-list.err"; then
    echo "$label を最後まで読めません（壊れているか、途中で切れています）: $(head -c 300 "$WORK/tar-list.err" | tr -cd '[:print:] ')"
    return 1
  fi
  while IFS= read -r line; do
    mode="${line%% *}"
    rest="${line#*\"}"
    [ "$rest" != "$line" ] || { echo "$label の一覧を読めません"; return 1; }
    [[ "$rest" =~ $qre ]] || { echo "$label の一覧を読めません"; return 1; }
    name="${BASH_REMATCH[1]}"; tail="${BASH_REMATCH[3]}"
    target=""
    case "$mode" in
      -*) regular[$name]=1 ;;
      d*) ;;
      l*)
        [[ "$tail" =~ ^\ -\>\ \"((\\.|[^\"\\])*)\"$ ]] || { echo "$label のリンクを読めません: \"$name\""; return 1; }
        target="${BASH_REMATCH[1]}" ;;
      h*)
        # ハードリンクは、書庫の中で先に出てきた普通のファイルを指すものだけ（tar -t はリンク先の先頭の / を外して表示するため、
        # 名前の形ではなく、書庫の中にそのファイルがあることで確かめる。アプリの Git リポジトリには通常できない）
        [[ "$tail" =~ ^\ link\ to\ \"((\\.|[^\"\\])*)\"$ ]] || { echo "$label のリンクを読めません: \"$name\""; return 1; }
        target="${BASH_REMATCH[1]}"
        [ -n "${regular[$target]+x}" ] || { echo "$label に書庫の外を指すハードリンクがあります: \"$name\""; return 1; } ;;
      *) echo "$label に特殊なファイル（種類 ${mode:0:1}）があります: \"$name\""; return 1 ;;
    esac
    case "${mode:3:1}${mode:6:1}" in *[sS]*) echo "$label に setuid / setgid のファイルがあります: \"$name\""; return 1 ;; esac
    for comp in "$name" "$target"; do
      [ -n "$comp" ] || continue
      case "$comp" in /*) echo "$label に絶対パスがあります: \"$name\""; return 1 ;; esac
      case "/$comp/" in */../*) echo "$label に .. を含む名前・リンク先があります: \"$name\""; return 1 ;; esac
    done
  done < "$list"
  return 0
}
for t in configs.tar ssh.tar terminal-logs.tar; do
  [ -f "$X/$t" ] || continue
  check_tar "$X/$t" "$t" || die "$t（ボリュームの書庫）に想定外のものがあるため、復元を中止します（何も変えていません）"
done

# 証明書: 作業用のディレクトリに展開し、certs/ の server.crt・server.key・ca.crt のうち、普通のファイルだけを使う
#   （ほかのもの＝ certs/README.md などは使わない。リンク・絶対パス・.. は GNU tar が展開しないか、ここで止める）
CERTS_X=""
if [ -f "$X/certs.tar" ]; then
  check_tar "$X/certs.tar" "certs.tar" || die "certs.tar（証明書の書庫）に想定外のものがあるため、復元を中止します（何も変えていません）"
  CERTS_X="$WORK/certs-x"
  mkdir "$CERTS_X"
  tar -C "$CERTS_X" --no-same-owner --no-same-permissions -xf "$X/certs.tar" \
    || die "certs.tar（証明書の書庫）を展開できません。復元を中止します（何も変えていません）"
  for f in $CERT_FILES; do
    p="$CERTS_X/certs/$f"
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then
      die "certs.tar の certs/$f が普通のファイルではありません。復元を中止します（何も変えていません）"
    fi
  done
  # server.crt と server.key は組でそろっているときだけ戻す（片方だけ置き換えると組が合わず、nginx が HTTP に戻る）
  if [ -f "$CERTS_X/certs/server.crt" ] && [ -f "$CERTS_X/certs/server.key" ]; then
    if command -v openssl >/dev/null; then
      # import_cert.sh と同じ確かめ方（公開鍵が一致するか）
      c_pub=$(openssl x509 -in "$CERTS_X/certs/server.crt" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum || true)
      k_pub=$(openssl pkey -in "$CERTS_X/certs/server.key" -pubout -outform DER 2>/dev/null | sha256sum || true)
      empty=$(printf '' | sha256sum)
      [ "$c_pub" = "$k_pub" ] && [ "$c_pub" != "$empty" ] \
        || die "certs.tar の server.crt と server.key の組が合いません（または読めません）。復元を中止します（何も変えていません）"
    else
      echo "[WARN] openssl が無いため、certs.tar の証明書と鍵の組を確かめられません（そのまま戻します）"
    fi
  else
    [ ! -f "$CERTS_X/certs/server.crt" ] && [ ! -f "$CERTS_X/certs/server.key" ] \
      || echo "[WARN] certs.tar に server.crt と server.key の片方しかないため、証明書は戻しません（今の証明書のまま）"
    CERTS_X=""
  fi
  [ -n "$CERTS_X" ] || echo "[INFO] 証明書（certs/）は戻しません"
fi

echo "----------------------------------------"
cat "$X/manifest.txt"
echo "----------------------------------------"

# .env: DEVICE_ENCRYPTION_KEY が違うときだけ戻す。違いはキーの名前だけを表示する（値は出さない）
#   バックアップの env と今の .env を、python-dotenv の読み方（コンテナへ渡る値）と「KEY=」の行（ホストのスクリプトが読む値）の
#   両方で読み、どちらかで違えば「違う」とする
ENV_MODE=""   # all / keys / 空（変えない）
declare -A B_DOT=() B_HOST=() C_DOT=() C_HOST=()
# C_AMB は parse_env が名前で受け取って書く（今の .env の読めない行。今は使わない）
B_AMB=()
# shellcheck disable=SC2034
C_AMB=()
if [ -f "$X/env" ]; then
  parse_env "$X/env" B_DOT B_HOST B_AMB
  [ ! -f "$INSTALL_DIR/.env" ] || parse_env "$INSTALL_DIR/.env" C_DOT C_HOST C_AMB
fi
# キーの値が両方の読み方で同じか（0 = 同じ）
same_key() { # $1 = キー
  [ "${B_DOT[$1]+x}" = "${C_DOT[$1]+x}" ] && [ "${B_DOT[$1]-}" = "${C_DOT[$1]-}" ] \
    && [ "${B_HOST[$1]+x}" = "${C_HOST[$1]+x}" ] && [ "${B_HOST[$1]-}" = "${C_HOST[$1]-}" ]
}
if [ -f "$X/env" ] && ! same_key DEVICE_ENCRYPTION_KEY; then
  CHANGED_KEYS=(); ONLY_BACKUP=(); ONLY_CURRENT=(); DANGER=()
  while IFS= read -r k; do
    [ -n "$k" ] || continue
    same_key "$k" && continue
    if [ -z "${B_DOT[$k]+x}${B_HOST[$k]+x}" ]; then ONLY_CURRENT+=("$k")
    elif [ -z "${C_DOT[$k]+x}${C_HOST[$k]+x}" ]; then ONLY_BACKUP+=("$k")
    else CHANGED_KEYS+=("$k"); fi
    [[ "$k" =~ $DANGER_KEYS_RE ]] && DANGER+=("$k")
  done < <(printf '%s\n' "${!B_DOT[@]}" "${!B_HOST[@]}" "${!C_DOT[@]}" "${!C_HOST[@]}" | LC_ALL=C sort -u)
  echo ""
  echo "■ .env の DEVICE_ENCRYPTION_KEY がバックアップと違います（別のサーバーから移す・.env を作り直した、など）。"
  echo "  違う鍵のままでは機器のパスワードを復号できないため、.env をバックアップに合わせます。違い（キーの名前だけ。値は表示しません）:"
  echo "    値が変わるキー           : ${CHANGED_KEYS[*]:-（なし）}"
  echo "    バックアップにだけあるキー : ${ONLY_BACKUP[*]:-（なし）}"
  echo "    今の .env にだけあるキー   : ${ONLY_CURRENT[*]:-（なし）}（丸ごと置き換えると消えます）"
  if [ ${#DANGER[@]} -gt 0 ]; then
    echo "  ⚠ 注意が要るキーが変わります: ${DANGER[*]}"
    echo "    （BACKUP_POST_COMMAND は root でコマンドとして実行され、BACKUP_COPY_DIR・OUTBOUND_*・GIT_EXPORT_* などは、データの送り先・"
    echo "      暗号化・接続先を変えます。心当たりのない値なら、丸ごとの置き換えはせず、keys を選んでください）"
  fi
  echo "  選べる扱い:"
  echo "    all  … .env を丸ごとバックアップのものにする（別のサーバーへ移すとき。以前からの動き）"
  echo "    keys … 今の .env のまま、${SECRET_KEYS// /・} だけをバックアップの値にする（ポート・バックアップの設定などは今のまま）"
  case "${RESTORE_ENV:-}" in
    all|keys) ENV_MODE="$RESTORE_ENV"; echo "  → RESTORE_ENV=$ENV_MODE で戻します" ;;
    "")
      if [ "${RESTORE_YES:-}" = "1" ]; then
        [ ${#DANGER[@]} -eq 0 ] \
          || die "注意が要るキー（${DANGER[*]}）が変わるため、RESTORE_YES=1 だけでは .env を戻しません。違いを確かめて RESTORE_ENV=all か RESTORE_ENV=keys を付けてください（何も変えていません）"
        ENV_MODE="all"; echo "  → 注意が要るキーは変わらないため、丸ごと戻します（RESTORE_YES=1）"
      else
        read -r -p "  .env の扱いを入力してください（all / keys。それ以外は中止）: " ans
        case "$ans" in all|keys) ENV_MODE="$ans" ;; *) echo "中止しました（何も変えていません）"; exit 1 ;; esac
      fi ;;
    *) die "RESTORE_ENV は all か keys を指定してください: ${RESTORE_ENV}" ;;
  esac
  [ "$ENV_MODE" != "keys" ] || [ -f "$INSTALL_DIR/.env" ] || die "今の .env が無いため keys は選べません（all を選んでください。何も変えていません）"
  # keys: 戻す鍵の値を、KEY=値 の 1 行で書ける形で取り出せること（バックアップの書き方に左右されないよう、python-dotenv の読み方の値を書く）
  if [ "$ENV_MODE" = "keys" ]; then
    for k in $SECRET_KEYS; do
      [ -z "${B_DOT[$k]+x}" ] || [[ "${B_DOT[$k]}" =~ ^[A-Za-z0-9._~+/=-]*$ ]] \
        || die "バックアップの $k の値を 1 行の形で書けません（keys では戻せません。all を選ぶか、別のバックアップで復元してください。何も変えていません）"
    done
  fi
  # bash では python-dotenv と同じに読めると言い切れない行（バックアップは直せないので、確かめてから進む）
  AMB=("${B_AMB[@]}")
  if [ "$ENV_MODE" = "keys" ]; then
    AMB=()
    for a in "${B_AMB[@]}"; do
      if [[ "$a" == *"（NUL）"* ]]; then AMB+=("$a"); continue; fi   # NUL の行はどのキーか分からないので、keys でも確かめる
      for k in $SECRET_KEYS; do [[ "$a" != *"（$k）"* ]] || AMB+=("$a"); done
    done
  fi
  if [ ${#AMB[@]} -gt 0 ]; then
    echo "  ⚠ バックアップの env に、コンテナが読む値（podman-compose の python-dotenv）と、このスクリプトの読み方が同じと言い切れない行があります（値は表示しません）:"
    for a in "${AMB[@]}"; do echo "      - $a"; done
    echo "    これらの行のキーは、上の違いの一覧から漏れている可能性があります。中身は: sudo tar -xzOf <バックアップ> ./env | sed -n '<行>p'（暗号化したものは gpg -d で）"
    if [ "${RESTORE_YES:-}" = "1" ]; then
      [ "${RESTORE_ENV_ALLOW_UNPARSED:-}" = "1" ] \
        || die "読み方が同じと言い切れない行があるため、RESTORE_YES=1 だけでは .env を戻しません。中身を確かめたうえで戻すなら RESTORE_ENV_ALLOW_UNPARSED=1 を付けてください（何も変えていません）"
      echo "  → RESTORE_ENV_ALLOW_UNPARSED=1 のため、このまま戻します"
    else
      read -r -p "  これらの行を確かめたうえで戻すなら yes と入力してください: " ans
      [ "$ans" = "yes" ] || { echo "中止しました（何も変えていません）"; exit 1; }
    fi
  fi
fi

echo ""
echo "現在のデータ（DB・コンフィグ履歴など）をすべてこのバックアップの内容に置き換えます。"
if [ "${RESTORE_YES:-}" != "1" ]; then
  read -r -p "続けるには yes と入力してください: " ans
  [ "$ans" = "yes" ] || { echo "中止しました（何も変えていません）"; exit 1; }
fi

STAGE="DB のコンテナの起動"
DB=$(container_of db)
[ -n "$DB" ] || die "db コンテナが見つかりません。先に setup.sh で起動してください（何も変えていません）"
$CONTAINER_CMD start "$DB" >/dev/null
DB_READY=0
for _ in $(seq 1 30); do
  if $CONTAINER_CMD exec "$DB" pg_isready -U netconfig >/dev/null 2>&1; then DB_READY=1; break; fi
  sleep 2
done
[ "$DB_READY" -eq 1 ] || die "DB が応答しません（1 分待ちました）。sudo podman logs $DB で確かめてください（データは変えていません）"
# DB を消す前に、ダンプをこの DB の pg_restore で読めるかを確かめる（壊れている・新しい版の PostgreSQL で作ったものを、消す前に見つける）
STAGE="DB のダンプの確認"
$CONTAINER_CMD exec -i "$DB" pg_restore -l < "$X/db.dump" >/dev/null \
  || die "DB のダンプを読めません（壊れているか、PostgreSQL の版が合いません）。復元を中止します（データは変えていません）"

# ---------------------------------------------------------------- 2. 今の .env と証明書の控え
STAGE="今の .env と証明書の控え"
TS=$(date +%Y%m%d-%H%M%S)
if ! { mkdir -p "$ENV_BACKUP_DIR" && chmod 700 "$ENV_BACKUP_DIR"; }; then die "控えの置き場（$ENV_BACKUP_DIR）を作れません（何も変えていません）"; fi
if [ -f "$INSTALL_DIR/.env" ]; then
  # 同じ秒に 2 回実行しても、前の控え（元の .env のことがある）を上書きしない
  ENV_SAVED="$ENV_BACKUP_DIR/env-before-restore-$TS"
  [ ! -e "$ENV_SAVED" ] || ENV_SAVED=$(mktemp "$ENV_SAVED.XXXX")
  install -m 600 "$INSTALL_DIR/.env" "$ENV_SAVED" || die ".env の控えを取れません（何も変えていません）"
  log "[INFO] 今の .env の控え: $ENV_SAVED"
fi
if [ -n "$CERTS_X" ]; then
  have_cur=0
  for f in $CERT_FILES; do [ -e "$INSTALL_DIR/certs/$f" ] && have_cur=1; done
  if [ "$have_cur" -eq 1 ]; then
    CERTS_SAVED="$ENV_BACKUP_DIR/certs-before-restore-$TS"
    if [ -e "$CERTS_SAVED" ]; then CERTS_SAVED=$(mktemp -d "$CERTS_SAVED.XXXX") || die "証明書の控えの置き場を作れません（何も変えていません）"
    else mkdir -m 700 "$CERTS_SAVED" || die "証明書の控えの置き場を作れません（何も変えていません）"; fi
    for f in $CERT_FILES; do
      if [ -e "$INSTALL_DIR/certs/$f" ]; then
        cp -p "$INSTALL_DIR/certs/$f" "$CERTS_SAVED/" || { CERTS_SAVED=""; die "証明書（certs/$f）の控えを取れません（何も変えていません）"; }
      fi
    done
    log "[INFO] 今の証明書の控え: $CERTS_SAVED/"
  fi
fi

# ---------------------------------------------------------------- 3. アプリを止める
CHANGED=1
STAGE="アプリの停止"
for s in "${APP_SERVICES[@]}"; do
  c=$(container_of "$s")
  [ -n "$c" ] || continue
  log "[INFO] 停止: $s"
  APP_STOPPED=1
  $CONTAINER_CMD stop "$c" >/dev/null
done

# ---------------------------------------------------------------- 4. DB を作り直して流し込む
STAGE="DB の作り直し"
PHASE="data"
log "[INFO] DB を復元しています..."
DB_STATE="消している途中か、空の可能性があります"
$CONTAINER_CMD exec "$DB" psql -q -U netconfig -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'netconfig' AND pid <> pg_backend_pid();" \
  -c "DROP DATABASE IF EXISTS netconfig;" -c "CREATE DATABASE netconfig OWNER netconfig;" >/dev/null
STAGE="DB のダンプの流し込み"
DB_STATE="空か、流し込みの途中です（バックアップの内容は一部しか入っていません）"
$CONTAINER_CMD exec -i "$DB" pg_restore -U netconfig -d netconfig --no-owner --exit-on-error < "$X/db.dump"
DB_STATE="バックアップの内容に戻しました"

# ---------------------------------------------------------------- 5. ボリュームの中身を入れ替える
STAGE="ボリュームの入れ替え"
restore_volume() {  # $1=ボリューム名の後半 $2=tar
  [ -f "$X/$2" ] || return 0
  local vol="${PROJECT_NAME}_$1" mp
  mp=$($CONTAINER_CMD volume inspect -f '{{.Mountpoint}}' "$vol" 2>/dev/null) || { log "[WARN] ボリューム $vol がありません（スキップ）"; return 0; }
  [ -n "$mp" ] && [ -d "$mp" ] || { log "[WARN] ボリューム $vol の場所が分かりません（スキップ）"; return 0; }
  log "[INFO] 復元: $vol"
  VOL_STATE="入れ替えの途中です（$vol が空か途中の可能性があります）"
  find "$mp" -mindepth 1 -delete
  tar -C "$mp" --numeric-owner -xf "$X/$2"
}
restore_volume config_repo configs.tar
restore_volume ssh_data ssh.tar
restore_volume terminal_logs terminal-logs.tar
VOL_STATE="バックアップの内容に戻しました"

# ---------------------------------------------------------------- 6. 証明書（控えは 2. で取った）
if [ -n "$CERTS_X" ]; then
  STAGE="証明書の配置"
  CERT_STATE="置き換えの途中です${CERTS_SAVED:+（元の証明書は $CERTS_SAVED/）}"
  mkdir -p "$INSTALL_DIR/certs"
  for f in $CERT_FILES; do
    [ -f "$CERTS_X/certs/$f" ] || continue
    mode=644; [ "$f" = server.key ] && mode=600
    install -m "$mode" "$CERTS_X/certs/$f" "$INSTALL_DIR/certs/$f"
  done
  CERT_STATE="バックアップのものに戻しました${CERTS_SAVED:+（元の証明書は $CERTS_SAVED/）}"
fi

# ---------------------------------------------------------------- 7. .env と DB のパスワード
if [ -n "$ENV_MODE" ]; then
  STAGE=".env の書き換え"
  NEW_ENV="$WORK/env.new"
  if [ "$ENV_MODE" = "all" ]; then
    cp "$X/env" "$NEW_ENV"
    PGPW="${B_DOT[POSTGRES_PASSWORD]-}"
  else
    # 今の .env の行のまま、SECRET_KEYS のキーを定める行（export つき・空白つきも）を、最初の 1 つはバックアップの値の
    # 「KEY=値」の行にし、残りは除く（今の .env に無ければ末尾に足す）
    declare -A done_k=()
    : > "$NEW_ENV"
    while IFS= read -r line || [ -n "$line" ]; do
      k=""
      if [[ "${line%$'\r'}" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*= ]]; then k="${BASH_REMATCH[2]}"; fi
      if [ -n "$k" ] && [[ " $SECRET_KEYS " == *" $k "* ]] && [ -n "${B_DOT[$k]+x}" ]; then
        [ -n "${done_k[$k]+x}" ] || printf '%s=%s\n' "$k" "${B_DOT[$k]}" >> "$NEW_ENV"
        done_k[$k]=1
        continue
      fi
      printf '%s\n' "$line" >> "$NEW_ENV"
    done < "$INSTALL_DIR/.env"
    for k in $SECRET_KEYS; do
      [ -n "${B_DOT[$k]+x}" ] && [ -z "${done_k[$k]+x}" ] && printf '%s=%s\n' "$k" "${B_DOT[$k]}" >> "$NEW_ENV"
    done
    PGPW="${C_DOT[POSTGRES_PASSWORD]-}"
  fi
  # DB ユーザーのパスワードを、これから使う .env（コンテナへは python-dotenv の読み方の値が渡る）に合わせる。.env より先に変える
  STAGE="DB のパスワードの設定"
  PHASE="env"
  if [ -n "$PGPW" ]; then
    printf "ALTER USER netconfig PASSWORD '%s';\n" "${PGPW//\'/\'\'}" \
      | $CONTAINER_CMD exec -i "$DB" psql -q -U netconfig -d postgres -v ON_ERROR_STOP=1 >/dev/null
  fi
  PHASE="start"   # ここから先の失敗は、作り直して起動すれば直る（DB のパスワードはこれから使う .env に合わせた）
  STAGE=".env の書き換え"
  ENV_STATE="書き換えの途中です${ENV_SAVED:+（元の .env は $ENV_SAVED）}"
  install -m 600 "$NEW_ENV" "$INSTALL_DIR/.env"
  ENV_STATE="バックアップに合わせました（$ENV_MODE）${ENV_SAVED:+。元の .env は $ENV_SAVED}"
  log "[INFO] .env をバックアップに合わせました（$ENV_MODE）${ENV_SAVED:+。今までの .env: $ENV_SAVED}"
else
  STAGE="DB のパスワードの設定"
  PHASE="env"
  PGPW="${C_DOT[POSTGRES_PASSWORD]-}"
  [ -n "$PGPW" ] || PGPW=$(cur_env_value POSTGRES_PASSWORD)
  if [ -n "$PGPW" ]; then
    printf "ALTER USER netconfig PASSWORD '%s';\n" "${PGPW//\'/\'\'}" \
      | $CONTAINER_CMD exec -i "$DB" psql -q -U netconfig -d postgres -v ON_ERROR_STOP=1 >/dev/null
  fi
fi

# ---------------------------------------------------------------- 8. 起動
STAGE="アプリの起動"
PHASE="start"
# いつも作り直す（setup.sh と同じ: プロキシの環境変数を渡さない・出力の伏せ字。lib/compose.sh）。.env を変えたときに
# 反映されるほか、前の復元が起動の途中で止まり、古い .env のコンテナが残っていても、もう一度の復元で直るように
log "[INFO] コンテナを作り直して起動します..."
if [ "$(basename "$CONTAINER_CMD")" = "podman" ] && declare -F ncm_compose_up >/dev/null; then
  ncm_compose_up "$INSTALL_DIR" "$COMPOSE_FILE"
elif [ "$(basename "$CONTAINER_CMD")" = "podman" ]; then
  (cd "$INSTALL_DIR" && env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY \
     podman-compose -f "$COMPOSE_FILE" up -d --force-recreate 2>&1) | { if declare -F ncm_redact_output >/dev/null; then ncm_redact_output; else cat; fi; }
else
  (cd "$INSTALL_DIR" && env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY \
     docker compose -f "$COMPOSE_FILE" up -d --force-recreate 2>&1) | { if declare -F ncm_redact_output >/dev/null; then ncm_redact_output; else cat; fi; }
fi
APP_STOPPED=0
CHANGED=0
log "[INFO] 復元が完了しました。画面で機器・コンフィグ履歴を確認してください"
