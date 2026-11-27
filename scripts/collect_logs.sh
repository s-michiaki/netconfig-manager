#!/usr/bin/env bash
# NetConfig Manager の調査用ログを集める
#
#   起動しない・動きがおかしいときに、原因を調べるための情報を 1 つのファイル
#   （netconfig-logs-YYYYmmdd-HHMMSS.tar.gz）にまとめる。コンテナが止まっていても、
#   podman 自体が動いていなくても、集められるものだけを集めて最後まで進む。
#
# 使い方（root、または sudo が使えるユーザーで実行）:
#   bash scripts/collect_logs.sh                # 直近 3 日分・コンテナごとに最大 5000 行
#   bash scripts/collect_logs.sh --days 7       # さかのぼる日数を変える
#   bash scripts/collect_logs.sh --lines 20000  # コンテナごとの行数の上限を変える
#   bash scripts/collect_logs.sh --full         # 行数の上限なし（期間の指定は有効。大きくなることがある）
#   bash scripts/collect_logs.sh --out /tmp     # 保存先を変える（既定: /var/tmp/netconfig-logs）
#   bash scripts/collect_logs.sh --keep 5       # 保存先に残す数（既定 5。古いものから消す）
#
# 集めるもの:
#   - アプリの版・Git の状態、OS・podman の版、ディスク・メモリの空き
#   - コンテナの一覧と状態（終了コード・再起動の回数・メモリ不足で止まったか）、コンテナごとのログ
#   - 設定（.env）。パスワード・暗号化キー・Webhook の URL などの値は伏せる
#   - 起動確認（/api/health、自己診断）、DB のマイグレーションの版、Redis・DB の応答
#   - アプリが記録した直近の警告・エラー（アクティビティ）
#   - systemd（自動起動・バックアップのタイマー）の状態とログ、ファイアウォール、待ち受けポート、
#     SELinux の拒否、メモリ不足（OOM）の記録、証明書の期限、最後のバックアップの結果
#
# 集めないもの（機密のため）:
#   - 機器のコンフィグ、DB の中身（ダンプ）、ターミナルの記録、.env の秘密の値、証明書の秘密鍵
#
# ※ ログには機器名・IP アドレス・ユーザー名が含まれる。Webhook の URL やトークンらしい文字列は伏せるが、
#   外部へ渡す前に中身を確かめること（中身は tar -xzf で展開して読めるテキスト）。
set -uo pipefail   # 途中の失敗で止めない（-e は付けない）。集められるものだけ集める

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROJECT_NAME="${PROJECT_NAME:-$(basename "$INSTALL_DIR")}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"
# root でなければ sudo を付ける（SUDO を空にすると付けない。動作確認用）
if [ -z "${SUDO+x}" ]; then
  if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi
fi

DAYS=3
LINES=5000
FULL=0
OUT_DIR="${COLLECT_OUT_DIR:-/var/tmp/netconfig-logs}"
KEEP=5
CMD_TIMEOUT=30          # 1 つのコマンドの制限時間（秒）。応答しないコマンドで止まらないように
WARN_MB=50              # これを超えたら、絞り込みを案内する

usage() { sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
need_number() { [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "$1 には数（整数）を指定してください"; exit 1; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --days)  need_number "$1" "${2:-}"; DAYS="$2"; shift 2 ;;
    --lines) need_number "$1" "${2:-}"; LINES="$2"; shift 2 ;;
    --keep)  need_number "$1" "${2:-}"; KEEP="$2"; shift 2 ;;
    --out)   [ -n "${2:-}" ] || { echo "--out には保存先を指定してください"; exit 1; }; OUT_DIR="$2"; shift 2 ;;
    --full)  FULL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "不明なオプションです: $1（--help で使い方を表示）"; exit 1 ;;
  esac
done
[ "$DAYS" -ge 1 ] || DAYS=1
HOURS=$((DAYS * 24))   # podman logs --since は「時間」で指定する（日の単位は使えない）

STAMP=$(date +%Y%m%d-%H%M%S)
NAME="netconfig-logs-$STAMP"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/netconfig-logs.XXXXXX") || { echo "作業用のフォルダを作れません"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/$NAME"
mkdir -p "$ROOT/containers" "$ROOT/system" "$ROOT/app"
ERRORS="$ROOT/collect-errors.txt"   # 集められなかったものの記録

log() { echo "$(date '+%T') $*"; }

# 秘密らしい文字列を伏せる（Webhook の URL、URL に埋め込んだパスワード、トークン、鍵）
redact() {
  sed -E \
    -e 's#(https://(discord(app)?\.com/api/webhooks|hooks\.slack\.com/services)/)[A-Za-z0-9/_.-]+#\1***#g' \
    -e 's#(https://[A-Za-z0-9.-]+\.environment\.api\.powerplatform\.com)(:[0-9]+)?/[^[:space:]"'"'"']+#\1/***#Ig' \
    -e 's#(://[^/:@[:space:]]+:)[^@/[:space:]]+@#\1***@#g' \
    -e 's#eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}#***TOKEN***#g' \
    -e 's#gAAAA[A-Za-z0-9_=-]{40,}#***ENCRYPTED***#g' \
    -e 's#(-----BEGIN [A-Z ]*PRIVATE KEY-----).*#\1 ***#g' \
    -e 's#(^|[^A-Za-z0-9_])(([Hh][Tt][Tt][Pp][Ss]?|[Aa][Ll][Ll])_[Pp][Rr][Oo][Xx][Yy]=[A-Za-z][A-Za-z0-9+.-]*://)[^/@[:space:]"'"'"']*@#\1\2***@#g' \
    -e 's#(([Pp]assword|[Pp]asswd|[Ss]ecret|[Tt]oken|[Aa]pi[_-]?[Kk]ey)["'"'"']?[=:] ?["'"'"']?)[^"'"'"' ,;&]+#\1***#g'
}

# コマンドを実行して出力を保存する。失敗しても続け、失敗したことを記録する
#   save <保存先（ROOT からの相対パス）> <コマンド...>
save() {
  local out="$ROOT/$1"; shift
  {
    echo "\$ $*"
    timeout "$CMD_TIMEOUT" "$@" 2>&1
    local rc=$?
    [ $rc -eq 0 ] || echo "（終了コード $rc$([ $rc -eq 124 ] && echo "。${CMD_TIMEOUT} 秒で打ち切り")）"
  } | redact > "$out"
  if grep -q "^（終了コード " "$out" 2>/dev/null; then
    echo "$(basename "$out"): 「$1 ${2:-}」が失敗しました" >> "$ERRORS"
  fi
  return 0
}
have() { command -v "$1" >/dev/null 2>&1; }
# OS の判定（scripts/lib/os.sh）。無くても収集は続ける（OS の行は os-release の名前だけにする）
# shellcheck source=lib/os.sh
[ -f "$SCRIPT_DIR/lib/os.sh" ] && . "$SCRIPT_DIR/lib/os.sh"
# コンテナのコマンド（podman）。root でなければ sudo を付ける。timeout から呼べるよう配列で持つ
# shellcheck disable=SC2206  # SUDO は空か "sudo" のどちらか
CC=($SUDO "$CONTAINER_CMD")
cc() { "${CC[@]}" "$@"; }

env_value() {
  local v=""
  [ -f "$INSTALL_DIR/.env" ] && v=$( ($SUDO grep -E "^$1=" "$INSTALL_DIR/.env" 2>/dev/null || true) | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//')
  echo "${v:-$2}"
}

log "ログを集めます（直近 ${DAYS} 日分$([ "$FULL" -eq 1 ] && echo "・行数の上限なし" || echo "・コンテナごとに最大 ${LINES} 行")）"

# ---------------------------------------------------------------- 概要
{
  echo "NetConfig Manager 調査用ログ"
  echo "収集日時     : $(date '+%F %T %Z')"
  echo "ホスト名     : $(hostname 2>/dev/null)"
  echo "設置場所     : $INSTALL_DIR"
  echo "プロジェクト : $PROJECT_NAME"
  echo "対象の期間   : 直近 ${DAYS} 日"
  echo "行数の上限   : $([ "$FULL" -eq 1 ] && echo "なし（--full）" || echo "コンテナごとに ${LINES} 行")"
  echo "アプリの版   : $(grep -oE 'version="[0-9.]+"' "$INSTALL_DIR/backend/app/main.py" 2>/dev/null | head -1 | tr -d '"' | cut -d= -f2)"
  if [ -n "${NCM_OS_FAMILY:-}" ]; then
    echo "OS           : ${NCM_OS_PRETTY:-不明}（系統: ${NCM_OS_FAMILY}、対応: ${NCM_OS_LEVEL}）"
    [ -z "${NCM_OS_NOTE:-}" ] || echo "OS の注意    : $NCM_OS_NOTE"
  else
    echo "OS           : $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-不明}")"
  fi
  echo "カーネル     : $(uname -r 2>/dev/null)"
  echo "稼働時間     : $(uptime 2>/dev/null | sed 's/^ *//')"
} > "$ROOT/summary.txt"

# ---------------------------------------------------------------- アプリ（Git・設定）
if have git && [ -d "$INSTALL_DIR/.git" ]; then
  # リポジトリの所有者として実行する（root 以外が所有するリポジトリを root で読むと「dubious ownership」になるため）
  owner=$(stat -c %U "$INSTALL_DIR" 2>/dev/null || echo "")
  GIT=(git -C "$INSTALL_DIR")
  if [ -n "$owner" ] && [ "$owner" != "$(id -un)" ] && have sudo; then GIT=(sudo -u "$owner" git -C "$INSTALL_DIR"); fi
  save app/git.txt "${GIT[@]}" log -5 --format='%h %ad %s' --date=iso
  { echo; echo "\$ git status --short（手で変更したファイル）"; timeout "$CMD_TIMEOUT" "${GIT[@]}" status --short 2>&1 | head -100; } >> "$ROOT/app/git.txt"
else
  echo "Git リポジトリではありません（$INSTALL_DIR）" > "$ROOT/app/git.txt"
fi

# .env: 秘密の値は伏せる（キーの名前で判断。値が空かどうかは分かるようにする）
#   秘密でないキーの値も redact に通し、URL に書かれた認証情報（https://user:token@host）は伏せる（#14）
#   プロキシ（OUTBOUND_PROXY・廃止した VULN_HTTPS_PROXY）は、認証情報だけを伏せて host:port は残す（http://***@proxy.example.test:3128。
#   起動時のログ・システム状態の画面と同じ。切り分けに使う）。OUTBOUND_NO_PROXY は件数だけ、OUTBOUND_CA_FILE（ファイル名）はそのまま
if $SUDO test -f "$INSTALL_DIR/.env"; then
  $SUDO cat "$INSTALL_DIR/.env" 2>/dev/null | awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      eq = index($0, "="); if (eq == 0) { print; next }
      key = substr($0, 1, eq - 1); val = substr($0, eq + 1)
      if (key ~ /PROXY/ && key !~ /NO_PROXY/) {
        v = val; gsub(/^["\047]|["\047]\r?$|\r$/, "", v)
        if (v == "") { print key "=（空）"; next }
        if (v ~ /@/) {   # 認証情報（最後の @ まで）を伏せる。スキームが無い値も同じ
          if (v ~ /:\/\//) { p = index(v, "://"); s = substr(v, 1, p + 2); r = substr(v, p + 3) } else { s = ""; r = v }
          sub(/.*@/, "", r); v = s "***@" r
        }
        print key "=" v; next
      }
      if (key ~ /NO_PROXY/) {
        v = val; gsub(/^["\047]|["\047]\r?$|\r$/, "", v)
        print key "=" (v == "" ? "（空）" : "***（" split(v, _parts, ",") " 件）"); next
      }
      if (key ~ /(PASSWORD|PASSWD|SECRET|KEY|TOKEN|WEBHOOK|DATABASE_URL|REDIS_URL|BROKER|COMMAND)/)
        print key "=" (val == "" ? "（空）" : "***（" length(val) " 文字）")
      else
        print key "=" val
    }' | redact | sed -E 's#(https?://)[^/@[:space:]]+@#\1***@#g' > "$ROOT/app/env.txt"
else
  echo ".env がありません（$INSTALL_DIR/.env）。setup.sh が途中で止まった可能性があります" > "$ROOT/app/env.txt"
  echo "env.txt: .env がありません" >> "$ERRORS"
fi

# ---------------------------------------------------------------- コンテナ
if have "$CONTAINER_CMD" || [ -x "$CONTAINER_CMD" ]; then
  save containers/version.txt "${CC[@]}" version
  save containers/ps.txt "${CC[@]}" ps -a --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --format '{{.ID}}  {{.Names}}  {{.Status}}  {{.Image}}'
  save containers/ps-all.txt "${CC[@]}" ps -a
  save containers/images.txt "${CC[@]}" images
  save containers/volumes.txt "${CC[@]}" volume ls
  save containers/disk-usage.txt "${CC[@]}" system df

  IDS=$(cc ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME" 2>/dev/null)
  if [ -z "$IDS" ]; then
    echo "プロジェクト $PROJECT_NAME のコンテナが 1 つもありません（podman ps -a の結果は ps-all.txt）" >> "$ERRORS"
  fi
  for id in $IDS; do
    name=$(cc inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    name="${name:-$id}"
    safe=$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')
    # 状態: 環境変数（秘密を含む）は出さず、必要な項目だけを取り出す
    save "containers/$safe.state.txt" "${CC[@]}" inspect --format \
'名前          : {{.Name}}
イメージ      : {{.ImageName}}
状態          : {{.State.Status}}
終了コード    : {{.State.ExitCode}}
エラー        : {{.State.Error}}
メモリ不足    : {{.State.OOMKilled}}
再起動の回数  : {{.RestartCount}}
開始          : {{.State.StartedAt}}
終了          : {{.State.FinishedAt}}' "$id"
    # ログ: 期間と行数で絞る（大きくなりすぎないように）
    if [ "$FULL" -eq 1 ]; then
      { cc logs --timestamps --since "${HOURS}h" "$id" 2>&1 || echo "（ログを取得できませんでした）"; } | redact > "$ROOT/containers/$safe.log"
    else
      { cc logs --timestamps --since "${HOURS}h" --tail "$LINES" "$id" 2>&1 || echo "（ログを取得できませんでした）"; } | redact > "$ROOT/containers/$safe.log"
    fi
    log "  コンテナ $name: $(wc -l < "$ROOT/containers/$safe.log") 行"
  done

  container_of() {
    cc ps -q --filter "label=com.docker.compose.project=$PROJECT_NAME" --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1
  }
  BACKEND=$(container_of backend)
  DB=$(container_of db)
  REDIS=$(container_of redis)

  # ---- 動いているコンテナに聞く
  if [ -n "$BACKEND" ]; then
    save app/selfcheck.txt "${CC[@]}" exec "$BACKEND" python -m app.tools.selfcheck
    save app/migration.txt "${CC[@]}" exec "$BACKEND" python -c \
"from sqlalchemy import create_engine, text
from app.core.config import settings
url = settings.DATABASE_URL.replace('+asyncpg', '+psycopg2').replace('+aiosqlite', '')
with create_engine(url).connect() as c:
    print('DB のマイグレーションの版:', c.execute(text('select version_num from alembic_version')).scalar())"
    save app/pip-freeze.txt "${CC[@]}" exec "$BACKEND" pip freeze
  else
    echo "backend コンテナが動いていません（自己診断・マイグレーションの版は取得できません）" > "$ROOT/app/selfcheck.txt"
    echo "selfcheck.txt: backend コンテナが動いていません" >> "$ERRORS"
  fi
  if [ -n "$DB" ]; then
    # SQL は標準入力で渡す（引用符を重ねないため）。接続先はコンテナの環境変数から
    psql_save() {
      local out="$ROOT/$1"
      { echo "\$ psql（$1）"; printf '%s\n' "$2" | timeout "$CMD_TIMEOUT" "${CC[@]}" exec -i "$DB" \
          sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F "  "' 2>&1 || echo "（取得できませんでした）"; } | redact > "$out"
      grep -q "^（取得できませんでした）" "$out" && echo "$(basename "$out"): DB から取得できませんでした" >> "$ERRORS"
      return 0
    }
    save app/db-ready.txt "${CC[@]}" exec "$DB" sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
    psql_save app/db.txt "select 'DB の大きさ: ' || pg_size_pretty(pg_database_size(current_database()));
select 'マイグレーションの版: ' || version_num from alembic_version;
select '機器の数: ' || count(*) from devices;
select '収集の結果（直近 ${DAYS} 日）: ' || status || ' ' || count(*) from collect_logs where started_at > now() - interval '${DAYS} days' group by status;"
    # アプリが記録した直近の警告・エラー（収集の失敗、システムの異常など）
    psql_save app/activity-warnings.txt "select to_char(at, 'YYYY-MM-DD HH24:MI:SS'), level, event, coalesce(device_name, '-'), left(message, 300)
from activity_logs where level <> 'info' and at > now() - interval '${DAYS} days' order by at desc limit 300;"
  else
    echo "db コンテナが動いていません" > "$ROOT/app/db.txt"
    echo "db.txt: db コンテナが動いていません" >> "$ERRORS"
  fi
  if [ -n "$REDIS" ]; then
    save app/redis.txt "${CC[@]}" exec "$REDIS" sh -c 'redis-cli ping; redis-cli info server | grep -E "redis_version|uptime_in_seconds"; redis-cli info memory | grep -E "used_memory_human|maxmemory_human"; redis-cli dbsize'
  else
    echo "redis コンテナが動いていません" > "$ROOT/app/redis.txt"
    echo "redis.txt: redis コンテナが動いていません" >> "$ERRORS"
  fi
else
  echo "$CONTAINER_CMD が見つかりません。Podman が入っていない可能性があります" | tee "$ROOT/containers/ps.txt" >> "$ERRORS"
fi

# ---------------------------------------------------------------- 画面の応答
HTTP_PORT=$(env_value HTTP_PORT 80)
HTTPS_PORT=$(env_value HTTPS_PORT 443)
if have curl; then
  save app/health-http.txt curl -sS -m 10 -o /dev/null -w 'HTTP %{http_code}  転送先: %{redirect_url}\n' "http://127.0.0.1:${HTTP_PORT}/api/health"
  save app/health-https.txt curl -sS -k -m 10 -w '\nHTTP %{http_code}\n' "https://127.0.0.1:${HTTPS_PORT}/api/health"
fi

# ---------------------------------------------------------------- 証明書・バックアップ
if have openssl; then
  for crt in "$INSTALL_DIR"/certs/*.crt; do
    [ -f "$crt" ] || continue
    save "app/cert-$(basename "$crt").txt" $SUDO openssl x509 -in "$crt" -noout -subject -issuer -dates
  done
  # 外部への接続で追加で信頼する CA（certs-outbound/。期限切れ・取り違えの確認用。証明書は秘密ではない）
  for crt in "$INSTALL_DIR"/certs-outbound/*; do
    [ -f "$crt" ] || continue
    case "$crt" in *.pem|*.crt|*.cer) ;; *) continue ;; esac
    save "app/outbound-ca-$(basename "$crt").txt" $SUDO openssl x509 -in "$crt" -noout -subject -issuer -dates
  done
fi
BACKUP_DIR=$(env_value BACKUP_DIR /var/backups/netconfig-manager)
{
  echo "保存先: $BACKUP_DIR"
  $SUDO cat "$BACKUP_DIR/last-result.json" 2>/dev/null || echo "（最後の結果の記録はありません）"
  echo
  $SUDO ls -lh "$BACKUP_DIR" 2>/dev/null | tail -20
} | redact > "$ROOT/app/backup.txt"

# ---------------------------------------------------------------- システム
save system/df.txt df -h
save system/df-inodes.txt df -i
have free && save system/memory.txt free -m
have ss && save system/ports.txt $SUDO ss -ltnp
have getenforce && save system/selinux.txt getenforce
have firewall-cmd && save system/firewall.txt $SUDO firewall-cmd --list-all
# Ubuntu: ufw と AppArmor（コンテナが不許可で止まる原因の確認用）
have ufw && save system/ufw.txt $SUDO env LC_ALL=C ufw status verbose
have aa-status && save system/apparmor.txt $SUDO aa-status
if have systemctl; then
  for unit in "container-$PROJECT_NAME" "$PROJECT_NAME" netconfig-manager netconfig-backup.timer netconfig-backup.service podman-restart podman; do
    $SUDO systemctl cat "$unit" >/dev/null 2>&1 || continue
    save "system/systemd-$unit.txt" $SUDO systemctl status --no-pager --full "$unit"
  done
  save system/systemd-failed.txt $SUDO systemctl --failed --no-pager
fi
if have journalctl; then
  JLINES=$([ "$FULL" -eq 1 ] && echo 100000 || echo "$LINES")
  # このアプリに関係するユニットのログ
  save system/journal-units.txt $SUDO journalctl --no-pager --since "${DAYS} days ago" -n "$JLINES" \
    -u netconfig-backup.service -u netconfig-backup.timer -u "$PROJECT_NAME" -u podman -u podman-restart
  # メモリ不足でプロセスが止められた記録（コンテナが突然落ちる原因になる）
  { echo "\$ journalctl -k | grep -i 'out of memory\\|oom'"; $SUDO journalctl -k --no-pager --since "${DAYS} days ago" 2>/dev/null | grep -iE "out of memory|oom-kill|killed process" | tail -100; } > "$ROOT/system/oom.txt"
  # 優先度が「エラー」以上のもの（全体）
  save system/journal-errors.txt $SUDO journalctl --no-pager --since "${DAYS} days ago" -p err -n "$JLINES"
fi
if have journalctl && have aa-status; then
  # AppArmor に拒否された操作（Ubuntu。SELinux の拒否と同じ使い方）
  { echo "\$ journalctl -k | grep 'apparmor=\"DENIED\"'"; $SUDO journalctl -k --no-pager --since "${DAYS} days ago" 2>/dev/null | grep -i 'apparmor="DENIED"' | tail -200; } > "$ROOT/system/apparmor-denials.txt"
fi
if have ausearch; then
  # SELinux に拒否された操作（ボリュームが読めない・ポートを開けない、などの原因になる）
  { echo "\$ ausearch -m avc -ts recent"; $SUDO timeout "$CMD_TIMEOUT" ausearch -m avc,user_avc -ts today 2>&1 | tail -200; } > "$ROOT/system/selinux-denials.txt"
fi

# ---------------------------------------------------------------- まとめる
[ -s "$ERRORS" ] || echo "（集められなかったものはありません）" > "$ERRORS"
{
  echo
  echo "---- 集められなかったもの・気づいた点"
  cat "$ERRORS"
  echo
  echo "---- 入っているファイル"
  (cd "$ROOT" && find . -type f -printf '%8s バイト  %P\n' | sort -k3)
} >> "$ROOT/summary.txt"

$SUDO mkdir -p "$OUT_DIR" 2>/dev/null
if ! $SUDO test -w "$OUT_DIR"; then
  OUT_DIR="${TMPDIR:-/tmp}"
  log "保存先に書き込めないため、$OUT_DIR に保存します"
fi
OUT="$OUT_DIR/$NAME.tar.gz"
RAW_KB=$(du -sk "$ROOT" | cut -f1)
# テキストなので gzip でよく縮む（最高の圧縮率を使う）
if ! tar -C "$WORK" -cf - "$NAME" | gzip -9 | $SUDO tee "$OUT" >/dev/null; then
  echo "❌ ファイルを作れませんでした: $OUT"
  exit 1
fi
$SUDO chmod 600 "$OUT"
[ -n "$SUDO" ] && $SUDO chown "$(id -u):$(id -g)" "$OUT" 2>/dev/null   # 実行した人が持ち出せるように
SIZE_KB=$($SUDO du -k "$OUT" | cut -f1)

# 古いものを消す（保存先にたまり続けないように）
if [ "$KEEP" -gt 0 ]; then
  $SUDO find "$OUT_DIR" -maxdepth 1 -name 'netconfig-logs-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn | tail -n +"$((KEEP + 1))" | cut -d' ' -f2- | while read -r old; do $SUDO rm -f "$old"; done
fi

fmt_kb() { awk -v k="$1" 'BEGIN { if (k >= 1024) printf "%.1f MB", k / 1024; else printf "%d KB", k }'; }
echo
echo "✅ ログを集めました"
echo "   ファイル : $OUT"
echo "   大きさ   : $(fmt_kb "$SIZE_KB")（圧縮前 $(fmt_kb "$RAW_KB")）"
if grep -qv "^（集められなかったものはありません）" "$ERRORS"; then
  echo "   集められなかったもの:"
  sed 's/^/     - /' "$ERRORS"
fi
if [ "$SIZE_KB" -gt $((WARN_MB * 1024)) ]; then
  echo "   ※ ${WARN_MB} MB を超えています。--days や --lines を小さくすると減らせます"
fi
echo
echo "   中身を見る   : tar -xzf $OUT -C /tmp && less /tmp/$NAME/summary.txt"
echo "   まず見る場所 : summary.txt（概要と集められなかったもの）→ containers/*.state.txt（止まった理由）→ containers/*.log"
echo "   ※ 機器名・IP アドレス・ユーザー名が含まれます。秘密の値は伏せていますが、外部へ渡す前に中身を確かめてください"
