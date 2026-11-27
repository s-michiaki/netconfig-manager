#!/usr/bin/env bash
# =============================================================================
# NetConfig Manager 導入前チェック
#
# サーバーに netconfig-manager をインストールできるか確認する（変更は一切行わない）。
#
# 使い方:
#   bash scripts/check_env.sh [オプション]
#
# オプション:
#   -d HOST[:PORT]     収集・ターミナルの対象機器（複数指定可。PORT 省略時は 22）
#   -j HOST[:PORT]     踏み台サーバ（複数指定可）
#   -f FILE            機器を1行1台で列挙したファイル（"HOST[:PORT]"、# 以降はコメント）
#   -m prod|dev        構成（prod: 80・443番を使用 / dev: 3000・8000番を使用。既定 prod）
#   -r                 hello-world コンテナを実際に起動して確認する（イメージを取得します）
#   -c FILE            追加で信頼する CA（PEM。.env の OUTBOUND_CA_FILE より後。初回の導入で setup.sh が渡す）
#   -h                 このヘルプ
#
# プロキシ: .env の OUTBOUND_PROXY（無ければ環境変数 https_proxy など）を通して、インターネットへの到達を確かめる
#
# 例:
#   bash scripts/check_env.sh
#   bash scripts/check_env.sh -d 10.0.0.1 -d 10.0.0.2:2222 -j 192.168.1.10 -r
#
# 終了コード: 0 = 問題なし（警告のみを含む） / 1 = 対応が必要な項目あり
# =============================================================================
set -u

MODE="prod"
RUN_CONTAINER=0
DEVICES=()
JUMPS=()

# ---------------------------------------------------------------- 表示
if [ -t 1 ]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_NG=$'\e[31m'; C_H=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_NG=""; C_H=""; C_0=""
fi
N_OK=0; N_WARN=0; N_NG=0
ok()   { printf '  %s[ OK ]%s %s\n' "$C_OK" "$C_0" "$*"; N_OK=$((N_OK + 1)); }
warn() { printf '  %s[WARN]%s %s\n' "$C_WARN" "$C_0" "$*"; N_WARN=$((N_WARN + 1)); }
ng()   { printf '  %s[ NG ]%s %s\n' "$C_NG" "$C_0" "$*"; N_NG=$((N_NG + 1)); }
info() { printf '         %s\n' "$*"; }
section() { printf '\n%s== %s ==%s\n' "$C_H" "$*" "$C_0"; }
have() { command -v "$1" >/dev/null 2>&1; }

# OS ごとの違い（判定・パッケージ名・案内文）は scripts/lib/os.sh にまとめてある
NCM_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/os.sh"
[ -f "$NCM_LIB" ] || { echo "scripts/lib/os.sh が見つかりません（リポジトリの scripts/ ごと配置してください）" >&2; exit 2; }
# shellcheck source=lib/os.sh
. "$NCM_LIB"

usage() { sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ---------------------------------------------------------------- 引数
add_from_file() {
  local line
  [ -r "$1" ] || { echo "ファイルを読めません: $1" >&2; exit 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && DEVICES+=("$line")
  done < "$1"
}

while getopts ":d:j:f:m:c:rh" opt; do
  case "$opt" in
    c) export OUTBOUND_CA_FILE="$OPTARG" ;;
    d) DEVICES+=("$OPTARG") ;;
    j) JUMPS+=("$OPTARG") ;;
    f) add_from_file "$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    r) RUN_CONTAINER=1 ;;
    h) usage ;;
    :) echo "オプション -$OPTARG には値が必要です" >&2; exit 2 ;;
    *) echo "不明なオプション: -$OPTARG（-h でヘルプ）" >&2; exit 2 ;;
  esac
done
case "$MODE" in prod|dev) ;; *) echo "-m には prod か dev を指定してください" >&2; exit 2 ;; esac

SUDO=""
if [ "$(id -u)" -ne 0 ] && have sudo && sudo -n true 2>/dev/null; then SUDO="sudo -n"; fi

printf '%sNetConfig Manager 導入前チェック%s  (%s / 構成: %s)\n' "$C_H" "$C_0" "$(date '+%F %T')" "$MODE"

# =============================================================================
section "1. OS・リソース"
# =============================================================================
# NCM_OS_RELEASE_FILE で読むファイルを差し替えられる（テスト用）
if [ -r "$NCM_OS_RELEASE_FILE" ]; then
  case "$NCM_OS_LEVEL" in
    ok)
      ok "OS: ${NCM_OS_PRETTY:-$NCM_OS_ID}"
      [ -z "$NCM_OS_NOTE" ] || info "$NCM_OS_NOTE" ;;
    warn) warn "OS: ${NCM_OS_PRETTY:-$NCM_OS_ID}（${NCM_OS_NOTE}）" ;;
    *) warn "OS: ${NCM_OS_PRETTY:-不明}（対象外の OS です。対応は AlmaLinux / RHEL 10 系と Ubuntu 24.04 LTS。dnf・apt / firewalld・ufw / SELinux・AppArmor の手順は読み替えが必要）" ;;
  esac
else
  warn "$NCM_OS_RELEASE_FILE が無いため OS を判定できません"
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64|arm64) ok "アーキテクチャ: $ARCH" ;;
  *) ng "アーキテクチャ: $ARCH（使用するコンテナイメージが x86_64 / arm64 のみ対応）" ;;
esac

CPUS="$(nproc 2>/dev/null || echo 0)"
if [ "$CPUS" -ge 2 ]; then ok "CPU: ${CPUS} コア"; else warn "CPU: ${CPUS} コア（2コア以上を推奨）"; fi

MEM_MB="$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
if   [ "$MEM_MB" -ge 4000 ]; then ok "メモリ: ${MEM_MB} MB"
elif [ "$MEM_MB" -ge 2000 ]; then warn "メモリ: ${MEM_MB} MB（4GB 以上を推奨。フロントエンドのビルドで不足する場合あり）"
else ng "メモリ: ${MEM_MB} MB（最低 2GB 必要）"; fi

check_disk() { # $1=path
  local avail_gb
  avail_gb="$(df -Pk "$1" 2>/dev/null | awk 'NR==2 {printf "%d", $4/1024/1024}')"
  [ -n "$avail_gb" ] || { warn "空き容量: $1 を確認できません"; return; }
  if   [ "$avail_gb" -ge 10 ]; then ok "空き容量 ($1): ${avail_gb} GB"
  elif [ "$avail_gb" -ge 5 ];  then warn "空き容量 ($1): ${avail_gb} GB（10GB 以上を推奨。コンフィグ履歴の増加に注意）"
  else ng "空き容量 ($1): ${avail_gb} GB（5GB 以上必要）"; fi
}
check_disk /
[ -d /var/lib/containers ] && check_disk /var/lib/containers
[ -d /var/lib/docker ] && check_disk /var/lib/docker

# =============================================================================
section "2. コンテナ実行環境"
# =============================================================================
RUNTIME=""
if have podman; then
  ok "Podman: $(podman --version 2>/dev/null)"
  RUNTIME="podman"
  CG="$(podman info --format '{{.Host.CgroupsVersion}}' 2>/dev/null)"
  if [ "$CG" = "v2" ]; then ok "cgroups: v2"; elif [ -n "$CG" ]; then warn "cgroups: $CG（v2 を推奨）"; fi
fi
if have docker; then
  if docker info >/dev/null 2>&1; then
    ok "Docker: $(docker --version 2>/dev/null)"
    [ -z "$RUNTIME" ] && RUNTIME="docker"
  elif docker --version 2>/dev/null | grep -qi podman; then
    info "docker コマンドは podman-docker（Podman の互換コマンド）です"
  else
    warn "Docker はインストール済みですが利用できません（デーモン停止中、または docker グループに未所属）"
    info "sudo systemctl enable --now docker / sudo usermod -aG docker \$USER"
  fi
fi
[ -n "$RUNTIME" ] || { ng "Podman も Docker も見つかりません"; info "$(ncm_install_hint podman podman-compose)"; }

COMPOSE=""
if have docker && docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"; ok "Compose: $(docker compose version 2>/dev/null | head -1)"
elif have podman-compose; then
  COMPOSE="podman-compose"; ok "Compose: $(podman-compose --version 2>/dev/null | grep -i podman-compose | head -1)"
elif have podman && podman compose version >/dev/null 2>&1; then
  COMPOSE="podman compose"; ok "Compose: podman compose"
elif have docker-compose; then
  warn "docker-compose (v1) のみ検出。v2（docker compose）または podman-compose を推奨"
  COMPOSE="docker-compose"
else
  ng "Compose が見つかりません（podman-compose または docker compose が必要）"
  info "$(ncm_install_hint podman-compose)"
fi

if [ "$RUNTIME" = "podman" ] && [ "$(id -u)" -ne 0 ]; then
  if grep -q "^$(id -un):" /etc/subuid 2>/dev/null; then ok "rootless Podman 用の subuid 設定あり"
  else warn "/etc/subuid に $(id -un) の設定がありません（rootless Podman で必要）"; fi
fi

if [ "$RUN_CONTAINER" -eq 1 ] && [ -n "$RUNTIME" ]; then
  if timeout 180 "$RUNTIME" run --rm docker.io/library/hello-world >/dev/null 2>&1; then
    ok "コンテナの起動テスト（hello-world）に成功"
  else
    ng "コンテナの起動テストに失敗（$RUNTIME run --rm docker.io/library/hello-world を手動で実行して原因を確認）"
  fi
elif [ -n "$RUNTIME" ]; then
  info "コンテナの起動テストは省略（-r で実行）"
fi

# =============================================================================
section "3. Git"
# =============================================================================
if have git; then
  ok "Git: $(git --version)"
else
  ng "Git が見つかりません"; info "$(ncm_install_hint git)"
fi

# =============================================================================
section "4. インターネット接続（ビルド時のダウンロード）"
# =============================================================================
# プロキシ・追加の CA（scripts/lib/proxy.sh。setup.sh と同じ読み方: .env → 環境変数）。値は伏せ字でだけ表示する
PROXY_VARS="$(env | grep -iE '^(https?|no)_proxy=' | sed 's/=.*//' | tr '\n' ' ')"
PX_LIB="$(dirname "$NCM_LIB")/proxy.sh"
PX_SET=0; PX_CACERT=""
if [ -f "$PX_LIB" ]; then
  # shellcheck source=lib/proxy.sh
  . "$PX_LIB"
  if ncm_proxy_load "$(cd "$(dirname "$NCM_LIB")/../.." && pwd)"; then
    ncm_proxy_apply --no-sudo
    if ncm_proxy_is_set; then
      PX_SET=1
      ok "プロキシ: $(ncm_proxy_mask)（${_NCM_PX_SRC}。導入・更新とアプリが使います）"
      info "プロキシを通さない宛先: $no_proxy"
    else
      info "プロキシ: なし（直接接続）"
    fi
    if [ -n "$(ncm_proxy_ca_path)" ]; then
      PX_CACERT="${GIT_SSL_CAINFO:-}"   # OS の信頼ストア＋追加の CA の束（git と同じもの）
      if ncm_proxy_ca_registered; then ok "追加の CA: $(ncm_proxy_ca_path)（OS の信頼ストアにも登録済み）"
      else
        warn "追加の CA: $(ncm_proxy_ca_path) が OS の信頼ストアに未登録（パッケージの導入・podman pull が証明書のエラーになる場合あり）"
        while IFS= read -r line; do info "${line#       }"; done < <(_ncm_px_trust_hint "$(ncm_proxy_ca_path)")
      fi
    fi
    for n in "${_NCM_PX_NOTES[@]}"; do warn "$n"; done
  else
    ng "$(ncm_proxy_error)（値は表示しません）"
  fi
  trap 'ncm_proxy_cleanup' EXIT
fi
[ -n "$PROXY_VARS" ] && info "プロキシ環境変数: $PROXY_VARS（setup.sh がコンテナのビルドにも渡します）"

# 到達の確認。プロキシがあれば、届かない・407（認証）・CONNECT の拒否・証明書の検証の失敗を切り分ける
cert_hint() {
  if [ -n "$(declare -F ncm_proxy_ca_path >/dev/null && ncm_proxy_ca_path)" ]; then
    info "追加の CA（$(ncm_proxy_ca_path)）が、プロキシの証明書の発行元か確かめてください"
  else
    info "HTTPS の中身を検査するプロキシなら、組織の CA（PEM）を certs-outbound/ に置き、.env の OUTBOUND_CA_FILE に名前を書いてください（README「プロキシ環境での導入」）"
  fi
}
check_url() { # $1=name $2=url
  local out rc code conn args=(-s -o /dev/null -m 10 -w '%{http_code} %{http_connect}')
  if ! have curl; then warn "$1: curl が無いため確認できません"; return; fi
  [ -z "$PX_CACERT" ] || args+=(--cacert "$PX_CACERT")
  out="$(curl "${args[@]}" "$2" 2>/dev/null)"; rc=$?
  code="${out%% *}"; conn=""; [[ "$out" == *" "* ]] && conn="${out#* }"
  if [ -n "$code" ] && [ "$code" != "000" ]; then ok "$1 に接続可能 (HTTP $code)"; return; fi
  if [ "$PX_SET" -eq 1 ]; then
    case "$conn" in
      407) ng "$1: プロキシの認証に失敗しました（407）。ユーザー名・パスワードと、記号の URL エンコード（@ → %40 など）を確かめてください"; return ;;
      ""|000|200) ;;
      *) ng "$1: プロキシが $2 への接続を拒否しました（CONNECT に HTTP $conn）。プロキシの許可リストに加えてもらってください"; return ;;
    esac
    case "$rc" in
      5) ng "$1: プロキシのホスト名を解決できません（OUTBOUND_PROXY のホスト名・DNS）"; return ;;
      7) ng "$1: プロキシに接続できません（OUTBOUND_PROXY のホスト・ポート、サーバーからプロキシまでのファイアウォール）"; return ;;
    esac
  fi
  case "$rc" in
    60|77|83) ng "$1: 証明書を検証できません ($2)"; cert_hint; return ;;
    35) ng "$1: TLS の接続に失敗しました ($2)"; [ "$PX_SET" -eq 0 ] || cert_hint; return ;;
    28) ng "$1 に接続できません（応答がありません。$2）"; return ;;
  esac
  ng "$1 に接続できません ($2)"
}
check_url "Docker Hub"   "https://registry-1.docker.io/v2/"
check_url "PyPI"         "https://pypi.org/simple/"
check_url "npm registry" "https://registry.npmjs.org/"
check_url "Debian apt"   "https://deb.debian.org/debian/"
check_url "GitHub"       "https://github.com/"

# =============================================================================
section "5. 使用ポート"
# =============================================================================
if [ "$MODE" = "prod" ]; then PORTS=(80 443); else PORTS=(3000 8000); fi
if have ss; then
  for p in "${PORTS[@]}"; do
    if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then
      ng "ポート $p は使用中です（$($SUDO ss -Hltnp "sport = :$p" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | sed 's/users:(("//')）"
    else
      ok "ポート $p は空いています"
    fi
  done
else
  # ss が無い環境: 自分自身のポートに接続できるか（=待ち受けがあるか）で判定
  for p in "${PORTS[@]}"; do
    if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null; then
      ng "ポート $p は使用中です"
    else
      ok "ポート $p は空いています"
    fi
  done
fi
if [ "$MODE" = "prod" ] && [ "$RUNTIME" = "podman" ] && [ "$(id -u)" -ne 0 ]; then
  START="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
  if [ "$START" -gt 80 ]; then
    warn "rootless Podman は既定で 80・443番を開けません（HTTP_PORT=8080・HTTPS_PORT=8443 等に変更するか、sysctl net.ipv4.ip_unprivileged_port_start=80）"
  fi
fi

# =============================================================================
section "6. SELinux・AppArmor / ファイアウォール / 時刻"
# =============================================================================
if have getenforce; then
  SE="$(getenforce)"
  if [ "$SE" = "Enforcing" ]; then
    warn "SELinux: Enforcing（Podman でソースをマウントする開発構成では volumes に :z が必要。README 参照）"
  else
    ok "SELinux: $SE"
  fi
else
  info "SELinux: getenforce なし（対象外）"
fi

if have aa-status; then
  # AppArmor（Ubuntu）。Podman のコンテナは標準のプロファイルで動くので、状態を示すだけ
  if $SUDO aa-status --enabled >/dev/null 2>&1; then info "AppArmor: 有効（コンテナが不許可で止まったら journalctl -k | grep -i apparmor を確認）"
  else info "AppArmor: 無効、または root 権限が無いため確認できません"; fi
fi

if have firewall-cmd && $SUDO firewall-cmd --state >/dev/null 2>&1; then
  ZONE_LIST="$($SUDO firewall-cmd --list-all 2>/dev/null)"
  for p in "${PORTS[@]}"; do
    if echo "$ZONE_LIST" | grep -qE "(ports:.*\b$p/tcp\b)" || { [ "$p" = 80 ] && echo "$ZONE_LIST" | grep -qE 'services:.*\bhttp\b'; } \
       || { [ "$p" = 443 ] && echo "$ZONE_LIST" | grep -qE 'services:.*\bhttps\b'; }; then
      ok "firewalld: $p/tcp は許可済み"
    else
      warn "firewalld: $p/tcp が未許可（sudo firewall-cmd --permanent --add-port=$p/tcp && sudo firewall-cmd --reload）"
    fi
  done
elif have firewall-cmd; then
  info "firewalld: 停止中、または root 権限が無いため確認できません（sudo で実行すると確認できます）"
fi

if have ufw; then
  UFW_STATE="$($SUDO env LC_ALL=C ufw status 2>/dev/null)"
  if echo "$UFW_STATE" | grep -q '^Status: active'; then
    for p in "${PORTS[@]}"; do
      if echo "$UFW_STATE" | grep -qE "^$p(/tcp)?[[:space:]].*ALLOW"; then
        ok "ufw: $p/tcp は許可済み"
      else
        warn "ufw: $p/tcp が未許可（sudo ufw allow $p/tcp。setup.sh が自動で行います）"
      fi
    done
  else
    info "ufw: 無効、または root 権限が無いため確認できません（有効な場合のみ setup.sh がポートを開けます）"
  fi
fi

if have timedatectl; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
    ok "時刻同期: 有効（$(timedatectl show -p Timezone --value 2>/dev/null)）"
  else
    warn "時刻同期: 未同期（スケジュール実行の時刻がずれる可能性。$(ncm_timesync_hint)）"
  fi
fi

# =============================================================================
section "7. ネットワーク機器・踏み台への到達性"
# =============================================================================
# 22番に TCP 接続し、SSH バナー（SSH-2.0-...）が返るかを見る。ログインはしない
probe_ssh() { # $1=label $2=HOST[:PORT]
  local target="$2" host port banner
  if [[ "$target" =~ ^\[(.+)\]:([0-9]+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  elif [[ "$target" =~ ^([^:]+):([0-9]+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  else host="$target"; port=22; fi

  if ! timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
    ng "$1 $host:$port に TCP 接続できません"
    return 1
  fi
  # SSH サーバーは接続直後に1行のバナーを送ってくるので、その1行だけ読む
  banner="$(timeout 6 bash -c "exec 3<>/dev/tcp/$host/$port; IFS= read -r -t 5 line <&3; printf '%s' \"\$line\"" 2>/dev/null | tr -d '\r')"
  if [[ "$banner" == SSH-* ]]; then ok "$1 $host:$port 到達可（$banner）"
  else warn "$1 $host:$port に接続できたが SSH の応答がありません（${banner:-応答なし}）"; fi
}

if [ ${#DEVICES[@]} -eq 0 ] && [ ${#JUMPS[@]} -eq 0 ]; then
  info "対象が指定されていないため省略（-d 機器 / -j 踏み台 / -f ファイル で指定）"
fi
for j in "${JUMPS[@]}"; do probe_ssh "踏み台" "$j"; done
for d in "${DEVICES[@]}"; do
  if [ ${#JUMPS[@]} -gt 0 ]; then
    # 踏み台を使う構成ではサーバーから直接届かないのが普通なので、失敗しても警告扱い
    if ! timeout 5 bash -c "exec 3<>/dev/tcp/${d%:*}/$([[ "$d" == *:* ]] && echo "${d##*:}" || echo 22)" 2>/dev/null; then
      info "機器 $d: サーバーからは直接届きません（踏み台経由で使う想定なら問題なし）"
      continue
    fi
  fi
  probe_ssh "機器" "$d"
done
if [ ${#JUMPS[@]} -gt 0 ] && [ ${#DEVICES[@]} -gt 0 ]; then
  info "踏み台経由の到達確認は認証が必要なため手動で実施してください:"
  info "  ssh -J <踏み台ユーザー>@${JUMPS[0]} <機器ユーザー>@${DEVICES[0]}"
  info "  （失敗する場合は踏み台 sshd の AllowTcpForwarding を確認。アプリの「到達確認」ボタンでも確認可）"
fi

# =============================================================================
section "結果"
# =============================================================================
printf '  %sOK: %d%s  %sWARN: %d%s  %sNG: %d%s\n' "$C_OK" "$N_OK" "$C_0" "$C_WARN" "$N_WARN" "$C_0" "$C_NG" "$N_NG" "$C_0"
if [ "$N_NG" -gt 0 ]; then
  echo "  → NG の項目を解消してからインストールしてください。"
  exit 1
fi
if [ -n "$COMPOSE" ]; then
  if [ "$MODE" = "prod" ]; then
    echo "  → インストール可能です。次の手順: cp .env.example .env（値を設定）→ $COMPOSE -f docker-compose.prod.yml up -d --build"
  else
    echo "  → インストール可能です。次の手順: cp .env.example .env（値を設定）→ $COMPOSE up -d --build"
  fi
fi
exit 0
