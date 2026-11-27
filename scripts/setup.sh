#!/bin/bash
# =============================================================================
# NetConfig Manager 自動セットアップ（AlmaLinux / RHEL 10 系・Ubuntu 24.04 LTS・Podman）
#   ※ Ubuntu 24.04 LTS は実機での導入を未確認（OS ごとの違いは scripts/lib/os.sh）
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
      echo "  プロキシが必要な環境: export https_proxy=http://ホスト:ポート してから実行（README「プロキシ環境での導入」）"
      exit 0 ;;
    *) echo "不明なオプションです: $arg（--help で使い方を表示）"; exit 1 ;;
  esac
done

# テスト用の差し替えが設定されていれば知らせる（本番では設定しない。設定すると、バックアップ先の差し替えには
# chmod 700 をかけ、systemd が読まない場所にユニットを書いて enable に失敗する）
for v in NCM_ENV_BACKUP_DIR NCM_SYSTEMD_UNIT_DIR NCM_OS_RELEASE_FILE NCM_SYSTEMD_DROPIN_DIR NCM_OS_CA_BUNDLE; do
  [ -z "${!v:-}" ] || echo "[WARN] テスト用の差し替え（$v）が設定されています"
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
    ncm_sudo_out -u "$owner" git -C "$1" pull --ff-only || return 1
  fi
  PULLED_DIR="$1"
}
# .env の値を 1 つ読む（前後の引用符と CR は取り除く。.env 自体は書き換えない）
# lib/os.sh の ncm_env_get（import_cert.sh が使う）と同じ出力。lib を読む前にも使うので、ここにも置いている
env_get() { # $1 = キー, $2 = .env
  sudo sed -n "s/^$1=//p" "$2" | tail -1 | tr -d '\r' | sed -e "s/^[\"']//" -e "s/[\"']\$//"
}
file_hash() { sha256sum "$1" 2>/dev/null | cut -d" " -f1 || true; }

# =========================
# 外部への通信のプロキシ・追加で信頼する CA（scripts/lib/proxy.sh）
# =========================
# git pull より前に読む（更新の pull もプロキシを通すため）。設定は .env の OUTBOUND_PROXY・OUTBOUND_NO_PROXY・
# OUTBOUND_CA_FILE、.env に無ければ実行時の環境変数（初回: export https_proxy=... してから実行）。
# 外へ出るコマンド（git・dnf / apt-get・podman pull・podman-compose build）は ncm_sudo_out で実行し、プロキシの環境変数を
# 名前で引き継ぐ（sudo は環境変数を落とすため。値はコマンドラインに出さない）。設定が無ければ sudo と同じ
#
# lib が無いあいだ（setup.sh だけをダウンロードした初回の、ソースの取得まで）は、環境変数のプロキシを名前で引き継ぐだけ
# （sudo の設定で名前の引き継ぎが許されないときは、値を自分だけが読める一時ファイルに書いて root の bash に読ませる。
#   sudo のログ・コマンドラインにはファイルのパスしか出ない。この間に使うのは sudo の引数の無い呼び出しだけ）
BOOT_PX_FILE=""
ncm_sudo_out() {
  local -; set +x
  local v keep=""
  for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do [ -z "${!v:-}" ] || keep="${keep:+$keep,}$v"; done
  if [ -z "$keep" ]; then sudo "$@"
  elif sudo -n --preserve-env="$keep" true >/dev/null 2>&1; then sudo --preserve-env="$keep" "$@"
  else
    if [ -z "$BOOT_PX_FILE" ]; then
      BOOT_PX_FILE=$(umask 077; mktemp)
      for v in ${keep//,/ }; do printf 'export %s=%q\n' "$v" "${!v}"; done > "$BOOT_PX_FILE"
    fi
    # shellcheck disable=SC2016  # $1 などは root の bash の中で展開する
    sudo bash -c '. "$1"; shift; exec "$@"' _ "$BOOT_PX_FILE" "$@"
  fi
}
# 一時ファイル（git 用の CA の束・sudo に渡すプロキシの設定）を消す
cleanup_tmp() {
  px cleanup
  if [ -n "$BOOT_PX_FILE" ]; then rm -f "$BOOT_PX_FILE"; BOOT_PX_FILE=""; fi
}
# podman-compose の出力の秘密（podman run の -e キー=値・URL の認証情報）を伏せる（lib が無ければそのまま）
redact_out() { if declare -F ncm_redact_output >/dev/null; then ncm_redact_output; else cat; fi; }
# lib/proxy.sh の関数を呼ぶ（lib が無い・古いときは何もしない）。px load → ncm_proxy_load
px() { local f="ncm_proxy_$1"; shift; if declare -F "$f" >/dev/null; then "$f" "$@"; fi; }
load_proxy_lib() { # $1 = lib/proxy.sh
  [ -n "$1" ] || return 0
  declare -F ncm_proxy_load >/dev/null && return 0
  # shellcheck source=lib/proxy.sh
  if [ -r "$1" ]; then . "$1"; elif sudo test -r "$1" 2>/dev/null; then . <(sudo cat "$1"); fi
  return 0
}
PROXY_DIR=""
setup_proxy() { # $1 = 設置場所。設定を読み、以後のコマンドに渡す（設置場所が変わったときだけ読み直す）。形式が正しくなければ止める
  declare -F ncm_proxy_load >/dev/null || return 0
  [ "$PROXY_DIR" != "$1" ] || return 0
  PROXY_DIR="$1"
  if ! ncm_proxy_load "$1"; then
    echo "❌ $(ncm_proxy_error)"
    echo "   値は表示していません。README「プロキシ環境での導入」の書き方（http://[ユーザー:パスワード@]ホスト:ポート）を確かめてください"
    exit 1
  fi
  ncm_proxy_apply
  ncm_proxy_describe
}
if [ -f "$SCRIPT_DIR/../docker-compose.prod.yml" ]; then PROXY_LIB="$SCRIPT_DIR/lib/proxy.sh"; else PROXY_LIB="$INSTALL_DIR/scripts/lib/proxy.sh"; fi
[ -f "$PROXY_LIB" ] || PROXY_LIB=""
load_proxy_lib "$PROXY_LIB"
# 終了時に一時ファイル（git 用の CA の束・sudo に渡すプロキシの設定）を消す
trap 'cleanup_tmp' EXIT
setup_proxy "$INSTALL_DIR"

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
    px fail_hint "ソースの更新（git pull）"
    exit 1
  }
  # 実行中のスクリプトと、更新後のリポジトリのスクリプトが違えば、新しいほうで最初からやり直す
  # （リポジトリの外に置いた setup.sh から実行した場合も、リポジトリのものに切り替わる）
  if [ -f "$REPO_SCRIPT" ] && [ "$BEFORE" != "$(file_hash "$REPO_SCRIPT")" ]; then
    echo "[INFO] setup.sh が更新されました。新しい内容でやり直します"
    echo ""
    # exec では終了時の処理（trap）が動かないので、一時ファイルを先に消す。プロキシの環境変数はそのまま引き継がれる
    cleanup_tmp
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

# 設置場所を変えたときは、そこの .env のプロキシの設定を読み直す
setup_proxy "$INSTALL_DIR"

ask "IP Address Please Enter [${IPADD}]: " Red_IPADD
if [ -n "${Red_IPADD}" ]; then IPADD="${Red_IPADD}" ; fi
# URL と .env（sed の置き換え）に入れるので、ホスト名・IPv4・IPv6 の文字だけを許す
[[ "$IPADD" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo "IP Address が不正です（英数字と . : - だけ）: $IPADD"; exit 1; }

# 2回目以降は .env の値を既定にする（Enter だけで今のポートを維持）
if [ -f "$INSTALL_DIR/.env" ]; then
  v=$(env_get HTTP_PORT "$INSTALL_DIR/.env"); [ -n "$v" ] && HTTP_PORT="$v"
  v=$(env_get HTTPS_PORT "$INSTALL_DIR/.env"); [ -n "$v" ] && HTTPS_PORT="$v"
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

# テスト用の差し替え（本番では設定しない。tests/test_setup_script.py が、実際の /root・/etc に触れずに通すために使う）
#   NCM_ENV_BACKUP_DIR      .env のバックアップ先（既定 /root/netconfig-manager-backup）
#   NCM_SYSTEMD_UNIT_DIR    定期バックアップの systemd ユニットの置き場（既定 /etc/systemd/system）
ENV_BACKUP_DIR="${NCM_ENV_BACKUP_DIR:-/root/netconfig-manager-backup}"
SYSTEMD_UNIT_DIR="${NCM_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
TS=$(date +%Y%m%d-%H%M%S)

# =========================
# 依存チェック
# =========================
command -v sudo >/dev/null || { echo "sudo required"; exit 1; }

# OS ごとの違い（パッケージ・ファイアウォールなど）は scripts/lib/os.sh にまとめてある。
# setup.sh だけをダウンロードして実行した初回は、まだリポジトリが無く lib も無いので、
# git だけを先に入れてリポジトリを取得してから読み込む（OS の判定は lib の 1 か所だけにしている）
OS_LIB=""
# リポジトリの中の setup.sh（上の階層に docker-compose.prod.yml がある）はすぐ隣の lib を、
# リポジトリの外に置いた setup.sh は $INSTALL_DIR の lib だけを見る（無関係な場所の lib を読まないため）
if [ -f "$SCRIPT_DIR/../docker-compose.prod.yml" ]; then LIB_CAND="$SCRIPT_DIR/lib/os.sh"; else LIB_CAND="$INSTALL_DIR/scripts/lib/os.sh"; fi
if [ -f "$LIB_CAND" ]; then OS_LIB="$LIB_CAND"; fi
if [ -z "$OS_LIB" ]; then
  # 初回（lib もリポジトリも無い）: clone の前に、明らかに対象外の OS なら止める
  # （この時点では lib が読めないので、ID・ID_LIKE を軽く見るだけ。詳しい判定は lib が行う）
  BOOT_REL="${NCM_OS_RELEASE_FILE:-/etc/os-release}"
  BOOT_IDS=$( (sed -n -e 's/^ID=//p' -e 's/^ID_LIKE=//p' "$BOOT_REL" 2>/dev/null || true) | tr -d '"\r' | tr '[:upper:]' '[:lower:]' | tr '\n' ' ')
  case " $BOOT_IDS " in
    *" rhel "*|*" rocky "*|*" almalinux "*|*" centos "*|*" fedora "*|*" ubuntu "*|*" debian "*) ;;
    *) echo "対象外の OS です（${BOOT_IDS:-判定できません}）。対応しているのは AlmaLinux / RHEL 10 系と Ubuntu 24.04 LTS です"; exit 1 ;;
  esac
  echo "[INFO] OS の共通部品（scripts/lib/os.sh）が無いため、先に git を入れてソースを取得します"
  if ! command -v git >/dev/null; then
    if command -v apt-get >/dev/null; then
      ncm_sudo_out apt-get update
      ncm_sudo_out env DEBIAN_FRONTEND=noninteractive apt-get install -y git
    elif command -v dnf >/dev/null; then
      ncm_sudo_out dnf install -y git
    else
      echo "git が見つかりません。git を入れてから再実行してください"; exit 1
    fi
  fi
  if [ -d "$INSTALL_DIR/.git" ]; then
    pull_source "$INSTALL_DIR"
  else
    echo "[INFO] Cloning $REPO_URL ($BRANCH) into $INSTALL_DIR..."
    echo "       （プライベートリポジトリの場合、Password には GitHub の Personal Access Token を入力）"
    sudo mkdir -p "$(dirname "$INSTALL_DIR")"
    ncm_sudo_out git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
  PULLED_DIR="$INSTALL_DIR"  # 取得済み（後の「ソース取得」では繰り返さない）
  # 取得したリポジトリのプロキシの部品を読み、以後は .env の設定・形式の検査・追加の CA も使う
  load_proxy_lib "$INSTALL_DIR/scripts/lib/proxy.sh"
  setup_proxy "$INSTALL_DIR"
  OS_LIB="$INSTALL_DIR/scripts/lib/os.sh"
  [ -r "$OS_LIB" ] || sudo test -r "$OS_LIB" || { echo "$OS_LIB が見つかりません"; exit 1; }
fi
# shellcheck source=lib/os.sh
if [ -r "$OS_LIB" ]; then . "$OS_LIB"; else . <(sudo cat "$OS_LIB"); fi
# コンテナのビルドと作り直し（import_cert.sh・restore.sh と共通。無い＝古いチェックアウトなら、下の compose_build・compose_up が従来の手順で行う）
COMPOSE_LIB="$(dirname "$OS_LIB")/compose.sh"
# shellcheck source=lib/compose.sh
if [ -r "$COMPOSE_LIB" ]; then . "$COMPOSE_LIB"; elif sudo test -r "$COMPOSE_LIB" 2>/dev/null; then . <(sudo cat "$COMPOSE_LIB"); fi

echo "[INFO] OS: ${NCM_OS_PRETTY:-不明}（${NCM_OS_FAMILY}）"
if [ "$NCM_OS_LEVEL" = "unsupported" ]; then echo "対象外の OS です: $NCM_OS_NOTE"; exit 1; fi
[ -z "$NCM_OS_NOTE" ] || echo "[WARN] $NCM_OS_NOTE"
ncm_require_pkg_manager || exit 1
# 追加で信頼する CA が OS に登録されていなさそうなら、登録の手順を表示する（OS の信頼の設定は変えない）
px ca_check

# =========================
# 必要パッケージのインストール（git / podman / podman-compose）
# =========================
echo "[INFO] Checking packages..."
PKGS=()
command -v git            >/dev/null || PKGS+=(git)
command -v podman         >/dev/null || PKGS+=(podman)
command -v podman-compose >/dev/null || PKGS+=(podman-compose)
command -v curl           >/dev/null || PKGS+=(curl)
# Ubuntu は、コンテナ同士が名前で引けるようにするためのもの（netavark など）も確かめる
EXTRA_PKGS=()
mapfile -t EXTRA_PKGS < <(ncm_extra_packages)
PKGS+=("${EXTRA_PKGS[@]}")
if [ ${#PKGS[@]} -gt 0 ]; then
  echo "[INFO] Installing ${PKGS[*]}..."
  ncm_install_packages "${PKGS[@]}" || { px fail_hint "パッケージの導入"; exit 1; }
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
  pull_source "$INSTALL_DIR" || { px fail_hint "ソースの更新（git pull）"; exit 1; }
else
  echo "[INFO] Cloning $REPO_URL ($BRANCH) into $INSTALL_DIR..."
  echo "       （プライベートリポジトリの場合、Password には GitHub の Personal Access Token を入力）"
  sudo mkdir -p "$(dirname "$INSTALL_DIR")"
  ncm_sudo_out git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || { px fail_hint "ソースの取得（git clone）"; exit 1; }
fi
cd "$INSTALL_DIR"
[ -f "$COMPOSE_FILE" ] || { echo "$INSTALL_DIR/$COMPOSE_FILE が見つかりません"; exit 1; }
# 環境変数 OUTBOUND_CA_FILE でホスト上の CA を渡されたときは、certs-outbound/ へ写す（アプリも使う置き場所）
px import_ca || exit 1

# =========================
# 導入前チェック（check_env.sh があれば実行）
# =========================
# 更新時は自分のコンテナがポートを使用中で NG と誤判定されるため、初回のみ実行する
if [ "$FIRST_INSTALL" -eq 0 ]; then
  echo "[INFO] Update mode: skipping pre-install check"
elif [ -f scripts/check_env.sh ]; then
  echo "[INFO] Running pre-install check..."
  CHECK_ARGS=(-m prod)
  CHECK_CA=$(px ca_path || true)
  [ -z "$CHECK_CA" ] || CHECK_ARGS+=(-c "$CHECK_CA")  # 追加の CA（まだ .env が無いので引数で渡す）
  if ! ncm_sudo_out bash scripts/check_env.sh "${CHECK_ARGS[@]}" | sed 's/^/       /'; then
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
# .env のバックアップ（root のみ読める場所へ）。.env を作った直後、または更新で最初に変える前に取る
backup_env() {
  if declare -F ncm_backup_env >/dev/null; then
    ncm_backup_env "$INSTALL_DIR/.env" "$ENV_BACKUP_DIR" "$TS"  # lib/os.sh（import_cert.sh と共通）
  else
    # lib が古い（リポジトリの外に置いた新しい setup.sh を、古いチェックアウトに対して実行した場合）: 従来の手順
    echo "[INFO] Backing up .env..."
    sudo mkdir -p "$ENV_BACKUP_DIR"
    sudo chmod 700 "$ENV_BACKUP_DIR"
    sudo install -m 600 "$INSTALL_DIR/.env" "$ENV_BACKUP_DIR/env-$TS"
  fi
}
# コンテナのビルドと作り直し（scripts/lib/compose.sh。lib が古いときだけ従来の手順をここで行う。実行するコマンドは同じ）
compose_build() {
  if declare -F ncm_compose_build >/dev/null; then ncm_compose_build "$INSTALL_DIR" "$COMPOSE_FILE"; return; fi
  px stage_build_ca "$INSTALL_DIR" || return 1
  ncm_sudo_out env OS_UPGRADE="$(date +%Y%m%d)" podman-compose -f "$COMPOSE_FILE" build 2>&1 | redact_out
}
compose_up() {
  if declare -F ncm_compose_up >/dev/null; then ncm_compose_up "$INSTALL_DIR" "$COMPOSE_FILE"; return; fi
  local up_env=()
  if declare -F ncm_proxy_is_set >/dev/null && ncm_proxy_is_set; then
    up_env=(-u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY)
  fi
  sudo env "${up_env[@]}" OS_UPGRADE="$(date +%Y%m%d)" podman-compose -f "$COMPOSE_FILE" up -d --force-recreate 2>&1 | redact_out
}
compose_fail_hint() { # $1 = 段階 $2 = いまの状態
  if declare -F ncm_compose_fail_hint >/dev/null; then
    ncm_compose_fail_hint "$1" "$INSTALL_DIR" "$COMPOSE_FILE" "bash $INSTALL_DIR/scripts/setup.sh" "$2"
  else
    echo "❌ 「$1」で止まりました。ログ: cd $INSTALL_DIR && sudo podman-compose -f $COMPOSE_FILE logs --tail 50 backend / 再実行: bash $INSTALL_DIR/scripts/setup.sh"
  fi
}
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
  # 環境変数で渡されたプロキシ・追加の CA（空の値は書かない）
  px env_lines >> "$TMP_ENV"
  sudo install -m 600 -o root -g root "$TMP_ENV" "$INSTALL_DIR/.env"
  rm -f "$TMP_ENV"
  backup_env
  px saved_notice
else
  # .env を変える前に、まずバックアップを取る（壊れる前の内容を必ず残すため）
  backup_env
  # HTTP_PORT・HTTPS_PORT だけは入力値を反映する（値が同じなら .env は書き換えない）
  for kv in "HTTP_PORT=${HTTP_PORT}" "HTTPS_PORT=${HTTPS_PORT}"; do
    k="${kv%%=*}"
    if sudo grep -q "^${k}=" .env; then
      [ "$(env_get "$k" .env)" = "${kv#*=}" ] || sudo sed -i "s/^${k}=.*/${kv}/" .env
    else
      ncm_env_append .env "$kv"
    fi
  done
  # 環境変数で渡されたプロキシ・追加の CA で、.env にキーが無いものだけを足す（既存の行は変えない）
  px save_missing .env
fi

# =========================
# ファイアウォールのポート開放（RHEL 系: firewalld / Ubuntu: ufw が有効なときだけ）
# =========================
echo "[INFO] Configuring firewall..."
ncm_firewall_open "$HTTP_PORT" "$HTTPS_PORT"

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
    ncm_env_append "$INSTALL_DIR/.env" "PUBLIC_URL=${AUTO_URL}"
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
  if ! ncm_sudo_out podman pull -q "$img" >/dev/null; then
    echo "[WARN] $img を取り直せませんでした（手元のイメージで続けます）"
    PULL_FAILED+=("$img")
  fi
done
[ ${#PULL_FAILED[@]} -eq 0 ] || px fail_hint "イメージの取得（podman pull）"
# ビルド（追加の CA の build-ca/ への配置・OS_UPGRADE・プロキシの引き継ぎ・出力の伏せ字）は scripts/lib/compose.sh（import_cert.sh・restore.sh と共通）
# 出力は伏せ字のフィルタに通す（終了コードは podman-compose のもの。pipefail）
compose_build || { rc=$?; px fail_hint "コンテナのビルド"; compose_fail_hint "コンテナのビルド" "ビルドの前と同じ（動いているコンテナはそのまま）"; exit "$rc"; }
# 起動には渡さない（podman は既定で、起動したプロセスのプロキシの環境変数をコンテナにも渡すため。認証情報が
# podman inspect に残り、内向きの通信までプロキシへ向かう）。アプリは .env の OUTBOUND_PROXY だけを使う
compose_up || { rc=$?; compose_fail_hint "コンテナの作り直し（up -d --force-recreate）" "イメージは新しくなったが、コンテナの一部が古いまま、または止まっている可能性があります"; exit "$rc"; }
# 取り直し・作り直しで使われなくなった古いイメージ（名前の無いもの）を消す（ディスクの圧迫を防ぐ）
sudo podman image prune -f >/dev/null 2>&1 || true

# =========================
# 再起動後の自動起動（Podman にはデーモンが無いため）
# =========================
echo "[INFO] Enabling auto start on boot..."
ncm_enable_autostart

# =========================
# 定期バックアップ（DB・コンフィグ履歴・.env など。scripts/backup.sh を systemd タイマーで実行）
# =========================
# 実行時刻は .env の BACKUP_ON_CALENDAR（systemd の OnCalendar 形式、既定 毎日 03:15）。off で無効
# .env は root だけが読める（600）ので、sudo で読む（一般ユーザー + sudo で実行したときに、読めずに既定の時刻になっていた）
BACKUP_ON_CALENDAR=$(env_get BACKUP_ON_CALENDAR "$INSTALL_DIR/.env" || true)
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
  # タイマーは root でリポジトリの中の backup.sh（と lib/os.sh）を実行する。root 以外が書き換えられると、その人が root の権限で
  # コマンドを動かせてしまうので、所有者と書き込みの権限を確かめて知らせる（止めない。直し方を表示する）
  WEAK=()
  for f in "$INSTALL_DIR" "$INSTALL_DIR/scripts" "$INSTALL_DIR/scripts/lib" "$INSTALL_DIR/scripts/backup.sh" "$INSTALL_DIR/scripts/lib/os.sh"; do
    st=$(stat -c '%u %a %U' "$f" 2>/dev/null || true)   # 所有者と権限はディレクトリをたどれれば読める（sudo は要らない）
    [ -n "$st" ] || continue
    read -r f_uid f_mode f_user <<<"$st"
    if [ "$f_uid" != "0" ]; then WEAK+=("$f（所有者 $f_user）")
    elif [[ "$f_mode" =~ ^[0-7]+$ ]] && [ $(( 8#$f_mode & 8#022 )) -ne 0 ]; then WEAK+=("$f（権限 $f_mode。グループかほかの人が書き込める）")
    fi
  done
  if [ ${#WEAK[@]} -gt 0 ]; then
    echo "[WARN] 定期バックアップは root で $INSTALL_DIR/scripts/backup.sh を実行しますが、次のものを root 以外が書き換えられます:"
    for f in "${WEAK[@]}"; do echo "       - $f"; done
    echo "       書き換えられる人は root の権限でコマンドを動かせるため、そのアカウントは root と同じように守ってください。"
    echo "       root だけが書き換えられるようにするには（README「バックアップと復元」）: sudo chown -R root:root $INSTALL_DIR && sudo chmod -R go-w $INSTALL_DIR"
  fi
  sudo tee "$SYSTEMD_UNIT_DIR/netconfig-backup.service" >/dev/null <<UNIT
[Unit]
Description=NetConfig Manager backup (DB / config history / .env)
After=podman-restart.service

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_DIR/scripts/backup.sh
UNIT
  sudo tee "$SYSTEMD_UNIT_DIR/netconfig-backup.timer" >/dev/null <<UNIT
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
  if curl --noproxy '*' -fsSkL -m 3 "$HEALTH_URL" 2>/dev/null | grep -q '"ok"'; then READY=1; break; fi
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
SELFCHECK_DONE=0
if [ -z "$BACKEND_CT" ]; then
  echo "[WARN] backend のコンテナが見つからないため、動作確認（自己診断）を省略しました"
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
else
  SELFCHECK_DONE=1
fi

# 証明書を置いているのに HTTPS で応答しないとき（証明書を読み込めないと、frontend は画面に入れなくならないよう HTTP で起動する）は知らせる
if [ "$HTTPS_ENABLED" -eq 1 ] && ! curl --noproxy '*' -fsSk -m 5 "https://localhost:${HTTPS_PORT}/api/health" 2>/dev/null | grep -q '"ok"'; then
  echo "[WARN] certs/ に証明書がありますが、HTTPS（${HTTPS_PORT} 番）で応答がありません。証明書を読み込めず HTTP で動いている可能性があります"
  echo "       確かめ方: cd $INSTALL_DIR && sudo podman-compose -f $COMPOSE_FILE logs --tail 20 frontend（「証明書を読み込めません」の行）"
  echo "       証明書を取り込み直す: bash $INSTALL_DIR/scripts/import_cert.sh"
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
if [ "$SELFCHECK_DONE" -eq 1 ]; then
  echo "✅ 完了"
else
  # 画面の応答は確かめたが、収集などのバックグラウンド処理が動くかは確かめていない
  echo "⚠ 完了（自己診断は未実施: backend のコンテナが見つからなかったため、収集などのバックグラウンド処理が動くかを確かめていません）"
  echo "   確かめ方: sudo podman ps -a で backend が動いているかを見て、画面の「システム状態」を開く。"
  echo "   問題があれば: bash $INSTALL_DIR/scripts/collect_logs.sh"
fi
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
