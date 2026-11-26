#!/bin/bash
# =============================================================================
# 導入・運用スクリプトの共通部品: OS の判定と、OS ごとに違う操作（パッケージ・ファイアウォール）
#
# scripts/ のスクリプトが source して使う（単独では実行しない）。OS の判定はここ 1 か所だけで行う。
#   AlmaLinux / RHEL 10 系 ... 確認済み（dnf・EPEL・firewalld・SELinux）
#   Ubuntu 24.04 LTS      ... スクリプトは対応済みだが、実機での導入は未確認（apt・ufw・AppArmor）
#   Debian 12 以降        ... 未確認。Ubuntu と同じ手順で試す（警告を出す）
#
# テストでは NCM_OS_RELEASE_FILE に偽の os-release を指定し、PATH の先頭に偽のコマンドを置いて確かめる
# =============================================================================

# 読む os-release（テストで差し替える）
# shellcheck disable=SC2034  # 変数は source した側のスクリプトが使う
NCM_OS_RELEASE_FILE="${NCM_OS_RELEASE_FILE:-/etc/os-release}"

# os-release の値を 1 つ取り出す（source しない。ほかの変数を上書きしないため）
_ncm_osr_get() { # $1 = キー
  [ -r "$NCM_OS_RELEASE_FILE" ] || return 0
  sed -n "s/^$1=//p" "$NCM_OS_RELEASE_FILE" | tr -d '\r' | tail -1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

# OS を判定して、次の変数に入れる
#   NCM_OS_ID        os-release の ID（小文字。読めなければ空）
#   NCM_OS_VERSION   VERSION_ID
#   NCM_OS_PRETTY    表示用の名前
#   NCM_OS_FAMILY    rhel（dnf・firewalld）/ ubuntu（apt・ufw。Debian も同じ）/ unknown
#   NCM_OS_LEVEL     ok（対応）/ warn（未確認だが試せる）/ unsupported（対象外）
#   NCM_OS_NOTE      warn・unsupported の理由、実機未確認の注意（無ければ空）
ncm_detect_os() {
  local id like major
  NCM_OS_ID=$(_ncm_osr_get ID | tr '[:upper:]' '[:lower:]')
  NCM_OS_VERSION=$(_ncm_osr_get VERSION_ID)
  NCM_OS_PRETTY=$(_ncm_osr_get PRETTY_NAME)
  NCM_OS_FAMILY="unknown"; NCM_OS_LEVEL="unsupported"; NCM_OS_NOTE=""
  id="$NCM_OS_ID"
  like=" $(_ncm_osr_get ID_LIKE | tr '[:upper:]' '[:lower:]') "
  major="${NCM_OS_VERSION%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || major=""

  case "$id" in
    rhel|rocky|almalinux|centos)
      NCM_OS_FAMILY="rhel"
      if [ "$major" = "10" ]; then NCM_OS_LEVEL="ok"
      else NCM_OS_LEVEL="warn"; NCM_OS_NOTE="README の手順は RHEL 10 前提です。コンテナが動けば利用できます"; fi ;;
    fedora)
      NCM_OS_FAMILY="rhel"; NCM_OS_LEVEL="warn"; NCM_OS_NOTE="Fedora は未確認です（RHEL 系と同じ手順で試します）" ;;
    ubuntu)
      NCM_OS_FAMILY="ubuntu"
      if [ "$NCM_OS_VERSION" = "24.04" ]; then
        NCM_OS_LEVEL="ok"; NCM_OS_NOTE="Ubuntu 24.04 LTS はスクリプトの対応済みですが、実機での導入は未確認です"
      else
        NCM_OS_LEVEL="warn"; NCM_OS_NOTE="Ubuntu は 24.04 LTS を想定しています（この版は未確認。同じ手順で試します）"
      fi ;;
    debian)
      NCM_OS_FAMILY="ubuntu"; NCM_OS_LEVEL="warn"
      if [ -n "$major" ] && [ "$major" -ge 12 ]; then
        NCM_OS_NOTE="Debian は未確認です（Ubuntu と同じ手順で試します）"
      else
        NCM_OS_NOTE="Debian 12 以降を想定しています（この版は未確認。Ubuntu と同じ手順で試します）"
      fi ;;
    *)
      # ID が知らないものでも、ID_LIKE が分かれば近い系統として警告つきで扱う
      if [[ "$like" == *" rhel "* || "$like" == *" fedora "* ]]; then
        NCM_OS_FAMILY="rhel"; NCM_OS_LEVEL="warn"; NCM_OS_NOTE="${NCM_OS_PRETTY:-$id} は未確認です（RHEL 系と同じ手順で試します）"
      elif [[ "$like" == *" ubuntu "* || "$like" == *" debian "* ]]; then
        NCM_OS_FAMILY="ubuntu"; NCM_OS_LEVEL="warn"; NCM_OS_NOTE="${NCM_OS_PRETTY:-$id} は未確認です（Ubuntu と同じ手順で試します）"
      else
        NCM_OS_NOTE="${NCM_OS_PRETTY:-OS を判定できません}（対応しているのは AlmaLinux / RHEL 10 系と Ubuntu 24.04 LTS です）"
      fi ;;
  esac
}
ncm_detect_os

# パッケージ管理のコマンド。判定できない OS は、これまでどおり dnf を前提にする
ncm_pkg_manager() {
  if [ "$NCM_OS_FAMILY" = "ubuntu" ]; then echo "apt-get"; else echo "dnf"; fi
}

# パッケージ管理のコマンドが無ければ、理由を表示して 1 を返す
ncm_require_pkg_manager() {
  local pm
  pm=$(ncm_pkg_manager)
  command -v "$pm" >/dev/null && return 0
  if [ "$pm" = "apt-get" ]; then
    echo "apt-get required (Ubuntu 24.04 LTS で実行してください)"
  else
    echo "dnf required (AlmaLinux / RHEL 10 系、または Ubuntu 24.04 LTS で実行してください)"
  fi
  return 1
}

# 共通の名前（git podman podman-compose curl openssl gpg）を、この OS のパッケージ名に直す
_ncm_pkg_names() {
  local p
  for p in "$@"; do
    case "$p:$NCM_OS_FAMILY" in
      gpg:ubuntu) echo gnupg ;;
      gpg:*) echo gnupg2 ;;
      *) echo "$p" ;;
    esac
  done
}

# Ubuntu で、podman のほかに入れておきたいもの（入っていないものだけを返す。RHEL 系は何も返さない）
#   netavark・aardvark-dns: コンテナ同士が名前（db・redis など）で引けるようにする
#   uidmap: rootless の Podman に必要。podman 本体が推奨するだけで入らないことがあるため
ncm_extra_packages() {
  [ "$NCM_OS_FAMILY" = "ubuntu" ] || return 0
  local p
  for p in netavark aardvark-dns uidmap; do
    dpkg -s "$p" >/dev/null 2>&1 || echo "$p"
  done
}

# 案内文に出す導入コマンド（共通の名前を渡す）
ncm_install_hint() {
  local names
  names=$(_ncm_pkg_names "$@" | tr '\n' ' ')
  if [ "$NCM_OS_FAMILY" = "ubuntu" ]; then echo "sudo apt-get install -y ${names% }"
  else echo "sudo dnf install -y ${names% }"; fi
}

# パッケージを入れる（共通の名前を渡す。ncm_extra_packages の戻り値はそのまま渡してよい）
ncm_install_packages() {
  local names=()
  mapfile -t names < <(_ncm_pkg_names "$@")
  if [ "$NCM_OS_FAMILY" = "ubuntu" ]; then
    sudo apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${names[@]}"
  else
    # podman-compose は EPEL にある
    if [[ " $* " == *" podman-compose "* ]] && ! rpm -q epel-release >/dev/null 2>&1; then
      echo "[INFO] Installing epel-release (podman-compose is provided by EPEL)..."
      sudo dnf install -y epel-release
    fi
    sudo dnf install -y "${names[@]}"
  fi
}

# .env に 1 行を足す（引数: ファイル 行）。共通部品（OS には依存しない）
#   末尾が改行で終わっていなければ、先に改行を 1 つ補う（補わないと最後の行とつながり、暗号化キーなどが壊れる）。
#   空のファイルには補わない。既存の行の中身は変えない
#   ファイルがある前提（無ければ何も作らず 1 を返す。tee -a が 644 の権限で .env を新しく作らないため）
ncm_env_append() {
  sudo test -f "$1" || return 1
  if [ -n "$(sudo tail -c1 "$1")" ]; then echo | sudo tee -a "$1" >/dev/null; fi
  printf '%s\n' "$2" | sudo tee -a "$1" >/dev/null
}

# .env の値を 1 つ読む（引数: キー ファイル）。前後の引用符と CR は取り除く。.env 自体は書き換えない
#   引用符が両方そろっているときは、setup.sh の env_get と同じ出力（setup.sh は lib を読む前にも使うので、同じ処理を
#   setup.sh にも置いている。tests/test_setup_script.py が確かめる）。片方だけの引用符（HTTP_PORT="80 や 80"、"80'）・
#   閉じ引用符のあとに文字が続く値では、env_get は引用符を外して続行し、ncm_env_get は何も出さずに 1 を返す（呼び出し側が止める）
ncm_env_get() {
  local raw
  raw=$(sudo sed -n "s/^$1=//p" "$2" | tail -1 | tr -d '\r')
  case "$raw" in
    \"?*\"|\'?*\'|\"\"|\'\') ;;
    \"*|*\"|\'*|*\') return 1 ;;
  esac
  printf '%s\n' "$raw" | sed -e "s/^[\"']//" -e "s/[\"']\$//"
}

# .env のバックアップ（引数: .env 保存先ディレクトリ 名前に付ける時刻）。root のみ読める場所へ（setup.sh と import_cert.sh が共通で使う）
ncm_backup_env() {
  echo "[INFO] Backing up .env..."
  sudo mkdir -p "$2"
  sudo chmod 700 "$2"
  sudo install -m 600 "$1" "$2/env-$3"
}

# ポートを開ける（引数: ポート番号...）。ファイアウォールが動いていなければ何もしない
#   RHEL 系: firewalld が動いているとき（80・443 は service、それ以外は port で許可）
#   Ubuntu : ufw が有効（ufw status が active）のときだけ ufw allow
ncm_firewall_open() {
  local p list=""
  for p in "$@"; do list="${list:+$list, }${p}/tcp"; done
  if [ "$NCM_OS_FAMILY" = "ubuntu" ]; then
    # LC_ALL=C: 日本語環境でも "Status: active" で判定できるようにする
    # 出力を一度変数に受けてから判定する（パイプの途中で grep が先に終わると、pipefail で失敗扱いになるため）
    local ufw_state=""
    if command -v ufw >/dev/null; then ufw_state=$(sudo env LC_ALL=C ufw status 2>/dev/null || true); fi
    if grep -q '^Status: active' <<<"$ufw_state"; then
      for p in "$@"; do sudo ufw allow "${p}/tcp"; done
      echo "[INFO] Port ${list} opened in ufw"
    else
      echo "[INFO] ufw is not active, skipping"
    fi
    return 0
  fi
  if systemctl is-active --quiet firewalld; then
    for p in "$@"; do
      case "$p" in
        80) sudo firewall-cmd --permanent --add-service=http ;;
        443) sudo firewall-cmd --permanent --add-service=https ;;
        *) sudo firewall-cmd --permanent --add-port="${p}/tcp" ;;
      esac
    done
    sudo firewall-cmd --reload
    echo "[INFO] Port ${list} opened in firewalld"
  else
    echo "[INFO] firewalld is not running, skipping"
  fi
}

# podman-restart.service が unless-stopped のコンテナも起動するようにする（Ubuntu のときだけ呼ぶ）
#   入っているユニットの ExecStart に unless-stopped が含まれていれば何もしない。
#   無ければドロップイン（NCM_SYSTEMD_DROPIN_DIR。テストで差し替える）を置き、daemon-reload する。同じ内容なら書き直さない
_ncm_autostart_dropin() {
  local dir="${NCM_SYSTEMD_DROPIN_DIR:-/etc/systemd/system/podman-restart.service.d}"
  local file="$dir/10-netconfig-manager.conf" unit exec_line podman_bin content
  unit=$(systemctl cat podman-restart.service 2>/dev/null || true)
  exec_line=$(grep -m1 '^ExecStart=.' <<<"$unit" || true)
  # 含まれていれば足りている（ドロップインを置いたあとの再実行でもここに来る）
  [[ "$exec_line" == *unless-stopped* ]] && return 0
  podman_bin="${exec_line#ExecStart=}"
  podman_bin="${podman_bin#[-@:+!]}"
  podman_bin="${podman_bin%% *}"
  podman_bin="${podman_bin:-/usr/bin/podman}"
  content="[Service]
ExecStart=
ExecStart=${podman_bin} start --all --filter restart-policy=always --filter restart-policy=unless-stopped"
  if [ "$(sudo cat "$file" 2>/dev/null || true)" = "$content" ]; then return 0; fi
  sudo mkdir -p "$dir" || return 1
  printf '%s\n' "$content" | sudo tee "$file" >/dev/null || return 1
  sudo systemctl daemon-reload || return 1
  echo "[INFO] podman-restart.service に unless-stopped のコンテナも起動する設定を置きました（$file）"
}

# 再起動後に Podman のコンテナを自動で起動する設定（Podman にはデーモンが無いため）
#   RHEL 系: これまでどおり。失敗したら止める
#   Ubuntu : podman-restart.service がパッケージに含まれない版もあるため、無い・失敗のときは警告して続ける
ncm_enable_autostart() {
  if [ "$NCM_OS_FAMILY" != "ubuntu" ]; then
    sudo systemctl enable --now podman-restart.service
    return 0
  fi
  local units=""
  units=$(systemctl list-unit-files podman-restart.service 2>/dev/null || true)
  if grep -q '^podman-restart.service' <<<"$units"; then
    # Ubuntu 24.04 の podman-restart.service は restart-policy=always のコンテナしか起動しない。
    # docker-compose.prod.yml は unless-stopped なので、ドロップインで起動の対象に足す
    _ncm_autostart_dropin || echo "[WARN] podman-restart.service に unless-stopped のコンテナを起動する設定を足せませんでした。再起動後に一部のコンテナが起動しない可能性があります"
    sudo systemctl enable --now podman-restart.service \
      || echo "[WARN] podman-restart.service を有効にできませんでした。再起動後にコンテナが自動で起動しない可能性があります"
  else
    echo "[WARN] podman-restart.service が見つかりません。"
    echo "       再起動後にコンテナを自動で起動するには、README「Ubuntu 24.04 LTS で使う」の手順（podman-restart.service を自分で用意する）を行ってください"
  fi
}

# 時刻同期が無いときの案内（check_env.sh）
ncm_timesync_hint() {
  if [ "$NCM_OS_FAMILY" = "ubuntu" ]; then echo "sudo systemctl enable --now systemd-timesyncd（または chrony）"
  else echo "sudo systemctl enable --now chronyd"; fi
}
