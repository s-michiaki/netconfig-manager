#!/bin/bash
# =============================================================================
# 導入・運用スクリプトの共通部品: 外向きの通信のプロキシと、追加で信頼する CA（HTTPS の中身を検査するプロキシ用）
#
# scripts/ のスクリプトが source して使う（単独では実行しない）。os.sh と同じ置き場所に置く。
#
# 設定の出どころ（アプリと同じ .env の 3 つ。意味は README「外部への通信のプロキシ」）:
#   OUTBOUND_PROXY     http://[ユーザー:パスワード@]ホスト:ポート。.env が空・無ければ、実行時の環境変数
#                      （https_proxy → HTTPS_PROXY → http_proxy → HTTP_PROXY の順に最初の値）
#   OUTBOUND_NO_PROXY  プロキシを通さない宛先（カンマ区切り）。.env が空・無ければ環境変数 no_proxy → NO_PROXY
#   OUTBOUND_CA_FILE   追加で信頼する CA（PEM）の、<設置場所>/certs-outbound/ の中のファイル名。
#                      .env が空・無ければ環境変数 OUTBOUND_CA_FILE（初回の導入用。ホスト上の絶対パスも書ける。
#                      その場合は setup.sh が certs-outbound/outbound-ca.pem へ写して、.env にはその名前を書く）
#
# 認証情報を画面・ログ・プロセスの一覧に出さないための決まり:
#   - プロキシの URL の生の値は、この中の関数だけが扱う（_NCM_PX_URL）。表示は ncm_proxy_mask の形
#     （http://***@proxy.example.test:3128）だけ。エラーの文には値を入れない
#   - 生の値を扱う関数は先頭で `local -; set +x` にする（bash -x で実行しても値が出ない。関数を抜けると元に戻る）
#   - sudo には値ではなく変数の名前だけを渡す（sudo --preserve-env=http_proxy,...）。`sudo env https_proxy=...` と
#     違い、実行中のコマンドライン（ps）に値が出ない。sudo の設定で名前の引き継ぎが許されないときだけ
#     `sudo env` の形に戻し、そのことを警告する
#
# テストでは NCM_OS_CA_BUNDLE に偽の OS の信頼ストアを指定する（tests/test_proxy_scripts.py）
# =============================================================================

# OS の判定（信頼ストアの場所・登録の手順に使う）。呼び出し側が os.sh を読んでいなければ読む
if ! declare -F ncm_detect_os >/dev/null && [ -f "$(dirname "${BASH_SOURCE[0]}")/os.sh" ]; then
  # shellcheck source=os.sh
  . "$(dirname "${BASH_SOURCE[0]}")/os.sh"
fi

# プロキシを通さない宛先のうち、設定に関係なく常に入れるもの（自分自身と compose のサービス名。アプリと同じ一覧）
NCM_PROXY_ALWAYS_DIRECT="localhost,127.0.0.1,::1,db,redis,backend,worker,beat,frontend"
# 追加の CA を写す先のファイル名（certs-outbound/ の中・各ビルドコンテキストの build-ca/ の中）
NCM_PROXY_CA_IMPORT_NAME="outbound-ca.pem"
NCM_PROXY_BUILD_CA_NAME="outbound-ca.crt"   # update-ca-certificates は .crt だけを読む

_NCM_PX_URL=""; _NCM_PX_SRC=""; _NCM_PX_NO=""; _NCM_PX_NO_USER=""; _NCM_PX_CA=""; _NCM_PX_CA_SRC=""
_NCM_PX_GIT_BUNDLE=""; _NCM_PX_MODE="preserve"; _NCM_PX_KEEP=(); _NCM_PX_NOTES=(); _NCM_PX_ERR=""; _NCM_PX_ENVFILE=""
_NCM_PX_CA_PEM=""; _NCM_PX_ENV_BAD=""

# ---------------------------------------------------------------- 小さな部品
# 読めればそのまま、読めなければ sudo で読む（.env・certs-outbound/ は root だけが読めることがある）
_ncm_px_cat() {
  if [ -r "$1" ]; then cat "$1"; else sudo -n cat "$1" 2>/dev/null; fi
}
_ncm_px_exists() {
  [ -f "$1" ] || sudo -n test -f "$1" 2>/dev/null
}
# .env の値の前後の引用符と CR を外す（setup.sh の env_get と同じ）
_ncm_px_unquote() {
  local v="${1%$'\r'}"
  v="${v#[\"\']}"; v="${v%[\"\']}"
  printf '%s' "$v"
}
# カンマ区切り（空白も区切りとみなす。アプリの parse_no_proxy と同じ）を 1 行ずつに（空の要素は除く。* などを展開しない）
_ncm_px_split() {
  local IFS=$', \t\r\n' x arr=()
  read -ra arr <<<"${1//$'\n'/ }" || true
  for x in "${arr[@]}"; do
    [ -z "$x" ] || printf '%s\n' "$x"
  done
}
# PEM の中の証明書の本文（base64）を、1 つの証明書につき 1 行で出す（改行の位置の違いを無くして比べるため）
_ncm_px_bodies() {
  awk '/-----BEGIN CERTIFICATE-----/ { b = ""; on = 1; next }
       /-----END CERTIFICATE-----/   { if (on && b != "") print b; on = 0; next }
       on { gsub(/[ \t\r]/, ""); b = b $0 }'
}
# PEM から CERTIFICATE のブロックだけを取り出す（前後の説明の行・秘密鍵などは捨てる。CR は外す）
_ncm_px_cert_blocks() {
  awk '{ sub(/\r$/, "") }
       /-----BEGIN CERTIFICATE-----/ { on = 1; b = "" }
       on { b = b $0 "\n" }
       on && /-----END CERTIFICATE-----/ { printf "%s", b; on = 0 }'
}
# 証明書のブロックを 1 つずつ openssl x509 で読めるか確かめる（標準入力。0 = 読める / 1 = 読めないものがある / 2 = openssl が無い）
_ncm_px_check_certs() {
  local pem n i
  pem=$(cat)
  command -v openssl >/dev/null 2>&1 || return 2
  n=$(grep -c -- '-----BEGIN CERTIFICATE-----' <<<"$pem" || true)
  for ((i = 1; i <= n; i++)); do
    awk -v n="$i" '/-----BEGIN CERTIFICATE-----/ { c++ } c == n { print } c == n && /-----END CERTIFICATE-----/ { exit }' <<<"$pem" \
      | openssl x509 -noout >/dev/null 2>&1 || return 1
  done
  return 0
}

# ---------------------------------------------------------------- NO_PROXY の項目（アプリの parse_no_proxy と同じ規則）
#   * / IP・CIDR（IPv4・IPv6。[ ] で囲んでもよい）/ ホスト名・.ドメイン（*.example.test は .example.test とみなす。末尾の . は外す）
#   ホスト名は英小文字（大文字は小文字にする）・数字・_ と -（ラベルの先頭・末尾は - にできない、63 文字まで）。
#   ポートつき（host:8080）・<local>・途中の *（10.*・*example.test）・英字以外の文字のドメインは不正
_ncm_px_is_ipv4() {
  local IFS=. o p=()
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  read -ra p <<<"$1"
  for o in "${p[@]}"; do
    [[ "$o" == 0 || "$o" != 0* ]] || return 1   # 先頭の 0（010 など）は IP とみなさない（Python の ipaddress と同じ）
    [ "$((10#$o))" -le 255 ] || return 1
  done
}
_ncm_px_v4int() { local IFS=. a b c d; read -r a b c d <<<"$1"; echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d )); }
_ncm_px_is_ipv6() {
  local a="$1" tail part g n=0 gs=()
  [[ "$a" =~ ^[0-9a-f:.]+$ && "$a" == *:* ]] || return 1
  if [[ "$a" == *.* ]]; then   # 末尾の IPv4（::ffff:192.0.2.1）は 2 つの組とみなす
    tail="${a##*:}"
    _ncm_px_is_ipv4 "$tail" || return 1
    a="${a%"$tail"}0:0"
  fi
  if [[ "$a" == *::* ]]; then
    [[ "$a" != *::*::* && "$a" != *:::* ]] || return 1
    for part in "${a%%::*}" "${a#*::}"; do
      [ -n "$part" ] || continue
      [[ "$part" != :* && "$part" != *: ]] || return 1
      IFS=: read -ra gs <<<"$part"
      for g in "${gs[@]}"; do [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1; n=$((n + 1)); done
    done
    [ "$n" -le 7 ]
  else
    [[ "$a" != *: ]] || return 1
    IFS=: read -ra gs <<<"$a"
    [ "${#gs[@]}" -eq 8 ] || return 1
    for g in "${gs[@]}"; do [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1; done
  fi
}
_ncm_px_is_net() { # $1 = 小文字の IP・CIDR（[ ] は外したもの）
  local addr="${1%%/*}" pfx="" m inv
  if [[ "$1" == */* ]]; then pfx="${1#*/}"; [ -n "$pfx" ] && [[ "$pfx" != */* ]] || return 1; fi
  if [[ "$addr" == *:* ]]; then
    if [[ "$addr" == *%* ]]; then   # スコープ（fe80::1%eth0）。空・2 つ以上の % は不正（Python の ipaddress と同じ）
      [[ "$addr" =~ ^[^%]+%[^%]+$ ]] || return 1
      addr="${addr%%\%*}"
    fi
    _ncm_px_is_ipv6 "$addr" || return 1
    [ -z "$pfx" ] && return 0
    [[ "$pfx" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$((10#$pfx))" -le 128 ]
  else
    _ncm_px_is_ipv4 "$addr" || return 1
    [ -z "$pfx" ] && return 0
    if [[ "$pfx" =~ ^[0-9]{1,2}$ ]]; then [ "$((10#$pfx))" -le 32 ]; return; fi
    _ncm_px_is_ipv4 "$pfx" || return 1   # 10.0.0.0/255.0.0.0（ネットマスク）・/0.255.255.255（ホストマスク）
    m=$(_ncm_px_v4int "$pfx"); inv=$(( ~m & 0xffffffff ))
    [ $(( (inv + 1) & inv )) -eq 0 ] || [ $(( (m + 1) & m )) -eq 0 ]
  fi
}
# NO_PROXY の 1 項目を検査する。正しければ正規化した形（小文字・*. → .・末尾の . なし・[ ] なし）を出して 0、不正なら 1
ncm_proxy_noproxy_item() {
  local LC_ALL=C
  local item="${1,,}" bare name
  local hre='^\.?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$'
  if [ "$item" = "*" ]; then echo "*"; return 0; fi
  bare="$item"
  if [[ "$item" == \[*\] ]]; then bare="${item:1:${#item}-2}"; fi
  if _ncm_px_is_net "$bare"; then echo "$bare"; return 0; fi
  name="$item"
  while [[ "$name" == *. ]]; do name="${name%.}"; done
  if [[ "$name" == \*.* ]]; then name="${name:1}"; fi
  if [[ "$name" =~ $hre ]]; then echo "$name"; return 0; fi
  return 1
}

# OS の信頼ストア（CA の束）の場所。os.sh の判定を使い、判定できなければ、あるほうを使う
_ncm_px_os_bundle() {
  if [ -n "${NCM_OS_CA_BUNDLE:-}" ]; then echo "$NCM_OS_CA_BUNDLE"; return; fi
  if declare -F ncm_os_ca_bundle >/dev/null; then ncm_os_ca_bundle; return; fi
  local f
  for f in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
    [ -r "$f" ] && { echo "$f"; return; }
  done
}

# ---------------------------------------------------------------- 形式の検査・伏せ字
# プロキシの URL を検査する。正しければ 0。正しくなければ理由を _NCM_PX_ERR に入れて 1（理由に値は入れない）
#   対応: http://[ユーザー[:パスワード]@]ホスト:ポート（ホストは名前・IPv4・[IPv6]。末尾の / は許す）
ncm_proxy_check() {
  local -; set +x
  local u="$1" rest auth hostport port stripped
  local cre='^[A-Za-z0-9._~%!*+,;=&()-]+(:[A-Za-z0-9._~%!*+,;=&():-]*)?$'
  local hre='^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?):([0-9]+)$'
  local nre='^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)$'
  _NCM_PX_ERR=""
  case "$u" in
    http://*) ;;
    [Hh][Tt][Tt][Pp][Ss]://*)
      _NCM_PX_ERR="https:// のプロキシには対応していません（http:// で書いてください。宛先との HTTPS の通信は、プロキシまでが http:// でも暗号化されたままです）"; return 1 ;;
    [Ss][Oo][Cc][Kk][Ss]*://*)
      _NCM_PX_ERR="SOCKS のプロキシには対応していません（HTTP のプロキシ http://ホスト:ポート だけに対応しています）"; return 1 ;;
    *://*)
      _NCM_PX_ERR="http:// で始まる形で書いてください（http://[ユーザー:パスワード@]ホスト:ポート）"; return 1 ;;
    *)
      _NCM_PX_ERR="http:// で始まる形で書いてください（http://[ユーザー:パスワード@]ホスト:ポート。ホスト:ポート だけの書き方には対応していません）"; return 1 ;;
  esac
  rest="${u#http://}"
  rest="${rest%/}"
  case "$rest" in
    */*|*\?*|*\#*) _NCM_PX_ERR="ホスト:ポート のあとにパスなどを付けないでください（http://ホスト:ポート の形）"; return 1 ;;
  esac
  if [[ "$rest" == *@* ]]; then
    auth="${rest%@*}"; hostport="${rest##*@}"
    if [[ "$auth" == *@* ]]; then
      _NCM_PX_ERR="ユーザー名・パスワードの @ は %40 と URL エンコードしてください"; return 1
    fi
    if ! [[ "$auth" =~ $cre ]]; then
      _NCM_PX_ERR="ユーザー名・パスワードに、そのままでは使えない文字があります。記号は URL エンコードしてください（例: @ → %40、\$ → %24、# → %23、/ → %2F、空白 → %20）"; return 1
    fi
    stripped="${auth//%[0-9A-Fa-f][0-9A-Fa-f]/}"
    if [[ "$stripped" == *%* ]]; then
      _NCM_PX_ERR="URL エンコードの書き方が正しくありません（% のあとは 16 進数 2 桁。% そのものは %25）"; return 1
    fi
    if [[ "$auth" != *:* ]]; then
      _NCM_PX_ERR="ユーザー名だけでパスワードがありません（パスワードが空なら http://ユーザー:@ホスト:ポート と : を付けて書いてください）"; return 1
    fi
    if [[ "${auth%%:*}" =~ %3[Aa] ]] || [[ "$auth" =~ %[01][0-9A-Fa-f]|%7[Ff] ]]; then
      _NCM_PX_ERR="ユーザー名に : （%3A）や、制御文字（%00〜%1F・%7F）は使えません"; return 1
    fi
  else
    hostport="$rest"
  fi
  if [[ "$hostport" =~ $hre ]]; then
    port="${BASH_REMATCH[3]}"
  elif [[ "$hostport" =~ $nre ]]; then
    _NCM_PX_ERR="ポート番号がありません（http://ホスト:ポート の形で書いてください。例: :3128・:8080）"; return 1
  else
    _NCM_PX_ERR="ホスト名が正しくありません（http://ホスト:ポート の形で書いてください）"; return 1
  fi
  if [ "${#port}" -gt 5 ] || [ "$((10#$port))" -lt 1 ] || [ "$((10#$port))" -gt 65535 ]; then
    _NCM_PX_ERR="ポート番号は 1〜65535 で書いてください"; return 1
  fi
  return 0
}

# 表示用の伏せ字（引数を省くと、読み込んだ設定の値）。認証情報があれば http://***@ホスト:ポート の形にする
ncm_proxy_mask() {
  local -; set +x
  local u="${1-$_NCM_PX_URL}" scheme="" rest
  [ -n "$u" ] || return 0
  case "$u" in *://*) scheme="${u%%://*}://"; rest="${u#*://}" ;; *) rest="$u" ;; esac
  rest="${rest%%/*}"
  if [[ "$rest" == *@* ]]; then printf '%s***@%s\n' "$scheme" "${rest##*@}"
  else printf '%s%s\n' "$scheme" "$rest"; fi
}

# ---------------------------------------------------------------- 設定の読み込み
# 設定を読む（引数: 設置場所 [.env のパス]）。プロキシ・CA の値を決め、形式を検査する。環境はまだ変えない
#   戻り値: 0 = 読めた（プロキシが無くても 0）/ 1 = 形式が正しくない（理由は _NCM_PX_ERR。値は入れない）
ncm_proxy_load() {
  local -; set +x
  local dir="$1" envf="${2:-$1/.env}" raw="" line k v x
  local e_px="" e_no="" e_ca="" e_vuln=""
  _NCM_PX_HAVE_PX=0; _NCM_PX_HAVE_NO=0; _NCM_PX_HAVE_CA=0
  _NCM_PX_URL=""; _NCM_PX_SRC=""; _NCM_PX_URL_FROM_ENV=0
  _NCM_PX_NO=""; _NCM_PX_NO_USER=""; _NCM_PX_NO_FROM_ENV=0
  _NCM_PX_CA=""; _NCM_PX_CA_SRC=""; _NCM_PX_CA_NAME=""; _NCM_PX_CA_FROM_ENV=0; _NCM_PX_CA_IMPORT=""
  _NCM_PX_NOTES=(); _NCM_PX_ERR=""; _NCM_PX_VULN_OLD=0; _NCM_PX_DIR="$dir"; _NCM_PX_ENV_BAD=""; _NCM_PX_CA_PEM=""
  if _ncm_px_exists "$envf"; then
    raw=$(_ncm_px_cat "$envf" | grep -E '^(OUTBOUND_PROXY|OUTBOUND_NO_PROXY|OUTBOUND_CA_FILE|VULN_HTTPS_PROXY)=' || true)
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    k="${line%%=*}"; v=$(_ncm_px_unquote "${line#*=}")
    case "$k" in   # 同じキーが何度もあれば最後の行（setup.sh の env_get と同じ）
      OUTBOUND_PROXY) _NCM_PX_HAVE_PX=1; e_px="$v" ;;
      OUTBOUND_NO_PROXY) _NCM_PX_HAVE_NO=1; e_no="$v" ;;
      OUTBOUND_CA_FILE) _NCM_PX_HAVE_CA=1; e_ca="$v" ;;
      VULN_HTTPS_PROXY) e_vuln="$v" ;;
    esac
  done <<<"$raw"
  [ -z "$e_vuln" ] || _NCM_PX_VULN_OLD=1

  # プロキシ: .env → 環境変数。止めるのは .env の値が不正なときだけ（アプリも起動できないため。コンテナを作り直す前に止める）。
  # 環境変数の値が不正なとき（スキームの無い host:port・https://・socks など。勝手に読み替えない）は、使わずに今までどおり直接つなぐ
  if [ -n "$e_px" ]; then
    if ! ncm_proxy_check "$e_px"; then
      _NCM_PX_ERR="プロキシの設定（.env の OUTBOUND_PROXY）が正しくありません: ${_NCM_PX_ERR}"
      return 1
    fi
    _NCM_PX_URL="$e_px"; _NCM_PX_SRC=".env の OUTBOUND_PROXY"
  else
    for k in https_proxy HTTPS_PROXY http_proxy HTTP_PROXY; do
      [ -n "${!k:-}" ] || continue
      if ncm_proxy_check "${!k}"; then
        _NCM_PX_URL="${!k}"; _NCM_PX_SRC="環境変数 $k"; _NCM_PX_URL_FROM_ENV=1
      else
        _NCM_PX_ENV_BAD="$k"
        _NCM_PX_NOTES+=("環境変数 $k のプロキシは形式が違うため使いません（${_NCM_PX_ERR}）。今までどおり直接つなぎます。使うには .env に OUTBOUND_PROXY=http://… を書いてください")
      fi
      break
    done
    if [ "$_NCM_PX_URL_FROM_ENV" -eq 1 ] && [ "$_NCM_PX_HAVE_PX" -eq 1 ]; then
      _NCM_PX_NOTES+=(".env の OUTBOUND_PROXY が空のため、今回の導入・更新は環境変数のプロキシを使います。アプリ（通知・メール・脆弱性の取得）は直接つなぎます。アプリにも使うときは .env の OUTBOUND_PROXY= に書いてください")
    fi
  fi

  # プロキシを通さない宛先: .env（不正な項目があれば止める）→ 環境変数（プロキシを使うときだけ。アプリが受け付けない項目は
  # 警告して除き、正規化して保存する）。常に入れるもの（自分自身・サービス名）は保存しない
  local always=() user=() all=() bad=() norm
  mapfile -t always < <(_ncm_px_split "$NCM_PROXY_ALWAYS_DIRECT")
  if [ -n "$e_no" ]; then
    v="$e_no"
  elif [ -n "$_NCM_PX_URL" ]; then
    v="${no_proxy:-${NO_PROXY:-}}"
    [ -z "$v" ] || _NCM_PX_NO_FROM_ENV=1
  else
    v=""
  fi
  while IFS= read -r x; do
    [ -n "$x" ] || continue
    if ! norm=$(ncm_proxy_noproxy_item "$x"); then bad+=("${x:0:60}"); continue; fi
    [[ " ${always[*]} ${user[*]} " == *" $norm "* ]] || user+=("$norm")
  done < <(_ncm_px_split "$v")
  if [ "${#bad[@]}" -gt 0 ]; then
    if [ -n "$e_no" ]; then
      _NCM_PX_ERR=".env の OUTBOUND_NO_PROXY に正しくない項目があります: ${bad[*]:0:5}（ホスト名・.ドメイン・IP・CIDR・* をカンマ区切りで。ポートつき・<local>・途中の * は書けません）"
      return 1
    fi
    _NCM_PX_NOTES+=("環境変数 no_proxy の次の項目は、アプリが受け付けない形式のため除きました（ポートつき・<local>・途中の * など）: ${bad[*]:0:10}")
  fi
  all=("${always[@]}" "${user[@]}")
  # 各コマンドに渡す一覧では、.example.test に example.test も足す（道具によって .example.test がドメインそのものを含まないため）
  for x in "${user[@]}"; do
    [[ "$x" == .* ]] || continue
    [[ " ${all[*]} " == *" ${x#.} "* ]] || all+=("${x#.}")
  done
  _NCM_PX_NO=$(IFS=','; echo "${all[*]}")
  _NCM_PX_NO_USER=$(IFS=','; echo "${user[*]}")
  [ -n "$_NCM_PX_NO_USER" ] || _NCM_PX_NO_FROM_ENV=0

  # 追加の CA: .env（certs-outbound/ の中の名前）→ 環境変数 OUTBOUND_CA_FILE（名前、またはホスト上の絶対パス）
  local name="" src=""
  if [ -n "$e_ca" ]; then name="$e_ca"; src=".env の OUTBOUND_CA_FILE"
  elif [ -n "${OUTBOUND_CA_FILE:-}" ]; then name="$OUTBOUND_CA_FILE"; src="環境変数 OUTBOUND_CA_FILE"; _NCM_PX_CA_FROM_ENV=1
  fi
  case "$name" in
    "") ;;
    /etc/netconfig/outbound/*)  # コンテナの中のパス（アプリの上級者向けの書き方）→ ホストの certs-outbound/ に読み替える
      _NCM_PX_CA="$dir/certs-outbound/${name#/etc/netconfig/outbound/}"; _NCM_PX_CA_NAME="$name" ;;
    /*)
      if [ "$_NCM_PX_CA_FROM_ENV" -eq 1 ]; then
        # 初回の導入などで、ホスト上のファイルを渡された: setup.sh が certs-outbound/ へ写す（ncm_proxy_import_ca）
        _NCM_PX_CA="$name"; _NCM_PX_CA_IMPORT="$name"; _NCM_PX_CA_NAME="$NCM_PROXY_CA_IMPORT_NAME"
      else
        _NCM_PX_NOTES+=("${src} がコンテナの中のパス（${name}）のため、導入・更新（setup.sh）では追加の CA を使いません（certs-outbound/ の中のファイル名を書くと、ビルドにも使います）")
        name=""
      fi ;;
    */*)
      _NCM_PX_NOTES+=("${src} には certs-outbound/ の中のファイル名だけを書いてください（/ を含む値は、導入・更新では使いません）")
      name="" ;;
    *) _NCM_PX_CA="$dir/certs-outbound/$name"; _NCM_PX_CA_NAME="$name" ;;
  esac
  _NCM_PX_CA_SRC="$src"
  if [ -n "$_NCM_PX_CA" ]; then
    local pem=""
    if ! _ncm_px_exists "$_NCM_PX_CA"; then
      _NCM_PX_ERR="追加で信頼する CA（${src}）のファイルがありません: ${_NCM_PX_CA}"
      [ -n "$_NCM_PX_CA_IMPORT" ] || _NCM_PX_ERR="${_NCM_PX_ERR}（${dir}/certs-outbound/ に置いてください）"
      _NCM_PX_CA=""; return 1
    fi
    pem=$(_ncm_px_cat "$_NCM_PX_CA" || true)
    if [[ "$pem" == *"PRIVATE KEY-----"* ]]; then
      _NCM_PX_ERR="追加で信頼する CA（${src}: ${_NCM_PX_CA}）のファイルに秘密鍵が入っています。証明書だけのファイルにしてください（秘密鍵をビルドやアプリに渡さないため）"
      _NCM_PX_CA=""; return 1
    fi
    # 使うのは CERTIFICATE のブロックだけ（ビルド用の写し・git 用の束にも、これだけを書く）
    _NCM_PX_CA_PEM=$(printf '%s\n' "$pem" | _ncm_px_cert_blocks)
    if [ -z "$(printf '%s\n' "$_NCM_PX_CA_PEM" | _ncm_px_bodies)" ]; then
      _NCM_PX_ERR="追加で信頼する CA（${src}: ${_NCM_PX_CA}）が PEM 形式の証明書ではありません（-----BEGIN CERTIFICATE----- で始まるテキスト。DER なら openssl x509 -inform der -in 元のファイル -out ${NCM_PROXY_CA_IMPORT_NAME} で変換）"
      _NCM_PX_CA=""; _NCM_PX_CA_PEM=""; return 1
    fi
    local crc=0
    printf '%s\n' "$_NCM_PX_CA_PEM" | _ncm_px_check_certs || crc=$?
    if [ "$crc" -eq 1 ]; then
      _NCM_PX_ERR="追加で信頼する CA（${src}: ${_NCM_PX_CA}）に、証明書として読めないものがあります（openssl x509 -in <ファイル> -noout -text で確かめてください）"
      _NCM_PX_CA=""; _NCM_PX_CA_PEM=""; return 1
    elif [ "$crc" -eq 2 ]; then
      _NCM_PX_NOTES+=("openssl が無いため、追加の CA が証明書として読めるかの確認を省きました（形式と秘密鍵が無いことだけを確かめています）")
    fi
  elif [ -z "$name" ] && [ -d "$dir/certs-outbound" ]; then
    # 置いただけで設定していない CA に気づけるように
    for x in "$dir"/certs-outbound/*.pem "$dir"/certs-outbound/*.crt; do
      [ -e "$x" ] || continue
      _NCM_PX_NOTES+=("certs-outbound/ に $(basename "$x") がありますが、OUTBOUND_CA_FILE が空のため使いません（使うときは .env に OUTBOUND_CA_FILE=$(basename "$x")）")
      break
    done
  fi
  return 0
}

# ncm_proxy_load が 1 を返したときの理由（値は含まない）
ncm_proxy_error() { echo "$_NCM_PX_ERR"; }
# 読み込んだ設定があるか（判定でも値に触れるので、bash -x の表示を止める）
ncm_proxy_is_set() { local -; set +x; [ -n "$_NCM_PX_URL" ]; }
ncm_proxy_ca_path() { [ -n "$_NCM_PX_CA" ] && echo "$_NCM_PX_CA"; }
ncm_proxy_active() { local -; set +x; [ -n "$_NCM_PX_URL" ] || [ -n "$_NCM_PX_CA" ]; }

# ---------------------------------------------------------------- 環境への反映
# 読み込んだ設定を、このシェルから起動するコマンドに渡す（プロキシの環境変数・git 用の CA の束）
#   --no-sudo: sudo の引き継ぎの確かめを省く（check_env.sh のように sudo を使わない呼び出し側）
#   プロキシも CA も無ければ何もしない（今までと同じ）
ncm_proxy_apply() {
  local -; set +x
  local nosudo=0 os_bundle csv v
  [ "${1:-}" = "--no-sudo" ] && nosudo=1
  ncm_proxy_cleanup
  _NCM_PX_KEEP=(); _NCM_PX_MODE="preserve"
  if [ -n "$_NCM_PX_URL" ]; then
    export http_proxy="$_NCM_PX_URL" https_proxy="$_NCM_PX_URL" HTTP_PROXY="$_NCM_PX_URL" HTTPS_PROXY="$_NCM_PX_URL"
    export no_proxy="$_NCM_PX_NO" NO_PROXY="$_NCM_PX_NO"
    _NCM_PX_KEEP+=(http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY)
  fi
  if [ -n "$_NCM_PX_CA" ]; then
    # git 用: OS の信頼ストア＋追加の CA を束ねた一時ファイル（OS の設定は変えない。終了時に ncm_proxy_cleanup が消す）。
    # sudo -u <リポジトリの所有者> の git からも読めるように 644（CA の証明書は秘密ではない）
    _NCM_PX_GIT_BUNDLE=$(mktemp)
    chmod 644 "$_NCM_PX_GIT_BUNDLE"
    os_bundle=$(_ncm_px_os_bundle)
    if [ -n "$os_bundle" ] && [ -r "$os_bundle" ]; then
      cat "$os_bundle" > "$_NCM_PX_GIT_BUNDLE"
    else
      _NCM_PX_NOTES+=("OS の信頼ストア（CA の束）が見つからないため、git には追加の CA だけを渡します")
    fi
    printf '\n%s\n' "$_NCM_PX_CA_PEM" >> "$_NCM_PX_GIT_BUNDLE"
    export GIT_SSL_CAINFO="$_NCM_PX_GIT_BUNDLE"
    _NCM_PX_KEEP+=(GIT_SSL_CAINFO)
  fi
  if [ "${#_NCM_PX_KEEP[@]}" -gt 0 ] && [ "$nosudo" -eq 0 ]; then
    csv=$(IFS=','; echo "${_NCM_PX_KEEP[*]}")
    if ! sudo -n --preserve-env="$csv" true >/dev/null 2>&1; then
      # 名前で引き継げない（sudo の設定・timestamp_timeout=0 など）: 値を自分だけが読める一時ファイルに書き、root の bash に読ませる。
      # sudo のログとコマンドラインには、ファイルのパスしか出ない（終了時に ncm_proxy_cleanup が消す）
      _NCM_PX_MODE="file"
      _NCM_PX_ENVFILE=$(umask 077; mktemp)
      for v in "${_NCM_PX_KEEP[@]}"; do printf 'export %s=%q\n' "$v" "${!v}"; done > "$_NCM_PX_ENVFILE"
      echo "[INFO] sudo で環境変数を名前で引き継げないため、プロキシの設定は一時ファイル（root だけが読めるもの）で sudo に渡します"
    fi
  fi
  return 0
}

# 外へ出るコマンドを sudo で実行する（sudo は環境変数を落とすので、プロキシ・CA の変数を名前で引き継ぐ）
#   使い方は sudo と同じ（ncm_sudo_out -u user git ... / ncm_sudo_out env A=1 cmd ...）。設定が無ければ sudo "$@" と同じ
ncm_sudo_out() {
  local -; set +x
  if [ "${#_NCM_PX_KEEP[@]}" -eq 0 ]; then sudo "$@"; return; fi
  if [ "$_NCM_PX_MODE" = "preserve" ]; then
    sudo --preserve-env="$(IFS=','; echo "${_NCM_PX_KEEP[*]}")" "$@"; return
  fi
  # 名前で引き継げない sudo の設定: root の bash が一時ファイル（export 変数=値）を読んでから実行する。
  # sudo の引数（-u ユーザー など）があれば、root の sudo（root には名前の引き継ぎが許される）で切り替える
  local opts=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -u|-g|-C|-D|-h|-p|-r|-t|-U) opts+=("$1" "${2:-}"); shift 2 ;;
      --) shift; break ;;
      -*) opts+=("$1"); shift ;;
      *) break ;;
    esac
  done
  if [ "${#opts[@]}" -gt 0 ]; then
    # shellcheck disable=SC2016  # $1 などは root の bash の中で展開する
    sudo bash -c '. "$1"; shift; exec sudo --preserve-env="$1" "${@:2}"' _ "$_NCM_PX_ENVFILE" "$(IFS=','; echo "${_NCM_PX_KEEP[*]}")" "${opts[@]}" "$@"
  else
    # shellcheck disable=SC2016
    sudo bash -c '. "$1"; shift; exec "$@"' _ "$_NCM_PX_ENVFILE" "$@"
  fi
}

# 一時ファイル（git 用の CA の束）を消す。setup.sh は終了時と、自分自身をやり直す前に呼ぶ
ncm_proxy_cleanup() {
  if [ -n "${_NCM_PX_ENVFILE:-}" ]; then rm -f "$_NCM_PX_ENVFILE"; _NCM_PX_ENVFILE=""; fi
  if [ -n "$_NCM_PX_GIT_BUNDLE" ]; then
    rm -f "$_NCM_PX_GIT_BUNDLE"
    [ "${GIT_SSL_CAINFO:-}" != "$_NCM_PX_GIT_BUNDLE" ] || unset GIT_SSL_CAINFO
    _NCM_PX_GIT_BUNDLE=""
  fi
  return 0
}

# ---------------------------------------------------------------- 表示
# 使う設定を知らせる（値は伏せ字）。設定が無ければ何も出さない
ncm_proxy_describe() {
  local -; set +x
  local n
  [ -z "$_NCM_PX_URL" ] || echo "[INFO] 外部への接続にプロキシを使います: $(ncm_proxy_mask)（${_NCM_PX_SRC}）"
  [ -z "$_NCM_PX_CA" ] || echo "[INFO] 追加で信頼する CA: ${_NCM_PX_CA}（${_NCM_PX_CA_SRC}）"
  for n in "${_NCM_PX_NOTES[@]}"; do echo "[WARN] $n"; done
  if [ "$_NCM_PX_VULN_OLD" -eq 1 ]; then
    echo "[WARN] .env の VULN_HTTPS_PROXY は廃止しました（もう使われません）。プロキシは OUTBOUND_PROXY に書いてください"
  fi
  return 0
}

# 初回の導入で .env に書く行（環境変数で渡されたものだけ。空の値は書かない）
ncm_proxy_env_lines() {
  local -; set +x
  if [ -n "$_NCM_PX_URL" ]; then
    echo "OUTBOUND_PROXY=${_NCM_PX_URL}"
    [ -z "$_NCM_PX_NO_USER" ] || echo "OUTBOUND_NO_PROXY=${_NCM_PX_NO_USER}"
  fi
  [ -z "$_NCM_PX_CA_NAME" ] || [ "$_NCM_PX_CA_FROM_ENV" -ne 1 ] || echo "OUTBOUND_CA_FILE=${_NCM_PX_CA_NAME}"
  return 0
}

# 初回の導入で .env に書いたことを知らせる（伏せ字）
ncm_proxy_saved_notice() {
  local -; set +x
  if [ -n "$_NCM_PX_URL" ]; then
    echo "[INFO] .env に保存しました: OUTBOUND_PROXY=$(ncm_proxy_mask)"
    [ -z "$_NCM_PX_NO_USER" ] || echo "[INFO] .env に保存しました: OUTBOUND_NO_PROXY=${_NCM_PX_NO_USER}"
  fi
  [ -z "$_NCM_PX_CA_NAME" ] || [ "$_NCM_PX_CA_FROM_ENV" -ne 1 ] || echo "[INFO] .env に保存しました: OUTBOUND_CA_FILE=${_NCM_PX_CA_NAME}"
  return 0
}

# 更新: 環境変数で渡され、.env にキーが無いものだけを足す（引数: .env）。.env の既存の行は書き換えない。
#   キーが空の値で書いてある場合は足さない（ncm_proxy_describe が知らせる）
ncm_proxy_save_missing() {
  local -; set +x
  local envf="$1"
  declare -F ncm_env_append >/dev/null || return 0
  if [ "$_NCM_PX_URL_FROM_ENV" -eq 1 ] && [ "$_NCM_PX_HAVE_PX" -eq 0 ]; then
    ncm_env_append "$envf" "OUTBOUND_PROXY=${_NCM_PX_URL}" || return 1
    echo "[INFO] .env に保存しました: OUTBOUND_PROXY=$(ncm_proxy_mask)（環境変数で渡された値。以後はアプリも使います）"
  fi
  if [ -n "$_NCM_PX_URL" ] && [ "$_NCM_PX_NO_FROM_ENV" -eq 1 ] && [ "$_NCM_PX_HAVE_NO" -eq 0 ]; then
    ncm_env_append "$envf" "OUTBOUND_NO_PROXY=${_NCM_PX_NO_USER}" || return 1
    echo "[INFO] .env に保存しました: OUTBOUND_NO_PROXY=${_NCM_PX_NO_USER}"
  fi
  if [ "$_NCM_PX_CA_FROM_ENV" -eq 1 ] && [ -n "$_NCM_PX_CA_NAME" ] && [ "$_NCM_PX_HAVE_CA" -eq 0 ]; then
    ncm_env_append "$envf" "OUTBOUND_CA_FILE=${_NCM_PX_CA_NAME}" || return 1
    echo "[INFO] .env に保存しました: OUTBOUND_CA_FILE=${_NCM_PX_CA_NAME}"
  fi
  return 0
}

# ---------------------------------------------------------------- 追加の CA
# 環境変数 OUTBOUND_CA_FILE にホスト上の絶対パスを渡されたとき、<設置場所>/certs-outbound/outbound-ca.pem へ写す
#   すでに違う内容のファイルがあれば、上書きせずに 1 を返す
ncm_proxy_import_ca() {
  local src="$_NCM_PX_CA_IMPORT" dst
  [ -n "$src" ] || return 0
  dst="$_NCM_PX_DIR/certs-outbound/$NCM_PROXY_CA_IMPORT_NAME"
  if _ncm_px_exists "$dst"; then
    if [ "$(_ncm_px_cat "$dst" | _ncm_px_cert_blocks | sha256sum)" != "$(printf '%s\n' "$_NCM_PX_CA_PEM" | sha256sum)" ]; then
      echo "❌ $dst がすでにあり、渡された CA（$src）と内容が違います。どちらを使うか決めて、片方にしてから再実行してください"
      return 1
    fi
  else
    sudo install -d -m 755 "$_NCM_PX_DIR/certs-outbound"
    _ncm_px_install_pem "$dst"
    echo "[INFO] 追加で信頼する CA を $dst に置きました（証明書のブロックだけ。アプリも使います）"
  fi
  _NCM_PX_CA="$dst"; _NCM_PX_CA_IMPORT=""
  return 0
}

# 取り出した証明書（_NCM_PX_CA_PEM）を 644 で書く（引数: 書き先）
_ncm_px_install_pem() {
  local tmp
  tmp=$(mktemp)
  printf '%s\n' "$_NCM_PX_CA_PEM" > "$tmp"
  sudo install -m 644 "$tmp" "$1"
  rm -f "$tmp"
}

# 追加の CA の証明書が、すべて OS の信頼ストアに含まれるか（0 = 含まれる）
ncm_proxy_ca_registered() {
  local -; set +x
  local bundle mine theirs b
  [ -n "$_NCM_PX_CA" ] || return 1
  bundle=$(_ncm_px_os_bundle)
  [ -n "$bundle" ] && [ -r "$bundle" ] || return 1
  mine=$(printf '%s\n' "$_NCM_PX_CA_PEM" | _ncm_px_bodies)
  [ -n "$mine" ] || return 1
  theirs=$(_ncm_px_bodies < "$bundle")
  while IFS= read -r b; do
    grep -qxF -- "$b" <<<"$theirs" || return 1
  done <<<"$mine"
  return 0
}

# OS へ CA を登録する手順の案内（os.sh の ncm_ca_trust_hint。無ければ両方の OS の手順）
_ncm_px_trust_hint() {
  local ca="${1:-<CA のファイル>}"
  if declare -F ncm_ca_trust_hint >/dev/null; then ncm_ca_trust_hint "$ca"; return; fi
  echo "       AlmaLinux / RHEL: sudo cp $ca /etc/pki/ca-trust/source/anchors/netconfig-outbound-ca.pem && sudo update-ca-trust"
  echo "       Ubuntu: sudo cp $ca /usr/local/share/ca-certificates/netconfig-outbound-ca.crt && sudo update-ca-certificates"
}

# 追加の CA が OS に登録されていなさそうなら、登録の手順を出す（setup.sh は OS の信頼の設定を変えない）
ncm_proxy_ca_check() {
  [ -n "$_NCM_PX_CA" ] || return 0
  if ncm_proxy_ca_registered; then
    echo "[INFO] 追加の CA は OS の信頼ストアに登録済みです（パッケージの導入・イメージの取得にも使われます）"
    return 0
  fi
  echo "[WARN] 追加の CA（$_NCM_PX_CA）が OS の信頼ストアに登録されていないようです。"
  echo "       git とコンテナのビルドには setup.sh が渡しますが、パッケージの導入（dnf / apt-get）とイメージの取得（podman pull）は"
  echo "       OS の信頼ストアを使うため、証明書のエラーになることがあります。OS に登録するには（setup.sh は自動では行いません）:"
  _ncm_px_trust_hint "$_NCM_PX_CA"
  return 0
}

# 外へ出るコマンドが失敗したときの案内（引数: 何をしていたか）。プロキシも CA も無ければ何も出さない
ncm_proxy_fail_hint() {
  local -; set +x
  if [ -n "$_NCM_PX_ENV_BAD" ] && ! ncm_proxy_active; then
    echo ""
    echo "[WARN] ${1:-外部への接続} に失敗しました。環境変数 ${_NCM_PX_ENV_BAD} のプロキシは形式が違うため使わず、直接つないでいます。"
    echo "       プロキシが必要なら、http://[ユーザー:パスワード@]ホスト:ポート の形で .env の OUTBOUND_PROXY に書くか、環境変数を直して再実行してください（README「プロキシ環境での導入」）"
    return 0
  fi
  ncm_proxy_active || return 0
  echo ""
  echo "[WARN] ${1:-外部への接続} に失敗しました。$([ -n "$_NCM_PX_URL" ] && echo "プロキシ（$(ncm_proxy_mask)）を使っています。")上に出たエラーで切り分けてください:"
  if [ -n "$_NCM_PX_URL" ]; then
    echo "       - 407 / Proxy Authentication Required: プロキシのユーザー名・パスワード（記号は URL エンコード。例 @ → %40）"
    echo "       - 403 / Forbidden（CONNECT の拒否）: プロキシの許可リストに宛先（github.com・レジストリなど）を加えてもらう"
    echo "       - Could not resolve proxy / Connection refused: プロキシのホスト名・ポート"
  fi
  echo "       - 証明書のエラー（certificate verify failed / x509: certificate signed by unknown authority / SSL certificate problem）:"
  if [ -n "$_NCM_PX_CA" ]; then
    echo "         追加の CA（$_NCM_PX_CA）がプロキシの証明書の発行元か確かめ、パッケージの導入・イメージの取得のために OS にも登録する:"
    _ncm_px_trust_hint "$_NCM_PX_CA"
  else
    echo "         HTTPS の中身を検査するプロキシなら、組織の CA（PEM）を ${_NCM_PX_DIR:-<設置場所>}/certs-outbound/ に置いて .env の OUTBOUND_CA_FILE に名前を書き、"
    echo "         OS にも登録する:"
    _ncm_px_trust_hint "${_NCM_PX_DIR:-<設置場所>}/certs-outbound/outbound-ca.pem"
  fi
  echo "       確かめ方: sudo bash ${_NCM_PX_DIR:-<設置場所>}/scripts/check_env.sh（「インターネット接続」の項目）"
  return 0
}

# コンテナのビルドに追加の CA を渡す: 各ビルドコンテキストの build-ca/ に写す（Dockerfile が COPY して信頼する）。
#   CA が無ければ、前回写したものを消す（build-ca/ は README.md だけになり、ビルドは CA なしと同じ結果）
#   引数: 設置場所
ncm_proxy_stage_build_ca() {
  local dir="$1" ctx d dst
  for ctx in backend frontend; do
    d="$dir/$ctx/build-ca"; dst="$d/$NCM_PROXY_BUILD_CA_NAME"
    if [ -n "$_NCM_PX_CA" ]; then
      [ -d "$d" ] || sudo install -d -m 755 "$d"
      # 証明書のブロックだけを書く（説明の行などはイメージに入れない）
      if ! _ncm_px_exists "$dst" || [ "$(_ncm_px_cat "$dst" | sha256sum)" != "$(printf '%s\n' "$_NCM_PX_CA_PEM" | sha256sum)" ]; then
        _ncm_px_install_pem "$dst"
      fi
    elif _ncm_px_exists "$dst"; then
      sudo rm -f "$dst"
      echo "[INFO] 追加の CA を使わない設定のため、ビルド用の写し（$ctx/build-ca/$NCM_PROXY_BUILD_CA_NAME）を消しました"
    fi
  done
  [ -z "$_NCM_PX_CA" ] || echo "[INFO] コンテナのビルドに追加の CA を渡します（backend・frontend の build-ca/）"
  return 0
}

# ---------------------------------------------------------------- コマンドの出力の伏せ字
# podman-compose の出力（実行する podman run の引数 -e キー=値）の秘密を伏せる（標準入力 → 標準出力。1 行ずつすぐに出す）
#   キーの名前が秘密らしいもの（collect_logs.sh の .env の伏せ字と同じ規則＋ PROXY）の値と、scheme://ユーザー:パスワード@ の形を伏せる。
#   podman-compose 1.0.6 は値を引用せずに空白でつないで出すので、値に空白があっても、次の - で始まる引数の手前までを伏せる。
#   ほかの版のリストの形（'-e', 'キー=値'）も伏せる
ncm_redact_output() {
  local keys='[A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|KEY|TOKEN|WEBHOOK|DATABASE_URL|REDIS_URL|BROKER|COMMAND|PROXY)[A-Za-z0-9_]*'
  sed -u -E \
    -e "s#((^|[[:space:]])(-e|--env)[[:space:]]+${keys}=)[^[:space:]]*([[:space:]]+[^-[:space:]][^[:space:]]*)*#\\1***#g" \
    -e "s#((^|[[:space:]])--env=${keys}=)[^[:space:]]*#\\1***#g" \
    -e "s#(['\"](-e|--env)['\"],[[:space:]]*['\"]${keys}=)[^'\"]*#\\1***#g" \
    -e "s#([A-Za-z][A-Za-z0-9+.-]*://)[^/@[:space:]'\"]*@#\\1***@#g"
}
