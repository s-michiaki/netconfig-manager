#!/bin/bash
# =============================================================================
# 導入・運用スクリプトの共通部品: コンテナのビルドと作り直し（podman-compose build / up -d --force-recreate）
#
# setup.sh・import_cert.sh・restore.sh が source して使う（単独では実行しない）。os.sh・proxy.sh と同じ置き場所に置く。
# 3 つのスクリプトで、次の扱いをそろえるためのもの（以前は setup.sh にだけあった）:
#   - ビルドにはプロキシの環境変数を引き継ぐ（ncm_sudo_out。sudo は環境変数を落とすため。proxy.sh を読んでいれば使う）
#   - 追加で信頼する CA を、各ビルドコンテキストの build-ca/ に写す（ncm_proxy_stage_build_ca）
#   - OS_UPGRADE（Dockerfile の OS のパッケージの更新を、日に 1 回はやり直す目印）を渡す。同じ日の 2 回目以降は
#     ビルドのキャッシュが使われ、外へは出ない
#   - 起動（up）にはプロキシの環境変数を渡さない（podman は起動したプロセスのプロキシの環境変数をコンテナにも渡すため。
#     認証情報が podman inspect に残り、内向きの通信までプロキシへ向かう）。アプリは .env の OUTBOUND_PROXY だけを使う
#   - podman-compose の出力（podman run の -e キー=値 など）を伏せ字のフィルタ（ncm_redact_output）に通す
# 終了コードは podman-compose のもの（呼び出し側で set -o pipefail にしておくこと）。失敗したときの案内は
# ncm_compose_fail_hint で出す（どこで止まったか・ログの見方・再実行の方法）
# =============================================================================

NCM_COMPOSE_PROXY_VARS=(http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY)

# 伏せ字のフィルタ（proxy.sh が無ければそのまま。標準入力 → 標準出力）
_ncm_compose_redact() { if declare -F ncm_redact_output >/dev/null; then ncm_redact_output; else cat; fi; }

# root の権限で実行する。sudo が無く、すでに root なら、そのまま実行する（restore.sh を root で実行した場合など）
_ncm_compose_sudo() {
  if ! command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}
# 外へ出るコマンド（ビルド）: proxy.sh の ncm_sudo_out があれば使い、プロキシの環境変数を名前で引き継ぐ
_ncm_compose_sudo_out() {
  if declare -F ncm_sudo_out >/dev/null && command -v sudo >/dev/null 2>&1; then ncm_sudo_out "$@"; else _ncm_compose_sudo "$@"; fi
}

# プロキシの設定を読み込んでいる、または環境変数にプロキシがあるか（up のときに外すかどうか。値には触れない）
_ncm_compose_has_proxy() {
  local -; set +x
  local v
  if declare -F ncm_proxy_is_set >/dev/null && ncm_proxy_is_set; then return 0; fi
  for v in "${NCM_COMPOSE_PROXY_VARS[@]}"; do [ -z "${!v:-}" ] || return 0; done
  return 1
}

# ビルド（引数: 設置場所 compose ファイル）
ncm_compose_build() {
  local dir="$1" file="$2"
  # 追加で信頼する CA を、ビルドの中の apt-get・pip・npm・apk に渡す（各ビルドコンテキストの build-ca/。無ければ消す）
  if declare -F ncm_proxy_stage_build_ca >/dev/null; then ncm_proxy_stage_build_ca "$dir" || return 1; fi
  # OS_UPGRADE: Dockerfile の OS のパッケージの更新（apt-get upgrade / apk upgrade）を、キャッシュがあっても日に 1 回はやり直す
  # ビルドにはプロキシの環境変数を引き継ぐ（podman build は既定で RUN に渡すが、イメージには保存しない。README「確かめ方」）
  ( cd "$dir" && _ncm_compose_sudo_out env OS_UPGRADE="$(date +%Y%m%d)" podman-compose -f "$file" build 2>&1 ) | _ncm_compose_redact
}

# コンテナの作り直し（引数: 設置場所 compose ファイル）。ボリューム（DB・コンフィグ履歴）は保持される
#   podman-compose は compose ファイルが変わらない限り既存コンテナを作り直さないため、必ず --force-recreate を付ける
ncm_compose_up() {
  local dir="$1" file="$2" up_env=() v
  if _ncm_compose_has_proxy; then
    for v in "${NCM_COMPOSE_PROXY_VARS[@]}"; do up_env+=(-u "$v"); done
  fi
  # podman-compose 1.0.6 は、実行する podman run の引数（-e SECRET_KEY=… -e OUTBOUND_PROXY=… など）を画面に出すので、伏せ字のフィルタに通す
  ( cd "$dir" && _ncm_compose_sudo env "${up_env[@]}" OS_UPGRADE="$(date +%Y%m%d)" podman-compose -f "$file" up -d --force-recreate 2>&1 ) \
    | _ncm_compose_redact
}

# ビルド・作り直しが失敗したときの案内（引数: 段階の名前 設置場所 compose ファイル 再実行のコマンド [いまの状態の説明]）
#   コマンドは実行せず、表示するだけ（失敗した直後に、さらにコンテナを操作しない）
ncm_compose_fail_hint() {
  local step="$1" dir="$2" file="$3" rerun="$4" state="${5:-}"
  echo ""
  echo "❌ 「${step}」で止まりました"
  [ -z "$state" ] || echo "   いまの状態: $state"
  echo "   確かめ方:"
  echo "     コンテナの状態   : sudo podman ps -a"
  echo "     ログ（末尾）     : cd $dir && sudo podman-compose -f $file logs --tail 50 backend   （frontend・worker・beat・db も同じ）"
  echo "     まとめて集める   : bash $dir/scripts/collect_logs.sh"
  echo "   原因を直したら、もう一度実行してください: $rerun"
  echo "   （手で作り直す場合: cd $dir && sudo podman-compose -f $file up -d --force-recreate。DB・コンフィグ履歴のボリュームは消えません）"
}
