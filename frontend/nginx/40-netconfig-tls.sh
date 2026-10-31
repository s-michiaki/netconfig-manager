#!/bin/sh
# nginx 起動時に HTTP / HTTPS の設定を選ぶ（nginx 公式イメージの /docker-entrypoint.d から実行される）
#   /etc/nginx/certs に server.crt と server.key がある → HTTPS（HTTP は HTTPS へ転送）
#   無い                                               → HTTP のみ
# 証明書が壊れていて nginx の設定チェックに失敗した場合は、画面に入れなくならないよう HTTP で起動する
set -eu

CERT_DIR=/etc/nginx/certs
SRC=/etc/nginx/netconfig
DEST=/etc/nginx/conf.d/default.conf

use_http() {
    cp "$SRC/http.conf" "$DEST"
}

if [ -s "$CERT_DIR/server.crt" ] && [ -s "$CERT_DIR/server.key" ]; then
    port="${HTTPS_PORT:-443}"
    case "$port" in
        ''|*[!0-9]*) echo "netconfig: HTTPS_PORT が不正です（$port）。443 として扱います" >&2; port=443 ;;
    esac
    if [ "$port" = "443" ]; then suffix=""; else suffix=":$port"; fi
    sed "s|__HTTPS_SUFFIX__|$suffix|g" "$SRC/https.conf" > "$DEST"
    if nginx -t -q 2>/tmp/nginx-test.log; then
        echo "netconfig: HTTPS で起動します（証明書: $CERT_DIR/server.crt、HTTPS ポート: $port）"
    else
        echo "netconfig: 証明書を読み込めないため HTTP で起動します。scripts/import_cert.sh で配置し直してください" >&2
        cat /tmp/nginx-test.log >&2
        use_http
    fi
else
    echo "netconfig: 証明書が無いため HTTP で起動します（HTTPS 化: scripts/import_cert.sh）"
    use_http
fi
