# ルート CA 証明書のダウンロード（scripts/import_cert.sh で ca.crt を配置した場合のみ。無ければ 404）
# 利用者の PC に読み込ませて「信頼されたルート証明機関」に登録するために使う。
# 信頼する前に取得できるよう、HTTP でも配信する（公開鍵のみで秘密情報は含まない）
location = /ca.crt {
    alias /etc/nginx/certs/ca.crt;
    default_type application/x-x509-ca-cert;
    add_header Content-Disposition 'attachment; filename="netconfig-root-ca.crt"' always;
    add_header X-Content-Type-Options nosniff always;
    expires -1;
}
