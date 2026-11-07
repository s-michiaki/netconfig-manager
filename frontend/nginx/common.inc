# HTTP / HTTPS 共通の設定（http.conf・https.conf の server から include する）

root /usr/share/nginx/html;
index index.html;
client_max_body_size 1m;
server_tokens off;

add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy same-origin always;

# REST API / WebSocket（SSHターミナル・Ping監視）を backend へ中継
location /api/ {
    proxy_pass http://backend:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    # 前段のプロキシは nginx だけなので、クライアントが送った X-Forwarded-For は引き継がずに上書きする
    # （引き継ぐと監査ログの接続元 IP を偽装できる）
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    # ターミナルの無操作時間で切断されないよう長めに取る
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}

# API ドキュメント（不要なら削除してよい）
location ~ ^/(docs|openapi\.json)$ {
    proxy_pass http://backend:8000;
    proxy_set_header X-Forwarded-For $remote_addr;
}

location /assets/ {
    # location 内で add_header を使うと server の add_header が継承されなくなるため expires のみ
    expires 1y;
}

# SPA: 存在しないパスは index.html を返す
location / {
    try_files $uri $uri/ /index.html;
    expires -1;
}
