# ---- 依存関係 ----
FROM docker.io/library/node:22-alpine AS deps
WORKDIR /app
# 追加で信頼する CA（scripts/setup.sh がビルドの直前に build-ca/outbound-ca.crt へ写す。無ければ README.md だけ）。
# npm ci の間だけ NODE_EXTRA_CA_CERTS で使い、消す（このステージは本番のイメージに入らない）。
# プロキシの URL・認証情報は ARG / ENV に書かない（podman build が RUN にだけ渡し、イメージには残さない）
COPY build-ca/ /tmp/build-ca/
COPY package.json package-lock.json ./
RUN set -e; \
    if ls /tmp/build-ca/*.crt >/dev/null 2>&1; then cat /tmp/build-ca/*.crt > /tmp/build-ca.pem; export NODE_EXTRA_CA_CERTS=/tmp/build-ca.pem; fi; \
    npm ci; \
    rm -rf /tmp/build-ca /tmp/build-ca.pem

# ---- 開発用（docker-compose.yml）: Vite dev サーバー ----
FROM deps AS dev
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

# ---- ビルド ----
FROM deps AS build
COPY . .
RUN npm run build

# ---- 本番用（docker-compose.prod.yml）: nginx で静的配信 + /api を backend へ中継 ----
# stable 系（1.30.x）のタグを使い、パッチは setup.sh がイメージを取り直して取り込む（#17・#18）。
# 1.27 のようにマイナー版まで固定すると、その系列の更新が終わったときに修正が入らなくなる
FROM docker.io/library/nginx:1.30-alpine AS prod
# OS のパッケージのセキュリティ修正を取り込む（setup.sh が OS_UPGRADE に日付を渡し、日に 1 回はやり直す）。
# 追加で信頼する CA（build-ca/。無ければ README.md だけ）は apk upgrade の間だけ、OS の束に足した一時ファイルを
# SSL_CERT_FILE で渡して使い、消す（apk-tools 3 で確認。apk は SSL_CA_CERT_FILE は読まない）
COPY build-ca/ /tmp/build-ca/
ARG OS_UPGRADE=
RUN set -e; echo "OS_UPGRADE=${OS_UPGRADE}"; \
    if ls /tmp/build-ca/*.crt >/dev/null 2>&1; then \
      cat /etc/ssl/certs/ca-certificates.crt /tmp/build-ca/*.crt > /tmp/build-ca.pem; \
      export SSL_CERT_FILE=/tmp/build-ca.pem; \
    fi; \
    apk upgrade --no-cache; \
    rm -rf /tmp/build-ca /tmp/build-ca.pem
# HTTP / HTTPS の設定。起動時に 40-netconfig-tls.sh が証明書の有無でどちらを使うか選ぶ
COPY nginx/ /etc/nginx/netconfig/
RUN cp /etc/nginx/netconfig/http.conf /etc/nginx/conf.d/default.conf \
 && mv /etc/nginx/netconfig/40-netconfig-tls.sh /docker-entrypoint.d/ \
 && chmod 755 /docker-entrypoint.d/40-netconfig-tls.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
