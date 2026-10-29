# ---- 依存関係 ----
FROM docker.io/library/node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

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
FROM docker.io/library/nginx:1.27-alpine AS prod
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
