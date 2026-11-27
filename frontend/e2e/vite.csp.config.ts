import { defineConfig } from "vite";
import { readCsp } from "./csp";

/**
 * 画面テストの csp プロジェクト用: 本番ビルド（dist/e2e-csp）を、本番の nginx と同じ CSP を付けて配信する
 *   開発サーバー（vite）は React のホットリロード用にインラインのスクリプトを差し込むため、本番と同じ CSP では確認できない
 *   ヘッダーの付け方は nginx/csp.inc の map と同じ（どのパスも同じ値）。/docs・/openapi.json は本番の nginx と同じく中継しない
 */
const csp = readCsp();

export default defineConfig({
  // ビルドは通常の vite.config.ts で行い（npx vite build --outDir dist/e2e-csp）、ここでは配信だけする
  build: { outDir: "dist/e2e-csp" },
  plugins: [
    {
      name: "netconfig-csp-headers",
      configurePreviewServer(server) {
        server.middlewares.use((req, res, next) => {
          res.setHeader("Content-Security-Policy", csp.app);
          next();
        });
      },
    },
  ],
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", ws: true },
    },
  },
});
