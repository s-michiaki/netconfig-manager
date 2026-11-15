import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 開発サーバーは /api を backend に中継する（ブラウザからは同一オリジンに見える）
// Docker では API_PROXY_TARGET=http://backend:8000 を指定する
export default defineConfig({
  plugins: [react()],
  build: {
    // フォントは data: URL に埋め込まず、常にファイルとして出力する（CSP の font-src を 'self' だけにするため）
    assetsInlineLimit: (file) => (/\.(woff2?|ttf|otf)$/.test(file) ? false : undefined),
    rollupOptions: {
      output: {
        // 全画面で使うライブラリはまとめて1つにし、画面のファイルを小さく保つ（ブラウザのキャッシュも効きやすい）
        manualChunks: {
          vendor: ["react", "react-dom", "react-router-dom", "axios"],
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 3000,
    proxy: {
      "/api": {
        target: process.env.API_PROXY_TARGET || "http://localhost:8000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
