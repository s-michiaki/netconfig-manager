import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 開発サーバーは /api を backend に中継する（ブラウザからは同一オリジンに見える）
// Docker では API_PROXY_TARGET=http://backend:8000 を指定する
export default defineConfig({
  plugins: [react()],
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
