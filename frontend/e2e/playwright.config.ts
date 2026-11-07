import { defineConfig, devices } from "@playwright/test";

/**
 * 画面テスト（Playwright）
 *   実行: cd frontend && npm run e2e（初回は npx playwright install chromium）
 *   backend（SQLite・初期データ入り）と vite の開発サーバーを自動で起動する。Python と backend の依存パッケージが必要
 */
export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // 同じ DB を使うため順番に実行する
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://127.0.0.1:3000",
    locale: "ja-JP",
    timezoneId: "Asia/Tokyo",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
  webServer: [
    {
      command: "bash start-backend.sh", // e2e ディレクトリで実行される
      url: "http://127.0.0.1:8000/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      stdout: "pipe", // 初期データ投入の結果（seeded）を出す
    },
    {
      command: "npx vite --port 3000 --strictPort --host 127.0.0.1",
      cwd: "..",
      url: "http://127.0.0.1:3000",
      timeout: 60_000,
      reuseExistingServer: false,
      env: { API_PROXY_TARGET: "http://127.0.0.1:8000" },
    },
  ],
});
