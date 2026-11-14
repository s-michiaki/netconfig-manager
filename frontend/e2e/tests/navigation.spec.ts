import { expect, test } from "@playwright/test";
import { login } from "./helpers";

// 全画面を開いて、画面の読み込みや描画でエラーが出ないことを確認する（ルーター・遅延読み込みの更新時の確認用）
const PAGES = ["/dashboard", "/devices", "/topology", "/jump-hosts", "/collect", "/ping", "/history", "/terminal", "/schedules",
  "/compliance", "/notifications", "/activity", "/audit", "/users", "/system"];

test("すべての画面をエラーなく開ける", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  for (const path of PAGES) {
    await page.locator(`a[href="${path}"]`).first().click();
    await expect(page).toHaveURL(new RegExp(`${path}$`));
    await expect(page.locator(".page-title").first()).toBeVisible();
  }
  // URL のパラメータで開く画面
  await page.goto("/activity?ref=none");
  await expect(page.getByText("ひとつの実行")).toBeVisible();
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page).toHaveURL(/\/topology\/[\w-]+/);
  await page.reload();
  await expect(page.locator(".react-flow__node-device").first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("試験導入中のモニタリングは既定では表示されない", async ({ page }) => {
  // MONITORING_ENABLED=false（既定）ではメニューに出ず、API も 404 を返す
  await login(page);
  await expect(page.locator('a[href="/devices"]').first()).toBeVisible();
  await expect(page.locator('a[href="/monitoring"]')).toHaveCount(0);
  const res = await page.request.get("/api/health");
  expect((await res.json()).features?.monitoring).toBe(false);
});
