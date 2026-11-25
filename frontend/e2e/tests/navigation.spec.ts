import { expect, test } from "@playwright/test";
import { login, PAGES, openNav, expandNav } from "./helpers";

// 全画面を開いて、画面の読み込みや描画でエラーが出ないことを確認する（ルーター・遅延読み込みの更新時の確認用）

test("すべての画面をエラーなく開ける", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  for (const path of PAGES) {
    await openNav(page, path);
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
  await expandNav(page);
  // /health の応答（features）が届いてから確かめる（届く前は空なので、出ないのは当たり前になってしまう）
  await expect(page.locator(".version-tag")).toHaveText(/^v/);
  await expect(page.locator('a[href="/devices"]').first()).toBeVisible();
  await expect(page.locator('.sidebar-nav a[href="/monitoring"]')).toHaveCount(0);
  const res = await page.request.get("/api/health");
  expect((await res.json()).features?.monitoring).toBe(false);
});

test("システム状態にバックアップの項目があり、記録の無い環境では警告にしない", async ({ page }) => {
  // 画面テストの環境ではバックアップ（scripts/backup.sh）を使っていないので「—」（確認できない）になる
  await login(page);
  await page.goto("/system");
  const card = page.locator(".sys-card", { hasText: "バックアップ" });
  await expect(card).toBeVisible();
  await expect(card.locator(".badge")).toHaveText("—");
  await expect(card).toContainText("定期バックアップ");
  await expect(page.locator(".sys-note")).toContainText("バックアップは失敗するたびに通知");
});
