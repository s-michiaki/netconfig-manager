import { expect, test } from "@playwright/test";
import { USERS, login } from "./helpers";

test("違反を一覧し、例外として登録・削除できる", async ({ page }) => {
  await login(page, USERS.op);
  await page.goto("/compliance");
  const row = page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" });
  await expect(row).toBeVisible();
  await expect(page.locator("tr", { hasText: "DC-SW01" })).toBeVisible();

  await row.getByRole("button", { name: "例外にする" }).click();
  // 違反箇所から除外する行を選べる。ここでは機器単位で除外する
  await expect(page.locator(".cmp-suggest button")).toHaveCount(1);
  await page.getByLabel("この機器ではルールの違反をすべて除外する").check();
  await page.locator("#x-reason").fill("E2E: 検証用の機器のため");
  await page.locator(".modal").getByRole("button", { name: "登録して再検査" }).click();
  await expect(page.locator(".modal")).toHaveCount(0);
  await expect(page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" })).toHaveCount(0);

  await page.locator(".seg-tab", { hasText: "例外" }).click();
  const ex = page.locator("tr", { hasText: "E2E: 検証用の機器のため" });
  await expect(ex).toContainText("SW-2F");
  page.once("dialog", (d) => d.accept());
  await ex.getByRole("button", { name: "削除" }).click();
  await expect(ex).toHaveCount(0);
  await page.locator(".seg-tab", { hasText: "違反" }).first().click();
  await expect(page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" })).toBeVisible();
});

test("閲覧者は違反を見られるが例外は登録できない", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/compliance");
  await expect(page.locator("tr", { hasText: "DC-SW01" })).toBeVisible();
  await expect(page.getByRole("button", { name: "例外にする" })).toHaveCount(0);
});
