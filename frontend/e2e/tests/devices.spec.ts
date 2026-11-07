import { expect, test } from "@playwright/test";
import { login } from "./helpers";

test("機器はグループごとに表示し、グループの並び順を変えられる", async ({ page }) => {
  await login(page);
  const heads = page.locator(".dev-group-name");
  await expect(heads.first()).toHaveText(/本社/);
  await page.getByRole("button", { name: "グループの管理" }).click();
  await page.locator(".grp-row").nth(1).getByTitle("上へ").click();
  await expect(page.locator(".grp-row-name").first()).toContainText("データセンター");
  await page.locator(".grp-modal").getByRole("button", { name: "閉じる" }).click();
  await expect(heads.first()).toHaveText(/データセンター/);
  // 元に戻す（他のテストに影響させない）
  await page.getByRole("button", { name: "グループの管理" }).click();
  await page.locator(".grp-row").nth(1).getByTitle("上へ").click();
  await expect(page.locator(".grp-row-name").first()).toContainText("本社");
  await page.locator(".grp-modal").getByRole("button", { name: "閉じる" }).click();
});

test("世代管理で収集済みのコンフィグを表示する", async ({ page }) => {
  await login(page);
  await page.goto("/history");
  const select = page.locator(".page-header select");
  await select.selectOption({ label: "Core-SW01" });
  await page.getByRole("button", { name: "表示" }).first().click();
  await expect(page.getByText("hostname Core-SW01").first()).toBeVisible();
});
