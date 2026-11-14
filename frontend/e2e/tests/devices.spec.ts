import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { USERS, login } from "./helpers";

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

test("機器台帳（モデル・OS・シリアル）を表示し、検索と CSV 出力ができる", async ({ page }) => {
  await login(page, USERS.viewer);
  const card = page.locator(".device-card", { hasText: "Core-SW01" });
  await expect(card.locator(".device-card-inv")).toContainText("C9300-24T · 17.06.05");
  await expect(card.locator(".device-card-inv")).toContainText("S/N FCW2245L0AB");
  // シリアル番号でも探せる
  await page.getByPlaceholder("名前・IP・モデル・S/N").fill("fcw2245");
  await expect(page.locator(".device-card")).toHaveCount(1);
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "台帳 CSV" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^devices_\d{8}-\d{6}\.csv$/);
  const text = readFileSync((await dl.path())!, "utf8");
  expect(text).toContain("Core-SW01,10.0.1.1,22,本社,");
  expect(text).toContain("C9300-24T,FCW2245L0AB,17.06.05,Core-SW01");
  expect(text).toContain("SW-2F");
});
