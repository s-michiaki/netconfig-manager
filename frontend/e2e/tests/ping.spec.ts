import { expect, test } from "@playwright/test";
import { USERS, login } from "./helpers";

test("常時監視の対象と推移を確認し、対象を加えて外せる", async ({ page }) => {
  await login(page);
  await page.goto("/ping");
  await page.getByRole("tab", { name: "常時監視" }).click();
  const row = page.locator(".pmon-table tbody tr", { hasText: "Core-SW01" });
  await expect(row).toBeVisible();
  await expect(row.locator("td").nth(6)).toHaveText(/^9\d(\.\d)?%$/); // 途中に応答なしがあるので 100% ではない
  // 推移のグラフ
  await row.getByRole("button", { name: "推移" }).click();
  await expect(page.locator(".pmon-chart svg")).toBeVisible();
  await expect(page.locator(".pmon-loss").first()).toBeVisible();
  await expect(page.locator(".pmon-head")).toContainText("応答率");
  await page.getByRole("tab", { name: "7 日" }).click();
  await expect(page.getByRole("tab", { name: "7 日" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "閉じる" }).click();

  // 加える・外す
  await page.getByLabel("常時監視に加える対象").selectOption({ label: "DC-SW01（10.0.2.1）" });
  await page.getByRole("button", { name: "加える" }).click();
  const added = page.locator(".pmon-table tbody tr", { hasText: "DC-SW01" });
  await expect(added).toContainText("未確認");
  page.once("dialog", (d) => d.accept());
  await added.getByRole("button", { name: "やめる" }).click();
  await expect(added).toHaveCount(0);
});

test("閲覧者は常時監視を見られるが、加える・外すはできない", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/ping?tab=monitor");
  await expect(page.locator(".pmon-table tbody tr", { hasText: "Core-SW01" })).toBeVisible();
  await expect(page.getByLabel("常時監視に加える対象")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "やめる" })).toHaveCount(0);
});
