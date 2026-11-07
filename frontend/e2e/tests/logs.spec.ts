import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { login } from "./helpers";

test("監査ログに操作が残り、CSV で出力できる", async ({ page }) => {
  await login(page);
  await page.goto("/audit");
  await expect(page.locator(".audit-table tbody tr").first()).toBeVisible();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "CSV 出力" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^audit_logs_\d{8}-\d{6}\.csv$/);
  const text = readFileSync((await dl.path())!, "utf8");
  expect(text.charCodeAt(0)).toBe(0xfeff); // Excel 用の BOM
  expect(text).toContain("機器登録");
});

test("アクティビティに違反の発生が残る", async ({ page }) => {
  await login(page);
  await page.goto("/activity");
  await expect(page.locator(".act-row", { hasText: "違反" }).first()).toBeVisible();
});
