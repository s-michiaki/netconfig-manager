import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { login, openNav } from "./helpers";

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

test("ターミナルの記録をテキストで読み、保存し、記録の中を検索できる", async ({ page }) => {
  await login(page);
  await openNav(page, "/audit");
  await page.getByRole("tab", { name: "ターミナルの記録" }).click();
  const row = page.locator("tr", { hasText: "Core-SW01" }).first();
  await row.getByRole("button", { name: "テキスト" }).click();
  const viewer = page.locator(".modal");
  // 打ち直し・色・--More-- の跡が無い、読める形のテキスト
  await expect(viewer.locator(".audit-text")).toContainText("Core-SW01#show clock");
  await expect(viewer.locator(".audit-text")).toContainText("Core-SW01#show ip interface brief");
  await expect(viewer.locator(".audit-text")).toContainText("Vlan20   10.0.2.1");
  await expect(viewer.locator(".audit-text")).not.toContainText("More");
  await expect(viewer.locator(".audit-text")).not.toContainText("clcok");
  const [dl] = await Promise.all([page.waitForEvent("download"), viewer.getByRole("button", { name: "ファイルに保存（.txt）" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^terminal_admin_Core-SW01_\d{8}-\d{6}\.txt$/);
  expect(readFileSync((await dl.path())!, "utf8")).toContain("Core-SW01#show ip interface brief\nVlan10   10.0.1.1");
  await viewer.getByRole("button", { name: "閉じる" }).click();

  // 記録の中を探す → 一致した行から、その行を開く
  await page.getByPlaceholder(/show running-config/).fill("interface brief");
  await page.getByRole("button", { name: "記録を検索" }).click();
  const found = page.locator(".audit-found");
  await expect(found.locator(".srch-summary")).toContainText("1 件のセッションで一致");
  await expect(found.locator("mark")).toHaveText("interface brief");
  await found.locator(".audit-found-line").first().click();
  await expect(page.locator(".modal .audit-text-hit")).toContainText("show ip interface brief");
  await page.locator(".modal").getByRole("button", { name: "閉じる" }).click();
  await page.getByPlaceholder(/show running-config/).fill("no-such-command");
  await page.getByRole("button", { name: "記録を検索" }).click();
  await expect(found).toContainText("一致する記録はありませんでした");
  // 検索語は URL に残さない
  expect(page.url()).not.toContain("no-such-command");
});
