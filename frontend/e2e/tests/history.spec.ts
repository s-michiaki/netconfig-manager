import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { USERS, login } from "./helpers";

// Linux のブラウザは文字コードが UTF-8 の環境でないと日本語のファイル名を "download" に置き換えるため、UTF-8 で起動する
test.use({ launchOptions: { env: { ...process.env, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" } } });

// Core-SW01 は 2 世代（2 世代目で logging host を追加）。他の機器は 1 世代（seed.py）

test("世代を日時で選んで差分を見られ、一覧の A・B でも選べる", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  const a = page.getByLabel("比べる元の世代");
  await expect(a.locator("option")).toHaveCount(2);
  // 選択肢にハッシュと日時が出る
  await expect(a.locator("option").first()).toHaveText(/^[0-9a-f]{8}\s+\d{4}\/\d{1,2}\/\d{1,2} /);
  await page.getByRole("button", { name: "差分を表示" }).click();
  await expect(page.locator(".diff-add")).toHaveText(["+logging host 10.0.9.9"]);
  await expect(page.locator(".hist-title")).toContainText("→");
  // 一覧の A・B で入れ替える（新しい世代 → 古い世代）
  const rows = page.locator(".hist-table tr.hist-row");
  await rows.nth(0).getByRole("button", { name: "A", exact: true }).click();
  await rows.nth(1).getByRole("button", { name: "B", exact: true }).click();
  await expect(rows.nth(0).locator(".hist-mark")).toHaveText("A");
  await expect(rows.nth(1).locator(".hist-mark")).toHaveText("B");
  await page.getByRole("button", { name: "差分を表示" }).click();
  await expect(page.locator(".diff-del")).toHaveText(["-logging host 10.0.9.9"]);
  await expect(page.locator(".diff-add")).toHaveCount(0);
});

test("別の機器の最新コンフィグと比べられる", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  await page.getByRole("tab", { name: "別の機器と比べる" }).click();
  const other = page.getByLabel("比べる機器", { exact: true });
  // 自分自身は選択肢に出ない
  await expect(other.locator("option", { hasText: "Core-SW01" })).toHaveCount(0);
  await other.selectOption({ label: "SW-2F" });
  await page.getByRole("button", { name: "比較する" }).click();
  await expect(page.locator(".hist-title")).toContainText(/Core-SW01 [0-9a-f]{8}.*→ SW-2F [0-9a-f]{8}/);
  await expect(page.locator(".diff-add", { hasText: "+ip http server" })).toBeVisible();
  await expect(page.locator(".diff-add", { hasText: "+hostname SW-2F" })).toBeVisible();
  await expect(page.locator(".diff-del", { hasText: "-service password-encryption" })).toBeVisible();
  await expect(page.locator(".diff-del", { hasText: "-logging host 10.0.9.9" })).toBeVisible();
  // この機器の側を古い世代にすると logging host の差は消える
  const self = page.getByLabel("この機器の世代");
  await self.selectOption({ index: 2 });
  await page.getByRole("button", { name: "比較する" }).click();
  await expect(page.locator(".diff-del", { hasText: "logging host" })).toHaveCount(0);
  await expect(page.locator(".diff-add", { hasText: "+ip http server" })).toBeVisible();
});

test("閲覧者が選んだ世代のコンフィグをファイルに保存でき、監査ログに残る", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  const rows = page.locator(".hist-table tr.hist-row");
  // 古い世代（logging host が無い方）を保存する
  const [dl] = await Promise.all([page.waitForEvent("download"), rows.nth(1).getByRole("button", { name: "保存" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^Core-SW01_\d{8}-\d{6}_[0-9a-f]{8}\.txt$/);
  const text = readFileSync((await dl.path())!, "utf8");
  expect(text).toContain("hostname Core-SW01");
  expect(text).not.toContain("logging host");
  // 表示中のコンフィグからも保存できる
  await rows.nth(0).getByRole("button", { name: "表示" }).click();
  const [dl2] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "ファイルに保存" }).click()]);
  expect(readFileSync((await dl2.path())!, "utf8")).toContain("logging host 10.0.9.9");

  // 管理者の監査ログに記録が残る
  await page.getByRole("button", { name: "ログアウト" }).click();
  await login(page, USERS.admin);
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  const res = await page.request.get("/api/audit/logs?action=config.download", { headers: { Authorization: `Bearer ${token}` } });
  const logs = await res.json();
  expect(logs.total).toBeGreaterThanOrEqual(2);
  expect(logs.items[0].username).toBe("view1");
  expect(logs.items[0].target_name).toBe("Core-SW01");
});

test("日本語の機器名のファイル名で保存できる", async ({ page }) => {
  // サーバーの応答（filename* に UTF-8 の名前）を差し替えて、画面がファイル名を正しく取り出すことを確かめる
  await page.route("**/api/configs/*/download/*", (route) => route.fulfill({
    status: 200, contentType: "text/plain; charset=utf-8", body: "hostname x\n",
    headers: { "Content-Disposition": "attachment; filename=\"___-SW_20261115-093000_a1b2c3d4.txt\"; filename*=UTF-8''%E6%9D%B1%E4%BA%AC-SW_20261115-093000_a1b2c3d4.txt" },
  }));
  await login(page, USERS.viewer);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "SW-3F" });
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "保存" }).first().click()]);
  expect(dl.suggestedFilename()).toBe("東京-SW_20261115-093000_a1b2c3d4.txt");
});
