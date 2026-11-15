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

/** CSV 一括登録のテストで作った機器を消す（e2e の DB は全テストで共有。ほかのテストの件数を変えないように） */
async function deleteImported(page: import("@playwright/test").Page, prefix: string) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  const headers = { Authorization: `Bearer ${token}` };
  const list: { id: string; name: string }[] = await (await page.request.get("/api/devices/", { headers })).json();
  for (const d of list.filter((x) => x.name.startsWith(prefix))) {
    expect((await page.request.delete(`/api/devices/${d.id}`, { headers })).status()).toBe(204);
  }
}

test("CSV から機器をまとめて登録する（内容を確認してから登録）", async ({ page }) => {
  await login(page);
  const prefix = "E2E-IMPORT-";
  await deleteImported(page, prefix); // 前回の失敗で残っていても同じ結果になるように
  try {
    await page.getByRole("button", { name: "CSV 取り込み" }).click();
    const modal = page.locator(".imp-modal");
    await expect(modal.locator(".imp-warn")).toContainText("平文");
    // ひな形
    const [tpl] = await Promise.all([page.waitForEvent("download"), modal.getByRole("button", { name: "ひな形をダウンロード" }).click()]);
    expect(tpl.suggestedFilename()).toBe("device_import_template.csv");
    expect(readFileSync((await tpl.path())!, "utf8")).toContain("名前,ホスト / IP,ポート,グループ,機種");

    const csv = "﻿名前,ホスト / IP,グループ,機種,ユーザー名,パスワード\r\n"
      + `${prefix}A,192.0.2.11,本社,Cisco IOS,admin,pw-a\r\n`
      + `${prefix}B,192.0.2.12,,yamaha,admin,pw-b\r\n`
      + `${prefix}C,192.0.2.13,無いグループ,cisco_ios,admin,pw-c\r\n`
      + "Core-SW01,10.0.1.1,本社,cisco_ios,admin,pw\r\n";
    await modal.locator('input[type="file"]').setInputFiles({ name: "devices.csv", mimeType: "text/csv", buffer: Buffer.from(csv) });
    await modal.getByRole("button", { name: "内容を確認" }).click();
    await expect(modal.locator(".imp-summary")).toContainText("4 行: 登録できる 2 件 / エラー 1 件 / スキップ 1 件");
    await expect(modal.locator(".imp-row-error")).toContainText("グループ「無いグループ」は登録されていません");
    await expect(modal.locator(".imp-row-skip")).toContainText("同じ名前の機器が既にあります");
    // 結果にパスワードは出ない
    await expect(modal).not.toContainText("pw-a");
    // エラーがあるうちは登録できない。「エラーのない行だけ登録する」で登録できる
    await expect(modal.getByRole("button", { name: "0 台を登録する" })).toBeDisabled();
    await modal.getByLabel(/エラーのない行だけ登録する/).check();
    await modal.getByRole("button", { name: "2 台を登録する" }).click();
    await expect(modal.locator(".imp-summary")).toContainText("2 台を登録しました");
    await modal.getByRole("button", { name: "閉じる" }).click();
    await expect(page.getByText("CSV から 2 台を登録しました")).toBeVisible();
    await expect(page.locator(".device-card", { hasText: `${prefix}A` })).toContainText("192.0.2.11");
    await expect(page.locator(".device-card", { hasText: `${prefix}B` })).toBeVisible();
    await expect(page.locator(".device-card", { hasText: `${prefix}C` })).toHaveCount(0);
  } finally {
    await deleteImported(page, prefix);
  }
});

test("CSV 取り込みは管理者だけに表示する", async ({ page }) => {
  for (const user of [USERS.op, USERS.viewer]) {
    await login(page, user);
    await expect(page.getByRole("button", { name: "台帳 CSV" })).toBeVisible();
    await expect(page.getByRole("button", { name: "CSV 取り込み" })).toHaveCount(0);
    await page.evaluate(() => localStorage.clear());
  }
});
