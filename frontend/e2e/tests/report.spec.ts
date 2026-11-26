import { expect, test, type Page } from "@playwright/test";
import { login, openNav, USERS } from "./helpers";

// 偽の URL（実在しない）。この spec は「いま送る」を押さない（外部へは送らない）
const DISCORD_URL = "https://discord.com/api/webhooks/123456789/e2e-report-token";

async function authHeaders(page: Page) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  return { Authorization: `Bearer ${token}` };
}

/** 作った設定を戻す（e2e の DB は全テストで共有） */
async function cleanup(page: Page) {
  const headers = await authHeaders(page);
  await page.request.put("/api/notifications/me", { headers, data: { mode: "inherit", discord_webhook: "", report: "off" } });
}

test("通知設定で定期レポートを選んで保存でき、プレビューで集計を確認できる", async ({ page }) => {
  await login(page);
  await cleanup(page);
  try {
    await openNav(page, "/notifications");
    await expect(page.locator(".page-title")).toHaveText("通知設定");
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await page.getByLabel(/^Discord の Webhook URL/).fill(DISCORD_URL);
    const select = page.getByLabel("定期レポート", { exact: true });
    await expect(select).toHaveValue("off");
    await expect(select.locator("option")).toHaveText(["送らない", "毎週（月曜に前の週の分）", "毎月（1 日に前の月の分）", "毎週と毎月の両方"]);
    await select.selectOption("weekly");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".ntf-ok")).toHaveText("保存しました");

    // 再読み込みしても選んだ値が残る
    await page.reload();
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await expect(page.getByLabel("定期レポート", { exact: true })).toHaveValue("weekly");

    // プレビュー（先週）: 題・期間・各項目。管理者には管理者向けの項目も付く
    const box = page.getByTestId("report-preview");
    await box.getByRole("button", { name: "プレビュー" }).click();
    await expect(box.getByText(/^週次レポート \d+\/\d+〜\d+\/\d+$/)).toBeVisible();
    for (const t of ["収集", "変更", "コンプライアンス", "基準のずれ・保存し忘れ", "Ping監視", "管理者向け"]) {
      await expect(box.locator("b", { hasText: new RegExp(`^${t}$`) })).toBeVisible();
    }
    await expect(box.getByText(/対象の機器: \d+ 台/)).toBeVisible();
    // 「期間内」の件数と「いま」の件数が分かる
    await expect(box.getByText("（期間内）").first()).toBeVisible();
    await expect(box.getByText("（いま）").first()).toBeVisible();
    // Webhook の URL はプレビューに出ない
    expect(await box.innerText()).not.toContain("e2e-report-token");

    // 先月に切り替えると月次（プレビューは数秒の間隔を空ける）
    await page.waitForTimeout(3200);
    await box.getByLabel("レポートの期間").selectOption("month");
    await box.getByRole("button", { name: "プレビュー" }).click();
    await expect(box.getByText(/^月次レポート \d+\/\d+〜\d+\/\d+$/)).toBeVisible();
    // 通知先があれば「いま送る」ボタンがある（押さない）
    await expect(box.getByRole("button", { name: /いま送る（先月分）/ })).toBeVisible();
  } finally {
    await cleanup(page);
  }
});

test("定期レポートだけを選んだ設定も保存できる。閲覧者のプレビューに管理者向けの項目は出ない", async ({ page, browser }) => {
  await login(page);
  await cleanup(page);
  try {
    await openNav(page, "/notifications");
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await page.getByLabel(/^Discord の Webhook URL/).fill(DISCORD_URL);
    // ほかの通知の内容をすべて外すと、定期レポートも無ければ保存できない
    for (const label of ["コンフィグの変更", "コンプライアンス違反の発生", "収集の失敗", "機器情報の変化", "Ping監視", "基準からのずれ", "保存し忘れ", "システムの異常"]) {
      const cb = page.locator("label.form-check", { hasText: label }).getByRole("checkbox").first();
      if (await cb.isChecked()) await cb.uncheck();
    }
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("定期レポート");
    await page.getByLabel("定期レポート", { exact: true }).selectOption("monthly");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".ntf-ok")).toHaveText("保存しました");
  } finally {
    await cleanup(page);
  }

  // 閲覧者（別のコンテキスト）: 個別設定を保存するとプレビューできるが、管理者向けの項目は出ない
  const ctx = await browser.newContext();
  const vp = await ctx.newPage();
  try {
    await login(vp, USERS.viewer);
    await openNav(vp, "/notifications");
    // 個別設定を選んでも、保存するまではプレビューの欄は出ない（案内だけ）
    await vp.getByRole("radio", { name: /個別に設定する/ }).check();
    await expect(vp.getByTestId("report-preview")).toHaveCount(0);
    await expect(vp.getByText(/個別設定を保存すると使えます/)).toBeVisible();
    await vp.getByLabel(/^Discord の Webhook URL/).fill(DISCORD_URL);
    await vp.getByRole("button", { name: "保存" }).click();
    await expect(vp.locator(".ntf-ok")).toHaveText("保存しました");
    const box = vp.getByTestId("report-preview");
    await box.getByRole("button", { name: "プレビュー" }).click();
    await expect(box.getByText(/^週次レポート /)).toBeVisible();
    await expect(box.locator("b", { hasText: /^収集$/ })).toBeVisible();
    await expect(box.locator("b", { hasText: /^管理者向け$/ })).toHaveCount(0);
    await expect(box.getByRole("button", { name: /いま送る/ })).toBeVisible(); // 押さない（外部へは送らない）
  } finally {
    const token = await vp.evaluate(() => localStorage.getItem("access_token"));
    await vp.request.put("/api/notifications/me", { headers: { Authorization: `Bearer ${token}` }, data: { mode: "inherit", discord_webhook: "", report: "off" } });
    await ctx.close();
  }
});

test("ユーザーグループの通知にも定期レポートの選択がある", async ({ page }) => {
  await login(page);
  try {
    await openNav(page, "/notifications");
    await page.getByRole("tab", { name: "ユーザーグループ" }).click();
    await page.getByRole("button", { name: /ユーザーグループを作成/ }).click();
    await page.locator("#ug-name").fill("e2e-report-grp");
    await page.getByLabel(/このグループの通知を有効にする/).check();
    await page.locator("#ug-discord").fill(DISCORD_URL);
    await page.locator("#ug-report").selectOption("both");
    await page.locator(".modal").getByRole("button", { name: "保存" }).click();
    const card = page.locator(".ntf-group", { hasText: "e2e-report-grp" });
    await expect(card.locator("dd", { hasText: "定期レポート（毎週・毎月）" })).toBeVisible();
  } finally {
    const headers = await authHeaders(page);
    const groups = await page.request.get("/api/notifications/groups", { headers });
    for (const g of (await groups.json()) as { id: string; name: string }[]) {
      if (g.name === "e2e-report-grp") await page.request.delete(`/api/notifications/groups/${g.id}`, { headers });
    }
  }
});

test("所属グループの設定を使うときは、プレビューと「いま送る」の欄を出さない", async ({ page }) => {
  await login(page);
  await cleanup(page);
  await openNav(page, "/notifications");
  await page.getByRole("radio", { name: /所属グループの設定を使う/ }).check();
  await expect(page.getByTestId("report-preview")).toHaveCount(0);
  await expect(page.getByText(/個別設定を保存すると使えます/)).toHaveCount(0);
});
