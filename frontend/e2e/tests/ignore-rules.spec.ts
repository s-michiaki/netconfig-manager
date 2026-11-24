import { expect, test, type Page } from "@playwright/test";
import { USERS, login } from "./helpers";

async function authHeaders(page: Page) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  return { Authorization: `Bearer ${token}` };
}

/** 途中で失敗しても、ほかの spec に影響しないよう、API からすべてのルールを消す（同じ DB を使うため） */
async function removeAllRules(page: Page) {
  const headers = await authHeaders(page);
  const res = await page.request.get("/api/ignore-rules/", { headers });
  if (!res.ok()) return;
  for (const r of (await res.json()) as { id: string }[]) {
    await page.request.delete(`/api/ignore-rules/${r.id}`, { headers });
  }
}

// 収集時に無視する行。シードの cisco_ios の機器は、すべて " description uplink" の行を持つ
test("管理者が無視する行を追加し、試して、保存・一覧・削除できる。オペレーターには出ない", async ({ browser }) => {
  const adminCtx = await browser.newContext();
  const page = await adminCtx.newPage();
  await login(page, USERS.admin);
  try {
    await page.locator('a[href="/ignore-rules"]').first().click();
    await expect(page).toHaveURL(/\/ignore-rules/);
    await expect(page.getByText("ルールはまだありません")).toBeVisible();
    await expect(page.getByText("追加後の最初の収集では、該当の行が消える変更が 1 回記録されます").first()).toBeVisible();
    await expect(page.getByText(/コンプライアンスの検査・コンフィグ検索・基準との比較からも見えなくなります/).first()).toBeVisible();

    await page.getByRole("button", { name: "ルールを追加" }).click();
    const modal = page.getByRole("dialog", { name: "ルールの追加" });
    // 対象を選ぶまで「試す」「保存」は押せない
    await expect(modal.getByRole("button", { name: "試す" })).toBeDisabled();
    await modal.getByLabel("機種（この機種のすべての機器に効きます）").selectOption("cisco_ios");
    await modal.getByLabel(/^正規表現/).fill("^ description uplink");
    await modal.getByLabel("説明（任意）").fill("回線の説明の行");
    await modal.getByRole("button", { name: "試す" }).click();
    const result = modal.getByLabel("試した結果");
    await expect(result.getByText("Core-SW01")).toBeVisible();
    await expect(result.locator(".badge", { hasText: "行が一致" }).first()).toBeVisible();
    await expect(result.locator(".ign-examples").first()).toContainText(" description uplink");
    await expect(result.getByText("保存済みの世代に当てています。すでに有効なルールで消えた行は出ません")).toBeVisible();
    // 全行の半分以上には一致しないので警告は出ない
    await expect(result.getByRole("alert")).toHaveCount(0);

    // 広すぎる正規表現は「試す」で警告し、保存時は確認のダイアログを出す。取りやめると保存しない
    await modal.getByLabel(/^正規表現/).fill("[a-z]");
    await modal.getByRole("button", { name: "試す" }).click();
    await expect(result.getByRole("alert")).toContainText("50% 以上に一致します");
    let asked = "";
    page.once("dialog", (d) => { asked = d.message(); void d.dismiss(); });
    await modal.getByRole("button", { name: "保存" }).click();
    await expect.poll(() => asked).toMatch(/で全行の \d+% が消えます.*。保存しますか？/);
    await expect(modal).toBeVisible();
    await expect(modal.getByRole("button", { name: "保存" })).toBeEnabled();

    // 空の行に一致するものは保存できない
    await modal.getByLabel(/^正規表現/).fill("x*");
    await modal.getByRole("button", { name: "保存" }).click();
    await expect(modal.locator(".form-error")).toContainText("空の行");

    await modal.getByLabel(/^正規表現/).fill("^ description uplink");
    await modal.getByRole("button", { name: "保存" }).click();
    await expect(modal).toHaveCount(0);
    const row = page.locator("table.data-table tbody tr");
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("^ description uplink");
    await expect(row).toContainText("回線の説明の行");
    await expect(row.getByRole("button", { name: "有効", exact: true })).toBeVisible();

    // 編集で広い正規表現にすると確認のダイアログ。了承すると confirm_broad を付けて保存する
    await row.getByRole("button", { name: "編集" }).click();
    const edit = page.getByRole("dialog", { name: "ルールの編集" });
    await edit.getByLabel(/^正規表現/).fill("[a-z]");
    page.once("dialog", (d) => { asked = d.message(); void d.accept(); });
    asked = "";
    await edit.getByRole("button", { name: "保存" }).click();
    await expect(edit).toHaveCount(0);
    expect(asked).toMatch(/保存しますか？/);
    await expect(row).toContainText("[a-z]");

    // 無効にする（無効にするときは確認しない）
    await row.getByRole("button", { name: "有効", exact: true }).click();
    await expect(row.getByRole("button", { name: "無効", exact: true })).toBeVisible();

    // オペレーターにはメニューも画面も出ない
    const opCtx = await browser.newContext();
    const op = await opCtx.newPage();
    await login(op, USERS.op);
    await expect(op.locator('a[href="/ignore-rules"]')).toHaveCount(0);
    await opCtx.close();

    // 削除
    page.once("dialog", (d) => d.accept());
    await row.getByRole("button", { name: "削除" }).click();
    await expect(page.getByText("ルールはまだありません")).toBeVisible();
  } finally {
    await removeAllRules(page);
    await adminCtx.close();
  }
});
