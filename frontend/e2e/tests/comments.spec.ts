import { expect, test } from "@playwright/test";
import { USERS, login } from "./helpers";

// 世代へのコメント（作業内容のメモ）。同じ DB を使うので、最後にコメントを消して元に戻す
test("オペレーターが世代にコメントを書き、閲覧者は世代管理とダッシュボードで読める", async ({ page }) => {
  const memo = "CHG-1234 syslog サーバーを追加（夜間作業）";
  page.on("dialog", (d) => d.accept());
  await login(page, USERS.op);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  const rows = page.locator(".hist-table tr.hist-row");
  await rows.nth(0).getByRole("button", { name: "メモ" }).click();
  await page.getByLabel(/メモ（1000 文字まで）/).fill(memo);
  await page.locator(".modal").getByRole("button", { name: "保存", exact: true }).click();
  await expect(page.locator(".modal")).toHaveCount(0);
  await expect(page.locator(".hist-comment").first()).toContainText(memo);
  await expect(page.locator(".hist-comment").first()).toContainText("op1");
  // 開き直しても残っていて、差分を見るときにも出る
  await page.reload();
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  await page.getByRole("button", { name: "差分を表示" }).click();
  await expect(page.locator(".hist-comment-note")).toContainText(memo);
  await page.getByRole("button", { name: "ログアウト" }).click();
  await expect(page).toHaveURL(/\/login/); // サーバー側の失効（/auth/logout）を待ってから移る

  // 閲覧者: コメントは読めるが、書くボタンは無い。ダッシュボードの「直近の変更」にも出る
  await login(page, USERS.viewer);
  await page.locator('a[href="/dashboard"]').first().click();
  const change = page.locator(".dash-panel", { hasText: "直近の変更" }).locator(".dash-row", { hasText: "Core-SW01" });
  await expect(change.locator(".dash-comment")).toContainText(memo);
  // 機器名からその世代の変更（1 つ前との差分）を開ける
  await change.getByRole("link", { name: "Core-SW01" }).click();
  await expect(page).toHaveURL(/\/history\?device=.+&commit=[0-9a-f]{40}/);
  await expect(page.locator(".diff-add")).toHaveText(["+logging host 10.0.9.9"]);
  await expect(page.locator(".hist-comment-note")).toContainText(memo);
  await expect(page.locator(".hist-comment").first()).toContainText(memo);
  await expect(page.getByRole("button", { name: "メモ" })).toHaveCount(0);
  await page.getByRole("button", { name: "ログアウト" }).click();
  await expect(page).toHaveURL(/\/login/); // サーバー側の失効（/auth/logout）を待ってから移る

  // 後始末: 書いた本人が削除する
  await login(page, USERS.op);
  await page.goto("/history");
  await page.locator(".page-header select").selectOption({ label: "Core-SW01" });
  await page.locator(".hist-table tr.hist-row").nth(0).getByRole("button", { name: "メモ" }).click();
  await page.locator(".modal").getByRole("button", { name: "削除" }).click();
  await expect(page.locator(".modal")).toHaveCount(0);
  await expect(page.locator(".hist-comment")).toHaveCount(0);
});
