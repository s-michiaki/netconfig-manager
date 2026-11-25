import { expect, test } from "@playwright/test";
import { USERS, expandNav, login } from "./helpers";

test("ログインに失敗するとメッセージを表示する", async ({ page }) => {
  await page.goto("/login");
  await page.locator("input").nth(0).fill("admin");
  await page.locator('input[type="password"]').fill("wrong-password");
  await page.locator("button.btn-primary").click();
  await expect(page.locator(".form-error")).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("ログインしていなければログイン画面へ戻す", async ({ page }) => {
  await page.goto("/topology");
  await expect(page).toHaveURL(/\/login/);
});

test("管理者はすべてのメニューを使え、バージョンを表示する", async ({ page }) => {
  await login(page);
  await expandNav(page);
  for (const label of ["デバイス管理", "構成図", "コンプライアンス", "監査ログ", "ユーザー管理"]) {
    await expect(page.getByRole("link", { name: label })).toBeVisible();
  }
  await expect(page.locator(".version-tag")).toHaveText(/^v\d+\.\d+\.\d+$/);
});

test("閲覧者は管理用のメニューと編集ボタンが表示されない", async ({ page }) => {
  await login(page, USERS.viewer);
  await expandNav(page);
  await expect(page.getByRole("link", { name: "デバイス管理" })).toBeVisible();
  for (const label of ["監査ログ", "ユーザー管理", "踏み台サーバ", "コンフィグ収集", "ターミナル", "コマンド実行"]) {
    await expect(page.getByRole("link", { name: label })).toHaveCount(0);
  }
  await expect(page.getByRole("button", { name: "＋ 追加" })).toHaveCount(0);
  // URL を直接開いても権限が無い画面は表示しない
  await page.goto("/audit");
  await expect(page.locator(".audit-table")).toHaveCount(0);
});

test("ログアウトするとログイン画面に戻る", async ({ page }) => {
  await login(page, USERS.op);
  await page.getByText("ログアウト").click();
  await expect(page).toHaveURL(/\/login/);
});

test("管理者がユーザーをログアウトさせると、その人の画面はログイン画面に戻る", async ({ page, browser }) => {
  // 閲覧者が別のブラウザでログインしている
  const other = await browser.newContext();
  const viewer = await other.newPage();
  await login(viewer, USERS.viewer);

  await login(page);
  await page.goto("/users");
  const row = page.locator("tr", { has: page.getByText(USERS.viewer.name, { exact: true }) });
  // 自分の行には出さない
  await expect(page.locator("tr", { hasText: "自分" }).getByRole("button", { name: "ログアウトさせる" })).toHaveCount(0);
  page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "ログアウトさせる" }).click();
  await expect(page.locator(".users-notice")).toHaveText(`「${USERS.viewer.name}」をログアウトさせました`);

  // 次の API 呼び出しで切られる。パスワードは変わらないので、そのまま再ログインできる
  await viewer.goto("/devices");
  await expect(viewer).toHaveURL(/\/login/);
  await login(viewer, USERS.viewer);
  await other.close();
});
