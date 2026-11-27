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

test("ログアウトするとログイン画面に戻り、そのトークンはサーバー側でも使えなくなる", async ({ page }) => {
  await login(page, USERS.op);
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  await page.getByText("ログアウト").click();
  await expect(page).toHaveURL(/\/login/);
  // 画面で捨てるだけでなく、サーバー側でも失効している（盗まれたトークンを使い続けられない）。
  // ほかの端末のログインが残ること（Redis に失効を記録する）は backend のテスト。e2e は Redis が無いので、すべての端末から切る動きになる
  expect((await page.request.get("/api/auth/me", { headers: { Authorization: `Bearer ${token}` } })).status()).toBe(401);
});

test("すべての端末からログアウトすると、ほかの端末のログインも切れる", async ({ page, browser }) => {
  const other = await browser.newContext();
  const second = await other.newPage();
  await login(second, USERS.viewer);

  await login(page, USERS.viewer);
  await page.getByRole("button", { name: "パスワード変更" }).click();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "すべての端末からログアウト" }).click();
  await expect(page).toHaveURL(/\/login/);
  await second.goto("/devices");
  await expect(second).toHaveURL(/\/login/);
  await login(second, USERS.viewer); // パスワードは変わらない
  await other.close();
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

test("管理者のユーザーを作るときは、操作する管理者のパスワードを入れ直す", async ({ page }) => {
  const name = `e2e-adm-${Date.now().toString(36)}`;
  await login(page);
  await page.goto("/users");
  await page.getByRole("button", { name: "＋ 追加" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input").first().fill(name);
  await modal.locator('input[type="password"]').first().fill("password-1234");
  await expect(modal.getByLabel(/操作する管理者）のパスワード/)).toHaveCount(0); // 閲覧者のときは要らない
  await modal.locator("select").selectOption("admin");
  await expect(modal.getByRole("button", { name: "追加" })).toBeDisabled();
  await modal.getByLabel(/操作する管理者）のパスワード/).fill("wrong-pass-xx");
  await modal.getByRole("button", { name: "追加" }).click();
  await expect(modal.locator(".form-error")).toContainText("パスワードが正しくありません");
  await modal.getByLabel(/操作する管理者）のパスワード/).fill(USERS.admin.password);
  await modal.getByRole("button", { name: "追加" }).click();
  const row = page.locator("tr", { has: page.getByText(name, { exact: true }) });
  await expect(row).toContainText("管理者");
  page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "削除" }).click();
  await expect(row).toHaveCount(0);
});

test("同じブラウザの別のタブでパスワードを変更しても、元のタブはログアウトされない", async ({ page, request }) => {
  await login(page, USERS.op);
  const other = await page.context().newPage(); // 同じ storage（localStorage を共有する）
  await other.goto("/devices");
  await expect(other).toHaveURL(/\/devices/);
  await other.getByRole("button", { name: "パスワード変更" }).click();
  const modal = other.locator(".modal");
  await modal.locator('input[type="password"]').nth(0).fill(USERS.op.password);
  await modal.locator('input[type="password"]').nth(1).fill("changed-pass-e2e");
  await modal.getByRole("button", { name: "変更" }).click();
  await expect(modal).toContainText("パスワードを変更しました");
  // 元のタブは、次の操作でも新しいトークンで続けられる
  await page.goto("/history");
  await expect(page).toHaveURL(/\/history/);
  await page.goto("/devices");
  await expect(page).toHaveURL(/\/devices/);
  // 元に戻す
  const tok = await page.evaluate(() => localStorage.getItem("access_token"));
  expect((await request.post("/api/auth/change-password", {
    headers: { Authorization: `Bearer ${tok}` },
    data: { current_password: "changed-pass-e2e", new_password: USERS.op.password },
  })).status()).toBe(200);
  await other.close();
});
