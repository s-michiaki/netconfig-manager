import { createHmac } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

/** 認証アプリと同じ計算（TOTP。SHA-1・6 桁・30 秒）。offset は時間枠のずれ */
function totp(secret: string, offset = 0): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "")) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30) + offset));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 0x0f;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function passwordStep(page: Page) {
  await page.goto("/login");
  await page.locator("input").nth(0).fill("mfa1");
  await page.locator('input[type="password"]').fill("password-1234");
  await page.locator("button.btn-primary").click();
}

test("2 段階認証を設定し、確認コードでログインし、解除できる", async ({ page }) => {
  await passwordStep(page);
  await expect(page).toHaveURL(/\/dashboard/);
  // 設定
  await page.getByRole("button", { name: /^2 段階認証/ }).click();
  // パスワードを入れ直してから始める（漏れたトークンだけでは設定できない）
  await expect(page.getByRole("button", { name: "設定を始める" })).toBeDisabled();
  await page.getByLabel("パスワード（本人の確認）").fill("wrong-pass-xx");
  await page.getByRole("button", { name: "設定を始める" }).click();
  await expect(page.locator(".form-error")).toContainText("パスワードが正しくありません");
  await page.getByLabel("パスワード（本人の確認）").fill("password-1234");
  await page.getByRole("button", { name: "設定を始める" }).click();
  await expect(page.locator(".mfa-qr svg")).toBeVisible();
  const secret = (await page.locator(".mfa-secret").textContent())!.trim();
  await page.getByLabel(/アプリに表示された 6 桁のコード/).fill("000000");
  await page.getByRole("button", { name: "確認して有効にする" }).click();
  await expect(page.locator(".form-error")).toContainText("確認コードが正しくありません");
  await page.getByLabel(/アプリに表示された 6 桁のコード/).fill(totp(secret));
  await page.getByRole("button", { name: "確認して有効にする" }).click();
  const codes = page.locator(".mfa-codes span");
  await expect(codes).toHaveCount(10);
  const recovery = (await codes.allTextContents()).map((s) => s.trim());
  await page.getByRole("button", { name: "控えました" }).click();
  await expect(page.locator(".badge", { hasText: "設定済み" })).toBeVisible();
  await page.getByRole("button", { name: "閉じる" }).click();
  await expect(page.getByRole("button", { name: "2 段階認証 ✓" })).toBeVisible();
  // 設定したあとも、この画面は新しいトークンでそのまま使える
  await page.goto("/history");
  await expect(page).toHaveURL(/\/history/);
  await page.getByRole("button", { name: "ログアウト" }).click();
  await expect(page).toHaveURL(/\/login/); // サーバー側の失効（/auth/logout）を待ってから移る

  // ログイン: パスワードのあとに確認コード（設定に使ったコードは再利用できないので次の時間枠）
  await passwordStep(page);
  await expect(page.getByLabel("確認コード")).toBeVisible();
  await page.getByLabel("確認コード").fill("111111");
  await page.locator("button.btn-primary").click();
  await expect(page.locator(".form-error")).toContainText("確認コードが正しくありません");
  await page.getByLabel("確認コード").fill(totp(secret, 1));
  await page.locator("button.btn-primary").click();
  await expect(page).toHaveURL(/\/dashboard/);
  await page.getByRole("button", { name: "ログアウト" }).click();
  await expect(page).toHaveURL(/\/login/); // サーバー側の失効（/auth/logout）を待ってから移る
  // 予備コードでも入れる
  await passwordStep(page);
  await page.getByLabel("確認コード").fill(recovery[0]);
  await page.locator("button.btn-primary").click();
  await expect(page).toHaveURL(/\/dashboard/);

  // 解除（ほかのテストのために元に戻す）
  await page.getByRole("button", { name: /^2 段階認証/ }).click();
  await page.getByRole("button", { name: "解除する" }).click();
  await page.getByLabel("パスワード").fill("password-1234");
  await page.getByLabel("確認コード").fill(recovery[1]);
  await page.locator(".modal .btn-danger", { hasText: "解除する" }).click();
  await expect(page.locator(".modal")).toContainText("2 段階認証を解除しました");
});

test("管理者が 2 段階認証を解除するときは、管理者のパスワードを入れ直す", async ({ page, request }) => {
  // mfa1 が API で 2 段階認証を設定する
  const tok = (await (await request.post("/api/auth/token", { form: { username: "mfa1", password: "password-1234" } })).json()).access_token;
  const h = { Authorization: `Bearer ${tok}` };
  const setup = await (await request.post("/api/auth/mfa/setup", { headers: h, data: { password: "password-1234" } })).json();
  expect((await request.post("/api/auth/mfa/enable", { headers: h, data: { code: totp(setup.secret) } })).status()).toBe(200);

  await page.goto("/login");
  await page.locator("input").nth(0).fill("admin");
  await page.locator('input[type="password"]').fill(process.env.E2E_ADMIN_PASSWORD ?? "initial-pass-123");
  await page.locator("button.btn-primary").click();
  await expect(page).toHaveURL(/\/dashboard/);
  await page.goto("/users");
  const row = page.locator("tr", { has: page.getByText("mfa1", { exact: true }) });
  await row.getByRole("button", { name: "2 段階認証を解除" }).click();
  const modal = page.locator(".modal");
  await modal.getByLabel(/操作する管理者）のパスワード/).fill("wrong-pass-xx");
  await modal.getByRole("button", { name: "解除する" }).click();
  await expect(modal.locator(".form-error")).toContainText("パスワードが正しくありません");
  await modal.getByLabel(/操作する管理者）のパスワード/).fill(process.env.E2E_ADMIN_PASSWORD ?? "initial-pass-123");
  await modal.getByRole("button", { name: "解除する" }).click();
  await expect(page.locator(".users-notice")).toHaveText("「mfa1」の 2 段階認証を解除しました");
  await expect(row).toContainText("未設定");
  // パスワードだけで入れるようになる
  await passwordStep(page);
  await expect(page).toHaveURL(/\/dashboard/);
});

test("Ping 監視を動かしたまま 2 段階認証を設定しても、予備コードが表示され、ログイン画面に移らない（Ping 監視はつなぎ直る）", async ({ page, request }) => {
  await passwordStep(page);
  await expect(page).toHaveURL(/\/dashboard/);
  await page.goto("/ping");
  await page.getByRole("button", { name: /^対象を選ぶ/ }).click();
  await page.locator(".ping-sel-item", { hasText: "Core-SW01" }).locator("input").check();
  await page.getByRole("button", { name: "決定" }).click();
  await page.getByRole("button", { name: "▶ 開始" }).click();
  // サーバーから ICMP を送れない環境（権限なし）では、監視は始まらずエラーの文が出る。その環境では確かめられないので飛ばす
  // （CI では net.ipv4.ping_group_range を設定して動かす）
  const unavailable = page.getByText(/PING を送れません/);
  await expect(page.locator(".badge", { hasText: "監視中" }).or(unavailable).first()).toBeVisible();
  await page.waitForTimeout(1500);
  test.skip(await unavailable.isVisible(), "この環境ではサーバーから ICMP を送れない");
  await expect(page.locator(".badge", { hasText: "監視中" })).toBeVisible();

  await page.getByRole("button", { name: /^2 段階認証/ }).click();
  await page.getByLabel("パスワード（本人の確認）").fill("password-1234");
  await page.getByRole("button", { name: "設定を始める" }).click();
  const secret = (await page.locator(".mfa-secret").textContent())!.trim();
  await page.getByLabel(/アプリに表示された 6 桁のコード/).fill(totp(secret));
  await page.getByRole("button", { name: "確認して有効にする" }).click();
  // 予備コードが表示され、ログイン画面へ移らない（Ping 監視の接続は 4409 で切れ、新しいトークンでつなぎ直す）
  const codes = page.locator(".mfa-codes span");
  await expect(codes).toHaveCount(10);
  const recovery = (await codes.allTextContents()).map((s) => s.trim());
  await page.waitForTimeout(1500);
  await expect(page).toHaveURL(/\/ping/);
  await page.getByRole("button", { name: "控えました" }).click();
  await page.getByRole("button", { name: "閉じる" }).click();
  await expect(page.locator(".badge", { hasText: "監視中" })).toBeVisible();
  await page.getByRole("button", { name: "■ 停止" }).click();

  // 元に戻す（ほかのテストのため）
  const tok = await page.evaluate(() => localStorage.getItem("access_token"));
  expect((await request.post("/api/auth/mfa/disable", {
    headers: { Authorization: `Bearer ${tok}` }, data: { password: "password-1234", code: recovery[0] },
  })).status()).toBe(200);
});
