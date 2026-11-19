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
  await page.getByRole("button", { name: "ログアウト" }).click();

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
