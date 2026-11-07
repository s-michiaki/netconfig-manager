import { expect, type Page } from "@playwright/test";

export const USERS = {
  admin: { name: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "initial-pass-123" },
  op: { name: "op1", password: "password-1234" },
  viewer: { name: "view1", password: "password-1234" },
};

/** ログインしてデバイス管理を開く */
export async function login(page: Page, user: { name: string; password: string } = USERS.admin) {
  await page.goto("/login");
  await page.locator("input").nth(0).fill(user.name);
  await page.locator('input[type="password"]').fill(user.password);
  await page.locator("button.btn-primary").click();
  await expect(page).toHaveURL(/\/devices/);
}
