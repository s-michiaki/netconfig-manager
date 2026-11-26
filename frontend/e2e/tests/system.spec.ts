import { expect, test } from "@playwright/test";
import { login, openNav } from "./helpers";

test("システム状態: 項目メニューで状態を確認し、画面に表示する項目を ＋/− で選ぶ", async ({ page }) => {
  await login(page);
  await page.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith("ncm.system.hidden.")).forEach((k) => localStorage.removeItem(k)));
  await openNav(page, "/system");
  const cards = page.locator(".sys-grid .sys-card");
  await expect(cards.filter({ hasText: "ディスクの空き" })).toHaveCount(1);
  const total = await cards.count();
  await expect(page.locator(".sys-note")).toContainText("通知先（Discord / Slack / Teams / メール）");

  // 項目メニュー: 選ぶと状態（詳細）を表示
  await page.getByRole("button", { name: /^項目/ }).click();
  const menu = page.getByRole("dialog", { name: "項目の状態と表示" });
  await expect(menu).toBeVisible();
  await expect(menu.locator(".sys-menu-item")).toHaveCount(total);
  await menu.getByRole("button", { name: /^ディスクの空き (正常|注意|異常|不明)/ }).click();
  await expect(menu.locator(".sys-menu-detail")).toContainText("コンフィグ履歴");

  // − で画面から外す（メニューでは確認できる）
  await menu.getByRole("button", { name: "ディスクの空き を画面から外す" }).click();
  await expect(cards.filter({ hasText: "ディスクの空き" })).toHaveCount(0);
  await expect(cards).toHaveCount(total - 1);
  await expect(page.getByRole("button", { name: /^項目/ })).toContainText("1 件非表示");

  // Esc で閉じる。再読み込みしても覚えている
  await page.keyboard.press("Escape");
  await expect(menu).toBeHidden();
  await page.reload();
  await expect(cards.first()).toBeVisible();
  await expect(cards.filter({ hasText: "ディスクの空き" })).toHaveCount(0);

  // ＋ で戻す
  await page.getByRole("button", { name: /^項目/ }).click();
  await menu.getByRole("button", { name: "ディスクの空き を画面に表示する" }).click();
  await expect(cards.filter({ hasText: "ディスクの空き" })).toHaveCount(1);
  await expect(cards).toHaveCount(total);
});

test("システム状態: 要確認の項目を外すと、画面の上に知らせる", async ({ page }) => {
  await login(page);
  await openNav(page, "/system");
  await expect(page.locator(".sys-grid .sys-card").first()).toBeVisible();
  // e2e の環境では Redis に接続できないため「Redis」は異常
  await page.getByRole("button", { name: /^項目/ }).click();
  const menu = page.getByRole("dialog", { name: "項目の状態と表示" });
  await menu.getByRole("button", { name: "Redis を画面から外す" }).click();
  await menu.getByRole("button", { name: "閉じる" }).click();
  const alert = page.locator(".sys-hidden-alert");
  await expect(alert).toContainText("Redis（異常）");
  await alert.getByRole("button", { name: /Redis/ }).click(); // 押すと画面に戻す
  await expect(alert).toBeHidden();
  await expect(page.locator(".sys-grid .sys-card .sys-head", { hasText: /^Redis/ })).toHaveCount(1);
});
