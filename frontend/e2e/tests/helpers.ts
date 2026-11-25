import { expect, type Page } from "@playwright/test";

export const USERS = {
  admin: { name: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "initial-pass-123" },
  op: { name: "op1", password: "password-1234" },
  viewer: { name: "view1", password: "password-1234" },
};

/** サイドメニューから開ける全画面（navigation.spec.ts・csp.spec.ts で使う） */
export const PAGES = ["/dashboard", "/devices", "/topology", "/jump-hosts", "/credential-profiles", "/commands", "/collect", "/ping", "/history", "/reviews", "/search", "/terminal", "/schedules",
  "/compliance", "/ignore-rules", "/notifications", "/activity", "/audit", "/users", "/system"];

/** サイドメニューの大項目ごとの小項目（App.tsx の NAV_GROUPS と合わせる） */
const NAV_GROUP_OF: Record<string, string> = {
  "/devices": "機器", "/topology": "機器", "/terminal": "機器", "/commands": "機器", "/jump-hosts": "機器", "/credential-profiles": "機器",
  "/collect": "コンフィグ", "/schedules": "コンフィグ", "/history": "コンフィグ", "/reviews": "コンフィグ",
  "/search": "コンフィグ", "/compliance": "コンフィグ", "/ignore-rules": "コンフィグ",
  "/ping": "監視", "/monitoring": "監視", "/activity": "監視",
  "/notifications": "管理", "/users": "管理", "/audit": "管理", "/system": "管理",
};

/** そのパスを含む大項目が閉じていれば開いてから、サイドメニューのリンクを押す */
export async function openNav(page: Page, path: string) {
  const group = NAV_GROUP_OF[path];
  if (group) {
    const head = page.locator(".nav-group-head", { hasText: group });
    if ((await head.getAttribute("aria-expanded")) !== "true") await head.click();
  }
  await page.locator(`.sidebar-nav a[href="${path}"]`).click();
}

/** すべての大項目を開く（「メニューに出ない」ことを確かめる前に呼ぶ。閉じているだけで通らないように） */
export async function expandNav(page: Page) {
  const heads = page.locator(".nav-group-head");
  await expect(heads.first()).toBeVisible();
  const n = await heads.count();
  for (let i = 0; i < n; i++) {
    const h = heads.nth(i);
    if ((await h.getAttribute("aria-expanded")) !== "true") await h.click();
  }
  await expect(page.locator('.nav-group-head[aria-expanded="false"]')).toHaveCount(0);
}

/** ログインしてデバイス管理を開く */
export async function login(page: Page, user: { name: string; password: string } = USERS.admin) {
  await page.goto("/login");
  await page.locator("input").nth(0).fill(user.name);
  await page.locator('input[type="password"]').fill(user.password);
  await page.locator("button.btn-primary").click();
  // ログイン後はダッシュボードが開く。各テストはデバイス管理から始める
  await expect(page).toHaveURL(/\/dashboard/);
  await expect(page.locator(".dash-tile").first()).toBeVisible();
  await openNav(page, "/devices");
  await expect(page).toHaveURL(/\/devices/);
}
