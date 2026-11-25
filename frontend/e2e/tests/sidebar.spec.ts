import { expect, test } from "@playwright/test";
import { USERS, expandNav, login } from "./helpers";

// 左ペインの大項目（機器・コンフィグ・監視・管理）の開閉

const link = (page: import("@playwright/test").Page, path: string) =>
  page.locator(`.sidebar-nav a[href="${path}"]`);
const head = (page: import("@playwright/test").Page, label: string) =>
  page.locator(".nav-group-head", { hasText: label });

test("大項目を押すと小項目が開閉し、閉じている間は小項目を描画しない", async ({ page }) => {
  await login(page); // ログイン後は /devices を開いているので「機器」だけが開いている
  await expect(head(page, "機器")).toHaveAttribute("aria-expanded", "true");
  await expect(head(page, "コンフィグ")).toHaveAttribute("aria-expanded", "false");
  await expect(link(page, "/history")).toHaveCount(0);

  // 複数の大項目を同時に開ける
  await head(page, "コンフィグ").click();
  await expect(link(page, "/history")).toBeVisible();
  await expect(link(page, "/devices")).toBeVisible();
  // aria-controls は開いた小項目の領域を指す
  const id = await head(page, "コンフィグ").getAttribute("aria-controls");
  await expect(page.locator(`#${id}`).locator('a[href="/history"]')).toBeVisible();

  await head(page, "コンフィグ").click();
  await expect(link(page, "/history")).toHaveCount(0);
  // 閉じても、開いている画面（デバイス管理）は残る。別の大項目の開閉は影響しない
  await expect(page).toHaveURL(/\/devices/);
  await expect(link(page, "/devices")).toBeVisible();
});

test("キーボードの Enter / Space で開閉できる", async ({ page }) => {
  await login(page);
  const h = head(page, "監視");
  await h.focus();
  await page.keyboard.press("Enter");
  await expect(h).toHaveAttribute("aria-expanded", "true");
  await page.keyboard.press("Space");
  await expect(h).toHaveAttribute("aria-expanded", "false");
});

test("開閉の状態はブラウザに覚えていて、再読み込みしても変わらない", async ({ page }) => {
  await login(page);
  await head(page, "管理").click();
  await head(page, "機器").click(); // 開いている画面の大項目を手で閉じる
  await expect(link(page, "/users")).toBeVisible();
  await expect(link(page, "/devices")).toHaveCount(0);
  // 閉じた大項目の中にいま開いている画面があるときは、見出しを選択中の色にする
  await expect(head(page, "機器")).toHaveClass(/active/);

  // 開いている画面を含む大項目は再読み込みで開くので、ダッシュボードへ移ってから再読み込みする
  await link(page, "/dashboard").click();
  await expect(head(page, "機器")).toHaveClass(/nav-group-head$/);
  await page.reload();
  await expect(head(page, "管理")).toHaveAttribute("aria-expanded", "true");
  await expect(head(page, "機器")).toHaveAttribute("aria-expanded", "false");
  await expect(link(page, "/devices")).toHaveCount(0);
  const saved = await page.evaluate(() =>
    Object.keys(localStorage).filter((k) => k.startsWith("ncm.nav.open.")));
  expect(saved).toEqual([`ncm.nav.open.${USERS.admin.name}`]);
});

test("URL を直接開くと、その画面を含む大項目が開く", async ({ page }) => {
  await login(page);
  await page.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith("ncm.nav.open.")).forEach((k) => localStorage.removeItem(k)));
  await page.goto("/audit");
  await expect(head(page, "管理")).toHaveAttribute("aria-expanded", "true");
  await expect(link(page, "/audit")).toHaveClass(/active/);
  // 初めての人は、いまの画面を含む大項目だけが開いている
  for (const other of ["機器", "コンフィグ", "監視"]) {
    await expect(head(page, other)).toHaveAttribute("aria-expanded", "false");
  }
});

test("手で閉じていても、別の大項目の画面へアプリ内のリンクで移れば開く", async ({ page }) => {
  await login(page);
  await link(page, "/dashboard").click();
  await head(page, "監視").click();
  await head(page, "監視").click();
  await expect(head(page, "監視")).toHaveAttribute("aria-expanded", "false");
  // ダッシュボードの「収集に失敗」のタイルは /activity（監視）へ移る（再読み込みではない移動）
  await page.locator(".dash-tile", { hasText: "収集に失敗" }).click();
  await expect(page).toHaveURL(/\/activity/);
  await expect(head(page, "監視")).toHaveAttribute("aria-expanded", "true");
  await expect(link(page, "/activity")).toHaveClass(/active/);
});

test("同じ大項目の中の移動では、手で閉じた大項目を開き直さない", async ({ page }) => {
  await login(page); // /devices（機器）
  await head(page, "機器").click();
  await expect(head(page, "機器")).toHaveAttribute("aria-expanded", "false");
  // 機器カードから /terminal/<id>（同じ「機器」の中）へ移る
  await page.getByText("クリックでターミナルを開く").first().click();
  await expect(page).toHaveURL(/\/terminal\/\d+/);
  await expect(head(page, "機器")).toHaveAttribute("aria-expanded", "false");
  await expect(head(page, "機器")).toHaveClass(/active/);
});

test("見られる小項目が 1 つも無い大項目は出さない（権限を絞ったロール）", async ({ browser }) => {
  const ctx = await browser.newContext();
  try {
    const page = await ctx.newPage();
    // 実際の応答の permissions だけを、機器の閲覧とコンフィグの閲覧に絞る
    await page.route("**/api/auth/me", async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      await route.fulfill({ response: res, json: { ...body, permissions: ["device:read", "config:read"] } });
    });
    await login(page, USERS.viewer);
    await expandNav(page);
    await expect(head(page, "機器")).toHaveCount(1);
    await expect(head(page, "コンフィグ")).toHaveCount(1);
    await expect(head(page, "監視")).toHaveCount(0);
    await expect(head(page, "管理")).toHaveCount(0);
    // 見出しがあるなら、その中に必ず小項目がある
    const groups = page.locator(".nav-group");
    const n = await groups.count();
    expect(n).toBe(2);
    for (let i = 0; i < n; i++) {
      await expect(groups.nth(i).locator(".nav-sub a").first()).toBeVisible();
    }
  } finally {
    await ctx.close();
  }
});

test("閲覧者には管理用の項目が出ない", async ({ browser }) => {
  const ctx = await browser.newContext();
  try {
    const page = await ctx.newPage();
    await login(page, USERS.viewer);
    await expandNav(page);
    await expect(link(page, "/users")).toHaveCount(0);
    await expect(link(page, "/audit")).toHaveCount(0);
    await expect(link(page, "/system")).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});

test("「管理」を閉じているとき、システム状態の印を大項目の見出しに出す", async ({ page }) => {
  await login(page);
  // e2e の環境では Redis に接続できないため、システム状態は異常（赤）になる
  await head(page, "管理").click();
  await expect(head(page, "管理").locator(".nav-alert")).toHaveCount(0); // 開いている間は項目に出る
  await expect(link(page, "/system").locator(".nav-alert")).toBeVisible();
  await head(page, "管理").click();
  await expect(head(page, "管理").locator(".nav-alert")).toBeVisible();
  await expect(link(page, "/system")).toHaveCount(0);
});
