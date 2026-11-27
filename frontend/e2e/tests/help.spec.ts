import { expect, test, type Page } from "@playwright/test";
import { USERS, login, openNav } from "./helpers";

// アプリ内のヘルプ（/help）。左ペインの「ヘルプ」・見出しの「?」・検索・権限による表示の違い・README への案内

const README = "https://github.com/s-michiaki/netconfig-manager/blob/master/README.md";
const article = (page: Page) => page.locator("article.help-article");
const articleTitle = (page: Page) => page.locator("article.help-article h2");
const helpNav = (page: Page) => page.locator("nav.help-nav");

test("左ペインの「ヘルプ」から、いま開いている画面の項目が開く", async ({ page }) => {
  await login(page); // デバイス管理を開いている
  await page.locator(".sidebar-footer").getByRole("link", { name: "ヘルプ" }).click();
  await expect(page).toHaveURL(/\/help\/devices$/);
  await expect(articleTitle(page)).toHaveText("デバイス管理");
  await expect(article(page).getByRole("heading", { name: "基本の使い方" })).toBeVisible();
  // 一覧の「デバイス管理」が選択中になる
  await expect(helpNav(page).getByRole("link", { name: "デバイス管理" })).toHaveAttribute("aria-current", "page");

  // 別の画面（ダッシュボード）では、その画面の項目
  await openNav(page, "/dashboard");
  await page.locator(".sidebar-footer").getByRole("link", { name: "ヘルプ" }).click();
  await expect(page).toHaveURL(/\/help\/dashboard$/);
  await expect(articleTitle(page)).toHaveText("ダッシュボード");

  // ヘルプの中から押すと、いま見ている項目のまま
  await page.locator(".sidebar-footer").getByRole("link", { name: "ヘルプ" }).click();
  await expect(page).toHaveURL(/\/help\/dashboard$/);
});

test("/help は「はじめに」を出し、大項目ごとに項目が並ぶ", async ({ page }) => {
  await login(page);
  await page.goto("/help");
  await expect(articleTitle(page)).toHaveText("はじめに");
  for (const g of ["ダッシュボード", "機器", "コンフィグ", "監視", "管理", "共通"]) {
    await expect(helpNav(page).locator(".help-nav-head", { hasText: new RegExp(`^${g}$`) })).toBeVisible();
  }
  for (const t of ["ログインと 2 段階認証", "ログアウト（この端末・すべての端末）", "API トークン",
    "ロールと権限（管理者・オペレーター・閲覧者でできること）", "導入・更新・バックアップ（管理者向け）"]) {
    await expect(helpNav(page).getByRole("link", { name: t })).toBeVisible();
  }
  await helpNav(page).getByRole("link", { name: "踏み台サーバ" }).click();
  await expect(page).toHaveURL(/\/help\/jump-hosts$/);
  await expect(articleTitle(page)).toHaveText("踏み台サーバ");
});

test("見出しの「?」から、その画面の項目が開く", async ({ page }) => {
  await login(page);
  const q = page.getByRole("link", { name: "この画面のヘルプ" });
  // 見出しの文字は変わらない（「?」は CSS で描く）
  await expect(page.locator(".page-title")).toHaveText("デバイス管理");
  await expect(q).toHaveAttribute("title", "この画面のヘルプ");
  await q.click();
  await expect(page).toHaveURL(/\/help\/devices$/);
  await expect(articleTitle(page)).toHaveText("デバイス管理");

  await openNav(page, "/topology");
  await expect(page).toHaveURL(/\/topology\/[\w-]+$/);
  await page.getByRole("link", { name: "この画面のヘルプ" }).click();
  await expect(page).toHaveURL(/\/help\/topology$/);
  await expect(articleTitle(page)).toHaveText("構成図");

  await openNav(page, "/ping");
  await page.getByRole("link", { name: "この画面のヘルプ" }).click();
  await expect(page).toHaveURL(/\/help\/ping$/);
  await expect(articleTitle(page)).toHaveText("Ping監視");
  // 「この画面を開く」で戻れる
  await article(page).getByRole("link", { name: "この画面を開く" }).click();
  await expect(page).toHaveURL(/\/ping$/);
});

test("検索で項目を絞り込める（大文字小文字を区別しない）。一致が無ければ「見つかりません」", async ({ page }) => {
  await login(page);
  await page.goto("/help");
  const search = page.getByRole("searchbox", { name: "ヘルプを検索" });
  await search.fill("踏み台");
  await expect(helpNav(page).getByRole("link", { name: "踏み台サーバ" })).toBeVisible();
  await expect(helpNav(page).getByRole("link", { name: "ダッシュボード" })).toHaveCount(0);

  await search.fill("PING");
  await expect(helpNav(page).getByRole("link", { name: "Ping監視" })).toBeVisible();
  await search.fill("ping");
  await expect(helpNav(page).getByRole("link", { name: "Ping監視" })).toBeVisible();

  await search.fill("zzzz-存在しない-zzzz");
  await expect(helpNav(page).getByText("見つかりません")).toBeVisible();
  await expect(helpNav(page).locator(".help-nav-group")).toHaveCount(0);

  await search.fill("");
  await expect(helpNav(page).getByRole("link", { name: "ダッシュボード" })).toBeVisible();
});

test("閲覧者には、管理者だけの画面の項目に「使えるロール」が出て、「この画面を開く」は出ない", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/help/users");
  await expect(articleTitle(page)).toHaveText("ユーザー管理");
  await expect(article(page).getByText("この画面は管理者が使えます。")).toBeVisible();
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveCount(0);
  // 項目そのものは隠さない（使い方は読める）
  await expect(article(page).getByRole("heading", { name: "基本の使い方" })).toBeVisible();

  await page.goto("/help/terminal");
  await expect(article(page).getByText("この画面はオペレーター以上が使えます。")).toBeVisible();
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveCount(0);

  // 閲覧者が使える画面には、開くリンクが出る
  await page.goto("/help/history");
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveAttribute("href", "/history");
});

test("管理者には「この画面を開く」が出る。機能が無効の画面には出ず、「無効になっています」と出る", async ({ page }) => {
  await login(page);
  await page.goto("/help/users");
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveAttribute("href", "/users");
  await expect(article(page).getByText("管理者が使えます")).toHaveCount(0);

  // モニタリングは既定で無効（画面テストの backend も無効のまま）
  await page.goto("/help/monitoring");
  await expect(articleTitle(page)).toHaveText("モニタリング");
  await expect(article(page).getByText("この環境では無効になっています。")).toBeVisible();
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveCount(0);

  // 脆弱性・サポート期限は有効（VULN_ENABLED=true で起動している）
  await page.goto("/help/vulns");
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveAttribute("href", "/vulns");
});

test("README への案内は管理者向けの項目だけにあり、別のタブで開く", async ({ page }) => {
  await login(page);
  await page.goto("/help/install");
  const links = article(page).locator(".help-readme a");
  await expect(links).not.toHaveCount(0);
  for (const a of await links.all()) {
    await expect(a).toHaveAttribute("target", "_blank");
    await expect(a).toHaveAttribute("rel", /noopener/);
    await expect(a).toHaveAttribute("href", new RegExp(`^${README.replace(/[.]/g, "\\.")}`));
  }
  // 記号の無い見出しにはアンカー、記号を含む見出しは README の先頭
  await expect(links.getByText("セットアップ", { exact: true })).toHaveAttribute("href", `${README}#セットアップ`);
  await expect(links.getByText("RHEL 10 本番設定")).toHaveAttribute("href", `${README}#rhel-10-本番設定`);
  await page.goto("/help/system");
  const sys = article(page).locator(".help-readme a", { hasText: "システム状態（止まっていることに気づく）" });
  await expect(sys).toHaveAttribute("href", README);
  await expect(article(page).getByText("/opt/netconfig-manager/README.md")).toBeVisible();

  // 管理者でない人が使う項目には、README の案内は無い
  await page.goto("/help/devices");
  await expect(article(page).locator(".help-readme")).toHaveCount(0);
});

test("知らない項目の URL は /help に戻る", async ({ page }) => {
  await login(page);
  await page.goto("/help/no-such-topic");
  await expect(page).toHaveURL(/\/help$/);
  await expect(articleTitle(page)).toHaveText("はじめに");
});

test("すべての項目を開ける（本文が出て、エラーにならない）", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  await page.goto("/help");
  const links = helpNav(page).locator("a.help-nav-item");
  await expect(links.first()).toBeVisible();
  const n = await links.count();
  expect(n).toBeGreaterThanOrEqual(25);
  for (let i = 1; i < n; i++) { // 0 番目は「はじめに」
    const title = ((await links.nth(i).textContent()) ?? "").trim();
    await links.nth(i).click();
    // 前の項目の見出しが残ったまま通らないよう、この項目の title になるのを待つ
    await expect(articleTitle(page)).toHaveText(title);
    await expect(article(page).getByRole("heading", { name: "基本の使い方" })).toBeVisible();
    await expect(article(page).getByRole("heading", { name: "つまずきやすいところ・注意" })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test("/api/health を読めないときは、機能の設定による「無効」の表示を出さず、権限だけで開くリンクを出す", async ({ page }) => {
  await login(page);
  await page.route("**/api/health", (route) => route.abort());
  await page.goto("/help/monitoring");
  await expect(articleTitle(page)).toHaveText("モニタリング");
  await expect(article(page).getByRole("link", { name: "この画面を開く" })).toHaveAttribute("href", "/monitoring");
  await expect(article(page).getByText("この環境では無効になっています。")).toHaveCount(0);
});

test("「?」の押せる範囲は 24px 以上で、見出しの行の高さは変わらない", async ({ page }) => {
  await login(page);
  await page.goto("/activity");
  const q = page.getByRole("link", { name: "この画面のヘルプ" });
  const box = await q.boundingBox();
  expect(box!.width).toBeGreaterThanOrEqual(24);
  expect(box!.height).toBeGreaterThanOrEqual(24);
  // 同じ作り（見出しと説明の文字だけ）のヘルプの画面の見出しの行と、高さが同じ
  const withLink = (await page.locator(".page-header").boundingBox())!.height;
  await page.goto("/help");
  await expect(articleTitle(page)).toBeVisible();
  const without = (await page.locator(".page-header").boundingBox())!.height;
  expect(withLink).toBe(without);
});
