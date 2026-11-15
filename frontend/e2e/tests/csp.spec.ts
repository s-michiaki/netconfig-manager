import { expect, test, type Page } from "@playwright/test";
import { readCsp } from "../csp";
import { login, PAGES } from "./helpers";

// 本番の nginx と同じ CSP を付けた本番ビルド（playwright.config.ts の csp プロジェクト・4173 番）で、
// 全画面・書き出し・ダウンロード・WebSocket が CSP に止められないことを確認する
const csp = readCsp();

/** CSP 違反（コンソールの「Refused to …」）とページのエラーを集める。印刷用などの新しいウィンドウも対象にする */
function collectViolations(page: Page) {
  const found: string[] = [];
  const watch = (p: Page) => {
    p.on("console", (m) => {
      if (/Content Security Policy|Refused to/i.test(m.text())) found.push(m.text());
    });
    p.on("pageerror", (e) => found.push(`pageerror: ${e.message}`));
  };
  watch(page);
  page.context().on("page", watch);
  return found;
}

test("本番と同じ CSP が付いている（/docs だけ別の値）", async ({ page }) => {
  const top = await page.request.get("/");
  expect(top.headers()["content-security-policy"]).toBe(csp.app);
  // スクリプトは同じサーバーのものだけ（インライン・eval は許可しない）
  expect(csp.app).toMatch(/script-src 'self';/);
  expect(csp.app).not.toContain("unsafe-eval");
  expect(csp.app).not.toMatch(/script-src[^;]*unsafe-inline/);
  // /docs（Swagger UI）は CDN を使うため別の値。中身は CDN に依存するのでヘッダーだけ確かめる
  const docs = await page.request.get("/docs");
  expect(docs.headers()["content-security-policy"]).toBe(csp.docs);
});

test("CSP を付けても全画面・書き出し・ダウンロード・WebSocket が動く", async ({ page }) => {
  test.setTimeout(90_000);
  const violations = collectViolations(page);
  // フォントなどを外部から読み込まない（閉じたネットワークでも表示が変わらないこと）
  const external: string[] = [];
  page.on("request", (r) => {
    const url = r.url();
    if (!/^(data|blob):/.test(url) && !url.startsWith("http://127.0.0.1:4173/")) external.push(url);
  });

  await login(page);
  for (const path of PAGES) {
    await page.locator(`a[href="${path}"]`).first().click();
    // 構成図は読み込み後に最後に開いた図（/topology/<id>）へ移るので、移り終わるのを待つ（次の画面への移動と競合しないように）
    await expect(page).toHaveURL(path === "/topology" ? /\/topology\/[\w-]+$/ : new RegExp(`${path}$`));
    await expect(page.locator(".page-title").first()).toBeVisible();
  }

  // ターミナル（xterm.js は <style> 要素を作って表示を整える）
  await page.goto("/terminal");
  await expect(page.locator(".xterm-rows")).toContainText("NetConfig Manager");
  // 画面のフォントはビルドに含めたものを使う
  const fonts = await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family.replace(/"/g, ""));
  });
  expect(fonts).toEqual(expect.arrayContaining(["Inter", "Noto Sans JP", "JetBrains Mono"]));

  // WebSocket（Ping 監視。ターミナルも同じく同じホストへの ws: で接続する）
  const ws = await page.evaluate(() => new Promise<string>((resolve) => {
    const s = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ping/ws`);
    s.onopen = () => { s.close(); resolve("open"); };
    s.onerror = () => resolve("error");
    setTimeout(() => resolve("timeout"), 5000);
  }));
  expect(ws).toBe("open");

  // CSV のダウンロード（blob: の URL）
  await page.goto("/devices");
  const [csv] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "台帳 CSV" }).click()]);
  expect(await csv.path()).toBeTruthy();

  // 構成図の書き出し（PNG・PDF）と印刷（新しいウィンドウに <style> と data: の画像を書き込む）
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page.locator(".react-flow__node-device").first()).toBeVisible();
  for (const name of [/PNG/, /PDF/]) {
    await page.getByRole("button", { name: /書き出し/ }).click();
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", { name }).first().click()]);
    expect(await dl.path()).toBeTruthy();
  }
  await page.getByRole("button", { name: /書き出し/ }).click();
  const [popup] = await Promise.all([page.context().waitForEvent("page"), page.getByRole("menuitem", { name: /印刷/ }).click()]);
  await expect.poll(() => popup.locator("img").evaluate((img: HTMLImageElement) => img.naturalWidth)).toBeGreaterThan(0);
  await popup.close();

  expect(violations).toEqual([]);
  expect(external).toEqual([]);
});
