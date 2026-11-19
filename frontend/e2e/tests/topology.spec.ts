import { expect, test } from "@playwright/test";
import { login } from "./helpers";

test("構成図を編集し、取り消し・やり直しのあと保存できる", async ({ page }) => {
  await login(page);
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page.locator(".react-flow__node-device")).toHaveCount(4);
  await page.getByRole("button", { name: "編集", exact: true }).click();

  const texts = page.locator(".react-flow__node-text");
  await page.getByRole("button", { name: "テキスト" }).click();
  await expect(texts).toHaveCount(1);
  await expect(page.locator(".topo-dirty")).toBeVisible();
  // 取り消すと保存済みの状態に戻り「未保存」も消える
  await page.getByRole("button", { name: "取り消す" }).click();
  await expect(texts).toHaveCount(0);
  await expect(page.locator(".topo-dirty")).toHaveCount(0);
  await page.getByRole("button", { name: "やり直す" }).click();
  await expect(texts).toHaveCount(1);

  await page.locator("button.btn-primary", { hasText: "保存" }).click();
  await expect(page.locator(".topo-notice")).toHaveText("保存しました");
  await page.reload();
  await expect(page.locator(".react-flow__node-text")).toHaveCount(1);
});

test("保存したあとも、保存より前の状態へ取り消せる", async ({ page }) => {
  await login(page);
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page.locator(".react-flow__node-device")).toHaveCount(4);
  await page.getByRole("button", { name: "編集", exact: true }).click();
  const texts = page.locator(".react-flow__node-text");
  const before = await texts.count();

  await page.getByRole("button", { name: "テキスト" }).click();
  await expect(texts).toHaveCount(before + 1);
  await page.locator("button.btn-primary", { hasText: "保存" }).click();
  await expect(page.locator(".topo-notice")).toHaveText("保存しました");
  await expect(page.locator(".topo-dirty")).toHaveCount(0);
  // 保存しても取り消せる。保存した状態から離れるので「未保存」になる
  await expect(page.getByRole("button", { name: "取り消す" })).toBeEnabled();
  await page.keyboard.press("ControlOrMeta+z");
  await expect(texts).toHaveCount(before);
  await expect(page.locator(".topo-dirty")).toBeVisible();
  // やり直すと保存した状態に戻り「未保存」が消える
  await page.getByRole("button", { name: "やり直す" }).click();
  await expect(texts).toHaveCount(before + 1);
  await expect(page.locator(".topo-dirty")).toHaveCount(0);
  // 取り消した状態を保存して元に戻す（ほかのテストに影響させない）
  await page.getByRole("button", { name: "取り消す" }).click();
  await page.locator("button.btn-primary", { hasText: "保存" }).click();
  await expect(page.locator(".topo-notice")).toHaveText("保存しました");
  await page.reload();
  await expect(page.locator(".react-flow__node-text")).toHaveCount(before);
});

test("構成図を PDF で書き出せる", async ({ page }) => {
  await login(page);
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page.locator(".react-flow__node-device").first()).toBeVisible();
  await page.getByRole("button", { name: /書き出し/ }).click();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", { name: /PDF/ }).click()]);
  const path = await dl.path();
  expect(path).toBeTruthy();
});

test("PNG は画面の配色と白背景でファイル名を分けて書き出す", async ({ page }) => {
  // ブラウザが付けるファイル名（suggestedFilename）は、実行環境のロケールが UTF-8 でないと日本語が "download" に
  // 置き換わるため、画面が指定した名前（a 要素の download 属性）を記録して確かめる
  await page.addInitScript(() => {
    const names: string[] = [];
    (window as unknown as { __downloads: string[] }).__downloads = names;
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      if (this.download) names.push(this.download);
      return click.call(this);
    };
  });
  await login(page);
  await page.goto("/topology");
  await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
  await expect(page.locator(".react-flow__node-device").first()).toBeVisible();
  const exportPng = async (name: string) => {
    await page.getByRole("button", { name: /書き出し/ }).click();
    await Promise.all([page.waitForEvent("download"), page.getByRole("menuitem", { name, exact: true }).click()]);
    return page.evaluate(() => (window as unknown as { __downloads: string[] }).__downloads.at(-1));
  };
  expect(await exportPng("PNG（画面の配色）")).toBe("本社ネットワーク_物理構成.png");
  expect(await exportPng("PNG（白背景）")).toBe("本社ネットワーク_物理構成_白背景.png");
});

// 「未保存の変更あり」が出ても消えても、編集中のボタンの位置は変わらない（狭い画面で折り返したときも）
for (const width of [1440, 1000]) {
  test(`編集中のボタンは「未保存」の表示で動かない（幅 ${width}px）`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await login(page);
    await page.goto("/topology");
    await page.locator(".topo-map-select").selectOption({ label: "本社ネットワーク" });
    await expect(page.locator(".react-flow__node-device").first()).toBeVisible();
    await page.getByRole("button", { name: "編集", exact: true }).click();

    const buttons = [
      page.getByRole("button", { name: /書き出し/ }),
      page.getByRole("button", { name: "取り消す" }),
      page.getByRole("button", { name: "やり直す" }),
      page.getByRole("button", { name: "変更を破棄" }),
      page.getByRole("button", { name: "編集を終了" }),
      page.locator("button.btn-primary", { hasText: "保存" }),
    ];
    const positions = async () => Promise.all(buttons.map(async (b) => {
      const box = await b.boundingBox();
      return box && { x: Math.round(box.x), y: Math.round(box.y) };
    }));
    const before = await positions();
    await page.getByRole("button", { name: "テキスト" }).click();
    await expect(page.locator(".topo-dirty")).toBeVisible();
    expect(await positions()).toEqual(before);
    await page.getByRole("button", { name: "取り消す" }).click();
    await expect(page.locator(".topo-dirty")).toHaveCount(0);
    expect(await positions()).toEqual(before);
  });
}
