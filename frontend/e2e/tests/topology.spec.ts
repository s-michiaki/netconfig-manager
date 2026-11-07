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
