import { expect, test } from "@playwright/test";
import { USERS, login } from "./helpers";

test("閲覧者がコンフィグを横断検索し、一致した機器としなかった機器を確認できる", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/search");
  await page.getByPlaceholder(/192\.168\.10\.1/).fill("ip http server");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText("2 台で 2 行が一致");
  const hit = page.locator(".srch-device", { hasText: "SW-2F" });
  await expect(hit.locator("mark")).toHaveText("ip http server");
  await expect(page.locator(".srch-device", { hasText: "DC-SW01" })).toBeVisible();
  // 一致しなかった機器（＝この設定が入っていない機器）
  const rest = page.locator("details", { hasText: "一致しなかった機器（2 台）" });
  await rest.locator("summary").click();
  await expect(rest).toContainText("Core-SW01");

  // 正規表現・前後の行・グループの絞り込み
  await page.locator("select").nth(0).selectOption("regex");
  await page.locator("select").nth(1).selectOption({ label: "本社" });
  await page.locator("select").nth(2).selectOption("1");
  await page.locator("input.mono").fill("^interface .*0/2$");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText("1 台で 1 行が一致（3 台を検索）");
  await expect(page.locator(".srch-ctx")).toContainText("description uplink");
  // 正規表現の誤りはメッセージで知らせる
  await page.locator("input.mono").fill("(");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".form-error")).toContainText("正規表現が正しくありません");
  // 世代管理へ移動できる
  await page.locator("input.mono").fill("hostname");
  await page.getByRole("button", { name: "検索" }).click();
  await page.locator(".srch-device").first().getByRole("link", { name: /世代管理で開く/ }).click();
  await expect(page).toHaveURL(/\/history\?device=/);
});
