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
  // （select は並び順ではなくラベルで選ぶ。項目を足しても壊れないように）
  await page.getByLabel("探し方").selectOption("regex");
  await page.getByLabel("機器グループ").selectOption({ label: "本社" });
  await page.getByLabel("前後の行").selectOption("1");
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

test("機種で絞り込み、検索結果の一致した行を CSV で出力できる", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/search");
  await page.locator("input.mono").fill("interface");
  // CSV のリクエストに検索語が URL として載らないことも確かめる
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText("4 台で 6 行が一致（4 台を検索）");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "CSV 出力" }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^config_search_\d{8}-\d{6}\.csv$/);
  const csv = (await (await import("node:fs/promises")).readFile((await dl.path())!, "utf-8")).replace(/^\uFEFF/, "");
  const lines = csv.trim().split("\r\n");
  expect(lines[0]).toBe("機器名,ホスト / IP,機種,グループ,世代,行番号,一致した行");
  expect(lines).toHaveLength(7);
  expect(lines[1]).toMatch(/^Core-SW01,10\.0\.1\.1,.*,本社,[0-9a-f]{7},3,interface GigabitEthernet0\/1$/);
  expect(urls.filter((u) => u.includes("interface"))).toEqual([]);

  // 機種で絞る（初期データの機器はすべて Cisco IOS）
  await page.getByLabel("機種").selectOption("fortinet");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText("0 台で 0 行が一致（0 台を検索）");
  await expect(page.getByRole("button", { name: "CSV 出力" })).toBeDisabled();
  await page.getByLabel("機種").selectOption("cisco_ios");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText("4 台で 6 行が一致（4 台を検索）");
});

test("過去の世代も含めて検索し、いつから入っているかを確認できる", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/search");
  await page.getByLabel("対象の世代").selectOption("history");
  await expect(page.getByLabel("期間の開始")).toBeVisible();
  await expect(page.getByLabel("前後の行")).toBeDisabled();
  await page.getByPlaceholder(/192\.168\.10\.1/).fill("logging host 10.0.9.9");
  await page.getByRole("button", { name: "検索" }).click();
  await expect(page.locator(".srch-summary")).toContainText(/1 台で 1 種類の行が一致（\d+ 台・\d+ 世代を検索）/);
  const hit = page.locator(".srch-device", { hasText: "Core-SW01" });
  await expect(hit.locator(".srch-seen")).toContainText("いまもある");
  // 最初に見つかった世代（2 世代目で追加した行）を世代管理で開ける
  await hit.locator(".srch-seen a").first().click();
  await expect(page).toHaveURL(/\/history\?device=.+&commit=[0-9a-f]{40}/);
});
