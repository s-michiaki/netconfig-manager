import { expect, test, type Page } from "@playwright/test";
import { USERS, login, openNav } from "./helpers";

// コマンド実行。e2e の backend には Redis・worker が無いので、実行の投入後（進み具合・結果・書き出し）は API をルートで差し替える。
// 入力中の検証（送れないコマンドの理由）は実際の API で確かめる

const NOW = "2026-11-25T01:00:00Z";
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const SAME = "Version 17.06.05\nuptime is 5 weeks";

function item(command: string, output: string) {
  return { command, output, truncated: false, chars: output.length };
}
function result(id: string, name: string, status: string, outputs: ReturnType<typeof item>[] | null, error: string | null = null) {
  return {
    id, device_id: `dev-${id}`, device_name: name, platform: "cisco_ios", platform_label: "Cisco IOS", status, error,
    started_at: NOW, finished_at: status === "ok" || status === "failed" ? NOW : null, outputs,
  };
}
const COMMANDS = ["show clock", "show version | include Version"];
const RESULTS = [
  result("r1", "Core-SW01", "ok", [item(COMMANDS[0], "12:00:00 JST"), item(COMMANDS[1], SAME)]),
  result("r2", "SW-2F", "ok", [item(COMMANDS[0], "12:00:00 JST  "), item(COMMANDS[1], SAME)]), // 行末の空白だけが違う
  result("r3", "SW-3F", "ok", [item(COMMANDS[0], "12:00:00 JST"), item(COMMANDS[1], "Version 15.2(7)E7")]),
];
const COUNTS_DONE = { queued: 0, running: 0, ok: 3, failed: 0, skipped: 0 };
const run = (finished: boolean, full: boolean) => ({
  id: RUN_ID, commands: COMMANDS, target: "devices", target_name: "Core-SW01、SW-2F、SW-3F", created_by: USERS.op.name,
  created_at: NOW, total: 3, finished_at: finished ? NOW : null, finished,
  counts: finished ? COUNTS_DONE : { queued: 1, running: 1, ok: 1, failed: 0, skipped: 0 },
  results: finished
    ? RESULTS.map((r) => (full ? r : { ...r, outputs: null }))
    : [result("r1", "Core-SW01", "ok", null), result("r2", "SW-2F", "running", null), result("r3", "SW-3F", "queued", null)],
  ...(finished && full
    ? {
      groups: [
        { index: 0, command: COMMANDS[0], groups: [{ result_id: "r1", truncated: false, count: 3, devices: RESULTS.map((r) => ({ id: r.device_id, name: r.device_name, result_id: r.id })) }] },
        {
          index: 1, command: COMMANDS[1], groups: [
            { result_id: "r1", truncated: false, count: 2, devices: [RESULTS[0], RESULTS[1]].map((r) => ({ id: r.device_id, name: r.device_name, result_id: r.id })) },
            { result_id: "r3", truncated: false, count: 1, devices: [{ id: RESULTS[2].device_id, name: "SW-3F", result_id: "r3" }] },
          ],
        },
      ],
    }
    : {}),
});

/** 実行の投入・進み具合・結果・書き出しを差し替える（1 回目の進み具合は実行中、2 回目から完了） */
async function mockRun(page: Page) {
  const state = { posted: null as unknown, polls: 0, listed: false };
  await page.route("**/api/commands/runs", async (route) => {
    if (route.request().method() === "POST") {
      state.posted = route.request().postDataJSON();
      return route.fulfill({ status: 201, json: { id: RUN_ID, total: 3, queued: 3, skipped: 0 } });
    }
    const body = state.polls > 0 ? [{ ...run(true, false), results: undefined }] : [];
    return route.fulfill({ json: body });
  });
  await page.route(`**/api/commands/runs/${RUN_ID}?*`, async (route) => {
    const light = new URL(route.request().url()).searchParams.get("outputs") === "false";
    if (light) {
      state.polls += 1;
      return route.fulfill({ json: run(state.polls > 1, false) });
    }
    return route.fulfill({ json: run(true, true) });
  });
  await page.route(`**/api/commands/runs/${RUN_ID}`, (route) => route.fulfill({ json: run(true, true) }));
  await page.route(`**/api/commands/runs/${RUN_ID}/export?*`, (route) => {
    const csv = new URL(route.request().url()).searchParams.get("format") === "csv";
    return route.fulfill({
      status: 200, contentType: csv ? "text/csv; charset=utf-8" : "text/plain; charset=utf-8",
      headers: { "Content-Disposition": `attachment; filename="command-run_20261125-100000.${csv ? "csv" : "txt"}"` },
      body: csv ? "機器名,出力\r\nCore-SW01,x\r\n" : "===== Core-SW01 =====\n",
    });
  });
  return state;
}

test("閲覧者にはメニューも画面も出ない", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/commands");
  await expect(page.locator("#cmd-input")).toHaveCount(0);
  await expect(page.locator('.sidebar-nav a[href="/commands"]')).toHaveCount(0);
});

test("送れないコマンドは入力中に理由が出て実行できず、送れるコマンドで実行して結果を見られる", async ({ browser }) => {
  const ctx = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const page = await ctx.newPage();
  const state = await (async () => { await login(page, USERS.op); return mockRun(page); })();

  await openNav(page, "/commands");
  await expect(page).toHaveURL(/\/commands$/);
  await expect(page.locator(".cmd-note")).toContainText("表示コマンドだけ送れます");
  const run_ = page.getByRole("button", { name: /実行/ }).first();
  await expect(run_).toBeDisabled(); // 機器もコマンドも未入力

  // 機器: グループを選ぶと、そのグループの機器が選ばれる
  await page.getByLabel("グループで選ぶ").selectOption({ label: "本社" });
  await expect(page.getByText("3 台を選択中")).toBeVisible();

  // 設定を変えるコマンド・危険な書き方は、実際の API の検証の理由が出て、実行できない
  const input = page.locator("#cmd-input");
  await input.fill("show clock\nconf t");
  const errors = page.getByRole("list", { name: "コマンドの確認結果" });
  await expect(errors).toContainText("2 行目: Cisco IOS の機器（3 台）には送れず、対象外になります");
  await expect(errors).toContainText("「conf」から始まるコマンドは送れません");
  await expect(page.getByText("選んだ機器のすべてに、送れないコマンドが含まれています")).toBeVisible();
  await expect(run_).toBeDisabled();
  await input.fill("show clock; reload");
  await expect(errors).toContainText("「;」は使えません");
  await expect(run_).toBeDisabled();
  await input.fill("show run | redirect flash:x");
  await expect(errors).toContainText("redirect");
  await input.fill("show clock\nshow version\nshow a\nshow b\nshow c\nshow d");
  await expect(page.getByText("コマンドは 5 個までです（6 個あります）")).toBeVisible();
  await expect(run_).toBeDisabled();

  // 送れるコマンドにすると、確認の表示が消えて実行できる
  await input.fill(COMMANDS.join("\n"));
  await expect(errors).toHaveCount(0);
  await expect(run_).toBeEnabled();
  await run_.click();
  await expect.poll(() => state.posted).not.toBeNull();
  expect(state.posted).toMatchObject({ commands: COMMANDS });
  expect((state.posted as { device_ids: string[] }).device_ids).toHaveLength(3);

  // 進み具合（自動で更新される）: 最初は実行中、そのあと完了
  const panel = page.getByLabel("実行結果");
  await expect(panel).toContainText("実行中");
  await expect(panel).toContainText("完了 1 / 失敗 0 / 対象外 0 / 実行中・待機中 2");
  await expect(panel.getByText("実行結果", { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(panel.getByRole("status")).toHaveText("完了 3 / 失敗 0 / 対象外 0");

  // 機器ごと: 折りたたみ。3 台なので開いている
  const devs = panel.locator("details.cmd-device");
  await expect(devs).toHaveCount(3);
  await expect(devs.nth(0).getByLabel("出力: show clock")).toHaveText("12:00:00 JST");
  await devs.nth(0).locator("summary").click();
  await expect(devs.nth(0).getByLabel("出力: show clock")).toBeHidden();
  await panel.getByRole("button", { name: "すべて開く" }).click();
  await expect(devs.nth(0).getByLabel("出力: show clock")).toBeVisible();
  await panel.getByRole("button", { name: "すべて閉じる" }).click();
  await expect(devs.nth(2).getByLabel("出力: show clock")).toBeHidden();
  // 閉じている機器の出力（<pre>）は DOM にない。開くと出る
  await expect(panel.locator("pre.cmd-output")).toHaveCount(0);
  await devs.nth(1).locator("summary").click();
  await expect(devs.nth(1).locator("pre.cmd-output")).toHaveCount(2);
  await expect(panel.locator("pre.cmd-output")).toHaveCount(2);
  await devs.nth(1).locator("summary").click();
  await expect(panel.locator("pre.cmd-output")).toHaveCount(0);
  await panel.getByRole("button", { name: "すべて開く" }).click();

  // コピー
  await devs.nth(0).getByRole("button", { name: "コピー" }).first().click();
  await expect(devs.nth(0).getByRole("button", { name: "コピーしました" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("12:00:00 JST");

  // 同じ出力ごと: show clock は 3 台とも同じ。show version は 2 台と 1 台に分かれる（行末の空白は無視）
  await panel.getByRole("tab", { name: "同じ出力ごと" }).click();
  const groups = panel.locator("details.cmd-device");
  await expect(groups).toHaveCount(3);
  await expect(groups.nth(0)).toContainText("3 台");
  await expect(groups.nth(1)).toContainText("2 台");
  await expect(groups.nth(1)).toContainText("Core-SW01、SW-2F");
  await expect(groups.nth(2)).toContainText("1 台");
  await expect(groups.nth(2)).toContainText("1 つ目と出力が違います");

  // テキスト・CSV の保存
  const [txt] = await Promise.all([page.waitForEvent("download"), panel.getByRole("button", { name: "テキスト保存" }).click()]);
  expect(txt.suggestedFilename()).toBe("command-run_20261125-100000.txt");
  const [csv] = await Promise.all([page.waitForEvent("download"), panel.getByRole("button", { name: "CSV 保存" }).click()]);
  expect(csv.suggestedFilename()).toBe("command-run_20261125-100000.csv");

  // 過去の実行の一覧から開き直せる
  const history = page.getByRole("table", { name: "過去の実行" });
  await expect(history.locator("tbody tr")).toHaveCount(1);
  await expect(history).toContainText(USERS.op.name);
  await expect(history).toContainText("show clock  /  show version | include Version");
  await expect(history).toContainText("完了 3 / 失敗 0 / 対象外 0");
  await page.reload();
  await expect(page.getByLabel("実行結果")).toHaveCount(0);
  await page.getByRole("table", { name: "過去の実行" }).getByRole("button", { name: "開く" }).click();
  await expect(page.getByLabel("実行結果").locator("details.cmd-device")).toHaveCount(3);
  await ctx.close();
});
