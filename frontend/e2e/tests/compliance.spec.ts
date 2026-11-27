import { expect, test, type Locator, type Page } from "@playwright/test";
import { USERS, login } from "./helpers";

test("違反を一覧し、例外として登録・削除できる", async ({ page }) => {
  await login(page, USERS.op);
  await page.goto("/compliance");
  const row = page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" });
  await expect(row).toBeVisible();
  await expect(page.locator("tr", { hasText: "DC-SW01" })).toBeVisible();

  await row.getByRole("button", { name: "例外にする" }).click();
  // 違反箇所から除外する行を選べる。ここでは機器単位で除外する
  await expect(page.locator(".cmp-suggest button")).toHaveCount(1);
  await page.getByLabel("この機器ではルールの違反をすべて除外する").check();
  await page.locator("#x-reason").fill("E2E: 検証用の機器のため");
  await page.locator(".modal").getByRole("button", { name: "登録して再検査" }).click();
  await expect(page.locator(".modal")).toHaveCount(0);
  await expect(page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" })).toHaveCount(0);

  await page.locator(".seg-tab", { hasText: "例外" }).click();
  const ex = page.locator("tr", { hasText: "E2E: 検証用の機器のため" });
  await expect(ex).toContainText("SW-2F");
  page.once("dialog", (d) => d.accept());
  await ex.getByRole("button", { name: "削除" }).click();
  await expect(ex).toHaveCount(0);
  await page.locator(".seg-tab", { hasText: "違反" }).first().click();
  await expect(page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" })).toBeVisible();
});

test("閲覧者は違反を見られるが例外は登録できない", async ({ page }) => {
  await login(page, USERS.viewer);
  await page.goto("/compliance");
  await expect(page.locator("tr", { hasText: "DC-SW01" })).toBeVisible();
  await expect(page.getByRole("button", { name: "例外にする" })).toHaveCount(0);
});

// ---------------------------------------------------------------- ルール集と直し方（環境変数 E2E_SHOT_DIR があるときだけ、確かめた画面の写真を保存する）

const shot = async (page: Page, name: string, target: Locator) => {
  const dir = process.env.E2E_SHOT_DIR;
  if (dir) await target.screenshot({ path: `${dir}/${name}` });
};

/** 追加したルールを、ルール一覧から削除する（画面テストの DB は 1 回の実行の間、共有される） */
async function deleteRule(page: Page, name: string) {
  await page.locator(".seg-tab", { hasText: "ルール" }).click();
  const row = page.locator("tr", { hasText: name });
  if ((await row.count()) === 0) return;
  page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "削除" }).click();
  await expect(page.locator("tr", { hasText: name })).toHaveCount(0);
}

test("ひな形を機種と分野で絞り込み、まとめて選んで追加できる。違反から直し方を見てコピーできる", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page, USERS.op);
  await page.goto("/compliance");
  await page.getByRole("button", { name: "テンプレートから追加" }).click();
  const modal = page.locator(".modal", { hasText: "テンプレートから追加" });
  const items = modal.locator(".cmp-tpl-item");
  await expect(items.first()).toBeVisible();
  const all = await items.count();
  expect(all).toBeGreaterThanOrEqual(80);

  // 機種で絞り込む（Arista EOS だけ）
  await modal.getByLabel("機種で絞り込む").selectOption("arista_eos");
  const eos = await items.count();
  expect(eos).toBeGreaterThanOrEqual(8);
  expect(eos).toBeLessThan(all);
  await expect(modal.getByText("EOS: Telnet サーバーを有効にしない")).toBeVisible();
  await expect(modal.getByText("JunOS: Telnet サービスを有効にしない")).toHaveCount(0);
  // 分野でさらに絞り込む
  await modal.getByLabel("分野で絞り込む").selectOption("SNMP");
  const snmp = await items.count();
  expect(snmp).toBeGreaterThanOrEqual(2);
  expect(snmp).toBeLessThan(eos);
  await expect(modal.getByTestId("tpl-count")).toContainText(`${snmp}件を表示`);
  // 表示中をまとめて選ぶ → 件数がボタンに出る → 外す
  await modal.getByRole("button", { name: "表示中をすべて選ぶ" }).click();
  await expect(modal.getByRole("button", { name: `${snmp}件を追加` })).toBeEnabled();
  await modal.getByRole("button", { name: "表示中の選択を外す" }).click();
  await expect(modal.getByRole("button", { name: "0件を追加" })).toBeDisabled();

  // すでに同じ名前のルールがあるものは「登録済み」で、選べず、まとめて選んでも入らない
  await modal.getByLabel("機種で絞り込む").selectOption("cisco_ios");
  await modal.getByLabel("分野で絞り込む").selectOption("管理アクセス");
  const exist = modal.locator(".cmp-tpl-item", { hasText: "HTTP サーバーの無効化" });
  await expect(exist).toContainText("登録済み");
  await expect(exist.getByRole("checkbox")).toBeDisabled();
  await modal.getByRole("button", { name: "表示中をすべて選ぶ" }).click();
  await expect(exist.getByRole("checkbox")).not.toBeChecked();
  await modal.getByRole("button", { name: "表示中の選択を外す" }).click();

  // 直し方を見る（追加前に内容を確かめられる）。長い文でも崩れないことを写真で確かめる
  await modal.getByLabel("分野で絞り込む").selectOption("");
  const target = modal.locator(".cmp-tpl-item", { hasText: "パスワードの暗号化表示" });
  await target.getByRole("button", { name: "直し方を見る" }).click();
  await expect(target.getByTestId("remediation-text")).toContainText("service password-encryption");
  // 長い文があっても、モーダルが横へはみ出さない
  expect(await modal.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
  const vendorItem = modal.locator(".cmp-tpl-item", { hasText: "VTY の接続元を ACL で制限する" });
  await vendorItem.getByRole("button", { name: "直し方を見る" }).click();
  await vendorItem.scrollIntoViewIfNeeded();
  await shot(page, "rules-template.png", modal);
  await page.setViewportSize({ width: 1024, height: 800 });
  await shot(page, "rules-template-1024.png", modal);
  await page.setViewportSize({ width: 1440, height: 900 });

  // 1 件選んで追加する（「パスワードの暗号化表示」は、見本の機器 2 台が違反になる）
  await target.getByRole("checkbox").check();
  await modal.getByRole("button", { name: "1件を追加" }).click();
  await expect(page.locator(".modal")).toHaveCount(0);
  await expect(page.locator(".topo-notice")).toContainText("1件のルールを追加しました");

  try {
    await page.locator(".seg-tab", { hasText: "違反" }).first().click();
    const row = page.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "パスワードの暗号化表示" });
    await expect(row).toBeVisible();
    await row.getByRole("button", { name: "直し方", exact: true }).click();
    const panel = page.getByTestId("remediation-panel");
    await expect(panel.getByTestId("remediation-text")).toHaveText("service password-encryption");
    await expect(panel).toContainText("機器へは送りません。内容を確かめてから、ご自身で投入してください");
    await expect(panel).toContainText("根拠: 一般的な堅牢化の推奨");
    await shot(page, "rules-remediation.png", page.locator(".table-scroll").first());
    await page.setViewportSize({ width: 1024, height: 800 });
    await shot(page, "rules-remediation-1024.png", page.locator(".table-scroll").first());
    await page.setViewportSize({ width: 1440, height: 900 });

    // コピー（クリップボードの API が使える場合）
    await panel.getByRole("button", { name: "コマンドをコピー" }).click();
    await expect(panel.getByRole("status")).toHaveText("コピーしました");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("service password-encryption");

    // クリップボードの API が使えない（http・権限なし）ときも壊れない
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true }));
    await panel.getByRole("button", { name: "コマンドをコピー" }).click();
    await expect(panel.getByRole("status")).toBeVisible();
    await expect(panel.getByTestId("remediation-text")).toBeVisible();

    // もう一度押すと閉じる
    await row.getByRole("button", { name: "直し方", exact: true }).click();
    await expect(page.getByTestId("remediation-panel")).toHaveCount(0);
  } finally {
    await deleteRule(page, "パスワードの暗号化表示");
  }
  expect(errors).toEqual([]);
});

test("ルールに直し方・根拠・分野を書ける。直し方は HTML として解釈せず、閲覧者も見られる（直し方が無いルールはその旨を表示）", async ({ page, browser }) => {
  const name = "E2E: 直し方の表示";
  await login(page, USERS.op);
  await page.goto("/compliance");
  await page.getByRole("button", { name: "＋ ルール追加" }).click();
  await page.locator("#r-name").fill(name);
  await page.locator("#r-expect").selectOption("absent");
  await page.locator("#r-match").selectOption("regex");
  await page.locator("#r-pattern").fill("^ip http server");
  await page.locator("#r-category").selectOption("サービス");
  await page.locator("#r-ref").fill("社内標準");
  await page.locator("#r-fix").fill('# 注意: 管理画面が使えなくなります\n<b id="xss">no ip http server</b>\n<img src=x onerror="window.__xss=1">\n' + "long-".repeat(80));
  await page.locator(".modal").getByRole("button", { name: "保存して検査" }).click();
  await expect(page.locator(".modal")).toHaveCount(0);

  try {
    // 保存した値が編集画面に戻る
    await page.locator(".seg-tab", { hasText: "ルール" }).click();
    const rule = page.locator("tr", { hasText: name });
    await expect(rule).toContainText("サービス");
    await rule.getByRole("button", { name: "編集" }).click();
    await expect(page.locator("#r-ref")).toHaveValue("社内標準");
    await expect(page.locator("#r-category")).toHaveValue("サービス");
    await expect(page.locator("#r-fix")).toHaveValue(/<b id="xss">/);
    await page.locator(".modal").getByRole("button", { name: "キャンセル" }).click();

    // 閲覧者: 違反を開いて直し方を見られる（編集・例外の操作は無い）。HTML は文字のまま表示される
    const viewer = await browser.newPage();
    await login(viewer, USERS.viewer);
    await viewer.goto("/compliance");
    const row = viewer.locator("tr", { hasText: "SW-2F" }).filter({ hasText: name });
    await expect(row).toBeVisible();
    await expect(viewer.getByRole("button", { name: "例外にする" })).toHaveCount(0);
    await row.getByRole("button", { name: "直し方", exact: true }).click();
    const text = viewer.getByTestId("remediation-text");
    await expect(text).toContainText('<b id="xss">no ip http server</b>');
    await expect(viewer.locator("#xss")).toHaveCount(0);
    await expect(viewer.locator("img[src='x']")).toHaveCount(0);
    expect(await viewer.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
    await expect(viewer.getByTestId("remediation-panel")).toContainText("「# 」で始まる行は説明で、コピーには含めません");
    await expect(viewer.getByTestId("remediation-panel")).toContainText("根拠: 社内標準");
    // 長い 1 行（区切りなし）でも、表が横へはみ出さない（1440px と 1024px）
    for (const width of [1440, 1024]) {
      await viewer.setViewportSize({ width, height: 900 });
      const over = await viewer.locator(".table-scroll").first().evaluate((el) => el.scrollWidth - el.clientWidth);
      expect(over).toBeLessThanOrEqual(1);
    }
    await shot(viewer, "rules-remediation-long.png", viewer.locator(".table-scroll").first());

    // 直し方の無い（以前の）ルール
    const old = viewer.locator("tr", { hasText: "SW-2F" }).filter({ hasText: "HTTP サーバーの無効化" });
    await old.getByRole("button", { name: "直し方", exact: true }).click();
    await expect(viewer.getByText("このルールには直し方が登録されていません")).toBeVisible();
    await viewer.close();
  } finally {
    await deleteRule(page, name);
  }
});
