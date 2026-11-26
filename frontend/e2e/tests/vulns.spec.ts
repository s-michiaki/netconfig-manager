import { expect, test, type Locator, type Page } from "@playwright/test";
import { expandNav, login, openNav, USERS } from "./helpers";

// 脆弱性・サポート期限（VULN_ENABLED=true で起動。見本のデータは seed.py。外部へは何もつながない）
// 未確認の一覧は既定で 9 行: 確定 6（FW-Edge01 は 0001・0002・0003、FW-Edge02 は 0003、FG-Branch01 は FG-IR-99-101・102）＋
// 候補 3（0005 は FW-Edge01、0006 は両方）。FG-Branch02（FortiOS 7.0）の候補 2 件（勧告に載っていない系列）は既定で折りたたむ。
// stale（0004）と取り下げ（0007）の行は出ない。環境変数 E2E_SHOT_DIR があるときだけ、確かめた画面の写真をそこへ保存する

const OPEN_ROWS = 9;
const NOT_LISTED = 2;
const shot = async (page: Page, name: string, target?: Locator) => {
  const dir = process.env.E2E_SHOT_DIR;
  if (!dir) return;
  // 画面の本文はスクロールする領域なので、全体の写真では下が切れる。対象があれば、その要素だけを撮る
  if (target) await target.screenshot({ path: `${dir}/${name}` });
  else await page.screenshot({ path: `${dir}/${name}` });
};

test("脆弱性の一覧を見て、確認済みにして、取り消せる", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  await openNav(page, "/vulns");
  await expect(page).toHaveURL(/\/vulns$/);
  await expect(page.locator(".page-title")).toHaveText("脆弱性・サポート期限");
  // 注意書きと出典
  await expect(page.locator(".vuln-notice")).toContainText("載っていない脆弱性がありえます");
  await expect(page.locator(".vuln-notice")).toContainText("Palo Alto Networks Security Advisories");
  // 要約（重大 2・高 2・悪用確認済み 1・候補 5・サポート終了済み 2 台・1 年以内に終了 2 台）と、情報源ごとの最後の取得
  const sum = page.getByTestId("vuln-summary");
  await expect(sum.locator(".cmp-card", { hasText: "重大" }).locator(".cmp-card-value")).toHaveText("2");
  await expect(sum.locator(".cmp-card", { hasText: "悪用確認済み" }).locator(".cmp-card-value")).toHaveText("1");
  await expect(sum.locator(".cmp-card", { hasText: "サポート終了済み" })).toContainText("2");
  await expect(sum.locator(".cmp-card", { hasText: "1 年以内に終了" })).toContainText("2");
  await expect(page.getByTestId("vuln-sources")).toContainText("Palo Alto の勧告");
  await expect(page.getByTestId("vuln-sources")).toContainText("最後の取得");

  // 一覧: 悪用確認済み・重大が先頭。出典のリンクは新しいタブ・rel 付き
  const rows = page.locator(".vuln-row");
  await expect(rows).toHaveCount(OPEN_ROWS);
  await expect(rows.first()).toContainText("FW-Edge01");
  await expect(rows.first()).toContainText("CVE-2099-0001");
  await expect(rows.first()).toContainText("悪用確認済み");
  await expect(rows.first()).toContainText("該当");
  const link = rows.first().locator("a").first();
  await expect(link).toHaveAttribute("href", "https://security.paloaltonetworks.com/CVE-2099-0001");
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("rel", /noopener/);
  await expect(link).toHaveAttribute("rel", /noreferrer/);

  // 絞り込み
  await page.getByLabel("重大度").selectOption("critical");
  await expect(rows).toHaveCount(2);
  await page.getByLabel("重大度").selectOption("");
  await expect(rows).toHaveCount(OPEN_ROWS);
  await page.getByLabel("悪用確認済みだけ").check();
  await expect(rows).toHaveCount(1);
  await page.getByLabel("悪用確認済みだけ").uncheck();
  await expect(rows).toHaveCount(OPEN_ROWS);

  // 確認済みにする（メモ必須）
  await rows.first().getByRole("button", { name: "確認済みにする" }).click();
  const modal = page.getByRole("dialog", { name: "確認済みにする" });
  await expect(modal.getByRole("button", { name: "確認済みにする" })).toBeDisabled();
  await modal.locator("textarea").fill("管理用ネットワークからしか届かないため、次回の保守で対応する");
  await modal.getByRole("button", { name: "確認済みにする" }).click();
  await expect(modal).toHaveCount(0);
  await expect(page.locator(".review-message")).toContainText("確認済みにしました");
  await expect(rows).toHaveCount(OPEN_ROWS - 1);
  await page.getByRole("tab", { name: "確認済み" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("管理用ネットワークからしか届かない");
  await expect(rows.first()).toContainText("admin");
  await rows.first().getByRole("button", { name: "未確認に戻す" }).click();
  await expect(rows).toHaveCount(0);
  await page.getByRole("tab", { name: "未確認" }).click();
  await expect(rows).toHaveCount(OPEN_ROWS);

  // 機器別 → その機器の一覧
  await page.getByRole("tab", { name: "機器別" }).click();
  await expect(page.getByRole("tab", { name: "機器別" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator(".vuln-row")).toHaveCount(0);
  const edge01 = page.locator("tbody tr", { hasText: "FW-Edge01" });
  await expect(edge01).toContainText("10.2.5-h1");
  await edge01.getByRole("button", { name: "一覧を見る" }).click();
  await expect(page).toHaveURL(/device=/);
  await expect(rows).toHaveCount(5); // 確定 3 ＋ 候補 2

  // CSV 出力
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "CSV 出力" }).click();
  expect((await download).suggestedFilename()).toMatch(/^vulns.*\.csv$/);
  expect(errors).toEqual([]);
});

test("サポート期限を手入力して、消すと自動取得に戻る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  await page.getByRole("tab", { name: "サポート期限" }).click();
  await expect(page.locator(".eol-row").first()).toBeVisible();
  const edge01 = page.locator(".eol-row", { hasText: "FW-Edge01" });
  const edge02 = page.locator(".eol-row", { hasText: "FW-Edge02" });
  await expect(edge01).toContainText("終了済み");
  await expect(edge01).toContainText("自動取得");
  await expect(page.locator(".eol-row", { hasText: "Core-SW01" })).toContainText(/あと \d+ 日/);
  // 短い順（終了済みが先頭）
  await expect(page.locator(".eol-row").first()).toContainText("FW-Edge0");

  await edge01.getByRole("button", { name: "手入力で上書き" }).first().click();
  const modal = page.getByRole("dialog", { name: "サポート終了日の手入力" });
  await expect(modal.getByLabel(/リリース系列/)).toHaveValue("10.2");
  await modal.getByLabel("サポート終了日").fill("2099-01-31");
  await modal.getByLabel("メモ（任意）").fill("延長保守契約");
  await modal.getByRole("button", { name: "保存" }).click();
  await expect(modal).toHaveCount(0);
  // 同じ系列の機器すべてに使われる
  for (const row of [edge01, edge02]) {
    await expect(row).toContainText("2099-01-31");
    await expect(row).toContainText("手入力");
    await expect(row).toContainText("延長保守契約");
  }
  await edge01.getByRole("button", { name: "手入力を消す" }).click();
  await expect(page.locator(".review-message")).toContainText("手入力のサポート終了日を消しました");
  await expect(edge01).toContainText("終了済み");
  await expect(edge01).not.toContainText("2099-01-31");
});

test("判定できない機器の一覧に理由が出る。範囲を読み取れなかった勧告は別に出る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  // 範囲を読み取れなかった勧告があることは、上部の注記に出る（該当・非該当のどちらにもしていない）
  await expect(page.getByTestId("vuln-range-note")).toContainText("範囲を読み取れなかった勧告が 1 件あります");
  await page.getByRole("tab", { name: /判定できない機器/ }).click();
  const main = page.locator("table.data-table:not([data-testid])");
  await expect(main.locator("thead th", { hasText: "理由" })).toBeVisible();
  await expect(main.locator("tbody tr", { hasText: "Core-SW01" })).toContainText("脆弱性の情報源が未対応");
  await expect(main.locator("tbody tr", { hasText: "SW-2F" })).toContainText("OS バージョンを読み取れていません");
  await expect(main.locator("tbody tr", { hasText: "FW-Edge01" })).toHaveCount(0);
  const ranges = page.getByTestId("vuln-range-unreadable");
  await expect(ranges.locator("tbody tr", { hasText: "FW-Edge01" })).toContainText("範囲を読み取れなかった勧告が 1 件あります");
  await expect(ranges.locator("tbody tr", { hasText: "CVE-2099-0004" }).first()).toBeVisible();
});

test("閲覧者は一覧だけ、オペレーターは確認済みにできるが「いま取得」は管理者だけ", async ({ page }) => {
  await login(page, USERS.viewer);
  await openNav(page, "/vulns");
  await expect(page.locator(".vuln-row")).toHaveCount(OPEN_ROWS);
  await expect(page.getByRole("button", { name: "確認済みにする" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "いま取得" })).toHaveCount(0);
  await page.getByRole("tab", { name: "サポート期限" }).click();
  await expect(page.locator(".eol-row").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "手入力で上書き" })).toHaveCount(0);
  await page.evaluate(() => localStorage.clear());
  await page.goto("/login");
  await login(page, USERS.op);
  await openNav(page, "/vulns");
  await expect(page.getByRole("button", { name: "確認済みにする" }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "いま取得" })).toHaveCount(0);
});

test("管理者には「いま取得」が出る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  await expect(page.getByRole("button", { name: "いま取得" })).toBeVisible();
});

test("無効のとき（features.vuln が false）はメニューに出ない", async ({ page }) => {
  // 実際の backend は有効で起動しているので、/health の応答だけを書き換えて、画面側の出し分けを確かめる
  await page.route("**/api/health", async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    await route.fulfill({ response: res, json: { ...body, features: { ...body.features, vuln: false } } });
  });
  await login(page);
  await expandNav(page);
  await expect(page.locator(".version-tag")).toHaveText(/^v/);
  await expect(page.locator('a[href="/devices"]').first()).toBeVisible();
  await expect(page.locator('.sidebar-nav a[href="/vulns"]')).toHaveCount(0);
});

test("システム状態に脆弱性情報の取得の項目が出る", async ({ page }) => {
  await login(page);
  await page.goto("/system");
  const card = page.locator(".sys-card", { hasText: "脆弱性情報の取得" });
  await expect(card).toBeVisible();
  await expect(card).toContainText("取得できています");
  await expect(card).toContainText("Palo Alto の勧告");
});

test("候補の行に、候補になった理由が出る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  // 候補は 5 件（0005 が FW-Edge01 の 1 件、0006 が両方の機器の 2 件、FG-Branch02 の 2 件）。確定の件数には数えない
  const sum = page.getByTestId("vuln-summary");
  await expect(sum.locator(".cmp-card", { hasText: "候補" }).locator(".cmp-card-value")).toHaveText("5");
  await expect(sum.locator(".cmp-card", { hasText: "高" }).first().locator(".cmp-card-value")).toHaveText("2");
  const rows = page.locator(".vuln-row");
  await expect(rows).toHaveCount(OPEN_ROWS);

  // 特定の機種だけに影響する勧告: 対象の機種が文に入る
  const platforms = rows.filter({ hasText: "CVE-2099-0005" });
  await expect(platforms).toHaveCount(1);
  await expect(platforms).toContainText("FW-Edge01");
  await expect(platforms).toContainText("候補");
  await expect(platforms).toContainText("特定の機種だけに影響する勧告です（対象: PA-3200 Series）。機種を確かめてください");

  // 記載のない系列も影響ありとする勧告: 両方の機器に出る
  const dflt = rows.filter({ hasText: "CVE-2099-0006" });
  await expect(dflt).toHaveCount(2);
  for (const r of await dflt.all()) {
    await expect(r).toContainText("候補");
    await expect(r).toContainText("勧告は、記載のない系列も影響ありとしています（この機器の系列は勧告の表に載っていません）");
  }
  // 確定の行には理由が出ない
  await expect(rows.filter({ hasText: "CVE-2099-0001" })).not.toContainText("候補");
  await expect(rows.filter({ hasText: "CVE-2099-0001" })).toContainText("該当");
  await shot(page, "vulns-candidate.png", page.locator(".vuln-table"));
});

test("取り下げられた勧告は、該当の一覧にも件数にも出ない", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  const rows = page.locator(".vuln-row");
  await expect(rows).toHaveCount(OPEN_ROWS);
  await expect(page.locator(".vuln-table")).not.toContainText("CVE-2099-0007");
  await expect(page.locator(".vuln-table")).not.toContainText("取り下げられた勧告");
  // 確認済みの一覧にも出ない（このテストの機器・勧告に確認済みは無いので 0 件）
  await page.getByRole("tab", { name: "確認済み" }).click();
  await expect(page.getByText("該当する記録はありません。")).toBeVisible();
  await expect(rows).toHaveCount(0);
  // 要約の「高」は、取り下げの勧告（高）を数えない（高は 0002 と FG-IR-99-102 の 2 件だけ）
  const sum = page.getByTestId("vuln-summary");
  await expect(sum.locator(".cmp-card", { hasText: "高" }).first().locator(".cmp-card-value")).toHaveText("2");
});

test("解消・すべての一覧では、取り下げで解消になった行に「取り下げ」と出る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  await expect(page.locator(".vuln-row")).toHaveCount(OPEN_ROWS);
  for (const tab of ["解消", "すべて"]) {
    await page.getByRole("tab", { name: tab, exact: true }).click();
    const rejected = page.locator(".vuln-row", { hasText: "CVE-2099-0007" });
    await expect(rejected.first()).toBeVisible();
    for (const r of await rejected.all()) {
      await expect(r.getByTestId("vuln-rejected")).toHaveText("取り下げ");
      await expect(r).toContainText("勧告の取り下げで解消");
    }
    // 取り下げではない行には出ない
    await expect(page.locator(".vuln-row", { hasText: "CVE-2099-0001" }).getByTestId("vuln-rejected")).toHaveCount(0);
  }
});

test("判定できない機器のタブに、前回は該当だった行（stale）が出る", async ({ page }) => {
  await login(page);
  await openNav(page, "/vulns");
  // 要約: stale は該当の件数・一覧から外れ、注記に件数が出る（FW-Edge01 と FW-Edge02 の 0004 の 2 件）
  await expect(page.getByTestId("vuln-stale-note")).toContainText("前回は該当だった勧告のうち 2 件は、機器の版が変わり、いまの版では判定できません");
  await expect(page.locator(".vuln-row")).toHaveCount(OPEN_ROWS);
  await expect(page.locator(".vuln-row", { hasText: "CVE-2099-0004" })).toHaveCount(0); // 一覧には出ない

  await page.getByRole("tab", { name: /判定できない機器/ }).click();
  const ranges = page.getByTestId("vuln-range-unreadable");
  await expect(ranges).toBeVisible();
  const label = (v: string) => `CVE-2099-0004: 前回（版 ${v}）は該当。版が変わり、いまの版では判定できません`;

  // 未確認の行: メモの括弧は出ない
  const edge01 = ranges.locator("tbody tr", { hasText: "FW-Edge01" });
  await expect(edge01.getByTestId("vuln-stale")).toHaveCount(1);
  await expect(edge01.getByTestId("vuln-stale")).toHaveText(label("10.2.4"));
  await expect(edge01.getByTestId("vuln-stale")).not.toContainText("確認済み");
  // 確認済みの行: メモが付く
  const edge02 = ranges.locator("tbody tr", { hasText: "FW-Edge02" });
  await expect(edge02.getByTestId("vuln-stale")).toHaveCount(1);
  await expect(edge02.getByTestId("vuln-stale")).toHaveText(`${label("10.2.8")}（確認済み: 次回の保守で版を確かめる）`);
  // 件数が 20 以下なので「ほか n 件」は出ない
  await expect(ranges).not.toContainText("ほか");
  await shot(page, "vulns-stale.png");
});

// API の応答だけを差し替えて、見本では作れない形（stale の行だけ・21 件以上）を確かめる
const unknownReply = (body: unknown) => async (route: import("@playwright/test").Route) => {
  await route.fulfill({ json: body });
};

test("機器の行が無く stale の行だけのとき、「判定できない機器はありません。」を出さない。20 件を超えると「ほか n 件」", async ({ page }) => {
  const stale = Array.from({ length: 20 }, (_, i) => ({
    advisory: `CVE-2099-${String(9000 + i)}`, previous_version: "10.2.1", state: "open", note: null,
    label: "前回（版 10.2.1）は該当。版が変わり、いまの版では判定できません",
  }));
  await page.route("**/api/vulns/unknown", unknownReply({
    items: [],
    range_unreadable: [{ device_id: "dev-sample", name: "FW-Sample01", group_name: null, os_version: "10.2.9", count: 0,
      advisories: [], stale, stale_count: 23 }],
  }));
  await login(page);
  await page.goto("/vulns?tab=unknown");
  const ranges = page.getByTestId("vuln-range-unreadable");
  await expect(ranges).toBeVisible();
  await expect(page.getByText("判定できない機器はありません。")).toHaveCount(0);
  await expect(ranges.getByTestId("vuln-stale")).toHaveCount(20);
  await expect(ranges).toContainText("ほか 3 件");
  // 範囲を読み取れなかった勧告の件数の文は、count が 0 なので出ない
  await expect(ranges).not.toContainText("範囲を読み取れなかった勧告が");

  // 20 件ちょうど（stale_count も 20）なら「ほか」は出ない
  await page.unroute("**/api/vulns/unknown");
  await page.route("**/api/vulns/unknown", unknownReply({
    items: [],
    range_unreadable: [{ device_id: "dev-sample", name: "FW-Sample01", group_name: null, os_version: "10.2.9", count: 0,
      advisories: [], stale, stale_count: 20 }],
  }));
  await page.reload();
  await expect(page.getByTestId("vuln-range-unreadable").getByTestId("vuln-stale")).toHaveCount(20);
  await expect(page.getByTestId("vuln-range-unreadable")).not.toContainText("ほか");

  // どちらも空のときだけ、「判定できない機器はありません。」が出る
  await page.unroute("**/api/vulns/unknown");
  await page.route("**/api/vulns/unknown", unknownReply({ items: [], range_unreadable: [] }));
  await page.reload();
  await expect(page.getByText("判定できない機器はありません。")).toBeVisible();
  await expect(page.getByTestId("vuln-range-unreadable")).toHaveCount(0);
});

// ================================================================ Fortinet（FortiOS）・取得済みの範囲・過去の勧告の取り込み

test("Fortinet の勧告: 該当・出典のリンク・載っていない系列の候補を折りたたみ、表示できる", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  await openNav(page, "/vulns");
  await expect(page.locator(".vuln-notice")).toContainText("Fortinet PSIRT Advisories");
  await expect(page.getByTestId("vuln-sources")).toContainText("Fortinet の勧告（FortiOS）");
  // 取得済みの範囲と注意書き
  const cov = page.getByTestId("vuln-coverage");
  await expect(cov).toContainText("Fortinet の勧告（FortiOS）: 2 件");
  await expect(cov).toContainText("ほかの製品の勧告 1 件");
  // 要確認の告知（製品の記載が無い勧告）は機器ごとの件数に入れず、上部に 1 か所だけ出す
  const notices = page.getByTestId("vuln-notices");
  await expect(notices).toContainText("要確認の告知（製品の記載が無く、機器を特定できない勧告）が 1 件あります");
  await notices.getByRole("button", { name: "一覧を見る" }).click();
  const nlink = notices.locator("a", { hasText: "FG-IR-99-103" });
  await expect(nlink).toHaveAttribute("href", "https://www.fortiguard.com/psirt/FG-IR-99-103");
  await expect(nlink).toHaveAttribute("rel", /noopener noreferrer/);
  await expect(page.getByTestId("vuln-sources")).toContainText("要確認の告知 1 件");
  await expect(page.locator(".vuln-table")).not.toContainText("FG-IR-99-103");
  await shot(page, "vulns-fortinet-top.png", page.locator(".page-body"));
  await expect(cov).toContainText("勧告が見つからないことは、安全であることを意味しません");
  const rows = page.locator(".vuln-row");
  await expect(rows).toHaveCount(OPEN_ROWS);
  const fg = rows.filter({ hasText: "FG-Branch01" });
  await expect(fg).toHaveCount(2);
  await expect(fg.filter({ hasText: "FG-IR-99-101" })).toContainText("該当");
  const link = fg.filter({ hasText: "FG-IR-99-101" }).locator("a").first();
  await expect(link).toHaveAttribute("href", "https://www.fortiguard.com/psirt/FG-IR-99-101");
  // 確定版でない文書（102）は「暫定の勧告」と添える
  await expect(fg.filter({ hasText: "FG-IR-99-102" }).getByTestId("vuln-provisional")).toHaveText("暫定の勧告");
  await expect(fg.filter({ hasText: "FG-IR-99-101" }).getByTestId("vuln-provisional")).toHaveCount(0);
  await expect(link).toHaveAttribute("rel", /noopener/);
  await expect(link).toHaveAttribute("rel", /noreferrer/);
  // 勧告に載っていない系列（FG-Branch02 の FortiOS 7.0）の候補は既定で折りたたむ
  await expect(rows.filter({ hasText: "FG-Branch02" })).toHaveCount(0);
  const folded = page.getByTestId("vuln-not-listed-folded");
  await expect(folded).toContainText(`「候補」${NOT_LISTED} 件を折りたたんでいます`);
  await folded.getByRole("button", { name: "表示する" }).click();
  await expect(rows).toHaveCount(OPEN_ROWS + NOT_LISTED);
  const nl = rows.filter({ hasText: "FG-Branch02" });
  await expect(nl).toHaveCount(NOT_LISTED);
  for (const r of await nl.all()) {
    await expect(r).toContainText("候補");
    await expect(r).toContainText("勧告のデータにこの系列が載っていません。勧告のページで確かめてください");
  }
  // 判定の絞り込み: 載っていない系列による候補だけ
  await page.getByLabel("判定").selectOption("not_listed");
  await expect(rows).toHaveCount(NOT_LISTED);
  await page.getByLabel("判定").selectOption("confirmed");
  await expect(rows).toHaveCount(6);
  await page.getByLabel("判定").selectOption("");
  await expect(rows).toHaveCount(OPEN_ROWS + NOT_LISTED);
  // 長い文で表が崩れない（1440px と 1024px。ページ全体が横にはみ出さない・理由の列が潰れない）
  for (const width of [1440, 1024]) {
    await page.setViewportSize({ width, height: 900 });
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(over, `${width}px で横にはみ出す`).toBeLessThanOrEqual(1);
    const reason = nl.first().locator(".topo-small", { hasText: "載っていません" });
    expect((await reason.boundingBox())!.width).toBeGreaterThan(120);
    const table = page.locator(".table-scroll");
    await table.scrollIntoViewIfNeeded();
    await shot(page, width === 1440 ? "vulns-fortinet.png" : "vulns-fortinet-1024.png", table);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  // 6000 / 7000 系は判定できない機器
  await page.getByRole("tab", { name: /判定できない機器/ }).click();
  await expect(page.locator("tbody tr", { hasText: "FG-DC7121" })).toContainText("FortiGate 6000 / 7000 系");
  expect(errors).toEqual([]);
});

test("過去の勧告の取り込み（管理者だけ）: ID を入れて依頼し、結果が出る", async ({ page }) => {
  let posted: unknown = null;
  let state: unknown = null;
  // worker（Redis）が無い画面テストなので、取り込みの API の応答を差し替える（入力の検査は本物の API で確かめる）
  await page.route("**/api/vulns/fortinet/import", async (route) => {
    const req = route.request();
    if (req.method() === "POST") {
      const body = req.postDataJSON() as { ids: string };
      if (!/^FG-IR-/.test(body.ids.trim())) return route.fallback();
      posted = body;
      state = { status: "done", by: "admin", ids: ["FG-IR-24-015", "FG-IR-18-384"], at: new Date().toISOString(),
        finished_at: new Date().toISOString(), results: [
          { ext_id: "FG-IR-24-015", ok: true, result: "fortios", message: "取り込みました（FortiOS の勧告）" },
          { ext_id: "FG-IR-18-384", ok: false, result: "no_csaf", message: "機械で読める形式（CSAF）の文書がありません（2021 年以前の勧告か、題名が後から変わった勧告の可能性があります。勧告のページで確かめてください）" },
        ] };
      return route.fulfill({ status: 202, json: { queued: true, ids: ["FG-IR-24-015", "FG-IR-18-384"], task_id: "t" } });
    }
    return route.fulfill({ json: { state, max: 20 } });
  });
  await login(page);
  await openNav(page, "/vulns");
  await page.getByRole("button", { name: /Fortinet の過去の勧告を取り込む/ }).click();
  const panel = page.getByTestId("vuln-import");
  await expect(panel).toContainText("1 回に 20 件まで");
  // 形の違う ID は本物の API が断る
  await panel.getByLabel("勧告の ID").fill("CVE-2024-0001");
  await panel.getByRole("button", { name: "取り込む" }).click();
  await expect(panel.locator(".form-error")).toContainText("FG-IR-YY-NNN");
  await panel.getByLabel("勧告の ID").fill("FG-IR-24-015\nFG-IR-18-384");
  await expect(panel).toContainText("2 件");
  await panel.getByRole("button", { name: "取り込む" }).click();
  const st = page.getByTestId("vuln-import-state");
  await expect(st).toContainText("取り込みが終わりました");
  await expect(st.locator("tbody tr")).toHaveCount(2);
  await expect(st.locator("tbody tr", { hasText: "FG-IR-18-384" })).toContainText("CSAF");
  expect(posted).toEqual({ ids: "FG-IR-24-015\nFG-IR-18-384" });
  await shot(page, "vulns-import.png", panel);
});

test("閲覧者・オペレーターには過去の勧告の取り込みが出ない", async ({ page }) => {
  await login(page, USERS.op);
  await openNav(page, "/vulns");
  await expect(page.getByTestId("vuln-coverage")).toBeVisible();
  await expect(page.getByRole("button", { name: /過去の勧告を取り込む/ })).toHaveCount(0);
});

test("ダッシュボードに脆弱性のタイルが出て、押すと脆弱性の画面へ", async ({ page }) => {
  await login(page);
  await page.goto("/dashboard");
  const tile = page.locator(".dash-tile", { hasText: "脆弱性" });
  // 未確認の該当（確定）6 件・うち悪用確認済み 1 件。サポート終了まで 90 日以内は 3 台（終了済み 2 台・FortiOS 7.0 が約 60 日後）
  await expect(tile.locator(".dash-tile-value")).toHaveText("6");
  await expect(tile).toContainText("うち悪用確認済み 1 件");
  await expect(tile).toContainText("サポート終了まで 90 日以内: 3 台（終了済み 2 台）");
  await shot(page, "dashboard-vuln.png", page.locator(".dash-tiles"));
  await tile.click();
  await expect(page).toHaveURL(/\/vulns$/);
});

test("無効のときはダッシュボードに脆弱性のタイルを出さない", async ({ page }) => {
  await page.route("**/api/dashboard", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), vuln: null } });
  });
  await login(page);
  await page.goto("/dashboard");
  await expect(page.locator(".dash-tile").first()).toBeVisible();
  await expect(page.locator(".dash-tile", { hasText: "脆弱性" })).toHaveCount(0);
});

test("通知設定に「脆弱性・サポート期限」がある（既定は無効）", async ({ page }) => {
  await login(page);
  await openNav(page, "/notifications");
  // 自分の通知を「個別に設定する」にすると、通知する内容に出る（保存はしない）
  await page.locator("label.ntf-mode", { hasText: "個別に設定する" }).locator("input").check();
  const item = page.locator("label.form-check", { hasText: "脆弱性・サポート期限" });
  await expect(item).toBeVisible();
  await expect(item.locator("input")).not.toBeChecked();
  await expect(item).toContainText("候補・判定できないは通知しません");
});
