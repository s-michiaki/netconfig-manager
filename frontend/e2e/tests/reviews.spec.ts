import { expect, test } from "@playwright/test";
import { USERS, login } from "./helpers";

// 変更の確認。SW-3F は 2 世代（初回の収集と、その後の変更）、Core-SW01 も 2 世代（初回の収集の行は無いが、最初の世代は Git で判定する
// ので 2 世代目は一覧に出る）。同じ DB を使うので、最後に未確認へ戻す
test("オペレーターが変更を確認済みにし、閲覧者は状態を見られるが操作できない", async ({ browser }) => {
  // ユーザーごとに別のコンテキストを使う（同じ page でログインし直すと、古い画面のポーリングの 401 と重なって不安定になる）
  const opCtx = await browser.newContext();
  const op = await opCtx.newPage();
  await login(op, USERS.op);

  // 未確認の一覧: 最初の世代だけの機器・初回の収集は出ない。Core-SW01 と SW-3F の変更がある
  await op.locator('a[href="/reviews"]').first().click();
  await expect(op).toHaveURL(/\/reviews/);
  const all = op.locator("tr.review-row");
  const rows = all.filter({ hasText: "SW-3F" });
  await expect(all).toHaveCount(2);
  await expect(all.filter({ hasText: "Core-SW01" })).toHaveCount(1);
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("+1");
  await expect(rows.first().locator(".review-badge")).toHaveText("未確認");
  await expect(op.getByRole("tab", { name: "未確認（2）" })).toBeVisible();

  // 差分へのリンク（その世代の変更を開く）
  await rows.first().getByRole("link", { name: "差分" }).click();
  await expect(op).toHaveURL(/\/history\?device=.+&commit=[0-9a-f]{40}/);
  await expect(op.locator(".diff-add")).toHaveText(["+snmp-server location rack-12"]);
  await op.goBack();

  // 確認済みにすると、未確認の一覧から消える
  await rows.first().getByRole("button", { name: "確認済み", exact: true }).click();
  await expect(rows).toHaveCount(0);
  await expect(all).toHaveCount(1);
  await expect(op.getByRole("tab", { name: "未確認（1）" })).toBeVisible();
  await op.getByRole("tab", { name: /^確認済み/ }).click();
  await expect(op.locator("tr.review-row")).toHaveCount(1);
  await expect(op.locator("tr.review-row .review-badge").first()).toHaveText("確認済み");

  // 世代管理にバッジ（初回の世代には出ない）
  await op.goto("/history");
  await op.locator(".page-header select").selectOption({ label: "SW-3F" });
  const hist = op.locator(".hist-table tr.hist-row");
  await expect(hist).toHaveCount(2);
  await expect(hist.nth(0).locator(".review-badge")).toHaveText("確認済み");
  await expect(hist.nth(1).locator(".review-badge")).toHaveCount(0);
  await expect(hist.nth(1).getByRole("button", { name: "確認" })).toHaveCount(0);

  // 想定外に付け直す（メモ付き）。バッジは赤
  await hist.nth(0).getByRole("button", { name: "確認", exact: true }).click();
  await op.getByLabel(/メモ（任意/).fill("依頼のない設定変更");
  await op.locator(".modal").getByRole("button", { name: "想定外にする" }).click();
  await expect(op.locator(".modal")).toHaveCount(0);
  await expect(hist.nth(0).locator(".review-badge")).toHaveText("想定外");
  await expect(hist.nth(0).locator(".review-badge")).toHaveClass(/badge-danger/);

  // 閲覧者: 状態は見えるが、操作のボタンは無い。ダッシュボードのタイルに想定外の件数
  const viewerCtx = await browser.newContext();
  const viewer = await viewerCtx.newPage();
  await login(viewer, USERS.viewer);
  await viewer.goto("/history");
  await viewer.locator(".page-header select").selectOption({ label: "SW-3F" });
  await expect(viewer.locator(".hist-table tr.hist-row").nth(0).locator(".review-badge")).toHaveText("想定外");
  await expect(viewer.getByRole("button", { name: "確認", exact: true })).toHaveCount(0);
  await viewer.goto("/reviews?state=unexpected&days=0");
  await expect(viewer.locator("tr.review-row")).toHaveCount(1);
  await expect(viewer.locator("tr.review-row")).toContainText("依頼のない設定変更");
  await expect(viewer.locator("tr.review-row").getByRole("button")).toHaveCount(0);
  await expect(viewer.locator('input[type="checkbox"]')).toHaveCount(0);
  await viewer.locator('a[href="/dashboard"]').first().click();
  const tile = viewer.locator(".dash-tile", { hasText: "未確認の変更" });
  await expect(tile.locator(".dash-tile-value")).toHaveText("1"); // Core-SW01 の変更が未確認のまま
  await expect(tile).toContainText("想定外 1 件");
  await tile.click();
  await expect(viewer).toHaveURL(/\/reviews\?days=30/); // 未確認が残っているので、未確認の一覧（期間は CHANGE_REVIEW_DAYS）を開く
  await viewerCtx.close();

  // 後始末: 未確認に戻す → 一覧に戻り、ダッシュボードのタイルも 1 になる。まとめて確認済みにもできる
  await op.goto("/reviews?state=unexpected&days=0");
  await op.locator("tr.review-row").first().getByRole("button", { name: "未確認に戻す" }).click();
  await expect(op.locator("tr.review-row")).toHaveCount(0);
  await op.getByRole("tab", { name: /^未確認/ }).click();
  await expect(all).toHaveCount(2);
  await op.getByLabel("SW-3F", { exact: false }).first().check();
  await op.getByRole("button", { name: "確認済みにする" }).click();
  await expect(op.getByText("1 件を確認済みにしました")).toBeVisible();
  await expect(rows).toHaveCount(0);
  await op.getByRole("tab", { name: /^確認済み/ }).click();
  await op.locator("tr.review-row").first().getByRole("button", { name: "未確認に戻す" }).click();
  await expect(op.locator("tr.review-row")).toHaveCount(0);
  await op.getByRole("tab", { name: /^未確認/ }).click();
  await expect(all).toHaveCount(2);
  await opCtx.close();
});

// 基準の世代（ベースライン）。SW-3F の最初の世代を基準にすると、最新との差 +1 行がずれになる。同じ DB を使うので、最後に必ず解除する
test("オペレーターが基準を指定し、ずれがタブ・ダッシュボード・世代管理に出る", async ({ browser }) => {
  const opCtx = await browser.newContext();
  const op = await opCtx.newPage();
  const viewerCtx = await browser.newContext();
  try {
    await login(op, USERS.op);

    // 世代管理: 最初の世代を基準にする（メモ付き）。最新の世代にはボタンが残る
    await op.goto("/history");
    await op.locator(".page-header select").selectOption({ label: "SW-3F" });
    const hist = op.locator(".hist-table tr.hist-row");
    await expect(hist).toHaveCount(2);
    await expect(op.getByTestId("baseline-banner")).toHaveCount(0);
    await hist.nth(1).getByRole("button", { name: "基準にする" }).click();
    await op.getByLabel(/メモ（任意/).fill("2026 年度の見直しで承認");
    await op.locator(".modal").getByRole("button", { name: "基準にする", exact: true }).click();
    await expect(op.locator(".modal")).toHaveCount(0);
    await expect(hist.nth(1).locator(".baseline-badge")).toHaveText("基準");
    await expect(hist.nth(0).locator(".baseline-badge")).toHaveCount(0);
    await expect(hist.nth(1).getByRole("button", { name: "基準にする" })).toHaveCount(0);
    const banner = op.getByTestId("baseline-banner");
    await expect(banner).toContainText("から +1 -0 行のずれ");

    // 「差分を見る」: 基準 → 最新の差分
    await banner.getByRole("button", { name: "差分を見る" }).click();
    await expect(op.locator(".diff-add")).toHaveText(["+snmp-server location rack-12"]);

    // 変更の確認の「基準からのずれ」タブ
    await op.goto("/reviews");
    await op.getByRole("tab", { name: "基準からのずれ" }).click();
    await expect(op).toHaveURL(/tab=drift/);
    const rows = op.locator("tr.drift-row");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("SW-3F");
    await expect(rows.first()).toContainText("+1");
    await expect(rows.first()).toContainText("2026 年度の見直しで承認");
    await expect(op.getByTestId("drift-counts")).toContainText("ずれている 1 台");
    await expect(op.getByTestId("drift-counts")).toContainText("基準が未指定 3 台");
    await rows.first().getByRole("link", { name: "差分" }).click();
    await expect(op).toHaveURL(/\/history\?device=.+&drift=1/);
    await expect(op.locator(".diff-add")).toHaveText(["+snmp-server location rack-12"]);

    // 閲覧者: ずれは見えるが、操作のボタンは無い。ダッシュボードのタイル
    const viewer = await viewerCtx.newPage();
    await login(viewer, USERS.viewer);
    await viewer.goto("/reviews?tab=drift");
    await expect(viewer.locator("tr.drift-row")).toHaveCount(1);
    await expect(viewer.getByRole("button", { name: "最新を基準にする" })).toHaveCount(0);
    await viewer.locator('a[href="/dashboard"]').first().click();
    const tile = viewer.locator(".dash-tile", { hasText: "基準からずれている機器" });
    await expect(tile.locator(".dash-tile-value")).toHaveText("1");
    await tile.click();
    await expect(viewer).toHaveURL(/\/reviews\?tab=drift/);

    // 最新を基準にする → ずれの一覧から消え、世代管理のバッジが最新に移る
    await op.goto("/reviews?tab=drift");
    await rows.first().getByRole("button", { name: "最新を基準にする" }).click();
    await op.locator(".modal").getByRole("button", { name: "基準にする", exact: true }).click();
    await expect(rows).toHaveCount(0);
    await expect(op.getByTestId("drift-counts")).toContainText("基準どおり 1 台");
    await op.goto("/history");
    await op.locator(".page-header select").selectOption({ label: "SW-3F" });
    await expect(hist).toHaveCount(2);
    await expect(hist.nth(0).locator(".baseline-badge")).toHaveText("基準");
    await expect(op.getByTestId("baseline-banner")).toContainText("ずれなし");

    // 基準を解除する
    await op.getByRole("button", { name: "基準を解除" }).click();
    await op.locator(".modal").getByRole("button", { name: "基準を解除する" }).click();
    await expect(op.getByTestId("baseline-banner")).toHaveCount(0);
    await expect(op.locator(".baseline-badge")).toHaveCount(0);
  } finally {
    // 途中で失敗しても他のテストに残さない: SW-3F の基準を API で解除する
    await op.evaluate(async () => {
      const token = localStorage.getItem("access_token") ?? "";
      const h = { Authorization: `Bearer ${token}` };
      const list = await (await fetch("/api/configs/baselines?state=all", { headers: h })).json();
      for (const i of list.items ?? []) {
        if (i.baseline) await fetch(`/api/configs/${i.device_id}/baseline`, { method: "DELETE", headers: h });
      }
    }).catch(() => undefined);
    await viewerCtx.close();
    await opCtx.close();
  }
});
