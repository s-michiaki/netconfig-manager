import { expect, test, type Page } from "@playwright/test";
import { login, openNav } from "./helpers";

// 偽の URL（実在しない。sig・ワークフローの ID は画面に出ないことを確かめる）
const TEAMS_URL =
  "https://xxxx.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/WFIDEXAMPLE/triggers/manual/paths/invoke" +
  "?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SIGEXAMPLE";
const LEGACY_URL =
  "https://prod-00.japaneast.logic.azure.com:443/workflows/WFIDEXAMPLE/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SIGEXAMPLE";

async function authHeaders(page: Page) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  return { Authorization: `Bearer ${token}` };
}

/** 作った設定を戻す（e2e の DB は全テストで共有） */
async function cleanup(page: Page) {
  const headers = await authHeaders(page);
  await page.request.put("/api/notifications/me", { headers, data: { mode: "inherit", teams_webhook: "" } });
  const groups = await page.request.get("/api/notifications/groups", { headers });
  for (const g of (await groups.json()) as { id: string; name: string }[]) {
    if (g.name.startsWith("e2e-teams")) await page.request.delete(`/api/notifications/groups/${g.id}`, { headers });
  }
}

test("通知設定に Teams の欄があり、URL を検証して保存できる（URL は画面に出ない）", async ({ page }) => {
  await login(page);
  await cleanup(page);
  try {
    await openNav(page, "/notifications");
    await expect(page.locator(".page-title")).toHaveText("通知設定");
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await expect(page.getByText(/「Webhook 要求を受信したとき」のフローを作り/)).toBeVisible();
    const field = page.getByLabel(/^Teams の Webhook URL/);
    await expect(field).toBeVisible();

    // 旧形式（logic.azure.com）・公式以外のホストは保存できない。理由は出るが、入力した URL は出ない
    await field.fill(LEGACY_URL);
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("コピーし直してください");
    await expect(page.locator(".form-error")).not.toContainText("SIGEXAMPLE");
    await field.fill("https://example.com/powerautomate/automations/direct/x/triggers/manual/paths/invoke?sig=EXAMPLE");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("Teams の Webhook URL が正しくありません");

    // 正しい URL は保存でき、登録済みの表示は伏せ字（sig・ワークフローの ID を出さない）
    await field.fill(TEAMS_URL);
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".ntf-ok")).toHaveText("保存しました");
    await expect(page.getByLabel(/^Teams の Webhook URL/)).toHaveValue("");
    await expect(page.locator("label", { hasText: /Teams の Webhook URL（登録済み: https:\/\/xxxx…/ })).toBeVisible();
    const body = await page.locator("body").innerText();
    expect(body).not.toContain("SIGEXAMPLE");
    expect(body).not.toContain("WFIDEXAMPLE");
    await expect(page.getByRole("button", { name: "テスト通知を送る" })).toBeVisible(); // Teams だけでも通知先になる

    // 再読み込みしても登録済み。削除にチェックして保存すると消える
    await page.reload();
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await expect(page.locator("label", { hasText: /Teams の Webhook URL（登録済み/ })).toBeVisible();
    await page.locator(".form-group", { hasText: "Teams の Webhook URL" }).getByLabel("この通知先を削除する").check();
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("通知先"); // 通知先が 1 つも無いので保存できない
  } finally {
    await cleanup(page);
  }
});

test("ユーザーグループの通知にも Teams の欄があり、一覧に Teams と出る", async ({ page }) => {
  await login(page);
  await cleanup(page);
  try {
    await openNav(page, "/notifications");
    await page.getByRole("tab", { name: "ユーザーグループ" }).click();
    await page.getByRole("button", { name: /ユーザーグループを作成/ }).click();
    await page.locator("#ug-name").fill("e2e-teams-grp");
    await page.getByLabel(/このグループの通知を有効にする/).check();
    await page.locator("#ug-teams").fill(TEAMS_URL);
    await page.locator(".modal").getByRole("button", { name: "保存" }).click();
    const card = page.locator(".ntf-group", { hasText: "e2e-teams-grp" });
    await expect(card.locator("dd", { hasText: "Teams" }).first()).toBeVisible();
    expect(await page.locator("body").innerText()).not.toContain("SIGEXAMPLE");
  } finally {
    await cleanup(page);
  }
});
