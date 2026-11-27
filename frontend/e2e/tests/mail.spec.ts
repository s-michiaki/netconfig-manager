import { expect, test, type Page } from "@playwright/test";
import { login, openNav } from "./helpers";

async function authHeaders(page: Page) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  return { Authorization: `Bearer ${token}` };
}

/** 作った設定を戻す（e2e の DB は全テストで共有） */
async function cleanup(page: Page) {
  const headers = await authHeaders(page);
  await page.request.put("/api/notifications/me", { headers, data: { mode: "inherit", email_to: "" } });
  await page.request.put("/api/mail/server", { headers, data: { enabled: false, password: "" } });
}

test("メールサーバーを設定し、自分の通知にメールの宛先を登録する", async ({ page }) => {
  await login(page);
  await cleanup(page);
  try {
    await openNav(page, "/notifications");
    await expect(page.locator(".page-title")).toHaveText("通知設定");

    // 宛先を登録しようとしても、メールサーバーが無効なら保存できない
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await page.getByLabel(/^メールの宛先/).fill("ops@example.test");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("メール送信が設定されていません");

    // メールサーバー（SMTP Auth）
    await page.getByRole("tab", { name: "メールサーバー" }).click();
    await page.getByRole("radio", { name: /Microsoft 365/ }).check();
    await expect(page.getByRole("textbox", { name: "SMTP サーバー" })).toHaveValue("smtp.office365.com"); // 既定値が入る
    await expect(page.getByRole("textbox", { name: "テナント ID" })).toBeVisible();
    await page.getByRole("radio", { name: /SMTP Auth/ }).check();
    await page.getByRole("textbox", { name: "SMTP サーバー" }).fill("smtp.example.test");
    await page.getByRole("textbox", { name: "ユーザー名" }).fill("notify@example.test");
    await page.getByLabel(/^パスワード/).fill("smtp-pass-e2e");
    await page.getByLabel("送信元のメールアドレス").fill("notify@example.test");
    await page.getByLabel(/宛先に使えるドメイン/).fill("example.test");
    await page.getByLabel(/メール送信を有効にする/).check();
    await page.getByRole("button", { name: "保存", exact: true }).click();
    await expect(page.locator(".ntf-ok")).toHaveText("保存しました");
    await expect(page.locator(".badge-success", { hasText: "登録済み" })).toBeVisible(); // パスワードは表示しない
    await expect(page.getByLabel(/^パスワード/)).toHaveValue("");

    // テスト送信（届かない宛先の SMTP サーバーなので、理由が表示される）
    await page.getByLabel("テストメールの宛先").fill("ops@example.test");
    await page.getByRole("button", { name: "テストメールを送る" }).click();
    await expect(page.locator("p", { hasText: /SMTP サーバーに接続できません|送信できません/ })).toBeVisible({ timeout: 30_000 });

    // 自分の通知にメールの宛先（許可していないドメインは保存できない）
    await page.getByRole("tab", { name: "自分の通知" }).click();
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await page.getByLabel(/^メールの宛先/).fill("ops@outside.test");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".form-error")).toContainText("送れません");
    await page.getByLabel(/^メールの宛先/).fill("ops@example.test\nteam@example.test");
    await page.getByRole("button", { name: "保存" }).click();
    await expect(page.locator(".ntf-ok")).toHaveText("保存しました");
    await page.reload();
    await expect(page.getByLabel(/^メールの宛先/)).toHaveValue("ops@example.test\nteam@example.test");
  } finally {
    await cleanup(page);
  }
});

/**
 * 同じ GET の 2 回目だけを遅らせる。開発サーバーは React.StrictMode で、画面を開いたときの読み込みを 2 回走らせる
 * （負荷が高いと 2 回目の応答が操作のあとに届く）。遅れて届いた応答が、入力中の値を消さないことを確かめる
 * 戻り値の finished: 2 回目の応答を画面に返し終えたら解決する Promise（Promise をそのまま返すと await で待ってしまうので、オブジェクトに包む）
 */
async function delaySecondGet(page: Page, glob: string, ms: number): Promise<{ finished: Promise<void> }> {
  let n = 0;
  let done!: () => void;
  const finished = new Promise<void>((resolve) => { done = resolve; });
  await page.route(glob, async (route) => {
    if (route.request().method() !== "GET" || ++n !== 2) return route.continue();
    const res = await route.fetch();
    await new Promise((r) => setTimeout(r, ms));
    await route.fulfill({ response: res });
    done();
  });
  return { finished };
}

/** 表示の更新（React の再描画）が終わるまで待つ */
async function settleRender(page: Page) {
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
}

test("画面を開いたときの読み込みの応答が遅れて届いても、入力した値が消えない（通知設定・メールサーバー）", async ({ page }) => {
  await login(page);
  await cleanup(page);
  try {
    const me = await delaySecondGet(page, "**/api/notifications/me", 1500);
    const mail = await delaySecondGet(page, "**/api/mail/server", 1500);

    await openNav(page, "/notifications");
    await page.getByRole("radio", { name: /個別に設定する/ }).check();
    await page.getByLabel(/^メールの宛先/).fill("ops@example.test");
    await me.finished;
    await settleRender(page);
    await expect(page.getByRole("radio", { name: /個別に設定する/ })).toBeChecked();
    await expect(page.getByLabel(/^メールの宛先/)).toHaveValue("ops@example.test");

    await page.getByRole("tab", { name: "メールサーバー" }).click();
    await page.getByRole("radio", { name: /Microsoft 365/ }).check();
    await page.getByLabel("送信元のメールアドレス").fill("notify@example.test");
    await mail.finished;
    await settleRender(page);
    await expect(page.getByRole("radio", { name: /Microsoft 365/ })).toBeChecked();
    await expect(page.getByLabel("送信元のメールアドレス")).toHaveValue("notify@example.test");
  } finally {
    await page.unroute("**/api/notifications/me");
    await page.unroute("**/api/mail/server");
    await cleanup(page);
  }
});
