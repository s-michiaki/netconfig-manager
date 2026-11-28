import { expect, test, type Page } from "@playwright/test";
import { USERS, login } from "./helpers";

/**
 * 無操作のログアウト（src/idle.tsx）。page.clock で画面の時計を進めて、画面側の動きを確かめる。
 * サーバー側の判定（backend/tests/test_idle_timeout.py）は、画面テストの backend が Redis につながないので働かない（通す）。
 * 既定の IDLE_TIMEOUT_MIN=30 のまま。予告は切れる 1 分前（画面はサーバーの期限より 10 秒早く動く）
 */

const START = new Date("2026-11-26T09:00:00+09:00");
const MIN = 60_000;
const warning = (page: Page) => page.getByRole("alertdialog");
const REASON = "操作が無い時間が続いたため、ログアウトしました。";

/** ログインし、ログインの直後の操作（画面の移動のクリック）もサーバーへ送った状態にする（ここから 30 分で切れる） */
async function setup(page: Page) {
  await page.clock.install({ time: START });
  await login(page, USERS.op);
  await page.clock.fastForward(61_000); // 合図は 60 秒に 1 回に間引く
  await operate(page);
}

/** 利用者の操作（クリック）。サーバーへの合図が送られるのを待つ */
async function operate(page: Page) {
  const sent = page.waitForResponse((r) => r.url().endsWith("/api/auth/activity") && r.request().method() === "POST");
  await page.locator(".page-title").first().click();
  expect((await sent).status()).toBe(200);
}

test("操作が無いと 1 分前に予告が出て「続ける」で消え、時間が来るとログイン画面へ移って理由を表示する", async ({ page }) => {
  await setup(page);
  await page.clock.fastForward(28 * MIN);
  await expect(warning(page)).toHaveCount(0);
  await page.clock.fastForward(MIN);
  await expect(warning(page)).toBeVisible();
  await expect(warning(page)).toContainText("まもなくログアウトします");
  await expect(page.getByTestId("idle-remaining")).toHaveText(/^\d+$/);
  // 「続ける」はサーバーへすぐに送る
  const sent = page.waitForResponse((r) => r.url().endsWith("/api/auth/activity"));
  await warning(page).getByRole("button", { name: "続ける" }).click();
  expect((await sent).status()).toBe(200);
  await expect(warning(page)).toHaveCount(0);
  // 続けたあとも操作が無ければ、30 分で切れる（スリープから戻ったときと同じく、時刻の差で判定する）
  await page.clock.fastForward(31 * MIN);
  await expect(page).toHaveURL(/\/login\?.*reason=idle/);
  await expect(page.getByTestId("login-reason")).toHaveText(REASON);
  // ログインし直せば、元の画面に戻る
  await page.locator("input").nth(0).fill(USERS.op.name);
  await page.locator('input[type="password"]').fill(USERS.op.password);
  await page.locator("button.btn-primary").click();
  await expect(page).toHaveURL(/\/devices/);
});

test("予告は「続ける」にフォーカスし、Esc でも続けられる。時間切れのログアウトは reason=idle で送る", async ({ page }) => {
  await setup(page);
  await page.clock.fastForward(29 * MIN);
  await expect(warning(page)).toBeVisible();
  await expect(warning(page).getByRole("button", { name: "続ける" })).toBeFocused();
  const sent = page.waitForResponse((r) => r.url().endsWith("/api/auth/activity"));
  await page.keyboard.press("Escape");
  expect((await sent).status()).toBe(200);
  await expect(warning(page)).toHaveCount(0);
  const logout = page.waitForRequest((r) => r.url().endsWith("/api/auth/logout"));
  await page.clock.fastForward(31 * MIN);
  expect((await logout).postDataJSON()).toEqual({ reason: "idle" });
  await expect(page).toHaveURL(/\/login\?.*reason=idle/);
});

test("クリック・キー入力があれば予告は出ない", async ({ page }) => {
  await setup(page);
  await page.clock.fastForward(20 * MIN);
  await operate(page);
  await page.clock.fastForward(20 * MIN); // ログインから 41 分。最後の操作から 20 分
  await expect(warning(page)).toHaveCount(0);
  // キー入力も操作に数える
  const sent = page.waitForResponse((r) => r.url().endsWith("/api/auth/activity"));
  await page.keyboard.press("Shift");
  expect((await sent).status()).toBe(200);
  await page.clock.fastForward(20 * MIN);
  await expect(warning(page)).toHaveCount(0);
  await expect(page).toHaveURL(/\/devices/);
});

test("間引いて送らなかった操作も、予告を出す前に送って数える", async ({ page }) => {
  await setup(page);
  await page.clock.fastForward(10_000);
  await page.locator(".page-title").first().click(); // 前の合図から 60 秒たっていないので、まだ送らない
  const sent = page.waitForResponse((r) => r.url().endsWith("/api/auth/activity"));
  await page.clock.fastForward(29 * MIN); // 予告の時間に、送っていない操作を送る（予告は出さない）
  expect((await sent).status()).toBe(200);
  await page.clock.runFor(2_000);
  await expect(warning(page)).toHaveCount(0);
});

test("2 つのタブ: 片方の操作で、もう片方も切れない・予告が消える", async ({ page, context }) => {
  await setup(page);
  const other = await context.newPage();
  await other.goto("/devices");
  await expect(other.locator(".page-title").first()).toBeVisible();

  // もう片方のタブで操作 → このタブも延びる
  await page.clock.fastForward(20 * MIN);
  await operate(other);
  await page.clock.fastForward(20 * MIN);
  await expect(warning(page)).toHaveCount(0);
  await expect(warning(other)).toHaveCount(0);

  // 両方に予告（もう片方の操作から 29 分）→ 片方で「続ける」→ もう片方の予告も消える
  await page.clock.fastForward(9 * MIN);
  await expect(warning(page)).toBeVisible();
  await expect(warning(other)).toBeVisible();
  await warning(other).getByRole("button", { name: "続ける" }).click();
  await expect(warning(other)).toHaveCount(0);
  await expect(warning(page)).toHaveCount(0);

  // 時間が来ると、両方のタブがログイン画面へ
  await page.clock.fastForward(31 * MIN);
  await expect(page).toHaveURL(/\/login\?.*reason=idle/);
  await expect(other).toHaveURL(/\/login\?.*reason=idle/);
  await expect(other.getByTestId("login-reason")).toHaveText(REASON);
});

test("Ping 監視を動かしている間は予告を出さない", async ({ page }) => {
  await setup(page);
  await page.goto("/ping");
  await expect(page.getByTestId("ping-idle-note")).toHaveText(/監視中は、無操作でも自動ではログアウトしません/);
  await page.getByRole("button", { name: /^対象を選ぶ/ }).click();
  await page.locator(".ping-sel-item", { hasText: "Core-SW01" }).locator("input").check();
  await page.getByRole("button", { name: "決定" }).click();
  await page.getByRole("button", { name: "▶ 開始" }).click();
  // サーバーから ICMP を送れない環境では、監視は始まらない（mfa.spec.ts と同じく飛ばす）
  const unavailable = page.getByText(/PING を送れません/);
  await expect(page.locator(".badge", { hasText: "監視中" }).or(unavailable).first()).toBeVisible();
  await page.waitForTimeout(1500);
  test.skip(await unavailable.isVisible(), "この環境ではサーバーから ICMP を送れない");
  await expect(page.locator(".badge", { hasText: "監視中" })).toBeVisible();

  await page.clock.runFor(45 * MIN); // 監視中の印を書きながら進める
  await expect(warning(page)).toHaveCount(0);
  await expect(page).toHaveURL(/\/ping/);
  // 止めたあとは、そこから数えて切れる
  await page.getByRole("button", { name: "■ 停止" }).click();
  await page.clock.fastForward(31 * MIN);
  await expect(page).toHaveURL(/\/login\?.*reason=idle/);
});

test("サーバーが無操作で切ったとき（401）も、ログイン画面に理由を出す", async ({ page }) => {
  await login(page, USERS.op);
  await page.route("**/api/devices/", (route) => route.fulfill({
    status: 401,
    headers: { "X-Logout-Reason": "idle_timeout", "WWW-Authenticate": "Bearer" },
    json: { detail: "操作が無い時間が続いたため、ログアウトしました" },
  }));
  await page.reload();
  await expect(page).toHaveURL(/\/login\?.*reason=idle/);
  await expect(page.getByTestId("login-reason")).toHaveText(REASON);
});

test("ほかの理由の 401 では、理由を出さない", async ({ page }) => {
  await login(page, USERS.op);
  await page.route("**/api/devices/", (route) => route.fulfill({ status: 401, json: { detail: "認証情報が無効です" } }));
  await page.reload();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByTestId("login-reason")).toHaveCount(0);
});
