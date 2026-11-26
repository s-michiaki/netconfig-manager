import { expect, test } from "@playwright/test";
import { login } from "./helpers";

// ダッシュボードの時計（ブラウザのタイムゾーン。playwright.config.ts で Asia/Tokyo）。秒は出さない
const FORMAT = /^\d{4}\/\d{2}\/\d{2}（[日月火水木金土]）\d{2}:\d{2}$/;

test("ダッシュボードに時計が出て、形式が合う", async ({ page }) => {
  await login(page);
  await page.goto("/dashboard");
  const clock = page.getByTestId("dash-clock");
  await expect(clock).toBeVisible();
  expect((await clock.innerText()).replace(/\s+/g, "")).toMatch(FORMAT);
  await expect(clock).toHaveAttribute("datetime", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
  await expect(clock).not.toHaveAttribute("aria-live", /.*/);
});

test("決めた時刻を表示し、分が変わった直後に進み、日付の変わり目で日付と曜日が変わる", async ({ page }) => {
  await page.clock.install({ time: new Date("2026-11-26T11:00:00+09:00") });
  await login(page);
  await page.goto("/dashboard");
  const clock = page.getByTestId("dash-clock");
  await expect(clock).toBeVisible();
  await page.clock.pauseAt(new Date("2026-11-26T11:38:30+09:00"));
  await expect(clock).toHaveText(/2026\/11\/26（木）\s*11:38$/);
  await page.clock.runFor(29_000); // 11:38:59 はまだ 11:38
  await expect(clock).toHaveText(/11:38$/);
  await page.clock.runFor(1_100); // 11:39:00 を過ぎた直後に切り替わる
  await expect(clock).toHaveText(/2026\/11\/26（木）\s*11:39$/);

  await page.clock.pauseAt(new Date("2026-11-26T23:59:30+09:00"));
  await page.clock.runFor(1_000);
  await expect(clock).toHaveText(/2026\/11\/26（木）\s*23:59$/);
  await page.clock.runFor(30_000);
  await page.clock.runFor(100);
  await expect(clock).toHaveText(/2026\/11\/27（金）\s*00:00$/);
});

test("ほかのページには時計が出ない", async ({ page }) => {
  await login(page); // ログイン後はデバイス管理
  await expect(page).toHaveURL(/\/devices/);
  await expect(page.locator(".page-title").first()).toBeVisible();
  await expect(page.getByTestId("dash-clock")).toHaveCount(0);
});

test("裏にしているあいだは止まり、戻ったらすぐ正しい時刻になる", async ({ page }) => {
  await page.clock.install({ time: new Date("2026-11-26T11:00:00+09:00") });
  await login(page);
  await page.goto("/dashboard");
  const clock = page.getByTestId("dash-clock");
  await expect(clock).toBeVisible();
  await page.clock.pauseAt(new Date("2026-11-26T11:38:30+09:00"));
  await expect(clock).toHaveText(/11:38$/);

  const setVisibility = (state: "hidden" | "visible") =>
    page.evaluate((v) => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => v });
      document.dispatchEvent(new Event("visibilitychange"));
    }, state);

  await setVisibility("hidden");
  await page.clock.runFor(5 * 60_000); // 裏のあいだは更新しない
  await expect(clock).toHaveText(/11:38$/);
  await setVisibility("visible"); // 戻ったらすぐ新しい時刻
  await expect(clock).toHaveText(/2026\/11\/26（木）\s*11:43$/);
});
