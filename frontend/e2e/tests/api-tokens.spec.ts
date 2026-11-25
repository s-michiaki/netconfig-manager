import { expect, test, type APIRequestContext } from "@playwright/test";
import { login, USERS } from "./helpers";

const status = async (request: APIRequestContext, token: string, path = "/api/devices/") =>
  (await request.get(path, { headers: { Authorization: `Bearer ${token}` } })).status();

test("API トークンを発行し、その値で API を呼べ、失効させると呼べなくなる", async ({ page, request, browser }) => {
  await login(page, USERS.viewer);
  let token = "";
  try {
    await page.getByRole("button", { name: "API トークン" }).click();
    const modal = page.getByRole("dialog", { name: "API トークン" });
    await expect(modal.locator(".modal-title")).toHaveText("API トークン");

    // パスワードを間違えると発行できない
    await modal.getByLabel("名前（用途）").fill("e2e-夜間の確認");
    await modal.getByLabel("範囲").selectOption("read");
    await expect(modal.getByLabel(/期限（日/)).toHaveValue("90");
    await expect(modal.getByLabel(/期限（日/)).toHaveAttribute("max", "365");
    await modal.getByLabel(/期限（日/).fill("7");
    await modal.getByLabel("パスワード（本人の確認）").fill("wrong-password");
    await modal.getByRole("button", { name: "発行" }).click();
    await expect(modal.locator(".form-error")).toContainText("パスワードが正しくありません");

    await modal.getByLabel("パスワード（本人の確認）").fill(USERS.viewer.password);
    await modal.getByRole("button", { name: "発行" }).click();
    // 発行した直後だけ値を表示する
    await expect(modal.getByText("この画面を閉じると二度と表示できません")).toBeVisible();
    token = (await modal.getByTestId("api-token-value").textContent())!.trim();
    expect(token).toMatch(/^ncm_[A-Za-z0-9_-]{43}$/);
    await expect(modal.locator(".apitok-example")).toContainText(`Bearer ${token.slice(0, 12)}`);
    // クリップボードが使えないときは、手でコピーするよう案内する
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true }));
    await modal.getByRole("button", { name: "コピー" }).click();
    await expect(modal.getByRole("alert")).toContainText("手でコピーしてください");

    // その値で API を呼べる。read なので書き込みは不可、トークンでトークンは作れない
    expect(await status(request, token)).toBe(200);
    expect((await request.post("/api/devices/collect/all", { headers: { Authorization: `Bearer ${token}` } })).status()).toBe(403);
    expect(await status(request, token, "/api/auth/tokens")).toBe(403);

    // 「控えました」の後は値を表示しない（一覧には先頭だけ）
    await modal.getByRole("button", { name: "控えました" }).click();
    const row = modal.locator("tr", { hasText: "e2e-夜間の確認" });
    await expect(row).toContainText("閲覧だけ（read）");
    await expect(row).toContainText(token.slice(0, 12));
    await expect(row.locator(".badge")).toHaveText("有効");
    await expect(modal).not.toContainText(token);

    // 管理者のユーザー管理にトークンの数が出る
    const adminCtx = await browser.newContext();
    const admin = await adminCtx.newPage();
    await login(admin);
    await admin.goto("/users");
    const urow = admin.locator("tr", { has: admin.getByText(USERS.viewer.name, { exact: true }) });
    await expect(urow.getByTestId("user-api-tokens")).toHaveText("1 個");
    await expect(urow.getByRole("button", { name: "トークンを失効" })).toBeVisible();
    await adminCtx.close();

    // 失効させると、すぐに呼べなくなる
    page.once("dialog", (d) => d.accept());
    await row.getByRole("button", { name: "失効" }).click();
    await expect(row.locator(".badge")).toHaveText("失効");
    expect(await status(request, token)).toBe(401);
  } finally {
    // 途中で失敗したときも、作ったトークンを残さない（ほかのテストに影響しないように）
    if (token && (await status(request, token)) === 200) {
      const session = await page.evaluate(() => localStorage.getItem("access_token"));
      const list = await (await request.get("/api/auth/tokens", { headers: { Authorization: `Bearer ${session}` } })).json();
      for (const t of list.items) {
        if (t.status === "active") await request.delete(`/api/auth/tokens/${t.id}`, { headers: { Authorization: `Bearer ${session}` } });
      }
    }
  }
});
