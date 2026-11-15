import { expect, test, type Page } from "@playwright/test";
import { USERS, login } from "./helpers";

const PROFILE = "E2E-共通アカウント";
const DEVICE = "SW-3F";

async function authHeaders(page: Page) {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  return { Authorization: `Bearer ${token}` };
}

/** 作ったデータを消す（e2e の DB は全テストで共有。SW-3F は初期データと同じ認証情報に戻す） */
async function cleanup(page: Page) {
  const headers = await authHeaders(page);
  const devices: { id: string; name: string; credential_profile_id: string | null }[] =
    await (await page.request.get("/api/devices/", { headers })).json();
  const dev = devices.find((d) => d.name === DEVICE);
  if (dev?.credential_profile_id) {
    const r = await page.request.put(`/api/devices/${dev.id}`, {
      headers, data: { credential_profile_id: null, username: "admin", password: "pw" },
    });
    expect(r.status()).toBe(200);
  }
  const profiles: { id: string; name: string }[] = await (await page.request.get("/api/credential-profiles/", { headers })).json();
  for (const p of profiles.filter((x) => x.name === PROFILE)) {
    expect((await page.request.delete(`/api/credential-profiles/${p.id}`, { headers })).status()).toBe(204);
  }
}

test("認証情報プロファイルを作って機器に割り当て、カードに表示する", async ({ page }) => {
  await login(page);
  await cleanup(page); // 前回の失敗で残っていても同じ結果になるように
  try {
    // プロファイルの作成
    await page.locator('a[href="/credential-profiles"]').first().click();
    await expect(page.locator(".page-title")).toHaveText("認証情報プロファイル");
    await page.getByRole("button", { name: "＋ 追加" }).click();
    const modal = page.locator(".modal");
    await modal.getByLabel("名前").fill(PROFILE);
    await modal.getByLabel("ユーザー名").fill("netops");
    await modal.getByLabel(/^パスワード/).fill("e2e-secret-pw");
    await modal.getByRole("button", { name: "追加" }).click();
    const row = page.locator("tr", { hasText: PROFILE });
    await expect(row).toContainText("netops");
    await expect(row).toContainText("0台");
    // 一覧にパスワードは出ない
    await expect(page.locator(".page-body")).not.toContainText("e2e-secret-pw");

    // 機器の編集で「プロファイルを使う」に切り替える
    await page.locator('a[href="/devices"]').first().click();
    const card = page.locator(".device-card", { hasText: DEVICE });
    await card.getByRole("button", { name: "編集" }).click();
    const dm = page.locator(".modal");
    await expect(dm.getByLabel("ユーザー名")).toHaveValue("admin");
    await dm.getByRole("tab", { name: "プロファイルを使う" }).click();
    await expect(dm.getByLabel("ユーザー名")).toHaveCount(0); // 機器ごとの入力欄は隠す
    await expect(dm.getByRole("button", { name: "保存" })).toBeDisabled(); // 選ぶまでは保存できない
    await dm.getByLabel("認証情報プロファイル").selectOption({ label: `${PROFILE}（netops）` });
    await expect(dm).toContainText("ユーザー名 netops");
    await expect(dm).toContainText("この機器に入っていた認証情報は消えます");
    await dm.getByRole("button", { name: "保存" }).click();
    await expect(card.locator(".device-card-profile")).toHaveText(`🪪 認証: ${PROFILE}`);

    // 編集し直すとプロファイルが選ばれている。個別入力に戻すときはパスワードが必要
    await card.getByRole("button", { name: "編集" }).click();
    await expect(dm.getByLabel("認証情報プロファイル")).toHaveValue(/.+/);
    await dm.getByRole("tab", { name: "この機器だけの認証情報を入力する" }).click();
    await expect(dm).toContainText("プロファイルを外すと");
    await expect(dm.getByRole("button", { name: "保存" })).toBeDisabled();
    await dm.getByRole("button", { name: "キャンセル" }).click();

    // 使用中のプロファイルは削除できない
    await page.locator('a[href="/credential-profiles"]').first().click();
    await expect(row).toContainText("1台");
    page.once("dialog", (d) => d.accept());
    await row.getByRole("button", { name: "削除" }).click();
    await expect(page.locator(".form-error")).toContainText("1台のデバイスがこの認証情報プロファイルを使用しているため削除できません");
  } finally {
    await cleanup(page);
  }
  await page.locator('a[href="/devices"]').first().click();
  await expect(page.locator(".device-card", { hasText: DEVICE })).toBeVisible();
  await expect(page.locator(".device-card-profile")).toHaveCount(0);
});

test("認証情報プロファイルのメニューは管理者だけに表示する", async ({ page }) => {
  for (const user of [USERS.op, USERS.viewer]) {
    await login(page, user);
    await expect(page.locator('a[href="/devices"]').first()).toBeVisible();
    await expect(page.locator('a[href="/credential-profiles"]')).toHaveCount(0);
    await page.evaluate(() => localStorage.clear());
  }
});

test("ほかの管理者のプロファイルは編集・割り当てできず、引き継ぐと扱えるようになる", async ({ page }) => {
  const NAME = "E2E-所有者テスト";
  const OTHER = { name: "e2e-admin2", password: "password-1234" };
  await login(page);
  const admin = await authHeaders(page);
  const removeProfile = async (headers: Record<string, string>) => {
    const list: { id: string; name: string; can_manage: boolean }[] =
      await (await page.request.get("/api/credential-profiles/", { headers })).json();
    for (const p of list.filter((x) => x.name === NAME)) {
      if (!p.can_manage) await page.request.post(`/api/credential-profiles/${p.id}/takeover`, { headers });
      expect((await page.request.delete(`/api/credential-profiles/${p.id}`, { headers })).status()).toBe(204);
    }
  };
  const removeUser = async () => {
    const users: { id: string; username: string }[] = await (await page.request.get("/api/users/", { headers: admin })).json();
    for (const u of users.filter((x) => x.username === OTHER.name)) await page.request.delete(`/api/users/${u.id}`, { headers: admin });
  };
  await removeProfile(admin); // 前回の失敗で残っていても同じ結果になるように
  await removeUser();
  try {
    // admin がプロファイルを作る（共有なし = 所有者だけが編集・使用できる）
    expect((await page.request.post("/api/credential-profiles/", {
      headers: admin, data: { name: NAME, username: "netops", password: "e2e-secret-pw" },
    })).status()).toBe(201);
    expect((await page.request.post("/api/users/", {
      headers: admin, data: { username: OTHER.name, password: OTHER.password, role: "admin" },
    })).status()).toBe(201);
    await page.locator('a[href="/credential-profiles"]').first().click();
    const row = page.locator("tr", { hasText: NAME });
    await expect(row).toContainText("所有者のみ");
    await expect(row.getByRole("button", { name: "編集" })).toBeVisible();

    // 別の管理者: 見えるが、編集も割り当てもできない
    await page.evaluate(() => localStorage.clear());
    await login(page, OTHER);
    await page.locator('a[href="/credential-profiles"]').first().click();
    await expect(row).toContainText("admin");
    await expect(row).toContainText("操作できません");
    await expect(row.getByRole("button", { name: "編集" })).toHaveCount(0);
    await page.locator('a[href="/devices"]').first().click();
    await page.locator(".device-card", { hasText: "SW-3F" }).getByRole("button", { name: "編集" }).click();
    const dm = page.locator(".modal");
    await dm.getByRole("tab", { name: "プロファイルを使う" }).click();
    const option = dm.getByLabel("認証情報プロファイル").locator("option", { hasText: NAME });
    await expect(option).toBeDisabled();
    await expect(option).toContainText("使用できません");
    await dm.getByRole("button", { name: "キャンセル" }).click();

    // 引き継ぐと所有者になり、編集できる
    await page.locator('a[href="/credential-profiles"]').first().click();
    page.once("dialog", (d) => { expect(d.message()).toContain("監査ログに残り"); void d.accept(); });
    await row.getByRole("button", { name: "引き継ぐ" }).click();
    await expect(row.getByRole("button", { name: "編集" })).toBeVisible();
    await expect(row).toContainText(OTHER.name);
  } finally {
    await removeProfile(await authHeaders(page));
    await removeUser();
  }
});
