import axios, { AxiosError } from "axios";

// 同一オリジンの /api を使う（開発時は Vite のプロキシ、本番は nginx が backend へ中継）。
// localhost を直書きすると、サーバーに別の端末からアクセスしたとき端末自身の localhost を見に行ってしまう
export const api = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

const TOKEN_KEY = "access_token";

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

/**
 * ログイン画面へ移る（トークンを消す）。
 * usedToken: 失敗した要求・接続に使ったトークン。いまのトークンがそれと違えば、ほかのタブ・同じ画面の操作
 * （パスワード変更・2 段階認証の設定など）で新しいトークンに差し替わった後なので、消さずに何もしない
 * （古いトークンの 401 で、受け取ったばかりの新しいトークンを消して全タブをログアウトさせないため）
 */
export function redirectToLogin(usedToken?: string | null) {
  const now = getToken();
  if (usedToken && now && usedToken !== now) return;
  clearToken();
  if (window.location.pathname !== "/login") {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login?next=${next}`;
  }
}

// トークン自動付与
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// 401でログイン画面へ（ログイン要求自体の401は画面側で表示する）
api.interceptors.response.use(
  (r) => r,
  (err: AxiosError) => {
    if (err.response?.status === 401 && !err.config?.url?.startsWith("/auth/token") && !err.config?.url?.startsWith("/auth/mfa/verify")) {
      const auth = String(err.config?.headers?.Authorization ?? "");
      redirectToLogin(auth.startsWith("Bearer ") ? auth.slice(7) : null);
    }
    return Promise.reject(err);
  }
);

/** パスワードでログインする。2 段階認証を設定している人は、確認コードを送るための mfaToken を返す（まだログインしていない） */
export async function login(username: string, password: string): Promise<{ mfaToken: string | null }> {
  const body = new URLSearchParams({ username, password });
  const r = await api.post("/auth/token", body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  if (r.data.mfa_required) return { mfaToken: r.data.mfa_token as string };
  setToken(r.data.access_token);
  return { mfaToken: null };
}

/** 2 段階認証の 2 段目: 認証アプリのコード（または予備コード）を送ってログインを終える */
export async function verifyMfa(mfaToken: string, code: string): Promise<void> {
  const r = await api.post("/auth/mfa/verify", { mfa_token: mfaToken, code });
  setToken(r.data.access_token);
}

/** FastAPI のエラーレスポンスから表示用メッセージを取り出す */
export function errorMessage(err: unknown, fallback = "エラーが発生しました"): string {
  if (axios.isAxiosError(err)) {
    const detail = (err.response?.data as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        // 入力チェック（field_validator）のメッセージに付く "Value error, " は表示しない
        .map((d: { loc?: unknown[]; msg?: string }) => `${(d.loc ?? []).slice(1).join(".")}: ${(d.msg ?? "").replace(/^Value error, /, "")}`)
        .join(" / ");
    }
    if (err.message) return err.message;
  }
  return fallback;
}

/** WebSocket の URL（現在のページと同じホスト・プロトコル） */
export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api${path}`;
}
