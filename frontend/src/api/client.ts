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

export function redirectToLogin() {
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
    if (err.response?.status === 401 && !err.config?.url?.startsWith("/auth/token")) {
      redirectToLogin();
    }
    return Promise.reject(err);
  }
);

export async function login(username: string, password: string): Promise<void> {
  const body = new URLSearchParams({ username, password });
  const r = await api.post("/auth/token", body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  setToken(r.data.access_token);
}

/** FastAPI のエラーレスポンスから表示用メッセージを取り出す */
export function errorMessage(err: unknown, fallback = "エラーが発生しました"): string {
  if (axios.isAxiosError(err)) {
    const detail = (err.response?.data as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d: { loc?: unknown[]; msg?: string }) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`)
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
