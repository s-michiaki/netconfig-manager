import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api } from "./api/client";

/** backend/app/core/permissions.py の Perm と対応 */
export const PERM = {
  DEVICE_READ: "device:read",
  DEVICE_WRITE: "device:write",
  CONFIG_READ: "config:read",
  COLLECT: "collect:run",
  TERMINAL: "terminal:use",
  SCHEDULE_READ: "schedule:read",
  SCHEDULE_WRITE: "schedule:write",
  USER_ADMIN: "user:admin",
} as const;
export type Perm = (typeof PERM)[keyof typeof PERM];

export interface Me {
  id: string;
  username: string;
  role: string;
  role_label: string;
  permissions: string[];
}

interface AuthState {
  me: Me | null;
  can: (perm: Perm) => boolean;
  reload: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({ me: null, can: () => false, reload: async () => undefined });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [failed, setFailed] = useState(false);

  const reload = useCallback(async () => {
    try {
      const r = await api.get<Me>("/auth/me");
      setMe(r.data);
    } catch {
      setFailed(true); // 401 の場合は client.ts がログイン画面へ移動させる
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  if (!me) {
    return (
      <div className="login-wrap" style={{ color: "var(--color-muted)" }}>
        {failed ? "ユーザー情報を取得できませんでした。再読み込みしてください。" : "読み込み中..."}
      </div>
    );
  }

  // 画面表示の切り替え用。実際の権限チェックは必ずサーバー側で行われる
  const can = (perm: Perm) => me.permissions.includes(perm);
  return <AuthContext.Provider value={{ me, can, reload }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);

/** 権限が無いページを開いたときの表示 */
export function RequirePerm({ perm, children }: { perm: Perm; children: JSX.Element }) {
  const { can } = useAuth();
  if (!can(perm)) {
    return (
      <div className="page">
        <div className="page-body">
          <p style={{ color: "var(--color-muted)", padding: 24 }}>このページを表示する権限がありません。</p>
        </div>
      </div>
    );
  }
  return children;
}
