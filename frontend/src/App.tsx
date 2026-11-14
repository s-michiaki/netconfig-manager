import { ComponentType, lazy, Suspense, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, clearToken, errorMessage, getToken, setToken } from "./api/client";
import { AuthProvider, PERM, Perm, RequirePerm, useAuth } from "./auth";
import DevicesPage from "./pages/DevicesPage";
import LoginPage from "./pages/LoginPage";

/**
 * 画面ごとに分割して必要なときだけ読み込む（初回表示を軽くする。構成図の React Flow・ターミナルの xterm.js など）
 * 更新（再デプロイ）で古いファイルが消えていた場合は、一度だけ再読み込みして新しいものを取りに行く
 */
function lazyPage(load: () => Promise<{ default: ComponentType }>) {
  return lazy(() =>
    load()
      .then((m) => {
        sessionStorage.removeItem("chunk-reload");
        return m;
      })
      .catch((e) => {
        if (!sessionStorage.getItem("chunk-reload")) {
          sessionStorage.setItem("chunk-reload", "1");
          window.location.reload();
          return new Promise<never>(() => undefined);
        }
        throw e;
      }),
  );
}
const ActivityPage = lazyPage(() => import("./pages/ActivityPage"));
const AuditPage = lazyPage(() => import("./pages/AuditPage"));
const CollectPage = lazyPage(() => import("./pages/CollectPage"));
const CompliancePage = lazyPage(() => import("./pages/CompliancePage"));
const HistoryPage = lazyPage(() => import("./pages/HistoryPage"));
const JumpHostsPage = lazyPage(() => import("./pages/JumpHostsPage"));
const NotificationsPage = lazyPage(() => import("./pages/NotificationsPage"));
const PingPage = lazyPage(() => import("./pages/PingPage"));
const SchedulePage = lazyPage(() => import("./pages/SchedulePage"));
const TerminalPage = lazyPage(() => import("./pages/TerminalPage"));
const TopologyPage = lazyPage(() => import("./pages/TopologyPage"));
const UsersPage = lazyPage(() => import("./pages/UsersPage"));
const MonitoringPage = lazyPage(() => import("./pages/MonitoringPage"));
const SystemPage = lazyPage(() => import("./pages/SystemPage"));
const DashboardPage = lazyPage(() => import("./pages/DashboardPage"));
const SearchPage = lazyPage(() => import("./pages/SearchPage"));

const NAV_ITEMS: { path: string; label: string; icon: string; perm: Perm; feature?: string }[] = [
  { path: "/dashboard", label: "ダッシュボード", icon: "🏠", perm: PERM.DEVICE_READ },
  { path: "/devices", label: "デバイス管理", icon: "🖥", perm: PERM.DEVICE_READ },
  { path: "/topology", label: "構成図", icon: "⬢", perm: PERM.TOPOLOGY_READ },
  { path: "/jump-hosts", label: "踏み台サーバ", icon: "↪", perm: PERM.DEVICE_WRITE },
  { path: "/collect", label: "コンフィグ収集", icon: "↻", perm: PERM.COLLECT },
  { path: "/ping", label: "Ping監視", icon: "◉", perm: PERM.PING_USE },
  // 試験導入中（.env の MONITORING_ENABLED=true のときだけ表示）
  { path: "/monitoring", label: "モニタリング", icon: "📈", perm: PERM.MONITOR_READ, feature: "monitoring" },
  { path: "/history", label: "世代管理", icon: "🕐", perm: PERM.CONFIG_READ },
  { path: "/search", label: "コンフィグ検索", icon: "🔎", perm: PERM.CONFIG_READ },
  { path: "/terminal", label: "ターミナル", icon: "⌨", perm: PERM.TERMINAL },
  { path: "/schedules", label: "スケジュール", icon: "📅", perm: PERM.SCHEDULE_READ },
  { path: "/compliance", label: "コンプライアンス", icon: "✔", perm: PERM.COMPLIANCE_READ },
  { path: "/notifications", label: "通知設定", icon: "🔔", perm: PERM.NOTIFY_SELF },
  { path: "/activity", label: "アクティビティ", icon: "📋", perm: PERM.ACTIVITY_READ },
  { path: "/audit", label: "監査ログ", icon: "🛡", perm: PERM.AUDIT_READ },
  { path: "/users", label: "ユーザー管理", icon: "👥", perm: PERM.USER_ADMIN },
  { path: "/system", label: "システム状態", icon: "🩺", perm: PERM.SYSTEM_READ },
];

function PasswordModal({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const submit = async () => {
    setError("");
    try {
      const r = await api.post("/auth/change-password", { current_password: current, new_password: next });
      // 変更前のトークンは無効になるので、返ってきた新しいトークンに差し替える
      setToken(r.data.access_token);
      setDone(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">パスワード変更</p>
        {done ? (
          <p style={{ marginBottom: 16 }}>パスワードを変更しました。</p>
        ) : (
          <>
            <div className="form-group">
              <label className="form-label">現在のパスワード</label>
              <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">新しいパスワード（10文字以上）</label>
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
            </div>
            {error && <p className="form-error">{error}</p>}
          </>
        )}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
          {!done && (
            <button className="btn btn-primary" onClick={submit} disabled={!current || next.length < 10}>
              変更
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function Layout() {
  const location = useLocation();
  const { me, can } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [version, setVersion] = useState("");
  const [features, setFeatures] = useState<Record<string, boolean>>({});
  useEffect(() => {
    api.get<{ version?: string; features?: Record<string, boolean> }>("/health").then((r) => {
      setVersion(r.data.version ?? "");
      setFeatures(r.data.features ?? {});
    }).catch(() => undefined);
  }, []);

  // 管理者には、システムに異常・注意があることをメニューの印で知らせる（worker の停止などに気づけるように）
  const [systemStatus, setSystemStatus] = useState<string>("ok");
  const canSystem = can(PERM.SYSTEM_READ);
  useEffect(() => {
    if (!canSystem) return;
    const check = () => api.get<{ overall: string }>("/system/status")
      .then((r) => setSystemStatus(r.data.overall)).catch(() => undefined);
    check();
    const t = window.setInterval(check, 120_000);
    return () => window.clearInterval(t);
  }, [canSystem, location.pathname === "/system"]);

  const logout = () => {
    clearToken();
    window.location.href = "/login";
  };

  return (
    <div className="app-layout">
      {showPassword && <PasswordModal onClose={() => setShowPassword(false)} />}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-logo">⬡ NetConfig</span>
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.filter((item) => can(item.perm) && (!item.feature || features[item.feature])).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
              {item.path === "/system" && systemStatus !== "ok" && (
                <span className={`nav-alert${systemStatus === "error" ? " error" : ""}`}
                      title={systemStatus === "error" ? "システムに異常があります" : "確認が必要な項目があります"} />
              )}
            </Link>
          ))}
        </nav>
        <div className="sidebar-footer">
          {me && (
            <div className="sidebar-user">
              <span>
                👤 {me.username} <span className="role-tag">{me.role_label}</span>
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="link-btn" onClick={() => setShowPassword(true)}>パスワード変更</button>
                <button className="link-btn" onClick={logout}>ログアウト</button>
              </div>
            </div>
          )}
          <span className="version-tag">{version ? `v${version} · ` : ""}RHEL 10</span>
        </div>
      </aside>

      <main className="main-content">
        <Suspense fallback={<div className="page"><div className="page-body topo-muted">読み込み中...</div></div>}>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<RequirePerm perm={PERM.DEVICE_READ}><DashboardPage /></RequirePerm>} />
          <Route path="/devices" element={<RequirePerm perm={PERM.DEVICE_READ}><DevicesPage /></RequirePerm>} />
          <Route path="/topology" element={<RequirePerm perm={PERM.TOPOLOGY_READ}><TopologyPage /></RequirePerm>} />
          <Route path="/topology/:mapId" element={<RequirePerm perm={PERM.TOPOLOGY_READ}><TopologyPage /></RequirePerm>} />
          <Route path="/jump-hosts" element={<RequirePerm perm={PERM.DEVICE_WRITE}><JumpHostsPage /></RequirePerm>} />
          <Route path="/collect" element={<RequirePerm perm={PERM.COLLECT}><CollectPage /></RequirePerm>} />
          <Route path="/history" element={<RequirePerm perm={PERM.CONFIG_READ}><HistoryPage /></RequirePerm>} />
          <Route path="/search" element={<RequirePerm perm={PERM.CONFIG_READ}><SearchPage /></RequirePerm>} />
          <Route path="/terminal" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/terminal/:deviceId" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/ping" element={<RequirePerm perm={PERM.PING_USE}><PingPage /></RequirePerm>} />
          <Route path="/monitoring" element={<RequirePerm perm={PERM.MONITOR_READ}><MonitoringPage /></RequirePerm>} />
          <Route path="/schedules" element={<RequirePerm perm={PERM.SCHEDULE_READ}><SchedulePage /></RequirePerm>} />
          <Route path="/compliance" element={<RequirePerm perm={PERM.COMPLIANCE_READ}><CompliancePage /></RequirePerm>} />
          <Route path="/notifications" element={<RequirePerm perm={PERM.NOTIFY_SELF}><NotificationsPage /></RequirePerm>} />
          <Route path="/activity" element={<RequirePerm perm={PERM.ACTIVITY_READ}><ActivityPage /></RequirePerm>} />
          <Route path="/audit" element={<RequirePerm perm={PERM.AUDIT_READ}><AuditPage /></RequirePerm>} />
          <Route path="/users" element={<RequirePerm perm={PERM.USER_ADMIN}><UsersPage /></RequirePerm>} />
          <Route path="/system" element={<RequirePerm perm={PERM.SYSTEM_READ}><SystemPage /></RequirePerm>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
        </Suspense>
      </main>
    </div>
  );
}

function RequireAuth({ children }: { children: JSX.Element }) {
  const location = useLocation();
  if (!getToken()) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <AuthProvider>
              <Layout />
            </AuthProvider>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
