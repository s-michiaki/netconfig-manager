import { useState } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, clearToken, errorMessage, getToken, setToken } from "./api/client";
import { AuthProvider, PERM, Perm, RequirePerm, useAuth } from "./auth";
import AuditPage from "./pages/AuditPage";
import CollectPage from "./pages/CollectPage";
import CompliancePage from "./pages/CompliancePage";
import DevicesPage from "./pages/DevicesPage";
import HistoryPage from "./pages/HistoryPage";
import JumpHostsPage from "./pages/JumpHostsPage";
import LoginPage from "./pages/LoginPage";
import SchedulePage from "./pages/SchedulePage";
import TerminalPage from "./pages/TerminalPage";
import TopologyPage from "./pages/TopologyPage";
import UsersPage from "./pages/UsersPage";

const NAV_ITEMS: { path: string; label: string; icon: string; perm: Perm }[] = [
  { path: "/devices", label: "デバイス管理", icon: "🖥", perm: PERM.DEVICE_READ },
  { path: "/topology", label: "構成図", icon: "⬢", perm: PERM.TOPOLOGY_READ },
  { path: "/jump-hosts", label: "踏み台サーバ", icon: "↪", perm: PERM.DEVICE_WRITE },
  { path: "/collect", label: "コンフィグ収集", icon: "↻", perm: PERM.COLLECT },
  { path: "/history", label: "世代管理", icon: "🕐", perm: PERM.CONFIG_READ },
  { path: "/terminal", label: "ターミナル", icon: "⌨", perm: PERM.TERMINAL },
  { path: "/schedules", label: "スケジュール", icon: "📅", perm: PERM.SCHEDULE_READ },
  { path: "/compliance", label: "コンプライアンス", icon: "✔", perm: PERM.COMPLIANCE_READ },
  { path: "/audit", label: "監査ログ", icon: "🛡", perm: PERM.AUDIT_READ },
  { path: "/users", label: "ユーザー管理", icon: "👥", perm: PERM.USER_ADMIN },
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
          {NAV_ITEMS.filter((item) => can(item.perm)).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
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
          <span className="version-tag">v1.5.0 · RHEL 10</span>
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/devices" replace />} />
          <Route path="/devices" element={<RequirePerm perm={PERM.DEVICE_READ}><DevicesPage /></RequirePerm>} />
          <Route path="/topology" element={<RequirePerm perm={PERM.TOPOLOGY_READ}><TopologyPage /></RequirePerm>} />
          <Route path="/topology/:mapId" element={<RequirePerm perm={PERM.TOPOLOGY_READ}><TopologyPage /></RequirePerm>} />
          <Route path="/jump-hosts" element={<RequirePerm perm={PERM.DEVICE_WRITE}><JumpHostsPage /></RequirePerm>} />
          <Route path="/collect" element={<RequirePerm perm={PERM.COLLECT}><CollectPage /></RequirePerm>} />
          <Route path="/history" element={<RequirePerm perm={PERM.CONFIG_READ}><HistoryPage /></RequirePerm>} />
          <Route path="/terminal" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/terminal/:deviceId" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/schedules" element={<RequirePerm perm={PERM.SCHEDULE_READ}><SchedulePage /></RequirePerm>} />
          <Route path="/compliance" element={<RequirePerm perm={PERM.COMPLIANCE_READ}><CompliancePage /></RequirePerm>} />
          <Route path="/audit" element={<RequirePerm perm={PERM.AUDIT_READ}><AuditPage /></RequirePerm>} />
          <Route path="/users" element={<RequirePerm perm={PERM.USER_ADMIN}><UsersPage /></RequirePerm>} />
          <Route path="*" element={<Navigate to="/devices" replace />} />
        </Routes>
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
