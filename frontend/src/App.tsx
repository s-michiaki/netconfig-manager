import { ComponentType, lazy, Suspense, useEffect, useRef, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, clearToken, errorMessage, getToken, setToken } from "./api/client";
import { AuthProvider, PERM, Perm, RequirePerm, useAuth } from "./auth";
import ApiTokenModal from "./components/ApiTokenModal";
import MfaModal from "./components/MfaModal";
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
const CommandsPage = lazyPage(() => import("./pages/CommandsPage"));
const CollectPage = lazyPage(() => import("./pages/CollectPage"));
const CompliancePage = lazyPage(() => import("./pages/CompliancePage"));
const HistoryPage = lazyPage(() => import("./pages/HistoryPage"));
const JumpHostsPage = lazyPage(() => import("./pages/JumpHostsPage"));
const CredentialProfilesPage = lazyPage(() => import("./pages/CredentialProfilesPage"));
const NotificationsPage = lazyPage(() => import("./pages/NotificationsPage"));
const PingPage = lazyPage(() => import("./pages/PingPage"));
const SchedulePage = lazyPage(() => import("./pages/SchedulePage"));
const TerminalPage = lazyPage(() => import("./pages/TerminalPage"));
const TopologyPage = lazyPage(() => import("./pages/TopologyPage"));
const UsersPage = lazyPage(() => import("./pages/UsersPage"));
const MonitoringPage = lazyPage(() => import("./pages/MonitoringPage"));
const VulnsPage = lazyPage(() => import("./pages/VulnsPage"));
const SystemPage = lazyPage(() => import("./pages/SystemPage"));
const DashboardPage = lazyPage(() => import("./pages/DashboardPage"));
const ReviewsPage = lazyPage(() => import("./pages/ReviewsPage"));
const IgnoreRulesPage = lazyPage(() => import("./pages/IgnoreRulesPage"));
const SearchPage = lazyPage(() => import("./pages/SearchPage"));

type NavItem = { path: string; label: string; icon: string; perm: Perm; feature?: string };
type NavGroup = { id: string; label: string; items: NavItem[] };

/** 一番上に単独で出すメニュー */
const NAV_TOP: NavItem = { path: "/dashboard", label: "ダッシュボード", icon: "🏠", perm: PERM.DEVICE_READ };

/** 大項目と小項目（この順番で表示する。権限・機能の条件で小項目が 1 つも無い大項目は出さない） */
const NAV_GROUPS: NavGroup[] = [
  {
    id: "devices", label: "機器",
    items: [
      { path: "/devices", label: "デバイス管理", icon: "🖥", perm: PERM.DEVICE_READ },
      { path: "/topology", label: "構成図", icon: "⬢", perm: PERM.TOPOLOGY_READ },
      { path: "/terminal", label: "ターミナル", icon: "⌨", perm: PERM.TERMINAL },
      { path: "/commands", label: "コマンド実行", icon: "▤", perm: PERM.COMMAND_RUN },
      { path: "/jump-hosts", label: "踏み台サーバ", icon: "↪", perm: PERM.DEVICE_WRITE },
      { path: "/credential-profiles", label: "認証情報プロファイル", icon: "🪪", perm: PERM.DEVICE_WRITE },
    ],
  },
  {
    id: "config", label: "コンフィグ",
    items: [
      { path: "/collect", label: "コンフィグ収集", icon: "↻", perm: PERM.COLLECT },
      { path: "/schedules", label: "スケジュール", icon: "📅", perm: PERM.SCHEDULE_READ },
      { path: "/history", label: "世代管理", icon: "🕐", perm: PERM.CONFIG_READ },
      { path: "/reviews", label: "変更の確認", icon: "☑", perm: PERM.CONFIG_READ },
      { path: "/search", label: "コンフィグ検索", icon: "🔎", perm: PERM.CONFIG_READ },
      { path: "/compliance", label: "コンプライアンス", icon: "✔", perm: PERM.COMPLIANCE_READ },
      { path: "/ignore-rules", label: "無視する行", icon: "🚫", perm: PERM.CONFIG_IGNORE },
    ],
  },
  {
    id: "monitor", label: "監視",
    items: [
      { path: "/ping", label: "Ping監視", icon: "◉", perm: PERM.PING_USE },
      // 試験導入中（.env の MONITORING_ENABLED=true のときだけ表示）
      { path: "/monitoring", label: "モニタリング", icon: "📈", perm: PERM.MONITOR_READ, feature: "monitoring" },
      // 脆弱性・サポート期限（.env の VULN_ENABLED=true のときだけ表示。既定は無効）
      { path: "/vulns", label: "脆弱性・サポート期限", icon: "⚠", perm: PERM.VULN_READ, feature: "vuln" },
      { path: "/activity", label: "アクティビティ", icon: "📋", perm: PERM.ACTIVITY_READ },
    ],
  },
  {
    id: "admin", label: "管理",
    items: [
      { path: "/notifications", label: "通知設定", icon: "🔔", perm: PERM.NOTIFY_SELF },
      { path: "/users", label: "ユーザー管理", icon: "👥", perm: PERM.USER_ADMIN },
      { path: "/audit", label: "監査ログ", icon: "🛡", perm: PERM.AUDIT_READ },
      { path: "/system", label: "システム状態", icon: "🩺", perm: PERM.SYSTEM_READ },
    ],
  },
];

const isOnPath = (pathname: string, path: string) => pathname.startsWith(path);

/** いまの画面を含む大項目の id（権限・機能の条件に関係なく、定義から引く。モニタリングの有無が決まる前でも変わらない） */
function groupOfPath(pathname: string): string | undefined {
  return NAV_GROUPS.find((g) => g.items.some((i) => isOnPath(pathname, i.path)))?.id;
}

// 大項目の開閉（ブラウザに保存）
function navOpenKey(username: string | undefined) {
  return `ncm.nav.open.${username ?? ""}`;
}
function readNavOpen(username: string | undefined): string[] | null {
  try {
    const raw = localStorage.getItem(navOpenKey(username));
    if (raw === null) return null;
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : null;
  } catch {
    return null;
  }
}
function writeNavOpen(username: string | undefined, ids: string[]) {
  try {
    localStorage.setItem(navOpenKey(username), JSON.stringify(ids));
  } catch {
    /* 保存できなくても、この画面を開いている間は効く */
  }
}

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
            <p className="topo-muted topo-small" style={{ marginTop: 0 }}>API トークンは失効しません（漏れた疑いがあるときは「API トークン」から失効させてください）。</p>
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
  const { me, can, reload } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [showMfa, setShowMfa] = useState(false);
  const [showTokens, setShowTokens] = useState(false);
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

  // 大項目の開閉。初めての人は、いまの画面を含む大項目だけが開いた状態
  const username = me?.username;
  const [navOpen, setNavOpen] = useState<string[]>(() => {
    // 保存値に、いまの画面の大項目を足す（初回に閉じた状態が一瞬見えないように）
    const saved = readNavOpen(username) ?? [];
    const g = groupOfPath(location.pathname);
    return g && !saved.includes(g) ? [...saved, g] : saved;
  });
  const lastGroup = useRef(groupOfPath(location.pathname));
  useEffect(() => {
    // 開いている画面を含む大項目は、別の大項目から移ってきたときに自動で開く。
    // 同じ大項目の中の移動（/terminal → /terminal/5 など）では、手で閉じた状態を開き直さない
    const g = groupOfPath(location.pathname);
    if (g && g !== lastGroup.current) setNavOpen((prev) => (prev.includes(g) ? prev : [...prev, g]));
    lastGroup.current = g;
  }, [location.pathname]);
  useEffect(() => {
    writeNavOpen(username, navOpen);
  }, [username, navOpen]);
  const toggleGroup = (id: string) =>
    setNavOpen((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  const logout = () => {
    clearToken();
    window.location.href = "/login";
  };

  return (
    <div className="app-layout">
      {showPassword && <PasswordModal onClose={() => setShowPassword(false)} />}
      {showMfa && me && <MfaModal enabled={!!me.mfa_enabled} onClose={() => setShowMfa(false)} onChanged={() => { reload(); }} />}
      {showTokens && <ApiTokenModal onClose={() => setShowTokens(false)} />}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-logo">⬡ NetConfig</span>
        </div>
        <nav className="sidebar-nav">
          {can(NAV_TOP.perm) && (
            <Link to={NAV_TOP.path}
              className={`nav-item ${isOnPath(location.pathname, NAV_TOP.path) ? "active" : ""}`}>
              <span className="nav-icon">{NAV_TOP.icon}</span>
              {NAV_TOP.label}
            </Link>
          )}
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((item) => can(item.perm) && (!item.feature || features[item.feature]));
            if (items.length === 0) return null;
            const open = navOpen.includes(group.id);
            const hasCurrent = group.items.some((i) => isOnPath(location.pathname, i.path));
            const showAlert = !open && systemStatus !== "ok" && items.some((i) => i.path === "/system");
            return (
              <div key={group.id} className="nav-group">
                <button
                  type="button"
                  className={`nav-group-head${!open && hasCurrent ? " active" : ""}`}
                  aria-expanded={open}
                  aria-controls={open ? `nav-sub-${group.id}` : undefined}
                  onClick={() => toggleGroup(group.id)}
                >
                  <span className="nav-caret" aria-hidden="true">{open ? "▾" : "▸"}</span>
                  {group.label}
                  {showAlert && (
                    <span className={`nav-alert${systemStatus === "error" ? " error" : ""}`}
                          title={systemStatus === "error" ? "システムに異常があります" : "確認が必要な項目があります"} />
                  )}
                </button>
                {open && (
                  <div id={`nav-sub-${group.id}`} className="nav-sub">
                    {items.map((item) => (
                      <Link
                        key={item.path}
                        to={item.path}
                        title={item.label}
                        className={`nav-item nav-sub-item ${isOnPath(location.pathname, item.path) ? "active" : ""}`}
                      >
                        <span className="nav-icon">{item.icon}</span>
                        <span className="nav-label">{item.label}</span>
                        {item.path === "/system" && systemStatus !== "ok" && (
                          <span className={`nav-alert${systemStatus === "error" ? " error" : ""}`}
                                title={systemStatus === "error" ? "システムに異常があります" : "確認が必要な項目があります"} />
                        )}
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          {me && (
            <div className="sidebar-user">
              <span>
                👤 {me.username} <span className="role-tag">{me.role_label}</span>
              </span>
              <div style={{ display: "flex", gap: "2px 10px", flexWrap: "wrap", whiteSpace: "nowrap" }}>
                <button className="link-btn" onClick={() => setShowPassword(true)}>パスワード変更</button>
                <button className="link-btn" onClick={() => setShowMfa(true)} title={me.mfa_enabled ? "2 段階認証: 設定済み" : "2 段階認証: 未設定"}>
                  2 段階認証{me.mfa_enabled ? " ✓" : ""}
                </button>
                <button className="link-btn" onClick={() => setShowTokens(true)} title="スクリプトなどから API を使うためのトークン">
                  API トークン
                </button>
                <button className="link-btn" onClick={logout}>ログアウト</button>
              </div>
            </div>
          )}
          <span className="version-tag">{version ? `v${version}` : ""}</span>
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
          <Route path="/credential-profiles"
            element={<RequirePerm perm={PERM.DEVICE_WRITE}><CredentialProfilesPage /></RequirePerm>} />
          <Route path="/collect" element={<RequirePerm perm={PERM.COLLECT}><CollectPage /></RequirePerm>} />
          <Route path="/history" element={<RequirePerm perm={PERM.CONFIG_READ}><HistoryPage /></RequirePerm>} />
          <Route path="/reviews" element={<RequirePerm perm={PERM.CONFIG_READ}><ReviewsPage /></RequirePerm>} />
          <Route path="/search" element={<RequirePerm perm={PERM.CONFIG_READ}><SearchPage /></RequirePerm>} />
          <Route path="/terminal" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/commands" element={<RequirePerm perm={PERM.COMMAND_RUN}><CommandsPage /></RequirePerm>} />
          <Route path="/terminal/:deviceId" element={<RequirePerm perm={PERM.TERMINAL}><TerminalPage /></RequirePerm>} />
          <Route path="/ping" element={<RequirePerm perm={PERM.PING_USE}><PingPage /></RequirePerm>} />
          <Route path="/monitoring" element={<RequirePerm perm={PERM.MONITOR_READ}><MonitoringPage /></RequirePerm>} />
          <Route path="/vulns" element={<RequirePerm perm={PERM.VULN_READ}><VulnsPage /></RequirePerm>} />
          <Route path="/schedules" element={<RequirePerm perm={PERM.SCHEDULE_READ}><SchedulePage /></RequirePerm>} />
          <Route path="/ignore-rules" element={<RequirePerm perm={PERM.CONFIG_IGNORE}><IgnoreRulesPage /></RequirePerm>} />
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
