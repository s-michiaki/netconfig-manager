import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import { useAuth } from "../auth";

interface User {
  id: string;
  username: string;
  role: string;
  role_label: string;
  is_active: boolean;
  created_at: string | null;
  mfa_enabled: boolean;
  api_tokens: number; // 有効な API トークンの数
}
interface RoleInfo { role: string; label: string; permissions: string[]; }

const PERM_LABELS: Record<string, string> = {
  "device:read": "デバイス閲覧",
  "device:write": "デバイス登録・編集",
  "config:read": "コンフィグ・差分の閲覧・比較・保存",
  "config:comment": "変更へのコメント（作業内容のメモ）",
  "config:review": "変更の確認（確認済み・想定外を付ける）",
  "config:ignore": "収集時に無視する行の設定",
  "collect:run": "収集の実行",
  "terminal:use": "SSHターミナル",
  "command:run": "コマンド実行（表示コマンドの一括実行と結果の閲覧）",
  "schedule:read": "スケジュール閲覧",
  "schedule:write": "スケジュール編集",
  "user:admin": "ユーザー管理",
  "topology:read": "構成図閲覧",
  "topology:write": "構成図編集",
  "compliance:read": "コンプライアンス閲覧",
  "compliance:write": "コンプライアンスのルール編集",
  "audit:read": "監査ログ閲覧",
  "ping:use": "Ping監視の利用",
  "ping:write": "Ping監視の対象IPの追加・編集",
  "notify:self": "変更通知（自分の設定）",
  "activity:read": "アクティビティの閲覧",
};

function UserModal({
  user, roles, onClose, onSaved,
}: { user: User | null; roles: RoleInfo[]; onClose: () => void; onSaved: () => void }) {
  const isEdit = user !== null;
  const [username, setUsername] = useState(user?.username ?? "");
  const [role, setRole] = useState(user?.role ?? "viewer");
  const [isActive, setIsActive] = useState(user?.is_active ?? true);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      if (isEdit) {
        await api.patch(`/users/${user.id}`, { role, is_active: isActive, password: password || undefined });
      } else {
        await api.post("/users/", { username, password, role, is_active: isActive });
      }
      onSaved();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const selected = roles.find((r) => r.role === role);
  const canSave = isEdit ? !password || password.length >= 10 : username && password.length >= 10;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? `ユーザー編集: ${user.username}` : "ユーザー追加"}</p>
        {!isEdit && (
          <div className="form-group">
            <label className="form-label">ユーザー名（英数字と . _ @ -）</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
          </div>
        )}
        <div className="form-group">
          <label className="form-label">ロール</label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => <option key={r.role} value={r.role}>{r.label}</option>)}
          </select>
          {selected && (
            <p style={{ fontSize: 11, color: "var(--color-muted)", marginTop: 6 }}>
              {selected.permissions.map((p) => PERM_LABELS[p] ?? p).join(" / ")}
            </p>
          )}
          {isEdit && role !== user.role && user.api_tokens > 0 && (
            <p style={{ fontSize: 11, color: "var(--color-warning)", marginTop: 4 }}>
              ロールを変えると、このユーザーの API トークン（{user.api_tokens} 個）はすべて失効します
            </p>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">
            {isEdit ? "パスワードをリセット（変更時のみ・10文字以上）" : "初期パスワード（10文字以上）"}
          </label>
          <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          {isEdit && password && (
            <p style={{ fontSize: 11, color: "var(--color-warning)", marginTop: 4 }}>
              リセットすると、このユーザーはログアウトされ、API トークンもすべて失効します
            </p>
          )}
        </div>
        <label className="form-check" style={{ marginBottom: 14 }}>
          <input type="checkbox" checked={isActive} onChange={(e) => setIsActive(e.target.checked)} />
          有効（無効にするとログインできなくなり、ログイン中のセッションも切れます）
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={saving || !canSave}>
            {isEdit ? "保存" : "追加"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function UsersPage() {
  const { me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<RoleInfo[]>([]);
  const [modal, setModal] = useState<{ user: User | null } | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = () =>
    api.get<User[]>("/users/").then((r) => setUsers(r.data)).catch((e) => setError(errorMessage(e)));

  useEffect(() => {
    load();
    api.get<RoleInfo[]>("/users/roles").then((r) => setRoles(r.data)).catch((e) => setError(errorMessage(e)));
  }, []);

  // パスワードは変えずに、その人の既存のログインを切る（再ログインは可能）
  const forceLogout = async (u: User) => {
    if (!confirm(
      `ユーザー「${u.username}」をログアウトさせますか？\n` +
      "ログイン中の画面・API の利用と、開いているターミナルが切れます。API トークンもすべて失効します。" +
      "パスワードは変わらず、再ログインはできます。",
    )) return;
    setError("");
    setNotice("");
    try {
      const r = await api.post<{ closed_terminals: number }>(`/users/${u.id}/logout`);
      const n = r.data.closed_terminals;
      setNotice(`「${u.username}」をログアウトさせました${n ? `（開いていたターミナル ${n} 件も切断）` : ""}`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  // その人の API トークンをすべて失効させる（ログインはそのまま）
  const revokeTokens = async (u: User) => {
    if (!confirm(
      `ユーザー「${u.username}」の API トークン（有効なもの ${u.api_tokens} 個）をすべて失効させますか？\n` +
      "そのトークンを使っているスクリプトは、すぐに使えなくなります。ログインはそのままです。",
    )) return;
    setError("");
    setNotice("");
    try {
      const r = await api.delete<{ revoked_tokens: number }>(`/users/${u.id}/tokens`);
      setNotice(`「${u.username}」の API トークン ${r.data.revoked_tokens} 個を失効させました`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  // 認証アプリも予備コードも無くした人の 2 段階認証を解除する（本人は次のログインからパスワードだけで入れる）
  const resetMfa = async (u: User) => {
    if (!confirm(
      `ユーザー「${u.username}」の 2 段階認証を解除しますか？\n` +
      "本人が認証アプリを無くしたときに使います。本人であることを確かめてから解除し、再設定を案内してください。",
    )) return;
    setError("");
    setNotice("");
    try {
      await api.post(`/users/${u.id}/mfa-reset`);
      setNotice(`「${u.username}」の 2 段階認証を解除しました`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const del = async (u: User) => {
    if (!confirm(`ユーザー「${u.username}」を削除しますか？`)) return;
    setError("");
    setNotice("");
    try {
      await api.delete(`/users/${u.id}`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="page">
      {modal && <UserModal user={modal.user} roles={roles} onClose={() => setModal(null)} onSaved={load} />}
      <div className="page-header">
        <span className="page-title">ユーザー管理</span>
        <button className="btn btn-primary" onClick={() => setModal({ user: null })}>＋ 追加</button>
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {notice && <p className="users-notice" role="status">{notice}</p>}
        <p className="section-label">ユーザー ({users.length}人)</p>
        <table className="data-table">
          <thead>
            <tr>
              <th>ユーザー名</th>
              <th>ロール</th>
              <th>状態</th>
              <th>2 段階認証</th>
              <th>API トークン</th>
              <th>作成日</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const isMe = u.id === me?.id;
              return (
                <tr key={u.id}>
                  <td style={{ fontWeight: 500 }}>
                    {u.username}
                    {isMe && <span className="role-tag">自分</span>}
                  </td>
                  <td style={{ fontSize: 12 }}>{u.role_label}</td>
                  <td>
                    <span className={`badge ${u.is_active ? "badge-success" : "badge-neutral"}`}>
                      {u.is_active ? "有効" : "無効"}
                    </span>
                  </td>
                  <td>
                    {u.mfa_enabled
                      ? <span className="badge badge-success">設定済み</span>
                      : <span style={{ fontSize: 12, color: "var(--color-muted)" }}>未設定</span>}
                  </td>
                  <td style={{ fontSize: 12 }} data-testid="user-api-tokens">
                    {u.api_tokens ? `${u.api_tokens} 個` : <span style={{ color: "var(--color-muted)" }}>なし</span>}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--color-muted)" }}>
                    {u.created_at ? new Date(u.created_at + "Z").toLocaleDateString("ja-JP") : "—"}
                  </td>
                  <td>
                    {isMe ? (
                      <span style={{ fontSize: 11, color: "var(--color-muted)" }}>サイドバーからパスワード変更・2 段階認証・API トークン</span>
                    ) : (
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setModal({ user: u })}>
                          編集
                        </button>
                        <button
                          className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => forceLogout(u)}
                          title="パスワードを変えずに、ログイン中の画面・API・開いているターミナルを切ります"
                        >
                          ログアウトさせる
                        </button>
                        {u.api_tokens > 0 && (
                          <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => revokeTokens(u)}
                                  title="この人の API トークンをすべて失効させます（ログインはそのまま）">
                            トークンを失効
                          </button>
                        )}
                        {u.mfa_enabled && (
                          <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => resetMfa(u)}
                                  title="認証アプリを無くしたときなどに、2 段階認証を解除します">
                            2 段階認証を解除
                          </button>
                        )}
                        <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => del(u)}>
                          削除
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {roles.length > 0 && (
          <>
            <p className="section-label" style={{ marginTop: 24 }}>ロールと権限</p>
            <table className="data-table">
              <thead>
                <tr>
                  <th>権限</th>
                  {roles.map((r) => <th key={r.role}>{r.label}</th>)}
                </tr>
              </thead>
              <tbody>
                {Object.entries(PERM_LABELS).map(([perm, label]) => (
                  <tr key={perm}>
                    <td style={{ fontSize: 12 }}>{label}</td>
                    {roles.map((r) => (
                      <td key={r.role} style={{ color: r.permissions.includes(perm) ? "var(--color-success)" : "var(--color-muted)" }}>
                        {r.permissions.includes(perm) ? "✓" : "—"}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
