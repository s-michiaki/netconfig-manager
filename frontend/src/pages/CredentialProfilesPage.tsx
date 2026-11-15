import { ChangeEvent, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

export interface CredentialProfile {
  id: string;
  name: string;
  username: string;
  description: string | null;
  has_password: boolean;
  has_private_key: boolean;
  has_enable_secret: boolean;
  key_info: string | null;
  device_count: number;
}

const EMPTY = {
  name: "", username: "", description: "",
  password: "", private_key: "", key_passphrase: "", enable_secret: "",
  clear_password: false, clear_private_key: false, clear_enable_secret: false,
};

function ProfileModal({ profile, onClose, onSaved }: {
  profile: CredentialProfile | null; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = profile !== null;
  const [form, setForm] = useState(() =>
    profile ? { ...EMPTY, name: profile.name, username: profile.username, description: profile.description ?? "" } : EMPTY
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));

  // 秘密鍵ファイルを読み込んでテキスト欄に入れる（ブラウザ内で読むだけで、送信は「保存」時のみ）
  const loadKeyFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 16 * 1024) {
      setError("秘密鍵ファイルが大きすぎます（16KBまで）");
      return;
    }
    file.text().then((t) => set("private_key", t));
    e.target.value = "";
  };

  const willHavePassword = (isEdit && profile.has_password && !form.clear_password) || !!form.password;
  const willHaveKey = (isEdit && profile.has_private_key && !form.clear_private_key) || !!form.private_key;
  const canSave = form.name.trim() && form.username && (willHavePassword || willHaveKey);

  const save = async () => {
    setSaving(true);
    setError("");
    const body = {
      name: form.name,
      username: form.username,
      description: form.description || null,
      password: form.password || undefined,
      private_key: form.private_key || undefined,
      key_passphrase: form.key_passphrase || undefined,
      enable_secret: form.enable_secret || undefined,
      ...(isEdit ? {
        clear_password: form.clear_password, clear_private_key: form.clear_private_key,
        clear_enable_secret: form.clear_enable_secret,
      } : {}),
    };
    try {
      if (isEdit) await api.put(`/credential-profiles/${profile.id}`, body);
      else await api.post("/credential-profiles/", body);
      onSaved();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 520 }} onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? `認証情報プロファイル編集: ${profile.name}` : "認証情報プロファイル追加"}</p>
        {isEdit && profile.device_count > 0 && (
          <p className="form-hint platform-note" style={{ margin: "0 0 12px" }}>
            ⓘ このプロファイルは {profile.device_count} 台の機器が使っています。変更は、それらの機器の次の接続（収集・ターミナル・FW ヒット数）から反映されます。
          </p>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="cp-name">名前</label>
          <input id="cp-name" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="例: 本社スイッチ共通" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-user">ユーザー名</label>
          <input id="cp-user" value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
        </div>

        <p className="section-label" style={{ marginTop: 6 }}>認証（パスワード・SSH秘密鍵のどちらか、または両方）</p>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-pw">
            パスワード{isEdit && profile.has_password ? "（設定済み。変更時のみ入力）" : ""}
          </label>
          <input id="cp-pw" type="password" autoComplete="new-password" value={form.password}
            onChange={(e) => set("password", e.target.value)} disabled={form.clear_password} />
          {isEdit && profile.has_password && (
            <label className="form-check" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.clear_password} onChange={(e) => set("clear_password", e.target.checked)} />
              パスワードを削除する（鍵認証のみにする）
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">
            SSH秘密鍵（OpenSSH / PEM 形式）{isEdit && profile.has_private_key ? `— 設定済み: ${profile.key_info ?? ""}` : "（任意）"}
          </label>
          <textarea
            className="mono"
            rows={4}
            value={form.private_key}
            onChange={(e) => set("private_key", e.target.value)}
            disabled={form.clear_private_key}
            placeholder={isEdit && profile.has_private_key
              ? "変更する場合のみ貼り付け"
              : "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
            spellCheck={false}
            style={{ fontSize: 11, resize: "vertical" }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 6 }}>
            <label className="btn" style={{ padding: "2px 10px", fontSize: 11, cursor: "pointer" }}>
              ファイルから読み込む
              <input type="file" onChange={loadKeyFile} style={{ display: "none" }} disabled={form.clear_private_key} />
            </label>
            {isEdit && profile.has_private_key && (
              <label className="form-check">
                <input type="checkbox" checked={form.clear_private_key}
                  onChange={(e) => set("clear_private_key", e.target.checked)} />
                秘密鍵を削除する
              </label>
            )}
          </div>
        </div>
        {(form.private_key || (isEdit && profile.has_private_key && !form.clear_private_key)) && (
          <div className="form-group">
            <label className="form-label">鍵のパスフレーズ（鍵が保護されている場合）</label>
            <input type="password" autoComplete="new-password" value={form.key_passphrase}
              onChange={(e) => set("key_passphrase", e.target.value)} />
          </div>
        )}
        {!(willHavePassword || willHaveKey) && (
          <p className="form-error">パスワードとSSH秘密鍵の少なくとも一方が必要です</p>
        )}
        <div className="form-group">
          <label className="form-label">
            Enableシークレット（任意{isEdit && profile.has_enable_secret ? "・設定済み。変更時のみ入力" : ""}）
          </label>
          <input type="password" autoComplete="new-password" value={form.enable_secret}
            onChange={(e) => set("enable_secret", e.target.value)} disabled={form.clear_enable_secret} />
          {isEdit && profile.has_enable_secret && (
            <label className="form-check" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.clear_enable_secret}
                onChange={(e) => set("clear_enable_secret", e.target.checked)} />
              Enableシークレットを削除する
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="cp-desc">説明（任意）</label>
          <input id="cp-desc" value={form.description} onChange={(e) => set("description", e.target.value)} />
        </div>
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

export default function CredentialProfilesPage() {
  const canWrite = useAuth().can(PERM.DEVICE_WRITE);
  const [items, setItems] = useState<CredentialProfile[]>([]);
  const [modal, setModal] = useState<{ profile: CredentialProfile | null } | null>(null);
  const [error, setError] = useState("");

  const load = () =>
    api.get<CredentialProfile[]>("/credential-profiles/").then((r) => setItems(r.data)).catch((e) => setError(errorMessage(e)));
  useEffect(() => { load(); }, []);

  const del = async (p: CredentialProfile) => {
    if (!confirm(`認証情報プロファイル「${p.name}」を削除しますか？`)) return;
    setError("");
    try {
      await api.delete(`/credential-profiles/${p.id}`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="page">
      {modal && <ProfileModal profile={modal.profile} onClose={() => setModal(null)} onSaved={load} />}
      <div className="page-header">
        <span className="page-title">認証情報プロファイル</span>
        {canWrite && <button className="btn btn-primary" onClick={() => setModal({ profile: null })}>＋ 追加</button>}
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        <p style={{ fontSize: 12, color: "var(--color-muted)", marginBottom: 14 }}>
          同じアカウント（ユーザー名・パスワード・Enable・SSH 鍵）を使う機器が多いときは、ここで 1 つ作り、デバイスの編集で選びます。
          パスワードを変えるときはプロファイルを直すだけで、それを使う全機器の次の接続（収集・ターミナル・FW ヒット数）に反映されます。
          使用中のプロファイルは削除できません。
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>名前</th>
              <th>ユーザー名</th>
              <th>認証</th>
              <th>使用デバイス</th>
              {canWrite && <th>操作</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id}>
                <td style={{ fontWeight: 500 }}>
                  {p.name}
                  {p.description && <div style={{ fontSize: 11, color: "var(--color-muted)" }}>{p.description}</div>}
                </td>
                <td className="mono" style={{ fontSize: 12 }}>{p.username}</td>
                <td style={{ fontSize: 12 }}>
                  {p.has_password && <span className="badge badge-neutral" style={{ marginRight: 4 }}>パスワード</span>}
                  {p.has_private_key && <span className="badge badge-neutral" style={{ marginRight: 4 }} title={p.key_info ?? ""}>秘密鍵</span>}
                  {p.has_enable_secret && <span className="badge badge-neutral">Enable</span>}
                </td>
                <td style={{ fontSize: 12 }}>{p.device_count}台</td>
                {canWrite && (
                  <td>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setModal({ profile: p })}>
                        編集
                      </button>
                      <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => del(p)}>
                        削除
                      </button>
                    </div>
                  </td>
                )}
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 5 : 4} style={{ color: "var(--color-muted)", textAlign: "center", padding: 24 }}>
                認証情報プロファイルが登録されていません
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
