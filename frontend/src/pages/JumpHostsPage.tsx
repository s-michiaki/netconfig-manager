import { ChangeEvent, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

interface JumpHost {
  id: string;
  name: string;
  hostname: string;
  port: number;
  username: string;
  description: string | null;
  has_password: boolean;
  has_private_key: boolean;
  key_info: string | null;
  device_count: number;
}

type TestResult = { ok: boolean; message: string };

const EMPTY = {
  name: "", hostname: "", port: 22, username: "", description: "",
  password: "", private_key: "", key_passphrase: "",
  clear_password: false, clear_private_key: false,
};

function JumpHostModal({ jump, onClose, onSaved }: { jump: JumpHost | null; onClose: () => void; onSaved: () => void }) {
  const isEdit = jump !== null;
  const [form, setForm] = useState(() =>
    jump ? { ...EMPTY, name: jump.name, hostname: jump.hostname, port: jump.port, username: jump.username,
             description: jump.description ?? "" } : EMPTY
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

  const willHavePassword = (isEdit && jump.has_password && !form.clear_password) || !!form.password;
  const willHaveKey = (isEdit && jump.has_private_key && !form.clear_private_key) || !!form.private_key;
  const canSave = form.name && form.hostname && form.username && (willHavePassword || willHaveKey);

  const save = async () => {
    setSaving(true);
    setError("");
    const body = {
      name: form.name,
      hostname: form.hostname,
      port: form.port,
      username: form.username,
      description: form.description || null,
      password: form.password || undefined,
      private_key: form.private_key || undefined,
      key_passphrase: form.key_passphrase || undefined,
      ...(isEdit ? { clear_password: form.clear_password, clear_private_key: form.clear_private_key } : {}),
    };
    try {
      if (isEdit) await api.put(`/jump-hosts/${jump.id}`, body);
      else await api.post("/jump-hosts/", body);
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
        <p className="modal-title">{isEdit ? `踏み台サーバ編集: ${jump.name}` : "踏み台サーバ追加"}</p>
        <div className="form-group">
          <label className="form-label">名前</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="例: bastion-tokyo" />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
          <div className="form-group">
            <label className="form-label">IPアドレス / FQDN</label>
            <input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">SSHポート</label>
            <input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", +e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">ユーザー名</label>
          <input value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
        </div>

        <p className="section-label" style={{ marginTop: 6 }}>認証（パスワード・秘密鍵のどちらか、または両方）</p>
        <div className="form-group">
          <label className="form-label">
            パスワード{isEdit && jump.has_password ? "（設定済み。変更時のみ入力）" : ""}
          </label>
          <input type="password" autoComplete="new-password" value={form.password}
            onChange={(e) => set("password", e.target.value)} disabled={form.clear_password} />
          {isEdit && jump.has_password && (
            <label className="form-check" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.clear_password} onChange={(e) => set("clear_password", e.target.checked)} />
              パスワードを削除する
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">
            秘密鍵（OpenSSH / PEM 形式）{isEdit && jump.has_private_key ? `— 設定済み: ${jump.key_info ?? ""}` : ""}
          </label>
          <textarea
            className="mono"
            rows={5}
            value={form.private_key}
            onChange={(e) => set("private_key", e.target.value)}
            disabled={form.clear_private_key}
            placeholder={isEdit && jump.has_private_key
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
            {isEdit && jump.has_private_key && (
              <label className="form-check">
                <input type="checkbox" checked={form.clear_private_key}
                  onChange={(e) => set("clear_private_key", e.target.checked)} />
                秘密鍵を削除する
              </label>
            )}
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">鍵のパスフレーズ（鍵が保護されている場合）</label>
          <input type="password" autoComplete="new-password" value={form.key_passphrase}
            onChange={(e) => set("key_passphrase", e.target.value)} disabled={form.clear_private_key} />
        </div>
        <div className="form-group">
          <label className="form-label">説明（任意）</label>
          <input value={form.description} onChange={(e) => set("description", e.target.value)} />
        </div>
        {!(willHavePassword || willHaveKey) && (
          <p className="form-error">パスワードと秘密鍵の少なくとも一方が必要です</p>
        )}
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

export default function JumpHostsPage() {
  const canWrite = useAuth().can(PERM.DEVICE_WRITE);
  const [items, setItems] = useState<JumpHost[]>([]);
  const [modal, setModal] = useState<{ jump: JumpHost | null } | null>(null);
  const [error, setError] = useState("");
  const [tests, setTests] = useState<Record<string, TestResult | "running">>({});

  const load = () =>
    api.get<JumpHost[]>("/jump-hosts/").then((r) => setItems(r.data)).catch((e) => setError(errorMessage(e)));
  useEffect(() => { load(); }, []);

  const runTest = async (j: JumpHost) => {
    setTests((t) => ({ ...t, [j.id]: "running" }));
    try {
      const r = await api.post<TestResult>(`/jump-hosts/${j.id}/test`, {}, { timeout: 90000 });
      setTests((t) => ({ ...t, [j.id]: r.data }));
    } catch (e) {
      setTests((t) => ({ ...t, [j.id]: { ok: false, message: errorMessage(e) } }));
    }
  };

  const del = async (j: JumpHost) => {
    if (!confirm(`踏み台サーバ「${j.name}」を削除しますか？`)) return;
    setError("");
    try {
      await api.delete(`/jump-hosts/${j.id}`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="page">
      {modal && <JumpHostModal jump={modal.jump} onClose={() => setModal(null)} onSaved={load} />}
      <div className="page-header">
        <span className="page-title">踏み台サーバ</span>
        {canWrite && <button className="btn btn-primary" onClick={() => setModal({ jump: null })}>＋ 追加</button>}
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        <p style={{ fontSize: 12, color: "var(--color-muted)", marginBottom: 14 }}>
          デバイスに踏み台を設定すると、コンフィグ収集とSSHターミナルはこの踏み台を経由して接続します（1段まで）。
          踏み台側の sshd で TCP フォワーディング（AllowTcpForwarding）が許可されている必要があります。
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>名前</th>
              <th>接続先</th>
              <th>認証</th>
              <th>使用デバイス</th>
              {canWrite && <th>操作</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((j) => {
              const t = tests[j.id];
              return (
                <tr key={j.id}>
                  <td style={{ fontWeight: 500 }}>
                    {j.name}
                    {j.description && <div style={{ fontSize: 11, color: "var(--color-muted)" }}>{j.description}</div>}
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>{j.username}@{j.hostname}:{j.port}</td>
                  <td style={{ fontSize: 12 }}>
                    {j.has_password && <span className="badge badge-neutral" style={{ marginRight: 4 }}>パスワード</span>}
                    {j.has_private_key && <span className="badge badge-neutral" title={j.key_info ?? ""}>秘密鍵</span>}
                  </td>
                  <td style={{ fontSize: 12 }}>{j.device_count}台</td>
                  {canWrite && (
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => runTest(j)}
                          disabled={t === "running"}>
                          {t === "running" ? "テスト中..." : "接続テスト"}
                        </button>
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setModal({ jump: j })}>
                          編集
                        </button>
                        <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => del(j)}>
                          削除
                        </button>
                      </div>
                      {t && t !== "running" && (
                        <div style={{ fontSize: 11, marginTop: 4, color: t.ok ? "var(--color-success)" : "var(--color-danger)" }}>
                          {t.ok ? "✓ " : "✗ "}{t.message}
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 5 : 4} style={{ color: "var(--color-muted)", textAlign: "center", padding: 24 }}>
                踏み台サーバが登録されていません
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
