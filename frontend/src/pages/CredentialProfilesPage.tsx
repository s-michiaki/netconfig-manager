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
  owner_id: string | null;
  owner_name: string | null; // 所有者がいない（削除された）ときは null
  manage_groups: GroupRef[]; // 管理を任せたユーザーグループ（編集・削除・共有範囲の変更ができる）
  use_groups: GroupRef[]; // 使用を許可したユーザーグループ（機器へ割り当てられる）
  can_manage: boolean;
  can_use: boolean;
}
interface GroupRef { id: string; name: string; }
interface ShareOptions {
  groups: { id: string; name: string; members: number }[];
  admins: { id: string; username: string }[];
}

const EMPTY = {
  name: "", username: "", description: "",
  password: "", private_key: "", key_passphrase: "", enable_secret: "",
  clear_password: false, clear_private_key: false, clear_enable_secret: false,
};

/** ユーザーグループをチェックボックスで選ぶ */
function GroupChecks({ label, hint, options, value, exclude, onChange }: {
  label: string; hint: string; options: ShareOptions["groups"]; value: string[]; exclude: string[];
  onChange: (ids: string[]) => void;
}) {
  return (
    <div className="form-group">
      <span className="form-label">{label}</span>
      <p className="cp-hint" style={{ margin: "0 0 6px" }}>{hint}</p>
      <div className="cp-groups">
        {options.map((g) => {
          const taken = exclude.includes(g.id); // 「管理」に入れたグループは「使用」もできるので、選ばせない
          return (
            <label key={g.id} className="form-check" title={taken ? "管理を任せたグループは使用もできます" : undefined}>
              <input type="checkbox" checked={value.includes(g.id) || taken} disabled={taken}
                onChange={(e) => onChange(e.target.checked ? [...value, g.id] : value.filter((x) => x !== g.id))} />
              {g.name}（{g.members} 人）
            </label>
          );
        })}
      </div>
    </div>
  );
}

function ProfileModal({ profile, options, onClose, onSaved }: {
  profile: CredentialProfile | null; options: ShareOptions | null; onClose: () => void; onSaved: () => void;
}) {
  const isEdit = profile !== null;
  const [form, setForm] = useState(() =>
    profile ? { ...EMPTY, name: profile.name, username: profile.username, description: profile.description ?? "" } : EMPTY
  );
  const [manageIds, setManageIds] = useState<string[]>(() => profile?.manage_groups.map((g) => g.id) ?? []);
  const [useIds, setUseIds] = useState<string[]>(() => profile?.use_groups.map((g) => g.id) ?? []);
  const [ownerId, setOwnerId] = useState(profile?.owner_id ?? "");
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
      manage_group_ids: manageIds,
      use_group_ids: useIds.filter((id) => !manageIds.includes(id)),
      ...(isEdit && ownerId && ownerId !== profile.owner_id ? { owner_id: ownerId } : {}),
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

        <p className="section-label" style={{ marginTop: 6 }}>共有範囲（だれが編集・使用できるか）</p>
        <p className="cp-hint" style={{ margin: "0 0 10px" }}>
          何も選ばなければ、所有者{isEdit ? "" : "（あなた）"}だけが編集・使用できます。
          収集とターミナル接続は、共有範囲に関係なく今までどおり行えます。
        </p>
        {isEdit && options && (
          <div className="form-group">
            <label className="form-label" htmlFor="cp-owner">所有者</label>
            <select id="cp-owner" value={ownerId} onChange={(e) => setOwnerId(e.target.value)}>
              {!options.admins.some((a) => a.id === ownerId) && <option value={ownerId}>{profile.owner_name ?? "（所有者なし）"}</option>}
              {options.admins.map((a) => <option key={a.id} value={a.id}>{a.username}</option>)}
            </select>
          </div>
        )}
        {options && options.groups.length > 0 ? (
          <>
            <GroupChecks label="管理を任せるユーザーグループ" options={options.groups} value={manageIds} exclude={[]}
              hint="メンバーは、所有者と同じく編集・削除・共有範囲の変更ができます。" onChange={setManageIds} />
            <GroupChecks label="使用を許可するユーザーグループ" options={options.groups} value={useIds} exclude={manageIds}
              hint="メンバーは、このプロファイルを機器に割り当てたり、使っている機器の接続先を変えたりできます（編集はできません）。"
              onChange={setUseIds} />
          </>
        ) : (
          <p className="cp-hint">
            ユーザーグループがまだありません。ほかの人と共有するときは、「通知設定」のユーザーグループで作成してください。
          </p>
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

export default function CredentialProfilesPage() {
  const canWrite = useAuth().can(PERM.DEVICE_WRITE);
  const [items, setItems] = useState<CredentialProfile[]>([]);
  const [modal, setModal] = useState<{ profile: CredentialProfile | null } | null>(null);
  const [error, setError] = useState("");
  const [options, setOptions] = useState<ShareOptions | null>(null);

  const load = () =>
    api.get<CredentialProfile[]>("/credential-profiles/").then((r) => setItems(r.data)).catch((e) => setError(errorMessage(e)));
  useEffect(() => {
    load();
    if (canWrite) api.get<ShareOptions>("/credential-profiles/share-options").then((r) => setOptions(r.data)).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** 所有者を自分にする（所有者が不在で誰も編集できないときのための操作。前の所有者へ通知される） */
  const takeOver = async (p: CredentialProfile) => {
    const who = p.owner_name ? `現在の所有者は ${p.owner_name} です。` : "現在、所有者がいません。";
    if (!confirm(`認証情報プロファイル「${p.name}」の所有者を自分に変えますか？\n\n${who}`
      + "\nこの操作は監査ログに残り、前の所有者へ通知されます。所有者が不在で編集できないときに使ってください。")) return;
    setError("");
    try {
      await api.post(`/credential-profiles/${p.id}/takeover`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

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
      {modal && <ProfileModal profile={modal.profile} options={options} onClose={() => setModal(null)} onSaved={load} />}
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
          <br />
          編集・削除できるのは所有者と「管理」のユーザーグループ、機器に割り当てられるのは加えて「使用」のユーザーグループのメンバーだけです。
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>名前</th>
              <th>ユーザー名</th>
              <th>認証</th>
              <th>使用デバイス</th>
              <th>所有者</th>
              <th>共有範囲</th>
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
                <td style={{ fontSize: 12 }}>{p.owner_name ?? <span className="topo-muted">（所有者なし）</span>}</td>
                <td style={{ fontSize: 12 }}>
                  {p.manage_groups.map((g) => (
                    <span key={g.id} className="badge badge-neutral" style={{ marginRight: 4 }} title="編集・削除・使用ができます">管理: {g.name}</span>
                  ))}
                  {p.use_groups.map((g) => (
                    <span key={g.id} className="badge badge-neutral" style={{ marginRight: 4 }} title="機器への割り当てができます">使用: {g.name}</span>
                  ))}
                  {p.manage_groups.length + p.use_groups.length === 0 && <span className="topo-muted">所有者のみ</span>}
                </td>
                {canWrite && (
                  <td>
                    {p.can_manage ? (
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setModal({ profile: p })}>
                          編集
                        </button>
                        <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => del(p)}>
                          削除
                        </button>
                      </div>
                    ) : (
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <span className="topo-muted topo-small" title="編集・削除できるのは、所有者と「管理」のユーザーグループのメンバーだけです">
                          {p.can_use ? "使用のみ" : "操作できません"}
                        </span>
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => takeOver(p)}
                          title="所有者が不在で編集できないときに、所有者を自分に変えます（監査ログに残り、前の所有者へ通知されます）">
                          引き継ぐ
                        </button>
                      </div>
                    )}
                  </td>
                )}
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 7 : 6} style={{ color: "var(--color-muted)", textAlign: "center", padding: 24 }}>
                認証情報プロファイルが登録されていません
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
