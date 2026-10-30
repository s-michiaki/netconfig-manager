import React, { ChangeEvent, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

interface Device {
  id: string;
  name: string;
  hostname: string;
  platform: string;
  port: number;
  username: string;
  description: string | null;
  is_active: boolean;
  has_enable_secret: boolean;
  has_password: boolean;
  has_private_key: boolean;
  key_info: string | null;
  jump_host_id: string | null;
  group_id: string | null;
  group_name: string | null;
  jump_host_name: string | null;
  read_timeout: number | null;
}

interface JumpHostOption { id: string; name: string; hostname: string; }

interface DeviceGroup {
  id: string;
  name: string;
  description: string | null;
  color: string | null;
  device_count: number;
}

const PLATFORM_LABELS: Record<string, string> = {
  cisco_ios: "Cisco IOS",
  cisco_xe: "Cisco IOS-XE",
  cisco_nxos: "Cisco NX-OS",
  juniper_junos: "Juniper JunOS",
  arista_eos: "Arista EOS",
  hp_comware: "HP Comware",
  huawei: "Huawei VRP",
  paloalto_panos: "Palo Alto PAN-OS",
};

const EMPTY_FORM = {
  name: "", hostname: "", platform: "cisco_ios", port: 22,
  username: "", password: "", enable_secret: "", description: "", is_active: true,
  clear_enable_secret: false, jump_host_id: "", group_id: "",
  private_key: "", key_passphrase: "", clear_password: false, clear_private_key: false,
  read_timeout: "", // 空欄 = 既定値
};

function DeviceModal({
  device, jumpHosts, groups, defaultGroupId, onClose, onSave,
}: {
  device: Device | null; jumpHosts: JumpHostOption[]; groups: DeviceGroup[]; defaultGroupId?: string;
  onClose: () => void; onSave: () => void;
}) {
  const isEdit = device !== null;
  const [form, setForm] = useState(() =>
    device
      ? {
          ...EMPTY_FORM,
          name: device.name, hostname: device.hostname, platform: device.platform, port: device.port,
          username: device.username, description: device.description ?? "", is_active: device.is_active,
          jump_host_id: device.jump_host_id ?? "",
          group_id: device.group_id ?? "",
          read_timeout: device.read_timeout != null ? String(device.read_timeout) : "",
        }
      : { ...EMPTY_FORM, group_id: defaultGroupId ?? "" }
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [reach, setReach] = useState<{ ok: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [defaultTimeout, setDefaultTimeout] = useState<number | null>(null);
  useEffect(() => {
    api.get("/devices/defaults").then((r) => setDefaultTimeout(r.data.read_timeout)).catch(() => {});
  }, []);
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));

  const handleSubmit = async () => {
    setSaving(true);
    setError("");
    const body = {
      name: form.name,
      hostname: form.hostname,
      platform: form.platform,
      port: form.port,
      username: form.username,
      description: form.description || null,
      is_active: form.is_active,
      jump_host_id: form.jump_host_id || null,
      group_id: form.group_id || null,
      read_timeout: form.read_timeout.trim() ? Number(form.read_timeout) : null,
      // 編集時、空欄のパスワードは「変更しない」
      password: form.password || undefined,
      private_key: form.private_key || undefined,
      key_passphrase: form.key_passphrase || undefined,
      enable_secret: form.enable_secret || undefined,
      ...(isEdit
        ? {
            clear_enable_secret: form.clear_enable_secret,
            clear_password: form.clear_password,
            clear_private_key: form.clear_private_key,
          }
        : {}),
    };
    try {
      if (isEdit) await api.put(`/devices/${device.id}`, body);
      else await api.post("/devices/", body);
      onSave();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  /** 選択した踏み台から、このデバイスのIP:ポートに到達できるか確認する */
  const testReach = async () => {
    setTesting(true);
    setReach(null);
    try {
      const r = await api.post(`/jump-hosts/${form.jump_host_id}/test`, {
        dest_host: form.hostname, dest_port: form.port,
      }, { timeout: 90000 });
      setReach(r.data);
    } catch (e) {
      setReach({ ok: false, message: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  };

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

  const willHavePassword = (isEdit && device.has_password && !form.clear_password) || !!form.password;
  const willHaveKey = (isEdit && device.has_private_key && !form.clear_private_key) || !!form.private_key;
  const timeoutValid = !form.read_timeout.trim() || (/^\d+$/.test(form.read_timeout.trim())
    && Number(form.read_timeout) >= 10 && Number(form.read_timeout) <= 600);
  const canSave = form.name && form.hostname && form.username && (willHavePassword || willHaveKey) && timeoutValid;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? "デバイス編集" : "デバイス追加"}</p>
        <div className="form-group">
          <label className="form-label">ホスト名（識別名）</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="dev-group">グループ</label>
          <select id="dev-group" value={form.group_id} onChange={(e) => set("group_id", e.target.value)}>
            <option value="">（未分類）</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">IPアドレス / FQDN</label>
          <input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
          <div className="form-group">
            <label className="form-label">プラットフォーム</label>
            <select value={form.platform} onChange={(e) => set("platform", e.target.value)}>
              {Object.entries(PLATFORM_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">SSHポート</label>
            <input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", +e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">接続経路</label>
          <div style={{ display: "flex", gap: 8 }}>
            <select value={form.jump_host_id} onChange={(e) => { set("jump_host_id", e.target.value); setReach(null); }}>
              <option value="">直接接続</option>
              {jumpHosts.map((j) => <option key={j.id} value={j.id}>踏み台経由: {j.name}（{j.hostname}）</option>)}
            </select>
            {form.jump_host_id && (
              <button className="btn" style={{ whiteSpace: "nowrap" }} onClick={testReach} disabled={testing || !form.hostname}>
                {testing ? "確認中..." : "到達確認"}
              </button>
            )}
          </div>
          {reach && (
            <p style={{ fontSize: 11, marginTop: 6, color: reach.ok ? "var(--color-success)" : "var(--color-danger)" }}>
              {reach.ok ? "✓ " : "✗ "}{reach.message}
            </p>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">ユーザー名</label>
          <input value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
        </div>
        <p className="section-label" style={{ marginTop: 6 }}>認証（パスワード・SSH秘密鍵のどちらか、または両方）</p>
        <div className="form-group">
          <label className="form-label">
            パスワード{isEdit && device.has_password ? "（設定済み。変更時のみ入力）" : ""}
          </label>
          <input type="password" autoComplete="new-password" value={form.password}
            onChange={(e) => set("password", e.target.value)} disabled={form.clear_password} />
          {isEdit && device.has_password && (
            <label className="form-check" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.clear_password} onChange={(e) => set("clear_password", e.target.checked)} />
              パスワードを削除する（鍵認証のみにする）
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">
            SSH秘密鍵（OpenSSH / PEM 形式）{isEdit && device.has_private_key ? `— 設定済み: ${device.key_info ?? ""}` : "（任意）"}
          </label>
          <textarea
            className="mono"
            rows={4}
            value={form.private_key}
            onChange={(e) => set("private_key", e.target.value)}
            disabled={form.clear_private_key}
            placeholder={isEdit && device.has_private_key ? "変更する場合のみ貼り付け" : "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
            spellCheck={false}
            style={{ fontSize: 11, resize: "vertical" }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 6 }}>
            <label className="btn" style={{ padding: "2px 10px", fontSize: 11, cursor: "pointer" }}>
              ファイルから読み込む
              <input type="file" onChange={loadKeyFile} style={{ display: "none" }} disabled={form.clear_private_key} />
            </label>
            {isEdit && device.has_private_key && (
              <label className="form-check">
                <input type="checkbox" checked={form.clear_private_key}
                  onChange={(e) => set("clear_private_key", e.target.checked)} />
                秘密鍵を削除する
              </label>
            )}
          </div>
        </div>
        {(form.private_key || (isEdit && device.has_private_key && !form.clear_private_key)) && (
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
            Enableシークレット（任意{isEdit && device.has_enable_secret ? "・設定済み。変更時のみ入力" : ""}）
          </label>
          <input type="password" autoComplete="new-password" value={form.enable_secret}
            onChange={(e) => set("enable_secret", e.target.value)} disabled={form.clear_enable_secret} />
          {isEdit && device.has_enable_secret && (
            <label className="form-check" style={{ marginTop: 6 }}>
              <input type="checkbox" checked={form.clear_enable_secret}
                onChange={(e) => set("clear_enable_secret", e.target.checked)} />
              Enableシークレットを削除する
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">応答待ち時間（秒・任意）</label>
          <input type="number" min={10} max={600} value={form.read_timeout}
            placeholder={`空欄で既定値${defaultTimeout ? `（${defaultTimeout}秒）` : ""}`}
            onChange={(e) => set("read_timeout", e.target.value)} />
          <p style={{ fontSize: 11, marginTop: 4, color: timeoutValid ? "var(--color-muted)" : "var(--color-danger)" }}>
            {timeoutValid
              ? "ログイン後のプロンプトやコマンド結果を待つ上限（10〜600秒）。応答の遅い機器でタイムアウトする場合に延ばしてください"
              : "10〜600 の整数で入力してください"}
          </p>
        </div>
        <div className="form-group">
          <label className="form-label">説明（任意）</label>
          <input value={form.description} onChange={(e) => set("description", e.target.value)} />
        </div>
        <label className="form-check" style={{ marginBottom: 14 }}>
          <input type="checkbox" checked={form.is_active} onChange={(e) => set("is_active", e.target.checked)} />
          有効（一括収集・スケジュール収集の対象にする）
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={handleSubmit} disabled={saving || !canSave}>
            {isEdit ? "保存" : "追加"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ グループ管理

const GROUP_COLORS = ["#4f8ef7", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#c084fc", "#5eead4", "#7c82a3"];
const UNGROUPED = "__none__"; // 絞り込み・折りたたみでの「未分類」の識別子

function GroupManagerModal({
  groups, onClose, onChanged,
}: { groups: DeviceGroup[]; onClose: () => void; onChanged: () => void }) {
  const [editing, setEditing] = useState<{ id: string | null; name: string; description: string; color: string | null } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setError("");
    const body = { name: editing.name.trim(), description: editing.description.trim() || null, color: editing.color };
    try {
      if (editing.id) await api.put(`/device-groups/${editing.id}`, body);
      else await api.post("/device-groups/", body);
      setEditing(null);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (g: DeviceGroup) => {
    const msg = g.device_count
      ? `グループ「${g.name}」を削除しますか？\n所属している${g.device_count}台は「未分類」に戻ります（機器は削除されません）。`
      : `グループ「${g.name}」を削除しますか？`;
    if (!window.confirm(msg)) return;
    try {
      await api.delete(`/device-groups/${g.id}`);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal grp-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">グループの管理</p>
        {groups.length === 0 && !editing && (
          <p className="topo-muted" style={{ marginBottom: 12 }}>グループはまだありません。拠点や用途ごとに作ると、機器をまとめて表示できます。</p>
        )}
        <ul className="grp-list">
          {groups.map((g) => (
            <li key={g.id} className="grp-row">
              <span className="grp-dot" style={{ background: g.color ?? "#7c82a3" }} />
              <div className="grp-row-body">
                <div className="grp-row-name">{g.name}<span className="topo-muted topo-small">　{g.device_count}台</span></div>
                {g.description && <div className="topo-muted topo-small">{g.description}</div>}
              </div>
              <button className="btn" onClick={() => setEditing({ id: g.id, name: g.name, description: g.description ?? "", color: g.color })}>編集</button>
              <button className="btn btn-danger" onClick={() => remove(g)}>削除</button>
            </li>
          ))}
        </ul>
        {editing ? (
          <div className="grp-edit">
            <p className="section-label">{editing.id ? "グループを編集" : "新しいグループ"}</p>
            <div className="form-group">
              <label className="form-label" htmlFor="grp-name">名前</label>
              <input id="grp-name" value={editing.name} maxLength={128} autoFocus placeholder="例: 本社 / 大阪拠点 / DC"
                onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="grp-desc">説明（任意）</label>
              <input id="grp-desc" value={editing.description} maxLength={1000}
                onChange={(e) => setEditing({ ...editing, description: e.target.value })} />
            </div>
            <div className="form-group">
              <span className="form-label">色</span>
              <div className="topo-swatches" role="radiogroup" aria-label="色">
                {GROUP_COLORS.map((c) => (
                  <button key={c} type="button" role="radio" aria-checked={editing.color === c} aria-label={c}
                    className={`topo-swatch${editing.color === c ? " active" : ""}`} style={{ background: c }}
                    onClick={() => setEditing({ ...editing, color: c })} />
                ))}
              </div>
            </div>
            <div className="btn-row" style={{ marginTop: 8 }}>
              <button className="btn" onClick={() => setEditing(null)}>やめる</button>
              <button className="btn btn-primary" onClick={save} disabled={busy || !editing.name.trim()}>保存</button>
            </div>
          </div>
        ) : (
          <button className="btn" onClick={() => setEditing({ id: null, name: "", description: "", color: GROUP_COLORS[groups.length % GROUP_COLORS.length] })}>
            ＋ グループを追加
          </button>
        )}
        {error && <p className="form-error" style={{ marginTop: 10 }}>{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ 一覧

function readPref<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
function writePref(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* 保存できなくても動作に影響なし */
  }
}

function DeviceCard({
  d, canWrite, canTerminal, selecting, selected, showGroup, groupColor, onToggle, onOpen, onEdit, onDelete,
}: {
  d: Device; canWrite: boolean; canTerminal: boolean; selecting: boolean; selected: boolean; showGroup: boolean;
  groupColor: string | null; onToggle: () => void; onOpen: () => void;
  onEdit: (e: React.MouseEvent) => void; onDelete: (e: React.MouseEvent) => void;
}) {
  return (
    <div
      className={`device-card${selected ? " selected" : ""}`}
      style={canTerminal || selecting ? undefined : { cursor: "default" }}
      onClick={() => (selecting ? onToggle() : canTerminal && onOpen())}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 6 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {selecting && (
            <input type="checkbox" className="device-check" checked={selected} aria-label={`${d.name} を選択`}
              onClick={(e) => e.stopPropagation()} onChange={onToggle} />
          )}
          <span className={`badge ${d.is_active ? "badge-success" : "badge-neutral"}`}>
            {d.is_active ? "● Active" : "Inactive"}
          </span>
        </div>
        {canWrite && !selecting && (
          <div style={{ display: "flex", gap: 4 }}>
            <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={onEdit}>編集</button>
            <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={onDelete}>削除</button>
          </div>
        )}
      </div>
      <p className="device-card-name">{d.name}</p>
      <p className="device-card-info">{d.hostname}</p>
      <p className="device-card-info" style={{ marginTop: 2 }}>
        {PLATFORM_LABELS[d.platform] || d.platform} · port {d.port}
      </p>
      {d.has_private_key && (
        <p className="device-card-info" style={{ marginTop: 2 }}>🔑 鍵認証{d.has_password ? "＋パスワード" : ""}</p>
      )}
      {d.jump_host_name && (
        <p className="device-card-info" style={{ marginTop: 2 }}>↪ 踏み台経由: {d.jump_host_name}</p>
      )}
      {showGroup && (
        <p className="device-card-info device-card-group" style={{ marginTop: 4 }}>
          <span className="grp-dot" style={{ background: groupColor ?? "#4a5178" }} />
          {d.group_name ?? "未分類"}
        </p>
      )}
      {canTerminal && !selecting && (
        <p style={{ fontSize: 11, color: "var(--color-accent)", marginTop: 8 }}>クリックでターミナルを開く →</p>
      )}
    </div>
  );
}

export default function DevicesPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const canWrite = can(PERM.DEVICE_WRITE);
  const canTerminal = can(PERM.TERMINAL);
  const [devices, setDevices] = useState<Device[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [modal, setModal] = useState<{ device: Device | null; groupId?: string } | null>(null);
  const [managing, setManaging] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [message, setMessage] = useState("");
  const [jumpHosts, setJumpHosts] = useState<JumpHostOption[]>([]);
  const [error, setError] = useState("");
  // 表示の設定はブラウザに覚えておく
  const [view, setView] = useState<"group" | "list">(() => readPref("devices:view", "group"));
  const [groupFilter, setGroupFilter] = useState<string>(() => readPref("devices:group", ""));
  const [collapsed, setCollapsed] = useState<string[]>(() => readPref("devices:collapsed", []));
  const [query, setQuery] = useState("");
  const [selecting, setSelecting] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [moveTo, setMoveTo] = useState("");

  useEffect(() => writePref("devices:view", view), [view]);
  useEffect(() => writePref("devices:group", groupFilter), [groupFilter]);
  useEffect(() => writePref("devices:collapsed", collapsed), [collapsed]);

  const load = () => {
    api.get<Device[]>("/devices/").then((r) => setDevices(r.data)).catch((e) => setError(errorMessage(e)));
    api.get<DeviceGroup[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  };
  useEffect(() => {
    load();
    api.get<JumpHostOption[]>("/jump-hosts/").then((r) => setJumpHosts(r.data)).catch(() => undefined);
  }, []);

  // 絞り込みで指定していたグループが削除されたら解除する
  useEffect(() => {
    if (groupFilter && groupFilter !== UNGROUPED && groups.length && !groups.some((g) => g.id === groupFilter)) {
      setGroupFilter("");
    }
  }, [groups, groupFilter]);

  const collectAll = async () => {
    setCollecting(true);
    setError("");
    try {
      await api.post("/devices/collect/all");
      setMessage("全デバイスの収集をキューに投入しました。結果は「世代管理」で確認できます。");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setTimeout(() => setCollecting(false), 3000);
    }
  };

  const deleteDevice = async (d: Device, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`「${d.name}」を削除しますか？`)) return;
    try {
      await api.delete(`/devices/${d.id}`);
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });

  const moveSelected = async () => {
    if (!selected.size) return;
    setError("");
    try {
      const target = moveTo === UNGROUPED ? null : moveTo;
      await api.post("/device-groups/assign", { device_ids: [...selected], group_id: target });
      const name = target ? groups.find((g) => g.id === target)?.name : "未分類";
      setMessage(`${selected.size}台を「${name}」へ移動しました。`);
      setSelected(new Set());
      setSelecting(false);
      setMoveTo("");
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const colorOf = useMemo(() => new Map(groups.map((g) => [g.id, g.color])), [groups]);
  const q = query.trim().toLowerCase();
  const visible = devices.filter((d) => {
    if (groupFilter === UNGROUPED ? d.group_id : groupFilter && d.group_id !== groupFilter) return false;
    if (!q) return true;
    return `${d.name} ${d.hostname} ${d.description ?? ""}`.toLowerCase().includes(q);
  });

  // グループ別の表示: グループ（名前順）→ 未分類 の順。絞り込み中は該当するものだけ
  const sections = [
    ...groups.map((g) => ({ key: g.id, name: g.name, description: g.description, color: g.color, group: g })),
    { key: UNGROUPED, name: "未分類", description: null, color: null, group: null },
  ]
    .filter((s) => !groupFilter || groupFilter === s.key)
    .map((s) => ({ ...s, devices: visible.filter((d) => (d.group_id ?? UNGROUPED) === s.key) }))
    // 未分類と、検索で0台になったグループは出さない（空のグループは検索していないときだけ表示）
    .filter((s) => s.devices.length || (s.group && !q));

  const card = (d: Device, showGroup: boolean) => (
    <DeviceCard
      key={d.id} d={d} canWrite={canWrite} canTerminal={canTerminal} selecting={selecting}
      selected={selected.has(d.id)} showGroup={showGroup} groupColor={d.group_id ? colorOf.get(d.group_id) ?? null : null}
      onToggle={() => toggle(d.id)} onOpen={() => navigate(`/terminal/${d.id}`)}
      onEdit={(e) => { e.stopPropagation(); setModal({ device: d }); }} onDelete={(e) => deleteDevice(d, e)}
    />
  );

  return (
    <div className="page">
      {modal && (
        <DeviceModal device={modal.device} jumpHosts={jumpHosts} groups={groups} defaultGroupId={modal.groupId}
          onClose={() => setModal(null)} onSave={load} />
      )}
      {managing && <GroupManagerModal groups={groups} onClose={() => setManaging(false)} onChanged={load} />}
      <div className="page-header">
        <span className="page-title">デバイス管理</span>
        <div style={{ display: "flex", gap: 8 }}>
          {canWrite && <button className="btn" onClick={() => setManaging(true)}>グループの管理</button>}
          {canWrite && (
            <button className="btn" onClick={() => setModal({ device: null, groupId: groupFilter && groupFilter !== UNGROUPED ? groupFilter : undefined })}>
              ＋ 追加
            </button>
          )}
          {can(PERM.COLLECT) && (
            <button className="btn btn-primary" onClick={collectAll} disabled={collecting}>
              {collecting ? "投入中..." : "↻ 一括収集"}
            </button>
          )}
        </div>
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {message && <p style={{ fontSize: 12, color: "var(--color-success)", marginBottom: 12 }}>{message}</p>}

        <div className="dev-toolbar">
          <div className="seg-tabs" role="tablist" aria-label="表示方法">
            <button role="tab" aria-selected={view === "group"} className={`seg-tab${view === "group" ? " active" : ""}`} onClick={() => setView("group")}>グループ別</button>
            <button role="tab" aria-selected={view === "list"} className={`seg-tab${view === "list" ? " active" : ""}`} onClick={() => setView("list")}>一覧</button>
          </div>
          <select className="dev-filter" value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)} aria-label="グループで絞り込み">
            <option value="">すべてのグループ</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}（{g.device_count}）</option>)}
            <option value={UNGROUPED}>未分類（{devices.filter((d) => !d.group_id).length}）</option>
          </select>
          <input className="dev-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="名前・IPで検索" aria-label="名前・IPで検索" />
          <span className="topo-muted topo-small">{visible.length} / {devices.length}台</span>
          {canWrite && groups.length > 0 && (
            <button className={`btn${selecting ? " btn-primary" : ""}`} style={{ marginLeft: "auto" }}
              onClick={() => { setSelecting(!selecting); setSelected(new Set()); }}>
              {selecting ? "選択をやめる" : "選択してグループへ移動"}
            </button>
          )}
        </div>

        {selecting && (
          <div className="dev-selectbar">
            <span>{selected.size}台を選択中</span>
            <button className="link-btn" onClick={() => setSelected(new Set(visible.map((d) => d.id)))}>表示中をすべて選択</button>
            <button className="link-btn" onClick={() => setSelected(new Set())}>解除</button>
            <select value={moveTo} onChange={(e) => setMoveTo(e.target.value)} aria-label="移動先のグループ" style={{ width: "auto" }}>
              <option value="">移動先を選択</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              <option value={UNGROUPED}>未分類に戻す</option>
            </select>
            <button className="btn btn-primary" onClick={moveSelected} disabled={!selected.size || !moveTo}>移動</button>
          </div>
        )}

        {devices.length === 0 ? (
          <p className="topo-muted">デバイスが登録されていません。</p>
        ) : view === "list" ? (
          <div className="device-grid">{visible.map((d) => card(d, true))}</div>
        ) : (
          sections.map((s) => {
            const isCollapsed = collapsed.includes(s.key);
            return (
              <section key={s.key} className="dev-group">
                <button
                  className="dev-group-head" aria-expanded={!isCollapsed}
                  onClick={() => setCollapsed(isCollapsed ? collapsed.filter((k) => k !== s.key) : [...collapsed, s.key])}
                >
                  <span className="dev-group-caret">{isCollapsed ? "▸" : "▾"}</span>
                  <span className="grp-dot" style={{ background: s.color ?? "#4a5178" }} />
                  <span className="dev-group-name">{s.name}</span>
                  <span className="topo-muted topo-small">{s.devices.length}台</span>
                  {s.description && <span className="topo-muted topo-small dev-group-desc">— {s.description}</span>}
                </button>
                {!isCollapsed && (
                  s.devices.length ? (
                    <div className="device-grid">{s.devices.map((d) => card(d, false))}</div>
                  ) : (
                    <p className="topo-muted topo-small dev-group-empty">
                      このグループには機器がありません。
                      {canWrite && <> 機器の「編集」でグループを選ぶか、「選択してグループへ移動」で追加できます。</>}
                    </p>
                  )
                )}
              </section>
            );
          })
        )}
      </div>
    </div>
  );
}
