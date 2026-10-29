import React, { ChangeEvent, useEffect, useState } from "react";
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
  jump_host_name: string | null;
}

interface JumpHostOption { id: string; name: string; hostname: string; }

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
  clear_enable_secret: false, jump_host_id: "",
  private_key: "", key_passphrase: "", clear_password: false, clear_private_key: false,
};

function DeviceModal({
  device, jumpHosts, onClose, onSave,
}: { device: Device | null; jumpHosts: JumpHostOption[]; onClose: () => void; onSave: () => void }) {
  const isEdit = device !== null;
  const [form, setForm] = useState(() =>
    device
      ? {
          ...EMPTY_FORM,
          name: device.name, hostname: device.hostname, platform: device.platform, port: device.port,
          username: device.username, description: device.description ?? "", is_active: device.is_active,
          jump_host_id: device.jump_host_id ?? "",
        }
      : EMPTY_FORM
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [reach, setReach] = useState<{ ok: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
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
  const canSave = form.name && form.hostname && form.username && (willHavePassword || willHaveKey);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? "デバイス編集" : "デバイス追加"}</p>
        <div className="form-group">
          <label className="form-label">ホスト名（識別名）</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} />
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

export default function DevicesPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const canWrite = can(PERM.DEVICE_WRITE);
  const canTerminal = can(PERM.TERMINAL);
  const [devices, setDevices] = useState<Device[]>([]);
  const [modal, setModal] = useState<{ device: Device | null } | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [message, setMessage] = useState("");
  const [jumpHosts, setJumpHosts] = useState<JumpHostOption[]>([]);
  const [error, setError] = useState("");

  const load = () =>
    api.get<Device[]>("/devices/").then((r) => setDevices(r.data)).catch((e) => setError(errorMessage(e)));
  useEffect(() => {
    load();
    api.get<JumpHostOption[]>("/jump-hosts/").then((r) => setJumpHosts(r.data)).catch(() => undefined);
  }, []);

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

  const editDevice = (d: Device, e: React.MouseEvent) => {
    e.stopPropagation();
    setModal({ device: d });
  };

  return (
    <div className="page">
      {modal && <DeviceModal device={modal.device} jumpHosts={jumpHosts} onClose={() => setModal(null)} onSave={load} />}
      <div className="page-header">
        <span className="page-title">デバイス管理</span>
        <div style={{ display: "flex", gap: 8 }}>
          {canWrite && <button className="btn" onClick={() => setModal({ device: null })}>＋ 追加</button>}
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
        <p className="section-label">登録済みデバイス ({devices.length}台)</p>
        <div className="device-grid">
          {devices.map((d) => (
            <div
              key={d.id}
              className="device-card"
              style={canTerminal ? undefined : { cursor: "default" }}
              onClick={() => canTerminal && navigate(`/terminal/${d.id}`)}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <span className={`badge ${d.is_active ? "badge-success" : "badge-neutral"}`}>
                  {d.is_active ? "● Active" : "Inactive"}
                </span>
                {canWrite && <div style={{ display: "flex", gap: 4 }}>
                  <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={(e) => editDevice(d, e)}>
                    編集
                  </button>
                  <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={(e) => deleteDevice(d, e)}>
                    削除
                  </button>
                </div>}
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
              {canTerminal && (
                <p style={{ fontSize: 11, color: "var(--color-accent)", marginTop: 8 }}>
                  クリックでターミナルを開く →
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
