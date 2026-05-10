import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

interface Device {
  id: string;
  name: string;
  hostname: string;
  platform: string;
  port: number;
  username: string;
  description: string | null;
  is_active: boolean;
}

const PLATFORM_LABELS: Record<string, string> = {
  cisco_ios: "Cisco IOS",
  cisco_xe: "Cisco IOS-XE",
  cisco_nxos: "Cisco NX-OS",
  juniper_junos: "Juniper JunOS",
  arista_eos: "Arista EOS",
  hp_comware: "HP Comware",
  huawei: "Huawei VRP",
};

function AddDeviceModal({ onClose, onSave }: { onClose: () => void; onSave: () => void }) {
  const [form, setForm] = useState({
    name: "", hostname: "", platform: "cisco_ios", port: 22,
    username: "", password: "", enable_secret: "", description: "",
  });

  const handleSubmit = async () => {
    await api.post("/devices/", form);
    onSave();
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">デバイス追加</p>
        <div className="form-group">
          <label className="form-label">ホスト名（識別名）</label>
          <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="form-group">
          <label className="form-label">IPアドレス / FQDN</label>
          <input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
          <div className="form-group">
            <label className="form-label">プラットフォーム</label>
            <select value={form.platform} onChange={(e) => setForm({ ...form, platform: e.target.value })}>
              {Object.entries(PLATFORM_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">SSHポート</label>
            <input type="number" value={form.port} onChange={(e) => setForm({ ...form, port: +e.target.value })} />
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <div className="form-group">
            <label className="form-label">ユーザー名</label>
            <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </div>
          <div className="form-group">
            <label className="form-label">パスワード</label>
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Enableシークレット（任意）</label>
          <input type="password" value={form.enable_secret} onChange={(e) => setForm({ ...form, enable_secret: e.target.value })} />
        </div>
        <div className="form-group">
          <label className="form-label">説明（任意）</label>
          <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={handleSubmit}>追加</button>
        </div>
      </div>
    </div>
  );
}

export default function DevicesPage() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [collecting, setCollecting] = useState(false);

  const load = () => api.get("/devices/").then((r) => setDevices(r.data));
  useEffect(() => { load(); }, []);

  const collectAll = async () => {
    setCollecting(true);
    await api.post("/devices/collect/all");
    setTimeout(() => setCollecting(false), 3000);
  };

  const deleteDevice = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("このデバイスを削除しますか？")) return;
    await api.delete(`/devices/${id}`);
    load();
  };

  return (
    <div className="page">
      {showModal && <AddDeviceModal onClose={() => setShowModal(false)} onSave={load} />}
      <div className="page-header">
        <span className="page-title">デバイス管理</span>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" onClick={() => setShowModal(true)}>＋ 追加</button>
          <button className="btn btn-primary" onClick={collectAll} disabled={collecting}>
            {collecting ? "収集中..." : "↻ 一括収集"}
          </button>
        </div>
      </div>

      <div className="page-body">
        <p className="section-label">登録済みデバイス ({devices.length}台)</p>
        <div className="device-grid">
          {devices.map((d) => (
            <div key={d.id} className="device-card" onClick={() => navigate(`/terminal/${d.id}`)}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <span className={`badge ${d.is_active ? "badge-success" : "badge-neutral"}`}>
                  {d.is_active ? "● Active" : "Inactive"}
                </span>
                <button
                  className="btn btn-danger"
                  style={{ padding: "2px 8px", fontSize: 11 }}
                  onClick={(e) => deleteDevice(d.id, e)}
                >
                  削除
                </button>
              </div>
              <p className="device-card-name">{d.name}</p>
              <p className="device-card-info">{d.hostname}</p>
              <p className="device-card-info" style={{ marginTop: 2 }}>
                {PLATFORM_LABELS[d.platform] || d.platform} · port {d.port}
              </p>
              <p style={{ fontSize: 11, color: "var(--color-accent)", marginTop: 8 }}>
                クリックでターミナルを開く →
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
