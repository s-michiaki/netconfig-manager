import React, { useEffect, useState } from "react";
import { api } from "../api/client";

interface Schedule {
  id: string;
  name: string;
  cron_expression: string;
  target: string;
  is_active: boolean;
}

export default function SchedulePage() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: "", cron_expression: "0 9 * * *", target: "all", is_active: true });

  const load = () => api.get("/schedules/").then((r) => setSchedules(r.data));
  useEffect(() => { load(); }, []);

  const create = async () => {
    await api.post("/schedules/", form);
    setShowAdd(false);
    setForm({ name: "", cron_expression: "0 9 * * *", target: "all", is_active: true });
    load();
  };

  const toggle = async (id: string) => {
    await api.patch(`/schedules/${id}/toggle`);
    load();
  };

  const del = async (id: string) => {
    if (!confirm("削除しますか？")) return;
    await api.delete(`/schedules/${id}`);
    load();
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">スケジュール設定</span>
        <button className="btn btn-primary" onClick={() => setShowAdd(true)}>＋ 追加</button>
      </div>

      {showAdd && (
        <div className="modal-overlay" onClick={() => setShowAdd(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <p className="modal-title">スケジュール追加</p>
            <div className="form-group">
              <label className="form-label">名前</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="form-label">Cron式</label>
              <input
                value={form.cron_expression}
                onChange={(e) => setForm({ ...form, cron_expression: e.target.value })}
                className="mono"
              />
              <p style={{ fontSize: 11, color: "var(--color-muted)", marginTop: 4 }}>
                例: 0 9 * * * (毎日9時) / 0 2 * * 0 (毎週日曜2時)
              </p>
            </div>
            <div className="form-group">
              <label className="form-label">対象</label>
              <input
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
                placeholder="all または device_id"
              />
            </div>
            <div className="btn-row">
              <button className="btn" onClick={() => setShowAdd(false)}>キャンセル</button>
              <button className="btn btn-primary" onClick={create}>追加</button>
            </div>
          </div>
        </div>
      )}

      <div className="page-body">
        <p className="section-label">登録済みスケジュール</p>
        <table className="data-table">
          <thead>
            <tr>
              <th>名前</th>
              <th>対象</th>
              <th>Cron式</th>
              <th>状態</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td style={{ fontWeight: 500 }}>{s.name}</td>
                <td style={{ color: "var(--color-muted)", fontSize: 12 }}>{s.target}</td>
                <td><span className="mono" style={{ fontSize: 12 }}>{s.cron_expression}</span></td>
                <td>
                  <span className={`badge ${s.is_active ? "badge-success" : "badge-neutral"}`}>
                    {s.is_active ? "有効" : "無効"}
                  </span>
                </td>
                <td>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => toggle(s.id)}>
                      {s.is_active ? "無効化" : "有効化"}
                    </button>
                    <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => del(s.id)}>
                      削除
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {schedules.length === 0 && (
              <tr><td colSpan={5} style={{ color: "var(--color-muted)", textAlign: "center", padding: 24 }}>
                スケジュールが登録されていません
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
