import React, { useEffect, useState } from "react";
import { api } from "../api/client";

interface Device { id: string; name: string; hostname: string; platform: string; }
interface TaskStatus { task_id: string; status: string; }

export default function CollectPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [tasks, setTasks] = useState<TaskStatus[]>([]);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [log, setLog] = useState<string[]>([]);

  useEffect(() => {
    api.get("/devices/").then((r) => {
      setDevices(r.data);
      setSelected(new Set(r.data.map((d: Device) => d.id)));
    });
  }, []);

  const toggleAll = (checked: boolean) => {
    setSelected(checked ? new Set(devices.map((d) => d.id)) : new Set());
  };

  const toggleDevice = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const startCollect = async () => {
    if (selected.size === 0) return;
    setRunning(true);
    setProgress(0);
    setLog([]);

    const targets = devices.filter((d) => selected.has(d.id));
    const total = targets.length;
    let done = 0;

    for (const device of targets) {
      setLog((prev) => [...prev, `⏳ ${device.name} を収集中...`]);
      try {
        await api.post(`/devices/${device.id}/collect`);
        done++;
        setProgress(Math.round((done / total) * 100));
        setLog((prev) => [...prev.slice(0, -1), `✅ ${device.name} — 完了`]);
      } catch {
        done++;
        setProgress(Math.round((done / total) * 100));
        setLog((prev) => [...prev.slice(0, -1), `❌ ${device.name} — 失敗`]);
      }
    }

    setRunning(false);
    setLog((prev) => [...prev, "━━━ 収集完了 ━━━"]);
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">コンフィグ収集</span>
        <button
          className="btn btn-primary"
          onClick={startCollect}
          disabled={running || selected.size === 0}
        >
          {running ? "収集中..." : "▶ 収集開始"}
        </button>
      </div>

      <div className="page-body">
        {/* プログレス */}
        {(running || progress > 0) && (
          <div className="card" style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
              {running ? "収集中..." : "完了"}
            </span>
            <div className="progress-wrap">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
            <span style={{ fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>{progress}%</span>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 16 }}>
          {/* デバイステーブル */}
          <div>
            <p className="section-label">収集対象デバイス</p>
            <table className="data-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={selected.size === devices.length && devices.length > 0}
                      onChange={(e) => toggleAll(e.target.checked)}
                    />
                  </th>
                  <th>ホスト名</th>
                  <th>IPアドレス</th>
                  <th>プラットフォーム</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.has(d.id)}
                        onChange={() => toggleDevice(d.id)}
                      />
                    </td>
                    <td style={{ fontWeight: 500 }}>{d.name}</td>
                    <td className="mono" style={{ fontSize: 12, color: "var(--color-muted)" }}>{d.hostname}</td>
                    <td style={{ fontSize: 12, color: "var(--color-muted)" }}>{d.platform}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* ログ */}
          <div>
            <p className="section-label">収集ログ</p>
            <div
              style={{
                background: "#0d1117",
                border: "1px solid #30363d",
                borderRadius: 8,
                padding: "10px 14px",
                fontFamily: "monospace",
                fontSize: 12,
                color: "#c9d1d9",
                minHeight: 200,
                lineHeight: 1.8,
              }}
            >
              {log.length === 0
                ? <span style={{ color: "#8b949e" }}>待機中...</span>
                : log.map((l, i) => <div key={i}>{l}</div>)
              }
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
