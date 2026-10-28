import { useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../api/client";

interface Device { id: string; name: string; hostname: string; platform: string; is_active: boolean; }

type JobState = "queued" | "running" | "retry" | "success" | "unchanged" | "failed";
interface Job { device: Device; taskId?: string; state: JobState; message?: string; }

interface TaskResult {
  success?: boolean;
  skipped?: boolean;
  commit_hash?: string | null;
  added?: number;
  removed?: number;
  error?: string | null;
}

const POLL_INTERVAL_MS = 2000;
const POLL_TIMEOUT_MS = 15 * 60 * 1000;
const FINISHED: JobState[] = ["success", "unchanged", "failed"];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const ICON: Record<JobState, string> = {
  queued: "⏳", running: "🔄", retry: "🔁", success: "✅", unchanged: "➖", failed: "❌",
};

function describe(job: Job): string {
  switch (job.state) {
    case "queued": return "キュー投入済み";
    case "running": return "収集中";
    case "retry": return `リトライ待ち${job.message ? `（${job.message}）` : ""}`;
    case "success": return `完了 — 新しい世代を保存 ${job.message ?? ""}`;
    case "unchanged": return "完了 — 変更なし";
    case "failed": return `失敗 — ${job.message ?? "不明なエラー"}`;
  }
}

export default function CollectPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [jobs, setJobs] = useState<Job[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    api
      .get<Device[]>("/devices/")
      .then((r) => {
        setDevices(r.data);
        setSelected(new Set(r.data.filter((d) => d.is_active).map((d) => d.id)));
      })
      .catch((e) => setError(errorMessage(e)));
    return () => {
      mounted.current = false;
    };
  }, []);

  const toggleAll = (checked: boolean) => {
    setSelected(checked ? new Set(devices.map((d) => d.id)) : new Set());
  };

  const toggleDevice = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const updateJob = (deviceId: string, patch: Partial<Job>) =>
    setJobs((prev) => prev.map((j) => (j.device.id === deviceId ? { ...j, ...patch } : j)));

  /** タスクが終わるまでポーリングする（キュー投入＝完了ではないため） */
  const waitForTask = async (deviceId: string, taskId: string) => {
    const deadline = Date.now() + POLL_TIMEOUT_MS;
    while (mounted.current && Date.now() < deadline) {
      await sleep(POLL_INTERVAL_MS);
      try {
        const { data } = await api.get<{ state: string; result: TaskResult | null }>(`/tasks/${taskId}`);
        const r = data.result;
        if (data.state === "SUCCESS") {
          if (r?.success && r.commit_hash) {
            updateJob(deviceId, { state: "success", message: `(+${r.added ?? 0} / -${r.removed ?? 0})` });
          } else if (r?.success) {
            updateJob(deviceId, { state: "unchanged" });
          } else {
            updateJob(deviceId, { state: "failed", message: r?.error ?? undefined });
          }
          return;
        }
        if (data.state === "FAILURE") {
          updateJob(deviceId, { state: "failed", message: r?.error ?? undefined });
          return;
        }
        if (data.state === "RETRY") updateJob(deviceId, { state: "retry", message: r?.error ?? undefined });
        else if (data.state === "STARTED") updateJob(deviceId, { state: "running" });
      } catch (e) {
        updateJob(deviceId, { state: "failed", message: errorMessage(e) });
        return;
      }
    }
    if (mounted.current) updateJob(deviceId, { state: "failed", message: "タイムアウト（結果を確認できませんでした）" });
  };

  const startCollect = async () => {
    if (selected.size === 0) return;
    const targets = devices.filter((d) => selected.has(d.id));
    setRunning(true);
    setError("");
    setJobs(targets.map((device) => ({ device, state: "queued" })));

    await Promise.all(
      targets.map(async (device) => {
        try {
          const { data } = await api.post<{ task_id: string }>(`/devices/${device.id}/collect`);
          updateJob(device.id, { taskId: data.task_id });
          await waitForTask(device.id, data.task_id);
        } catch (e) {
          updateJob(device.id, { state: "failed", message: errorMessage(e) });
        }
      })
    );
    if (mounted.current) setRunning(false);
  };

  const finished = jobs.filter((j) => FINISHED.includes(j.state)).length;
  const progress = jobs.length ? Math.round((finished / jobs.length) * 100) : 0;
  const failed = jobs.filter((j) => j.state === "failed").length;

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">コンフィグ収集</span>
        <button className="btn btn-primary" onClick={startCollect} disabled={running || selected.size === 0}>
          {running ? "収集中..." : "▶ 収集開始"}
        </button>
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {jobs.length > 0 && (
          <div className="card" style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 12, color: "var(--color-muted)", whiteSpace: "nowrap" }}>
              {running ? "収集中..." : failed ? `完了（失敗 ${failed} 件）` : "完了"}
            </span>
            <div className="progress-wrap">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
            <span style={{ fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>
              {finished}/{jobs.length}
            </span>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 16 }}>
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
                      disabled={running}
                    />
                  </th>
                  <th>ホスト名</th>
                  <th>IPアドレス</th>
                  <th>プラットフォーム</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id} style={d.is_active ? undefined : { opacity: 0.5 }}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.has(d.id)}
                        onChange={() => toggleDevice(d.id)}
                        disabled={running}
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
              {jobs.length === 0
                ? <span style={{ color: "#8b949e" }}>待機中...</span>
                : jobs.map((j) => (
                  <div key={j.device.id}>
                    {ICON[j.state]} {j.device.name} — {describe(j)}
                  </div>
                ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
