import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errorMessage } from "../api/client";

/**
 * システムの状態: worker・スケジューラー・Redis・DB が動いているか、収集の状況、ディスク、証明書の期限
 * 「止まっていることに気づけない」をなくすための画面。異常は通知設定（システムの異常）の通知先にも送られる
 */

type Status = "ok" | "warn" | "error" | "unknown";
interface StaleDevice { id: string; name: string; last_success: string | null; }
interface Volume { name: string; path: string; free_gb: number; total_gb: number; free_pct: number; status: Status; }
interface Component {
  key: string; label: string; status: Status; summary: string;
  detail: {
    workers?: string[]; last_heartbeat?: string; active?: number; last_run?: string | null; last_success?: string | null;
    stale_days?: number; devices?: StaleDevice[]; volumes?: Volume[]; expires_at?: string; days_left?: number;
  };
}
export interface SystemStatus {
  overall: Status; checked_at: string; components: Component[];
  settings: { watchdog: boolean; alert_after_min: number; stale_days: number };
}

const BADGE: Record<Status, [string, string]> = {
  ok: ["badge-success", "正常"], warn: ["badge-warning", "注意"], error: ["badge-danger", "異常"], unknown: ["badge-neutral", "—"],
};
// 何のための項目か（止まると何が起きるか）
const HELP: Record<string, string> = {
  db: "機器・履歴・設定の保存先",
  redis: "収集などの処理の受け渡しに使用",
  worker: "コンフィグ収集・通知・コンプライアンスチェックを実行",
  beat: "スケジュール収集などを定刻に開始",
  schedule: "登録されているスケジュール",
  collect: "有効な機器のコンフィグを収集できているか",
  disk: "コンフィグ履歴・ターミナルの記録の保存先",
  cert: "画面を表示するための証明書",
};

function fmt(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function Detail({ c }: { c: Component }) {
  const d = c.detail;
  if (c.key === "beat" && d.last_heartbeat) return <p className="sys-sub">最後の定期実行: {fmt(d.last_heartbeat)}</p>;
  if (c.key === "schedule") {
    return <p className="sys-sub">最後に実行: {fmt(d.last_run)}　<Link to="/schedules">スケジュールを開く →</Link></p>;
  }
  if (c.key === "collect") {
    return (
      <>
        <p className="sys-sub">最後に成功した収集: {fmt(d.last_success)}</p>
        {!!d.devices?.length && (
          <ul className="sys-list">
            {d.devices.map((x) => (
              <li key={x.id}>
                <Link to={`/activity?device=${x.id}`}>{x.name}</Link>
                <span className="topo-muted">　{x.last_success ? `最後の成功 ${fmt(x.last_success)}` : "一度も収集できていません"}</span>
              </li>
            ))}
          </ul>
        )}
      </>
    );
  }
  if (c.key === "disk" && d.volumes) {
    return (
      <ul className="sys-list">
        {d.volumes.map((v) => (
          <li key={v.path}>{v.name}: 空き {v.free_gb} GB / {v.total_gb} GB（{v.free_pct}%）</li>
        ))}
      </ul>
    );
  }
  if (c.key === "cert" && d.expires_at) return <p className="sys-sub">期限: {fmt(d.expires_at)}</p>;
  return null;
}

export default function SystemPage() {
  const [data, setData] = useState<SystemStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api.get<SystemStatus>("/system/status")
      .then((r) => { setData(r.data); setError(""); })
      .catch((e) => setError(errorMessage(e)))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 30_000);
    return () => window.clearInterval(t);
  }, [load]);

  const bad = data?.components.filter((c) => c.status === "error" || c.status === "warn") ?? [];
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">システム状態</span>
        {data && <span className={`badge ${BADGE[data.overall][0]}`}>{data.overall === "ok" ? "すべて正常" : `要確認 ${bad.length} 件`}</span>}
        <span style={{ flex: 1 }} />
        {data && <span className="topo-muted topo-small">確認: {fmt(data.checked_at)}（30秒ごとに更新）</span>}
        <button className="btn" onClick={load} disabled={loading}>再確認</button>
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {data && (
          <>
            <div className="sys-grid">
              {data.components.map((c) => (
                <div key={c.key} className={`card sys-card sys-${c.status}`}>
                  <div className="sys-head">
                    <b>{c.label}</b>
                    <span className={`badge ${BADGE[c.status][0]}`}>{BADGE[c.status][1]}</span>
                  </div>
                  <p className="sys-summary">{c.summary}</p>
                  <Detail c={c} />
                  <p className="sys-help">{HELP[c.key]}</p>
                </div>
              ))}
            </div>
            <p className="topo-muted topo-small sys-note" style={{ marginTop: 14 }}>
              {data.settings.watchdog
                ? <>異常は <Link to="/notifications">通知設定</Link> で「システムの異常」を選んだ通知先（Discord / Slack）へ送ります。
                  worker・スケジューラー・Redis の停止は {data.settings.alert_after_min} 分続いたとき、
                  {data.settings.stale_days > 0 ? `${data.settings.stale_days} 日以上収集できていない機器・` : ""}ディスク・証明書は見つけたときに1回通知し、復旧したときにも通知します。</>
                : "異常の通知は無効です（.env の SYSTEM_WATCHDOG_ENABLED）。"}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
