import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

/**
 * ダッシュボード: ログイン後の最初の画面。
 * 「いま確認が必要なこと」（収集の失敗・未収集・違反）と、直近の変更・次のスケジュールを1画面で示す
 */

interface Failing { id: string; name: string; hostname: string; message: string; at: string; }
interface Never { id: string; name: string; hostname: string; }
interface Change { device_id: string; device_name: string; at: string; added: number; removed: number; commit: string; triggered_by: string; }
interface Upcoming { id: string; name: string; kind: string; target: string; next_run: string; }
interface Dashboard {
  devices: { total: number; active: number; inactive: number; failing: number; never: number; ok: number };
  last_success: string | null;
  failing: Failing[];
  never: Never[];
  changes: { last_24h: number; last_7d: number; recent: Change[] };
  compliance: { rules: number; by_severity: { high: number; medium: number; low: number }; violations: number; devices: number };
  schedules: { active: number; upcoming: Upcoming[] };
}

const TRIGGER: Record<string, string> = { manual: "手動", schedule: "スケジュール" };

function date(iso: string | null, utc = true): Date | null {
  if (!iso) return null;
  return new Date(utc && !iso.endsWith("Z") && !iso.includes("+") ? iso + "Z" : iso);
}
function fmt(iso: string | null, utc = true): string {
  const d = date(iso, utc);
  return d ? d.toLocaleString("ja-JP", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";
}
function ago(iso: string | null): string {
  const d = date(iso);
  if (!d) return "";
  const min = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
  if (min < 60) return `${min} 分前`;
  if (min < 60 * 48) return `${Math.round(min / 60)} 時間前`;
  return `${Math.round(min / 1440)} 日前`;
}

function Tile({ label, value, sub, tone, to }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: "bad" | "warn" | "good"; to: string }) {
  return (
    <Link to={to} className={`card dash-tile${tone ? ` dash-${tone}` : ""}`}>
      <span className="dash-tile-label">{label}</span>
      <span className="dash-tile-value">{value}</span>
      {sub && <span className="dash-tile-sub">{sub}</span>}
    </Link>
  );
}

export default function DashboardPage() {
  const { can } = useAuth();
  const [data, setData] = useState<Dashboard | null>(null);
  const [system, setSystem] = useState<string | null>(null);
  const [error, setError] = useState("");
  const canSystem = can(PERM.SYSTEM_READ);
  const load = useCallback(() => {
    api.get<Dashboard>("/dashboard").then((r) => { setData(r.data); setError(""); }).catch((e) => setError(errorMessage(e)));
    if (canSystem) api.get<{ overall: string }>("/system/status").then((r) => setSystem(r.data.overall)).catch(() => undefined);
  }, [canSystem]);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 60_000);
    return () => window.clearInterval(t);
  }, [load]);

  if (!data) return <div className="page"><div className="page-header"><span className="page-title">ダッシュボード</span></div><div className="page-body">{error && <p className="form-error">{error}</p>}</div></div>;
  const { devices: dv, compliance: cp, changes: ch } = data;
  const sev = cp.by_severity;
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">ダッシュボード</span>
        <span style={{ flex: 1 }} />
        <span className="topo-muted topo-small">最後に成功した収集: {fmt(data.last_success)}{data.last_success ? `（${ago(data.last_success)}）` : ""}</span>
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {system && system !== "ok" && (
          <Link to="/system" className={`dash-banner dash-banner-${system}`}>
            {system === "error" ? "システムに異常があります（収集が動いていない可能性があります）" : "システムに確認が必要な項目があります"}　システム状態を開く →
          </Link>
        )}
        <div className="dash-tiles">
          <Tile label="機器" value={dv.active} to="/devices"
                sub={dv.inactive ? `有効 ${dv.active} 台・無効 ${dv.inactive} 台` : "有効な機器（台）"} />
          <Tile label="収集に失敗" value={dv.failing} to="/activity?level=error" tone={dv.failing ? "bad" : "good"}
                sub={dv.failing ? "最新の収集が失敗している機器" : "失敗している機器はありません"} />
          <Tile label="未収集" value={dv.never} to="/collect" tone={dv.never ? "warn" : undefined}
                sub={dv.never ? "一度も収集していない機器" : "すべて収集済み"} />
          <Tile label="コンフィグの変更" value={ch.last_24h} to="/activity?category=collect"
                sub={`直近 24 時間（7 日間では ${ch.last_7d} 件）`} />
          <Tile label="コンプライアンス違反" value={cp.violations} to="/compliance" tone={sev.high ? "bad" : cp.violations ? "warn" : cp.rules ? "good" : undefined}
                sub={cp.rules === 0 ? "ルールが登録されていません"
                  : cp.violations ? `高 ${sev.high}・中 ${sev.medium}・低 ${sev.low}（${cp.devices} 台）` : "違反はありません"} />
        </div>

        <div className="dash-cols">
          <section className="card dash-panel">
            <h3>確認が必要な機器</h3>
            {!data.failing.length && !data.never.length && <p className="topo-muted">収集に失敗している機器・未収集の機器はありません。</p>}
            {data.failing.map((f) => (
              <div key={f.id} className="dash-row">
                <span className="badge badge-danger">失敗</span>
                <div className="dash-row-main">
                  <Link to={`/activity?device=${f.id}`}><b>{f.name}</b></Link> <span className="topo-muted mono">{f.hostname}</span>
                  <div className="dash-row-sub" title={f.message}>{f.message || "（エラーの内容は記録されていません）"}</div>
                </div>
                <span className="topo-muted topo-small nowrap">{ago(f.at)}</span>
              </div>
            ))}
            {data.never.map((n) => (
              <div key={n.id} className="dash-row">
                <span className="badge badge-neutral">未収集</span>
                <div className="dash-row-main"><b>{n.name}</b> <span className="topo-muted mono">{n.hostname}</span></div>
              </div>
            ))}
            {(dv.failing > data.failing.length || dv.never > data.never.length) && (
              <p className="topo-muted topo-small">ほかにもあります。<Link to="/devices">デバイス管理</Link> で確認してください。</p>
            )}
          </section>

          <section className="card dash-panel">
            <h3>直近の変更</h3>
            {!ch.recent.length && <p className="topo-muted">まだ収集した世代がありません。</p>}
            {ch.recent.map((c) => (
              <div key={`${c.device_id}-${c.commit}`} className="dash-row">
                <div className="dash-row-main">
                  <Link to={`/history?device=${c.device_id}`}><b>{c.device_name}</b></Link>
                  <span className="dash-diff"><span className="dash-add">+{c.added}</span> <span className="dash-del">-{c.removed}</span></span>
                  <span className="topo-muted topo-small">　{TRIGGER[c.triggered_by] ?? c.triggered_by}収集</span>
                </div>
                <span className="topo-muted topo-small nowrap">{fmt(c.at)}</span>
              </div>
            ))}
          </section>

          <section className="card dash-panel">
            <h3>次に実行されるスケジュール</h3>
            {!data.schedules.upcoming.length && (
              <p className="topo-muted">有効なスケジュールがありません。<Link to="/schedules">スケジュール</Link> で定期的な収集を登録できます。</p>
            )}
            {data.schedules.upcoming.map((s) => (
              <div key={s.id} className="dash-row">
                <div className="dash-row-main">
                  <b>{s.name}</b>
                  <div className="dash-row-sub">{s.kind}・{s.target}</div>
                </div>
                <span className="topo-small nowrap">{fmt(s.next_run, false)}</span>
              </div>
            ))}
          </section>
        </div>
      </div>
    </div>
  );
}
