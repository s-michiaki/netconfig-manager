import { Fragment, useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";

/**
 * アクティビティログ: システムで起きたこと（収集の結果・スケジュールの実行・違反の発生・通知の送信など）
 * 利用者の操作は監査ログに記録している
 */

interface Activity {
  id: string;
  at: string;
  category: string;
  event: string;
  level: "info" | "warning" | "error";
  device_id: string | null;
  device_name: string | null;
  message: string;
  detail: string | null;
  actor: string | null;
  ref: string | null;
}
interface Page { items: Activity[]; total: number; }
interface Labels { categories: Record<string, string>; events: Record<string, string>; levels: string[]; }
interface DeviceItem { id: string; name: string; }

const PAGE_SIZE = 100;
const SEVERITY_LABEL: Record<string, string> = { high: "高", medium: "中", low: "低" };
const KIND_LABEL: Record<string, string> = { discord: "Discord", slack: "Slack" };
const SCHEDULE_KIND_LABEL: Record<string, string> = { collect: "コンフィグ収集", compliance: "コンプライアンスチェック" };
const LEVEL_LABEL: Record<string, string> = { info: "情報", warning: "警告", error: "エラー" };
const LEVEL_BADGE: Record<string, string> = { info: "badge-neutral", warning: "badge-warning", error: "badge-danger" };
const DETAIL_LABELS: Record<string, string> = {
  commit: "世代", added: "追加行", removed: "削除行", lines: "行数", seconds: "所要秒", error: "エラー", attempt: "試行",
  devices: "台数", cron: "Cron", target: "対象", rule: "ルール", severity: "重要度", kind: "通知先", via: "設定",
  matches: "該当箇所", items: "内訳", schedule_kind: "種類", rules: "ルール数", checked: "検査数",
  new_violations: "新しい違反", resolved: "解消",
  audit_logs: "操作履歴", terminal_sessions: "ターミナル記録", activity_logs: "アクティビティ",
};

function fmtDate(iso: string): string {
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function Detail({ a }: { a: Activity }) {
  if (!a.detail) return null;
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(a.detail);
  } catch {
    return <pre className="act-detail">{a.detail}</pre>;
  }
  return (
    <div className="act-detail">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k}>
          <span className="topo-muted">{DETAIL_LABELS[k] ?? k}:</span>{" "}
          {k === "commit" && a.device_id ? (
            <Link to={`/history?device=${a.device_id}`}>{String(v).slice(0, 8)}（差分を見る）</Link>
          ) : Array.isArray(v) ? (
            <ul>{v.map((x, i) => <li key={i} className="mono">{String(x)}</li>)}</ul>
          ) : typeof v === "boolean" ? (v ? "はい" : "いいえ")
            : k === "severity" ? (SEVERITY_LABEL[String(v)] ?? String(v))
            : k === "kind" ? (KIND_LABEL[String(v)] ?? String(v))
            : k === "schedule_kind" ? (SCHEDULE_KIND_LABEL[String(v)] ?? String(v))
            : k === "target" && v === "all" ? "全機器" : String(v)}
        </div>
      ))}
    </div>
  );
}

export default function ActivityPage() {
  const [params, setParams] = useSearchParams();
  const ref = params.get("ref") ?? "";
  const [labels, setLabels] = useState<Labels | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [category, setCategory] = useState("");
  const [level, setLevel] = useState("");
  const [deviceId, setDeviceId] = useState(params.get("device") ?? "");
  const [q, setQ] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Labels>("/activity/events").then((r) => setLabels(r.data)).catch((e) => setError(errorMessage(e)));
    api.get<DeviceItem[]>("/devices/").then((r) => setDevices(r.data)).catch(() => undefined);
  }, []);

  const load = useCallback(async (o: number) => {
    setError("");
    try {
      const r = await api.get<Page>("/activity/logs", {
        params: {
          category: category || undefined, level: level || undefined, device_id: deviceId || undefined,
          ref: ref || undefined, q: q.trim() || undefined,
          since: since ? new Date(`${since}T00:00:00`).toISOString() : undefined,
          until: until ? new Date(new Date(`${until}T00:00:00`).getTime() + 86400_000).toISOString() : undefined,
          limit: PAGE_SIZE, offset: o,
        },
      });
      setPage(r.data);
      setOffset(o);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [category, level, deviceId, ref, q, since, until]);

  useEffect(() => {
    load(0);
  }, [category, level, deviceId, ref, since, until]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggle = (id: string) => {
    const n = new Set(open);
    if (n.has(id)) n.delete(id); else n.add(id);
    setOpen(n);
  };
  const clearRef = () => {
    params.delete("ref");
    setParams(params);
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">アクティビティ</span>
        <span className="topo-muted topo-small">収集の結果・スケジュールの実行・違反の発生・通知の送信など、システムで起きたことの記録（利用者の操作は監査ログ）</span>
      </div>
      <div className="page-body">
        {ref && (
          <div className="act-ref">
            ひとつの実行（収集の実行・スケジュール）に関する記録だけを表示しています
            <button className="btn btn-sm" onClick={clearRef}>すべて表示</button>
          </div>
        )}
        <form className="audit-filters" onSubmit={(e) => { e.preventDefault(); load(0); }}>
          <label className="audit-field">
            <span className="form-label">種類</span>
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">すべて</option>
              {labels && Object.entries(labels.categories).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="audit-field">
            <span className="form-label">重要度</span>
            <select value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="">すべて</option>
              <option value="warning+">警告とエラー</option>
              <option value="error">エラーのみ</option>
            </select>
          </label>
          <label className="audit-field">
            <span className="form-label">機器</span>
            <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
              <option value="">すべて</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </label>
          <label className="audit-field audit-field-wide">
            <span className="form-label">キーワード（機器・内容・きっかけ）</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="例: タイムアウト / admin" />
          </label>
          <label className="audit-field">
            <span className="form-label">期間（から）</span>
            <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
          </label>
          <label className="audit-field">
            <span className="form-label">期間（まで）</span>
            <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
          </label>
          <button className="btn btn-primary" type="submit">検索</button>
        </form>
        {error && <p className="form-error">{error}</p>}
        {page && (
          <>
            <div className="audit-bar act-bar">
              <span className="topo-muted topo-small">{page.total} 件{page.total > PAGE_SIZE && `中 ${offset + 1}–${Math.min(offset + PAGE_SIZE, page.total)}`}</span>
              {page.total > PAGE_SIZE && (
                <span style={{ display: "flex", gap: 6 }}>
                  <button className="btn" disabled={offset === 0} onClick={() => load(Math.max(0, offset - PAGE_SIZE))}>前へ</button>
                  <button className="btn" disabled={offset + PAGE_SIZE >= page.total} onClick={() => load(offset + PAGE_SIZE)}>次へ</button>
                </span>
              )}
            </div>
            <div className="table-scroll">
              <table className="data-table audit-table act-table">
                <thead>
                  <tr><th>日時</th><th>重要度</th><th>種類</th><th>機器</th><th>内容</th><th>きっかけ</th></tr>
                </thead>
                <tbody>
                  {page.items.map((a) => (
                    <Fragment key={a.id}>
                      <tr className={a.detail ? "act-row clickable" : "act-row"} onClick={() => a.detail && toggle(a.id)}>
                        <td className="nowrap mono topo-small">{fmtDate(a.at)}</td>
                        <td><span className={`badge ${LEVEL_BADGE[a.level] ?? "badge-neutral"}`}>{LEVEL_LABEL[a.level] ?? a.level}</span></td>
                        <td className="nowrap">{labels?.events[a.event] ?? a.event}</td>
                        <td className="nowrap">
                          {a.device_id ? (
                            <Link to={`/history?device=${a.device_id}`} onClick={(e) => e.stopPropagation()}>{a.device_name ?? "—"}</Link>
                          ) : (a.device_name ?? "—")}
                        </td>
                        <td>
                          {a.message}
                          {a.detail && <span className="act-more">{open.has(a.id) ? "▲" : "▼ 詳細"}</span>}
                        </td>
                        <td className="nowrap topo-small">{a.actor ?? "—"}</td>
                      </tr>
                      {open.has(a.id) && (
                        <tr className="act-detail-row"><td colSpan={6}><Detail a={a} /></td></tr>
                      )}
                    </Fragment>
                  ))}
                  {!page.items.length && (
                    <tr><td colSpan={6} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>該当する記録はありません</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
