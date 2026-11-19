import { useCallback, useEffect, useMemo, useState } from "react";
import { api, errorMessage } from "../api/client";

/**
 * Ping監視の「常時監視」: 画面を開いていなくても worker が一定間隔で PING し、
 * 結果を残して、続けて応答が無いと通知する（応答なし・復旧）。
 * ここでは対象の追加・解除、いまの状態、直近の応答時間と応答なしの推移を表示する
 */

interface Group { id: string; name: string; color: string | null; }
interface Target { key: string; kind: "device" | "custom"; name: string; address: string; group_id: string | null; is_active: boolean; }
interface Monitor {
  key: string; name: string; address: string; group_id: string | null; is_active: boolean;
  status: "up" | "down" | "unknown"; since: string | null; fails: number;
  last_at: string | null; last_rtt: number | null; last_ok: string | null;
  sent_24h: number; received_24h: number; created_by: string | null;
}
interface MonitorList { items: Monitor[]; interval_sec: number; alert_after: number; history_days: number; max_targets: number; }
interface Bucket { at: string; sent: number; lost: number; avg: number | null; max: number | null; }
interface History { key: string; hours: number; since: string; until: string; sent: number; lost: number; buckets: Bucket[]; }

const REFRESH_MS = 15000;
const RANGES: [number, string][] = [[1, "1 時間"], [6, "6 時間"], [24, "24 時間"], [24 * 7, "7 日"], [24 * 14, "14 日"]];

const fmt = (iso: string | null, withDate = true) => (iso
  ? new Date(iso).toLocaleString("ja-JP", withDate
    ? { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }
    : { hour: "2-digit", minute: "2-digit" })
  : "—");

function pct(received: number, sent: number): string {
  return sent ? `${((received / sent) * 100).toFixed(sent === received ? 0 : 1)}%` : "—";
}

/** 応答時間（平均）の線と、応答なしのあった区切りを示す帯。区切りにマウスを載せると値を表示する */
function HistoryChart({ h }: { h: History }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 900, H = 230, L = 52, R = 12, T = 22, B = 46, LOSS = 12;
  const plotH = H - T - B - LOSS - 6;
  const n = h.buckets.length;
  const bw = (W - L - R) / n;
  const maxAvg = Math.max(1, ...h.buckets.map((b) => b.avg ?? 0));
  // 目盛り: 1・2・5 × 10^k で 4 本前後
  const step = (() => {
    const raw = maxAvg / 4;
    const p = 10 ** Math.floor(Math.log10(raw));
    return [1, 2, 5, 10].map((m) => m * p).find((s) => s >= raw) ?? raw;
  })();
  const top = Math.ceil(maxAvg / step) * step;
  const decimals = step >= 1 ? 0 : step >= 0.1 ? 1 : 2;
  const y = (v: number) => T + plotH - (v / top) * plotH;
  const x = (i: number) => L + bw * i + bw / 2;
  // 平均の線（データの無い区切りで途切れさせる）
  const paths: string[] = [];
  let cur = "";
  h.buckets.forEach((b, i) => {
    if (b.avg == null) { if (cur) paths.push(cur); cur = ""; return; }
    cur += `${cur ? "L" : "M"}${x(i).toFixed(1)},${y(b.avg).toFixed(1)}`;
  });
  if (cur) paths.push(cur);
  const ticks = Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
  const labelEvery = Math.ceil(n / 6);
  const multiDay = h.hours > 24;
  const hb = hover != null ? h.buckets[hover] : null;
  const lossY = T + plotH + 6;

  return (
    <div className="pmon-chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="応答時間と応答なしの推移" onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={L} x2={W - R} y1={y(t)} y2={y(t)} className="pmon-grid" />
            <text x={L - 6} y={y(t) + 4} textAnchor="end" className="pmon-axis">{t.toFixed(decimals)}</text>
          </g>
        ))}
        <text x={L} y={T - 10} className="pmon-axis">応答時間の平均（ms）</text>
        {hover != null && <rect x={L + bw * hover} y={T} width={bw} height={plotH + LOSS + 6} className="pmon-hover" />}
        {paths.map((d, i) => <path key={i} d={d} className="pmon-line" />)}
        {h.buckets.map((b, i) => (b.avg != null && (i === 0 || h.buckets[i - 1].avg == null) && (i === n - 1 || h.buckets[i + 1].avg == null)
          ? <circle key={`p${i}`} cx={x(i)} cy={y(b.avg)} r={2.5} className="pmon-point" /> : null))}
        {/* 応答なしの帯（区切りの中の応答なしの割合で濃さを変える） */}
        <text x={L - 6} y={lossY + LOSS - 2} textAnchor="end" className="pmon-axis">応答なし</text>
        {h.buckets.map((b, i) => (
          <rect key={`l${i}`} x={L + bw * i + 1} y={lossY} width={Math.max(1, bw - 2)} height={LOSS} rx={2}
                className={b.sent === 0 ? "pmon-loss-none" : b.lost ? "pmon-loss" : "pmon-loss-ok"}
                style={b.lost ? { opacity: 0.35 + 0.65 * (b.lost / b.sent) } : undefined} />
        ))}
        {h.buckets.map((b, i) => (i % labelEvery === 0
          ? <text key={`x${i}`} x={L + bw * i} y={H - 14} className="pmon-axis">{fmt(b.at, multiDay)}</text> : null))}
        {/* マウスの当たり判定（区切りの幅いっぱい） */}
        {h.buckets.map((_, i) => (
          <rect key={`h${i}`} x={L + bw * i} y={T} width={bw} height={plotH + LOSS + 6} fill="transparent" onMouseEnter={() => setHover(i)} />
        ))}
      </svg>
      <div className="pmon-tip" aria-live="polite">
        {hb
          ? hb.sent
            ? <>{fmt(hb.at)} から　平均 <b>{hb.avg != null ? `${hb.avg} ms` : "—"}</b>　最大 {hb.max != null ? `${hb.max} ms` : "—"}　PING {hb.sent} 回中 応答なし <b className={hb.lost ? "pmon-lost" : ""}>{hb.lost}</b> 回</>
            : <>{fmt(hb.at)} から　記録なし</>
          : <span className="topo-muted">グラフにマウスを載せると、その時間の値を表示します</span>}
      </div>
    </div>
  );
}

function HistoryModal({ m, maxHours, onClose }: { m: Monitor; maxHours: number; onClose: () => void }) {
  const [hours, setHours] = useState(24);
  const [h, setH] = useState<History | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setError("");
    api.get<History>(`/ping/monitors/${encodeURIComponent(m.key)}/history`, { params: { hours } })
      .then((r) => setH(r.data)).catch((e) => setError(errorMessage(e)));
  }, [m.key, hours]);
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal pmon-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{m.name} <span className="topo-muted mono" style={{ fontWeight: 400 }}>{m.address}</span></p>
        <div className="pmon-head">
          <div className="seg-tabs" role="tablist" aria-label="期間">
            {RANGES.filter(([v]) => v <= maxHours).map(([v, label]) => (
              <button key={v} role="tab" aria-selected={hours === v} className={`seg-tab${hours === v ? " active" : ""}`} onClick={() => setHours(v)}>{label}</button>
            ))}
          </div>
          {h && (
            <span className="topo-small">
              応答率 <b>{pct(h.sent - h.lost, h.sent)}</b>（PING {h.sent} 回・応答なし {h.lost} 回）
            </span>
          )}
        </div>
        {error && <p className="form-error">{error}</p>}
        {h && (h.sent ? <HistoryChart h={h} /> : <p className="topo-muted">この期間の記録はありません。</p>)}
        <div className="btn-row"><button className="btn" onClick={onClose}>閉じる</button></div>
      </div>
    </div>
  );
}

export default function PingMonitorPanel({ groups, targets, canWrite }: { groups: Group[]; targets: Target[]; canWrite: boolean }) {
  const [list, setList] = useState<MonitorList | null>(null);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState("");
  const [busy, setBusy] = useState(false);
  const [showing, setShowing] = useState<Monitor | null>(null);

  const load = useCallback(async () => {
    try {
      setList((await api.get<MonitorList>("/ping/monitors")).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [load]);

  const groupName = useMemo(() => new Map(groups.map((g) => [g.id, g.name])), [groups]);
  const monitored = new Set(list?.items.map((m) => m.key));
  const candidates = targets.filter((t) => !monitored.has(t.key));

  const set = async (key: string, monitoredFlag: boolean) => {
    setBusy(true);
    setError("");
    try {
      await api.put(`/ping/monitors/${encodeURIComponent(key)}`, { monitored: monitoredFlag });
      setAdding("");
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = (m: Monitor) => {
    if (!window.confirm(`「${m.name}」の常時監視をやめますか？（これまでの結果の記録も削除します）`)) return;
    set(m.key, false);
  };

  if (!list) return <div className="card">{error ? <p className="form-error">{error}</p> : "読み込み中..."}</div>;
  const down = list.items.filter((m) => m.status === "down").length;

  return (
    <>
      {showing && <HistoryModal m={showing} maxHours={list.history_days * 24} onClose={() => setShowing(null)} />}
      <p className="topo-muted topo-small" style={{ marginTop: 0, marginBottom: 12 }}>
        画面を開いていなくても、サーバーが {list.interval_sec} 秒ごとに PING します。{list.alert_after} 回続けて応答が無いと「応答なし」として、
        応答が戻ると「復旧」として通知します（通知設定の「Ping監視」）。結果は {list.history_days} 日分残します。
      </p>
      {error && <p className="form-error">{error}</p>}
      {canWrite && (
        <div className="pmon-add">
          <select value={adding} onChange={(e) => setAdding(e.target.value)} aria-label="常時監視に加える対象" style={{ maxWidth: 420 }}>
            <option value="">常時監視に加える対象を選ぶ…</option>
            {candidates.map((t) => (
              <option key={t.key} value={t.key}>{t.name}（{t.address}）{t.kind === "custom" ? "・追加IP" : ""}{t.is_active ? "" : "・無効の機器"}</option>
            ))}
          </select>
          <button className="btn btn-primary" disabled={!adding || busy || list.items.length >= list.max_targets} onClick={() => set(adding, true)}>加える</button>
        </div>
      )}
      <div className="ping-summary">
        <span><i className="ping-dot ok" />応答あり {list.items.filter((m) => m.status === "up").length}</span>
        <span><i className="ping-dot error" />応答なし {down}</span>
        <span style={{ color: "var(--color-muted)" }}>／ 常時監視 {list.items.length}</span>
      </div>
      {list.items.length === 0 ? (
        <div className="card" style={{ color: "var(--color-muted)" }}>
          常時監視している対象はありません。{canWrite ? "上の一覧から機器や IP を選んで「加える」を押してください。" : ""}
        </div>
      ) : (
        <div className="table-scroll">
          <table className="data-table pmon-table">
            <thead>
              <tr>
                <th style={{ width: 130 }}>状態</th><th>名前</th><th>アドレス</th><th>グループ</th>
                <th className="num">最後の応答時間</th><th>最後に確認</th><th className="num">24 時間の応答率</th><th />
              </tr>
            </thead>
            <tbody>
              {list.items.map((m) => (
                <tr key={m.key} className={m.status === "down" ? "ping-row down" : undefined}>
                  <td>
                    {m.status === "down"
                      ? <span className="pmon-state"><i className="ping-dot down" />応答なし<span className="topo-muted topo-small">{fmt(m.since)} から</span></span>
                      : m.status === "up"
                        ? <span className="pmon-state"><i className={`ping-dot ${m.fails ? "warn" : "ok"}`} />応答あり{m.fails ? <span className="topo-muted topo-small">直近 {m.fails} 回応答なし</span> : null}</span>
                        : <span className="pmon-state"><i className="ping-dot" />{m.is_active ? "未確認" : "無効の機器"}</span>}
                  </td>
                  <td>{m.name}</td>
                  <td className="mono">{m.address}</td>
                  <td>{m.group_id ? groupName.get(m.group_id) ?? "—" : <span className="topo-muted">—</span>}</td>
                  <td className="num">{m.last_rtt != null ? `${m.last_rtt} ms` : "—"}</td>
                  <td>{fmt(m.last_at)}</td>
                  <td className="num">{pct(m.received_24h, m.sent_24h)}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button className="btn btn-sm" onClick={() => setShowing(m)}>推移</button>{" "}
                    {canWrite && <button className="btn btn-sm" onClick={() => remove(m)} disabled={busy}>やめる</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
