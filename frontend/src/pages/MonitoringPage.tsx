import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

/**
 * モニタリング（試験導入）
 * - インタフェース: SNMP で取得した帯域（bps・使用率）と推移のグラフ
 * - FW ルール: PAN-OS・FortiGate のルールのヒット数（未使用のルールの洗い出し）
 * - SNMP 設定: 機器ごとの SNMP（v2c / v3）の設定
 */

interface Iface {
  id: string; device_id: string; device_name: string; if_index: number; name: string; alias: string | null;
  speed_mbps: number | null; oper_up: boolean; in_bps: number | null; out_bps: number | null;
  in_util: number | null; out_util: number | null; last_at: string | null;
}
interface Point { at: string; in_bps: number; out_bps: number; in_max: number | null; out_max: number | null; }
interface Series { interface: Iface; hours: number; bucket_seconds: number; points: Point[]; }
interface FwDevice {
  device_id: string; name: string; platform: string; platform_label: string; collected_at: string | null;
  success: boolean | null; error: string | null; rule_count: number; unused_count: number; has_raw: boolean;
}
interface FwRule {
  position: number; rule_id: string | null; name: string; hit_count: number | null; delta: number | null;
  delta_hours: number | null; packets: number | null; bytes: number | null; first_hit_at: string | null;
  last_hit_at: string | null; unused: boolean;
}
interface SnmpDevice {
  device_id: string; name: string; hostname: string; platform: string; group_name: string | null; via_jump: boolean;
  configured: boolean; enabled: boolean; version: string | null; port: number | null; has_community: boolean;
  v3_user: string | null; v3_auth_proto: string | null; v3_priv_proto: string | null; has_auth_key: boolean;
  has_priv_key: boolean; last_polled_at: string | null; last_error: string | null; interface_count: number;
}

// 入力・出力の色（暗い背景で検証済み）。線の種類（実線・破線）でも区別する
const IN_COLOR = "#4f8ef7";
const OUT_COLOR = "#c97a3a";
const RANGES: [number, string][] = [[1, "1時間"], [6, "6時間"], [24, "24時間"], [24 * 7, "7日"], [24 * 30, "30日"]];

function utc(iso: string): Date {
  return new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
}
function fmtDate(iso: string | null, utcValue = true): string {
  if (!iso) return "—";
  const d = utcValue ? utc(iso) : new Date(iso);
  return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}
export function fmtBps(v: number | null | undefined): string {
  if (v == null) return "—";
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let x = v;
  let i = 0;
  while (x >= 1000 && i < units.length - 1) { x /= 1000; i++; }
  return `${x >= 100 || i === 0 || Number.isInteger(x) ? x.toFixed(0) : x.toFixed(1)} ${units[i]}`;
}
function fmtSpeed(mbps: number | null): string {
  if (!mbps) return "—";
  return mbps >= 1000 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`;
}
function fmtNum(v: number | null): string {
  return v == null ? "—" : v.toLocaleString("ja-JP");
}

function UtilBar({ value }: { value: number | null }) {
  if (value == null) return <span className="topo-muted">—</span>;
  const cls = value >= 80 ? "mon-bar-high" : value >= 50 ? "mon-bar-mid" : "";
  return (
    <span className="mon-util" title={`${value}%`}>
      <span className="mon-bar"><span className={`mon-bar-fill ${cls}`} style={{ width: `${Math.min(100, value)}%` }} /></span>
      <span className="mono">{value.toFixed(1)}%</span>
    </span>
  );
}

// ================================================================ グラフ（入力・出力の bps）

// 目盛りの間隔を 1・2・2.5・5 ×10^n から選び、上限を間隔の倍数にする
function niceScale(v: number): { max: number; ticks: number[] } {
  const raw = Math.max(v, 1000) / 4;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = ([1, 2, 2.5, 5, 10].find((m) => m * p >= raw) ?? 10) * p;
  const max = Math.ceil(Math.max(v, 1000) / step) * step;
  return { max, ticks: Array.from({ length: Math.round(max / step) + 1 }, (_, i) => i * step) };
}

function BpsChart({ series }: { series: Series }) {
  const W = 900;
  const H = 260;
  const pad = { l: 72, r: 16, t: 12, b: 28 };
  const pts = series.points;
  const wrap = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const end = Date.now();
  const start = end - series.hours * 3600_000;
  const speed = series.interface.speed_mbps ? series.interface.speed_mbps * 1e6 : null;
  const peak = Math.max(0, ...pts.map((p) => Math.max(p.in_bps, p.out_bps)));
  const { max: yMax, ticks: ticksY } = niceScale(peak * 1.05);
  const x = (t: number) => pad.l + ((t - start) / (end - start)) * (W - pad.l - pad.r);
  const y = (v: number) => pad.t + (1 - v / yMax) * (H - pad.t - pad.b);
  // 取得の間隔の3倍以上あいたところは線をつながない（取得できなかった時間）
  const gap = series.bucket_seconds * 3 * 1000;
  const path = (key: "in_bps" | "out_bps") => {
    let d = "";
    let prev = 0;
    pts.forEach((p, i) => {
      const t = utc(p.at).getTime();
      d += `${i === 0 || t - prev > gap ? "M" : "L"}${x(t).toFixed(1)},${y(p[key]).toFixed(1)}`;
      prev = t;
    });
    return d;
  };
  const ticksX = Array.from({ length: 6 }, (_, i) => start + ((end - start) * i) / 5);
  const xLabel = (t: number) => {
    const d = new Date(t);
    return series.hours > 48
      ? d.toLocaleDateString("ja-JP", { month: "numeric", day: "numeric" })
      : d.toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit" });
  };
  const onMove = (e: React.MouseEvent) => {
    if (!wrap.current || !pts.length) return;
    const r = wrap.current.getBoundingClientRect();
    const t = start + (((e.clientX - r.left) / r.width) * W - pad.l) / (W - pad.l - pad.r) * (end - start);
    let best = 0;
    pts.forEach((p, i) => {
      if (Math.abs(utc(p.at).getTime() - t) < Math.abs(utc(pts[best].at).getTime() - t)) best = i;
    });
    setHover(best);
  };
  const hp = hover != null ? pts[hover] : null;
  return (
    <div className="mon-chart" ref={wrap} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="入力・出力の帯域の推移">
        {ticksY.map((v) => (
          <g key={v}>
            <line x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} className="mon-grid" />
            <text x={pad.l - 8} y={y(v) + 4} textAnchor="end" className="mon-axis">{fmtBps(v)}</text>
          </g>
        ))}
        {ticksX.map((t) => (
          <text key={t} x={x(t)} y={H - 8} textAnchor="middle" className="mon-axis">{xLabel(t)}</text>
        ))}
        {speed && speed <= yMax && (
          <g>
            <line x1={pad.l} x2={W - pad.r} y1={y(speed)} y2={y(speed)} className="mon-speed" />
            <text x={W - pad.r} y={y(speed) - 4} textAnchor="end" className="mon-axis">回線速度</text>
          </g>
        )}
        <path d={path("in_bps")} fill="none" stroke={IN_COLOR} strokeWidth={2} strokeLinejoin="round" />
        <path d={path("out_bps")} fill="none" stroke={OUT_COLOR} strokeWidth={2} strokeLinejoin="round" strokeDasharray="6 3" />
        {hp && (
          <g>
            <line x1={x(utc(hp.at).getTime())} x2={x(utc(hp.at).getTime())} y1={pad.t} y2={H - pad.b} className="mon-cross" />
            <circle cx={x(utc(hp.at).getTime())} cy={y(hp.in_bps)} r={4} fill={IN_COLOR} className="mon-dot" />
            <circle cx={x(utc(hp.at).getTime())} cy={y(hp.out_bps)} r={4} fill={OUT_COLOR} className="mon-dot" />
          </g>
        )}
      </svg>
      {hp && (
        <div className="mon-tip" style={{ left: `${(x(utc(hp.at).getTime()) / W) * 100}%` }}>
          <div className="topo-muted">{fmtDate(hp.at)}</div>
          <div><span className="mon-key" style={{ background: IN_COLOR }} />入力 {fmtBps(hp.in_bps)}{hp.in_max != null && <span className="topo-muted">（最大 {fmtBps(hp.in_max)}）</span>}</div>
          <div><span className="mon-key mon-key-dash" style={{ borderColor: OUT_COLOR }} />出力 {fmtBps(hp.out_bps)}{hp.out_max != null && <span className="topo-muted">（最大 {fmtBps(hp.out_max)}）</span>}</div>
        </div>
      )}
      {!pts.length && <div className="mon-empty">この期間の記録はありません（取得は {Math.round(series.bucket_seconds / 60)} 分ごと。2回目の取得から表示されます）</div>}
    </div>
  );
}

function SeriesPanel({ iface, onClose }: { iface: Iface; onClose: () => void }) {
  const [hours, setHours] = useState(24);
  const [series, setSeries] = useState<Series | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => {
    api.get<Series>(`/monitoring/interfaces/${iface.id}/samples`, { params: { hours } })
      .then((r) => { setSeries(r.data); setError(""); })
      .catch((e) => setError(errorMessage(e)));
  }, [iface.id, hours]);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 60_000);
    return () => window.clearInterval(t);
  }, [load]);
  const pts = series?.points ?? [];
  const avg = (k: "in_bps" | "out_bps") => (pts.length ? pts.reduce((s, p) => s + p[k], 0) / pts.length : null);
  const max = (k: "in_bps" | "out_bps", m: "in_max" | "out_max") => (pts.length ? Math.max(...pts.map((p) => p[m] ?? p[k])) : null);
  return (
    <div className="card mon-series">
      <div className="mon-series-head">
        <div>
          <b>{iface.device_name} / {iface.name}</b>
          {iface.alias && <span className="topo-muted">　{iface.alias}</span>}
          <span className="topo-muted">　{fmtSpeed(iface.speed_mbps)}</span>
        </div>
        <div className="seg-tabs" role="tablist" aria-label="期間">
          {RANGES.map(([h, l]) => (
            <button key={h} role="tab" aria-selected={hours === h} className={`seg-tab${hours === h ? " active" : ""}`} onClick={() => setHours(h)}>{l}</button>
          ))}
        </div>
        <button className="btn btn-sm" onClick={onClose}>閉じる</button>
      </div>
      <div className="mon-legend">
        <span><span className="mon-key" style={{ background: IN_COLOR }} />入力（受信）</span>
        <span><span className="mon-key mon-key-dash" style={{ borderColor: OUT_COLOR }} />出力（送信）</span>
        {series && series.bucket_seconds > 600 && <span className="topo-muted">{Math.round(series.bucket_seconds / 60)} 分ごとの平均（ツールチップに最大値）</span>}
      </div>
      {error && <p className="form-error">{error}</p>}
      {series && <BpsChart series={series} />}
      {series && pts.length > 0 && (
        <table className="data-table mon-stats">
          <thead><tr><th /><th>平均</th><th>最大</th><th>直近</th></tr></thead>
          <tbody>
            <tr><td>入力</td><td>{fmtBps(avg("in_bps"))}</td><td>{fmtBps(max("in_bps", "in_max"))}</td><td>{fmtBps(pts[pts.length - 1].in_bps)}</td></tr>
            <tr><td>出力</td><td>{fmtBps(avg("out_bps"))}</td><td>{fmtBps(max("out_bps", "out_max"))}</td><td>{fmtBps(pts[pts.length - 1].out_bps)}</td></tr>
          </tbody>
        </table>
      )}
    </div>
  );
}

// ================================================================ インタフェース

function InterfacesTab({ devices }: { devices: SnmpDevice[] }) {
  const { can } = useAuth();
  const [deviceId, setDeviceId] = useState("");
  const [items, setItems] = useState<Iface[]>([]);
  const [top, setTop] = useState<Iface[]>([]);
  const [upOnly, setUpOnly] = useState(true);
  const [selected, setSelected] = useState<Iface | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const polled = devices.filter((d) => d.configured);

  const load = useCallback(() => {
    if (deviceId) {
      api.get<Iface[]>("/monitoring/interfaces", { params: { device_id: deviceId } }).then((r) => setItems(r.data)).catch((e) => setError(errorMessage(e)));
    } else {
      api.get<Iface[]>("/monitoring/interfaces/top", { params: { limit: 20 } }).then((r) => setTop(r.data)).catch((e) => setError(errorMessage(e)));
    }
  }, [deviceId]);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 60_000);
    return () => window.clearInterval(t);
  }, [load]);

  const pollNow = async () => {
    try {
      await api.post("/monitoring/snmp/poll");
      setNotice("取得を開始しました。1分ほどで反映されます（帯域は前回の取得との差から計算するため、初回は値が出ません）");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const rows = deviceId ? items.filter((i) => !upOnly || i.oper_up) : top;
  return (
    <>
      <div className="mon-bar-row">
        <label className="audit-field audit-field-wide">
          <span className="form-label">機器</span>
          <select value={deviceId} onChange={(e) => { setDeviceId(e.target.value); setSelected(null); }}>
            <option value="">使用率の高いインタフェース（全機器）</option>
            {polled.map((d) => <option key={d.device_id} value={d.device_id}>{d.name}</option>)}
          </select>
        </label>
        {deviceId && (
          <label className="form-check" style={{ alignSelf: "flex-end" }}>
            <input type="checkbox" checked={upOnly} onChange={(e) => setUpOnly(e.target.checked)} />稼働中（up）だけ
          </label>
        )}
        <span style={{ flex: 1 }} />
        {can(PERM.COLLECT) && polled.length > 0 && <button className="btn" onClick={pollNow}>今すぐ取得</button>}
      </div>
      {notice && <p className="ntf-ok">{notice}</p>}
      {error && <p className="form-error">{error}</p>}
      {polled.length === 0 ? (
        <p className="topo-muted" style={{ padding: 16 }}>SNMP を設定した機器がありません。「SNMP 設定」タブで機器ごとに設定してください。</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                {!deviceId && <th>機器</th>}
                <th>インタフェース</th><th>説明</th><th>状態</th><th>速度</th>
                <th>入力</th><th>入力の使用率</th><th>出力</th><th>出力の使用率</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} className={`clickable${selected?.id === i.id ? " mon-row-active" : ""}`} onClick={() => setSelected(i)}>
                  {!deviceId && <td className="nowrap">{i.device_name}</td>}
                  <td className="nowrap mono">{i.name}</td>
                  <td className="topo-small">{i.alias ?? ""}</td>
                  <td>{i.oper_up ? <span className="badge badge-success">up</span> : <span className="badge badge-neutral">down</span>}</td>
                  <td className="nowrap">{fmtSpeed(i.speed_mbps)}</td>
                  <td className="nowrap mono">{fmtBps(i.in_bps)}</td>
                  <td><UtilBar value={i.in_util} /></td>
                  <td className="nowrap mono">{fmtBps(i.out_bps)}</td>
                  <td><UtilBar value={i.out_util} /></td>
                </tr>
              ))}
              {!rows.length && (
                <tr><td colSpan={9} className="topo-muted" style={{ textAlign: "center", padding: 20 }}>
                  まだ値がありません（{deviceId ? "2回目の取得から表示されます" : "帯域は2回目の取得から計算されます"}）
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {selected && <SeriesPanel key={selected.id} iface={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

// ================================================================ FW ルール

function FwTab() {
  const { can } = useAuth();
  const [devices, setDevices] = useState<FwDevice[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [rules, setRules] = useState<FwRule[]>([]);
  const [filter, setFilter] = useState<"all" | "unused" | "used">("all");
  const [q, setQ] = useState("");
  const [raw, setRaw] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadDevices = useCallback(() => {
    api.get<FwDevice[]>("/monitoring/fw").then((r) => {
      setDevices(r.data);
      setDeviceId((cur) => cur || r.data[0]?.device_id || "");
    }).catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(loadDevices, [loadDevices]);
  const loadRules = useCallback(() => {
    if (!deviceId) return;
    api.get<FwRule[]>(`/monitoring/fw/${deviceId}/rules`).then((r) => setRules(r.data)).catch((e) => setError(errorMessage(e)));
  }, [deviceId]);
  useEffect(() => { setRaw(null); loadRules(); }, [loadRules]);

  const dev = devices.find((d) => d.device_id === deviceId);
  const collect = async () => {
    setError("");
    try {
      await api.post(`/monitoring/fw/${deviceId}/collect`);
      setNotice("取得を開始しました。終わったら表示を更新します");
      window.setTimeout(() => { loadDevices(); loadRules(); setNotice(""); }, 15_000);
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const showRaw = async () => {
    try {
      setRaw((await api.get<string>(`/monitoring/fw/${deviceId}/raw`, { responseType: "text" })).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const isForti = dev?.platform === "fortinet";
  const shown = rules
    .filter((r) => filter === "all" || (filter === "unused" ? r.unused : !r.unused))
    .filter((r) => !q || r.name.toLowerCase().includes(q.toLowerCase()) || r.rule_id === q);

  if (!devices.length) {
    return <p className="topo-muted" style={{ padding: 16 }}>ヒット数を取得できる FW（Palo Alto PAN-OS・Fortinet FortiGate）が登録されていません。</p>;
  }
  return (
    <>
      <div className="mon-fw-devices">
        {devices.map((d) => (
          <button key={d.device_id} className={`mon-fw-card${d.device_id === deviceId ? " active" : ""}`} onClick={() => setDeviceId(d.device_id)}>
            <b>{d.name}</b>
            <span className="topo-muted topo-small">{d.platform_label}</span>
            <span className="topo-small">
              {d.collected_at == null ? <span className="topo-muted">未取得</span>
                : d.success ? <>ルール {d.rule_count}・<span className={d.unused_count ? "mon-warn" : ""}>未使用 {d.unused_count}</span></>
                  : <span className="badge badge-danger">取得失敗</span>}
            </span>
          </button>
        ))}
      </div>
      {dev && (
        <>
          <div className="mon-bar-row">
            <span className="topo-small topo-muted">
              最終取得: {fmtDate(dev.collected_at)}（{dev.collected_at ? "定期的に自動取得" : "次の定期取得を待つか「今すぐ取得」"}）
            </span>
            <span style={{ flex: 1 }} />
            <div className="seg-tabs" role="tablist" aria-label="絞り込み">
              {([["all", "すべて"], ["unused", "未使用"], ["used", "使用中"]] as const).map(([k, l]) => (
                <button key={k} role="tab" aria-selected={filter === k} className={`seg-tab${filter === k ? " active" : ""}`} onClick={() => setFilter(k)}>{l}</button>
              ))}
            </div>
            <input placeholder="ルール名で絞り込み" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 220 }} aria-label="ルール名で絞り込み" />
            {can(PERM.COLLECT) && <button className="btn" onClick={collect}>今すぐ取得</button>}
            {can(PERM.DEVICE_WRITE) && dev.has_raw && <button className="btn" onClick={showRaw}>取得した出力</button>}
          </div>
          {dev.error && <p className="form-error">前回の取得に失敗しました: {dev.error}</p>}
          {notice && <p className="ntf-ok">{notice}</p>}
          {error && <p className="form-error">{error}</p>}
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>{isForti && <th>ID</th>}<th>ルール名</th><th>ヒット数</th><th>前回からの増加</th>
                  <th>最終ヒット</th><th>初回ヒット</th>{isForti && <th>パケット / バイト</th>}
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={`${r.position}-${r.name}`}>
                    <td className="topo-muted">{r.position}</td>
                    {isForti && <td className="mono">{r.rule_id}</td>}
                    <td>{r.name}{r.unused && <span className="badge badge-warning" style={{ marginLeft: 6 }} title={r.hit_count === 0 ? "一度もヒットしていません" : "30日以上ヒットしていません"}>未使用</span>}</td>
                    <td className="mono nowrap">{fmtNum(r.hit_count)}</td>
                    <td className="mono nowrap">{r.delta == null ? "—" : `+${fmtNum(r.delta)}`}{r.delta_hours != null && r.delta != null && <span className="topo-muted">（{r.delta_hours} 時間）</span>}</td>
                    <td className="nowrap topo-small">{fmtDate(r.last_hit_at, false)}</td>
                    <td className="nowrap topo-small">{fmtDate(r.first_hit_at, false)}</td>
                    {isForti && <td className="mono nowrap topo-small">{fmtNum(r.packets)} / {fmtNum(r.bytes)}</td>}
                  </tr>
                ))}
                {!shown.length && (
                  <tr><td colSpan={8} className="topo-muted" style={{ textAlign: "center", padding: 20 }}>
                    {rules.length ? "該当するルールはありません" : dev.collected_at ? "ルールを取得できていません" : "まだ取得していません"}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="topo-muted topo-small" style={{ marginTop: 6 }}>
            日時は機器の時刻です。「未使用」は一度もヒットしていない、または最終ヒットが30日以上前のルールです（ヒット数をリセットした場合はその後の値）。
          </p>
          {raw != null && (
            <div className="modal-overlay" onClick={() => setRaw(null)}>
              <div className="modal mon-raw" onClick={(e) => e.stopPropagation()}>
                <p className="modal-title">取得した出力（{dev.name}）</p>
                <p className="topo-muted topo-small">ヒット数を正しく読めないときの確認用です。表示が合わない場合はこの内容を開発者に伝えてください。</p>
                <pre className="mono">{raw}</pre>
                <div className="btn-row"><button className="btn" onClick={() => setRaw(null)}>閉じる</button></div>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}

// ================================================================ SNMP 設定

function SnmpModal({ d, onClose, onSaved }: { d: SnmpDevice; onClose: () => void; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(d.configured ? d.enabled : true);
  const [version, setVersion] = useState(d.version ?? "2c");
  const [port, setPort] = useState(d.port ?? 161);
  const [community, setCommunity] = useState("");
  const [user, setUser] = useState(d.v3_user ?? "");
  const [authProto, setAuthProto] = useState(d.v3_auth_proto ?? "SHA");
  const [authKey, setAuthKey] = useState("");
  const [privProto, setPrivProto] = useState(d.v3_priv_proto ?? "AES");
  const [privKey, setPrivKey] = useState("");
  const [error, setError] = useState("");
  const [test, setTest] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async (andTest: boolean) => {
    setBusy(true);
    setError("");
    setTest("");
    try {
      await api.put(`/monitoring/snmp/${d.device_id}`, {
        enabled, version, port,
        community: version === "2c" ? (community || null) : null,
        v3_user: version === "3" ? user : null,
        v3_auth_proto: version === "3" ? authProto : null, v3_auth_key: version === "3" ? (authKey || null) : null,
        v3_priv_proto: version === "3" ? privProto : null, v3_priv_key: version === "3" ? (privKey || null) : null,
      });
      onSaved();
      if (andTest) {
        const r = await api.post<{ sys_name: string; sys_descr: string }>(`/monitoring/snmp/${d.device_id}/test`);
        setTest(`応答あり: ${r.data.sys_name}（${r.data.sys_descr}）`);
      } else {
        onClose();
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">SNMP 設定: {d.name}（{d.hostname}）</p>
        {d.via_jump && <p className="form-error">この機器は踏み台経由です。SNMP はサーバーから機器へ UDP で直接届く必要があります。</p>}
        <label className="form-check" style={{ marginBottom: 10 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />帯域を定期的に取得する
        </label>
        <div style={{ display: "flex", gap: 10 }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor="snmp-ver">バージョン</label>
            <select id="snmp-ver" value={version} onChange={(e) => setVersion(e.target.value)}>
              <option value="2c">v2c</option><option value="3">v3</option>
            </select>
          </div>
          <div className="form-group" style={{ width: 110 }}>
            <label className="form-label" htmlFor="snmp-port">ポート</label>
            <input id="snmp-port" type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} />
          </div>
        </div>
        {version === "2c" ? (
          <div className="form-group">
            <label className="form-label" htmlFor="snmp-community">コミュニティ名{d.has_community ? "（登録済み。変更する場合のみ入力）" : ""}</label>
            <input id="snmp-community" type="password" autoComplete="off" value={community} onChange={(e) => setCommunity(e.target.value)} />
          </div>
        ) : (
          <>
            <div className="form-group">
              <label className="form-label" htmlFor="snmp-user">ユーザー名</label>
              <input id="snmp-user" value={user} onChange={(e) => setUser(e.target.value)} />
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <div className="form-group" style={{ width: 140 }}>
                <label className="form-label" htmlFor="snmp-auth">認証</label>
                <select id="snmp-auth" value={authProto} onChange={(e) => setAuthProto(e.target.value)}>
                  <option value="SHA">SHA</option><option value="SHA256">SHA-256</option><option value="MD5">MD5</option><option value="">なし</option>
                </select>
              </div>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label" htmlFor="snmp-authkey">認証パスワード{d.has_auth_key ? "（登録済み）" : ""}</label>
                <input id="snmp-authkey" type="password" autoComplete="off" value={authKey} disabled={!authProto} onChange={(e) => setAuthKey(e.target.value)} />
              </div>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <div className="form-group" style={{ width: 140 }}>
                <label className="form-label" htmlFor="snmp-priv">暗号化</label>
                <select id="snmp-priv" value={privProto} onChange={(e) => setPrivProto(e.target.value)}>
                  <option value="AES">AES-128</option><option value="AES256">AES-256</option><option value="DES">DES</option><option value="">なし</option>
                </select>
              </div>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label" htmlFor="snmp-privkey">暗号化パスワード{d.has_priv_key ? "（登録済み）" : ""}</label>
                <input id="snmp-privkey" type="password" autoComplete="off" value={privKey} disabled={!privProto} onChange={(e) => setPrivKey(e.target.value)} />
              </div>
            </div>
          </>
        )}
        {error && <p className="form-error">{error}</p>}
        {test && <p className="ntf-ok">{test}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
          <button className="btn" onClick={() => save(true)} disabled={busy}>保存して接続確認</button>
          <button className="btn btn-primary" onClick={() => save(false)} disabled={busy}>保存</button>
        </div>
      </div>
    </div>
  );
}

function SnmpTab({ devices, reload }: { devices: SnmpDevice[]; reload: () => void }) {
  const { can } = useAuth();
  const canEdit = can(PERM.DEVICE_WRITE);
  const [editing, setEditing] = useState<SnmpDevice | null>(null);
  const [onlyConfigured, setOnlyConfigured] = useState(false);
  const [error, setError] = useState("");
  const remove = async (d: SnmpDevice) => {
    if (!window.confirm(`${d.name} の SNMP 設定と帯域の記録を削除しますか？`)) return;
    try {
      await api.delete(`/monitoring/snmp/${d.device_id}`);
      reload();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const rows = devices.filter((d) => !onlyConfigured || d.configured);
  return (
    <>
      <div className="mon-bar-row">
        <span className="topo-muted topo-small">帯域は SNMP（IF-MIB の 64bit カウンタ）で定期的に取得します。機器側で SNMP を有効にし、サーバーから UDP で届くようにしてください。</span>
        <span style={{ flex: 1 }} />
        <label className="form-check"><input type="checkbox" checked={onlyConfigured} onChange={(e) => setOnlyConfigured(e.target.checked)} />設定済みだけ</label>
      </div>
      {error && <p className="form-error">{error}</p>}
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>機器</th><th>グループ</th><th>SNMP</th><th>インタフェース</th><th>最終取得</th><th>状態</th>{canEdit && <th />}</tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.device_id}>
                <td className="nowrap"><b>{d.name}</b><div className="topo-muted topo-small mono">{d.hostname}</div></td>
                <td className="topo-small">{d.group_name ?? "未分類"}</td>
                <td className="nowrap">
                  {d.configured ? (
                    <>{d.version === "3" ? `v3（${d.v3_user}）` : "v2c"}{!d.enabled && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>停止中</span>}</>
                  ) : <span className="topo-muted">未設定</span>}
                </td>
                <td>{d.interface_count || "—"}</td>
                <td className="nowrap topo-small">{fmtDate(d.last_polled_at)}</td>
                <td className="topo-small">
                  {!d.configured ? "" : d.last_error ? <span className="mon-err" title={d.last_error}>失敗: {d.last_error}</span>
                    : d.last_polled_at ? <span className="badge badge-success">OK</span> : <span className="topo-muted">次の取得を待っています</span>}
                </td>
                {canEdit && (
                  <td className="nowrap">
                    <button className="btn btn-sm" onClick={() => setEditing(d)}>{d.configured ? "編集" : "設定"}</button>
                    {d.configured && <button className="btn btn-sm btn-danger" style={{ marginLeft: 6 }} onClick={() => remove(d)}>削除</button>}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing && <SnmpModal d={editing} onClose={() => setEditing(null)} onSaved={reload} />}
    </>
  );
}

// ================================================================ ページ

type Tab = "interfaces" | "fw" | "snmp";

export default function MonitoringPage() {
  const [tab, setTab] = useState<Tab>("interfaces");
  const [devices, setDevices] = useState<SnmpDevice[]>([]);
  const [error, setError] = useState("");
  const reload = useCallback(() => {
    api.get<SnmpDevice[]>("/monitoring/snmp").then((r) => setDevices(r.data)).catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(reload, [reload]);
  const configured = useMemo(() => devices.filter((d) => d.configured).length, [devices]);
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">モニタリング</span>
        <span className="badge badge-warning" title="試験導入中の機能です">試験導入</span>
        <span style={{ flex: 1 }} />
        <div className="seg-tabs" role="tablist">
          {([["interfaces", "インタフェース"], ["fw", "FW ルール"], ["snmp", `SNMP 設定（${configured}）`]] as [Tab, string][]).map(([k, l]) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`seg-tab${tab === k ? " active" : ""}`} onClick={() => setTab(k)}>{l}</button>
          ))}
        </div>
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        <Fragment key={tab}>
          {tab === "interfaces" && <InterfacesTab devices={devices} />}
          {tab === "fw" && <FwTab />}
          {tab === "snmp" && <SnmpTab devices={devices} reload={reload} />}
        </Fragment>
      </div>
    </div>
  );
}
