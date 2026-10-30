import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage, getToken, redirectToLogin, wsUrl } from "../api/client";
import { PERM, useAuth } from "../auth";

/**
 * Ping監視（deadman 風）
 * - 登録済みの機器と、ここで追加した IP / ホスト名に一定間隔で PING して、応答時間と損失をリアルタイムに表示する
 * - PING はサーバーから送る。統計（損失率・平均など）はこの画面で集計し、画面を閉じると消える
 */

interface Group { id: string; name: string; color: string | null; }
interface Target {
  key: string;
  kind: "device" | "custom";
  id: string;
  name: string;
  address: string;
  group_id: string | null;
  description: string | null;
  is_active: boolean;
  platform: string | null;
}
interface TargetList { groups: Group[]; targets: Target[]; max_targets: number; }
interface Resolved { key: string; name: string; address: string; ip: string | null; error: string | null; }

interface Stat {
  sent: number;
  recv: number;
  last: number | null | undefined; // undefined: まだ送っていない / null: 応答なし
  sum: number;
  min: number | null;
  max: number | null;
  history: (number | null)[];
  lastOkAt: number | null;
  lossStreak: number;
}

const HISTORY = 60;
const INTERVALS = [1, 2, 5, 10];
const UNGROUPED = "__none__";
const LS_KEYS = "ncm.ping.keys";
const LS_INTERVAL = "ncm.ping.interval";

const newStat = (): Stat => ({ sent: 0, recv: 0, last: undefined, sum: 0, min: null, max: null, history: [], lastOkAt: null, lossStreak: 0 });

function loadJson<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}
function saveJson(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* 保存できなくても動作には影響しない */
  }
}

const fmtMs = (v: number | null | undefined) => (v === null || v === undefined ? "—" : v < 10 ? v.toFixed(2) : v.toFixed(1));

function ago(ts: number | null, now: number): string {
  if (ts === null) return "—";
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}秒前`;
  if (s < 3600) return `${Math.floor(s / 60)}分前`;
  return `${Math.floor(s / 3600)}時間前`;
}

type State = "idle" | "ok" | "warn" | "down" | "error";
function stateOf(st: Stat | undefined, resolveError: string | null | undefined): State {
  if (resolveError) return "error";
  if (!st || st.last === undefined) return "idle";
  if (st.last === null) return "down";
  return st.history.includes(null) ? "warn" : "ok";
}
const STATE_LABEL: Record<State, string> = { idle: "未測定", ok: "正常", warn: "損失あり", down: "応答なし", error: "名前解決失敗" };

/** 直近の結果を棒で表示（高さ＝応答時間、赤＝応答なし） */
function HistoryBar({ history }: { history: (number | null)[] }) {
  const max = Math.max(1, ...history.filter((v): v is number => v !== null));
  const pad = HISTORY - history.length;
  return (
    <div className="ping-hist" aria-hidden>
      {Array.from({ length: pad }, (_, i) => <span key={`p${i}`} className="ping-bar empty" />)}
      {history.map((v, i) => (
        <span
          key={i}
          className={`ping-bar ${v === null ? "lost" : ""}`}
          style={{ height: v === null ? "100%" : `${Math.max(8, Math.sqrt(v / max) * 100)}%` }}
          title={v === null ? "応答なし" : `${fmtMs(v)} ms`}
        />
      ))}
    </div>
  );
}

function TargetModal({
  groups, target, onClose, onSaved,
}: { groups: Group[]; target: Target | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(target?.name ?? "");
  const [address, setAddress] = useState(target?.address ?? "");
  const [groupId, setGroupId] = useState(target?.group_id ?? "");
  const [description, setDescription] = useState(target?.description ?? "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError("");
    const body = { name, address, group_id: groupId || null, description: description || null };
    try {
      if (target) await api.put(`/ping/targets/${target.id}`, body);
      else await api.post("/ping/targets", body);
      onSaved();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{target ? "監視対象の編集" : "監視対象の追加"}</p>
        <div className="form-group">
          <label className="form-label">名前</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="例: 本社 既定GW" autoFocus />
        </div>
        <div className="form-group">
          <label className="form-label">IP アドレス / ホスト名</label>
          <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="例: 192.168.1.1" />
        </div>
        <div className="form-group">
          <label className="form-label">表示するグループ</label>
          <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">（その他）</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">説明</label>
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={busy || !name.trim() || !address.trim()}>保存</button>
        </div>
      </div>
    </div>
  );
}

/** 追加IPの一覧（追加・編集・削除） */
function CustomManager({
  groups, targets, onClose, onChanged,
}: { groups: Group[]; targets: Target[]; onClose: () => void; onChanged: () => void }) {
  const [editing, setEditing] = useState<Target | null | "new">(null);
  const [error, setError] = useState("");
  const groupName = (id: string | null) => groups.find((g) => g.id === id)?.name ?? "その他";

  const remove = async (t: Target) => {
    if (!confirm(`「${t.name}」(${t.address}) を削除しますか？`)) return;
    try {
      await api.delete(`/ping/targets/${t.id}`);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 720, maxWidth: "95vw" }} onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">追加した監視対象（登録機器以外の IP）</p>
        {editing && (
          <TargetModal
            groups={groups}
            target={editing === "new" ? null : editing}
            onClose={() => setEditing(null)}
            onSaved={() => { setEditing(null); onChanged(); }}
          />
        )}
        <div className="table-scroll" style={{ maxHeight: "55vh", overflowY: "auto" }}>
          <table className="data-table">
            <thead><tr><th>名前</th><th>アドレス</th><th>グループ</th><th>説明</th><th /></tr></thead>
            <tbody>
              {targets.length === 0 && (
                <tr><td colSpan={5} style={{ color: "var(--color-muted)" }}>まだありません。「追加」から IP アドレスやホスト名を登録できます</td></tr>
              )}
              {targets.map((t) => (
                <tr key={t.key}>
                  <td>{t.name}</td>
                  <td className="mono">{t.address}</td>
                  <td>{groupName(t.group_id)}</td>
                  <td style={{ color: "var(--color-muted)" }}>{t.description}</td>
                  <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                    <button className="btn btn-sm" onClick={() => setEditing(t)}>編集</button>{" "}
                    <button className="btn btn-sm btn-danger" onClick={() => remove(t)}>削除</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
          <button className="btn btn-primary" onClick={() => setEditing("new")}>＋ 追加</button>
        </div>
      </div>
    </div>
  );
}

/** 監視対象の選択 */
function SelectModal({
  data, selected, onClose, onApply,
}: { data: TargetList; selected: Set<string>; onClose: () => void; onApply: (keys: Set<string>) => void }) {
  const [sel, setSel] = useState(() => new Set(selected));
  const [q, setQ] = useState("");
  const sections = useMemo(() => groupTargets(data, data.targets), [data]);
  const match = (t: Target) => !q || `${t.name} ${t.address}`.toLowerCase().includes(q.toLowerCase());

  const toggle = (keys: string[], on: boolean) =>
    setSel((s) => {
      const n = new Set(s);
      keys.forEach((k) => (on ? n.add(k) : n.delete(k)));
      return n;
    });
  const all = data.targets.map((t) => t.key);
  const activeOnly = data.targets.filter((t) => t.is_active).map((t) => t.key);
  const over = sel.size > data.max_targets;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 640, maxWidth: "95vw" }} onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">監視する対象を選ぶ</p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          <input placeholder="名前・アドレスで絞り込み" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
          <button className="btn btn-sm" onClick={() => setSel(new Set(all))}>すべて</button>
          <button className="btn btn-sm" onClick={() => setSel(new Set(activeOnly))}>有効なものだけ</button>
          <button className="btn btn-sm" onClick={() => setSel(new Set())}>解除</button>
        </div>
        <div style={{ maxHeight: "55vh", overflowY: "auto", border: "1px solid var(--color-border)", borderRadius: "var(--radius)" }}>
          {sections.map((sec) => {
            const items = sec.items.filter(match);
            if (!items.length) return null;
            const keys = items.map((t) => t.key);
            const checked = keys.every((k) => sel.has(k));
            return (
              <div key={sec.id}>
                <label className="ping-sel-head">
                  <input type="checkbox" checked={checked} onChange={(e) => toggle(keys, e.target.checked)} />
                  <span className="ping-dot-group" style={{ background: sec.color ?? "var(--color-muted)" }} />
                  {sec.name}
                  <span style={{ color: "var(--color-muted)", fontWeight: 400 }}>（{keys.filter((k) => sel.has(k)).length}/{keys.length}）</span>
                </label>
                {items.map((t) => (
                  <label key={t.key} className="ping-sel-item">
                    <input type="checkbox" checked={sel.has(t.key)} onChange={(e) => toggle([t.key], e.target.checked)} />
                    <span>{t.name}</span>
                    <span className="mono" style={{ color: "var(--color-muted)" }}>{t.address}</span>
                    {t.kind === "custom" && <span className="badge badge-neutral">追加IP</span>}
                    {!t.is_active && <span className="badge badge-warning">無効</span>}
                  </label>
                ))}
              </div>
            );
          })}
        </div>
        <p style={{ marginTop: 8, fontSize: 12, color: over ? "var(--color-danger)" : "var(--color-muted)" }}>
          {sel.size} 件を選択中（同時に監視できるのは {data.max_targets} 件まで）
        </p>
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" disabled={over} onClick={() => onApply(sel)}>決定</button>
        </div>
      </div>
    </div>
  );
}

interface Section { id: string; name: string; color: string | null; items: Target[]; }
function groupTargets(data: TargetList, targets: Target[]): Section[] {
  const by = new Map<string, Target[]>();
  for (const t of targets) {
    const gid = t.group_id && data.groups.some((g) => g.id === t.group_id) ? t.group_id : UNGROUPED;
    by.set(gid, [...(by.get(gid) ?? []), t]);
  }
  const sections: Section[] = data.groups
    .filter((g) => by.has(g.id))
    .map((g) => ({ id: g.id, name: g.name, color: g.color, items: by.get(g.id)! }));
  if (by.has(UNGROUPED)) sections.push({ id: UNGROUPED, name: "その他（未分類）", color: null, items: by.get(UNGROUPED)! });
  // 登録機器を先に、追加IPを後に並べる
  sections.forEach((s) => s.items.sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name, "ja") : a.kind === "device" ? -1 : 1)));
  return sections;
}

export default function PingPage() {
  const { can } = useAuth();
  const canWrite = can(PERM.PING_WRITE);
  const [data, setData] = useState<TargetList | null>(null);
  const [loadError, setLoadError] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [interval, setIntervalSec] = useState<number>(() => loadJson(LS_INTERVAL, 1));
  const [running, setRunning] = useState(false);
  const [connState, setConnState] = useState<"idle" | "connecting" | "running" | "reconnecting">("idle");
  const [error, setError] = useState("");
  const [resolved, setResolved] = useState<Record<string, Resolved>>({});
  const [showSelect, setShowSelect] = useState(false);
  const [showManage, setShowManage] = useState(false);
  const [onlyProblems, setOnlyProblems] = useState(false);
  const [, setTick] = useState(0);
  const [now, setNow] = useState(Date.now());

  const stats = useRef<Map<string, Stat>>(new Map());
  const wsRef = useRef<WebSocket | null>(null);
  const runningRef = useRef(false);
  const reconnectTimer = useRef<number | null>(null);
  const startMsg = useRef<{ keys: string[]; interval: number } | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get<TargetList>("/ping/targets");
      setData(r.data);
      setLoadError("");
      const valid = new Set(r.data.targets.map((t) => t.key));
      setSelected((cur) => {
        // 初回: 保存した選択（無ければ有効な機器と追加IPすべて）
        const base: string[] = cur.size ? [...cur] : loadJson<string[] | null>(LS_KEYS, null) ?? r.data.targets.filter((t) => t.is_active).map((t) => t.key);
        return new Set(base.filter((k) => valid.has(k)).slice(0, r.data.max_targets));
      });
    } catch (e) {
      setLoadError(errorMessage(e));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // 「最終応答」の経過時間を更新する
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  const connect = useCallback(() => {
    const token = getToken();
    if (!token) return redirectToLogin();
    if (!startMsg.current) return;
    wsRef.current?.close();
    const ws = new WebSocket(wsUrl("/ping/ws"));
    wsRef.current = ws;
    setConnState((s) => (s === "reconnecting" ? s : "connecting"));

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "auth", token }));
      ws.send(JSON.stringify({ type: "start", ...startMsg.current }));
    };
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "targets") {
        const m: Record<string, Resolved> = {};
        (msg.items as Resolved[]).forEach((it) => (m[it.key] = it));
        setResolved(m);
        setConnState("running");
        setError("");
      } else if (msg.type === "tick") {
        const ts = Date.now();
        for (const [key, rtt] of Object.entries(msg.results as Record<string, number | null>)) {
          let st = stats.current.get(key);
          if (!st) stats.current.set(key, (st = newStat()));
          st.sent += 1;
          st.last = rtt;
          if (rtt === null) {
            st.lossStreak += 1;
          } else {
            st.recv += 1;
            st.sum += rtt;
            st.min = st.min === null ? rtt : Math.min(st.min, rtt);
            st.max = st.max === null ? rtt : Math.max(st.max, rtt);
            st.lastOkAt = ts;
            st.lossStreak = 0;
          }
          st.history.push(rtt);
          if (st.history.length > HISTORY) st.history.shift();
        }
        setTick((n) => n + 1);
      } else if (msg.type === "error") {
        setError(msg.message);
        runningRef.current = false;
        setRunning(false);
        setConnState("idle");
        ws.close();
      }
    };
    ws.onclose = (e) => {
      if (wsRef.current !== ws) return;
      wsRef.current = null;
      if (e.code === 4401) return redirectToLogin();
      if (e.code === 4403) {
        setError("Ping監視を利用する権限がありません");
        runningRef.current = false;
        setRunning(false);
        setConnState("idle");
        return;
      }
      if (runningRef.current) {
        // サーバーの再起動などで切れたら、少し待って自動で再接続する（統計はそのまま続ける）
        setConnState("reconnecting");
        reconnectTimer.current = window.setTimeout(connect, 3000);
      } else {
        setConnState("idle");
      }
    };
  }, []);

  const stopWs = () => {
    if (reconnectTimer.current !== null) window.clearTimeout(reconnectTimer.current);
    reconnectTimer.current = null;
    const ws = wsRef.current;
    wsRef.current = null;
    if (ws) {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "stop" }));
      ws.close();
    }
  };

  useEffect(() => () => { runningRef.current = false; stopWs(); }, []);

  const start = (keys: Set<string> = selected, sec: number = interval) => {
    startMsg.current = { keys: [...keys], interval: sec };
    runningRef.current = true;
    setRunning(true);
    setError("");
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      // 接続中なら対象・間隔だけ切り替える
      ws.send(JSON.stringify({ type: "start", ...startMsg.current }));
    } else {
      connect();
    }
  };

  const stop = () => {
    runningRef.current = false;
    setRunning(false);
    setConnState("idle");
    stopWs();
  };

  const resetStats = () => {
    stats.current = new Map();
    setTick((n) => n + 1);
  };

  const applySelection = (keys: Set<string>) => {
    setSelected(keys);
    saveJson(LS_KEYS, [...keys]);
    setShowSelect(false);
    if (runningRef.current) start(keys);
  };

  const changeInterval = (sec: number) => {
    setIntervalSec(sec);
    saveJson(LS_INTERVAL, sec);
    if (runningRef.current) start(selected, sec);
  };

  if (!data) {
    return (
      <div className="page">
        <div className="page-header"><span className="page-title">Ping監視</span></div>
        <div className="page-body">{loadError ? <p className="form-error">{loadError}</p> : <p style={{ color: "var(--color-muted)" }}>読み込み中...</p>}</div>
      </div>
    );
  }

  const shown = data.targets.filter((t) => selected.has(t.key));
  const counts: Record<State, number> = { idle: 0, ok: 0, warn: 0, down: 0, error: 0 };
  shown.forEach((t) => (counts[stateOf(stats.current.get(t.key), resolved[t.key]?.error)] += 1));
  const visible = onlyProblems
    ? shown.filter((t) => ["warn", "down", "error"].includes(stateOf(stats.current.get(t.key), resolved[t.key]?.error)))
    : shown;
  const sections = groupTargets(data, visible);
  const customs = data.targets.filter((t) => t.kind === "custom");

  return (
    <div className="page">
      {showSelect && <SelectModal data={data} selected={selected} onClose={() => setShowSelect(false)} onApply={applySelection} />}
      {showManage && <CustomManager groups={data.groups} targets={customs} onClose={() => setShowManage(false)} onChanged={load} />}
      <div className="page-header">
        <span className="page-title">Ping監視</span>
        <span className={`badge ${connState === "running" ? "badge-success" : connState === "idle" ? "badge-neutral" : "badge-warning"}`}>
          {{ idle: "停止中", connecting: "接続中...", running: "監視中", reconnecting: "再接続中..." }[connState]}
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <label style={{ fontSize: 12, color: "var(--color-muted)" }}>間隔</label>
          <select value={interval} onChange={(e) => changeInterval(Number(e.target.value))} style={{ width: 80 }}>
            {INTERVALS.map((s) => <option key={s} value={s}>{s} 秒</option>)}
          </select>
          <button className="btn" onClick={() => setShowSelect(true)}>対象を選ぶ（{selected.size}）</button>
          {canWrite && <button className="btn" onClick={() => setShowManage(true)}>IP を追加・管理</button>}
          <button className="btn" onClick={resetStats}>統計リセット</button>
          {running ? (
            <button className="btn btn-danger" onClick={stop}>■ 停止</button>
          ) : (
            <button className="btn btn-primary" onClick={() => start()} disabled={selected.size === 0}>▶ 開始</button>
          )}
        </div>
      </div>
      <div className="page-body">
        {error && <div className="ping-alert">{error}</div>}
        <div className="ping-summary">
          <span><i className="ping-dot ok" />正常 {counts.ok}</span>
          <span><i className="ping-dot warn" />損失あり {counts.warn}</span>
          <span><i className="ping-dot down" />応答なし {counts.down}</span>
          {counts.error > 0 && <span><i className="ping-dot error" />名前解決失敗 {counts.error}</span>}
          <span style={{ color: "var(--color-muted)" }}>／ 監視対象 {shown.length}</span>
          <label style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center", fontSize: 12, whiteSpace: "nowrap" }}>
            <input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} />
            異常のみ表示
          </label>
        </div>

        {shown.length === 0 && (
          <div className="card" style={{ color: "var(--color-muted)" }}>
            監視する対象がありません。「対象を選ぶ」から機器や IP を選んでください。
            {canWrite && " 登録機器以外の IP は「IP を追加・管理」から追加できます。"}
          </div>
        )}
        {shown.length > 0 && visible.length === 0 && <div className="card" style={{ color: "var(--color-muted)" }}>異常のある対象はありません</div>}

        {sections.map((sec) => (
          <div key={sec.id} className="ping-section">
            <div className="ping-section-head">
              <span className="ping-dot-group" style={{ background: sec.color ?? "var(--color-muted)" }} />
              {sec.name}
              <span style={{ color: "var(--color-muted)", fontWeight: 400 }}>{sec.items.length}</span>
            </div>
            <div className="table-scroll">
              <table className="data-table ping-table">
                {/* グループごとの表で列の位置をそろえる */}
                <colgroup>
                  <col style={{ width: 40 }} />
                  <col style={{ width: "18%" }} />
                  <col style={{ width: "24%" }} />
                  <col style={{ width: 84 }} />
                  <col style={{ width: 84 }} />
                  <col style={{ width: 104 }} />
                  <col style={{ width: 64 }} />
                  <col style={{ width: 112 }} />
                  <col style={{ width: 80 }} />
                  <col style={{ width: 256 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th />
                    <th>名前</th>
                    <th>アドレス</th>
                    <th className="num">損失率</th>
                    <th className="num">送信/受信</th>
                    <th className="num">最新 (ms)</th>
                    <th className="num">平均</th>
                    <th className="num">最小/最大</th>
                    <th>最終応答</th>
                    <th>履歴（直近{HISTORY}回）</th>
                  </tr>
                </thead>
                <tbody>
                  {sec.items.map((t) => {
                    const st = stats.current.get(t.key);
                    const res = resolved[t.key];
                    const state = stateOf(st, res?.error);
                    const loss = st && st.sent ? ((st.sent - st.recv) / st.sent) * 100 : null;
                    return (
                      <tr key={t.key} className={`ping-row ${state}`}>
                        <td className="ping-state"><i className={`ping-dot ${state}`} title={STATE_LABEL[state]} /></td>
                        <td>
                          {t.name}
                          {t.kind === "custom" && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>追加IP</span>}
                          {!t.is_active && <span className="badge badge-warning" style={{ marginLeft: 6 }}>無効</span>}
                        </td>
                        <td className="mono" title={res?.error ? `${t.address}: ${res.error}` : t.address}>
                          {t.address}
                          {res?.ip && res.ip !== t.address && <span style={{ color: "var(--color-muted)" }}> ({res.ip})</span>}
                          {res?.error && <span style={{ color: "var(--color-danger)" }}> {res.error}</span>}
                        </td>
                        <td className="num" style={{ color: loss ? "var(--color-danger)" : undefined }}>{loss === null ? "—" : `${loss.toFixed(1)}%`}</td>
                        <td className="num">{st ? `${st.sent}/${st.recv}` : "—"}</td>
                        <td className="num" style={{ color: st?.last === null ? "var(--color-danger)" : undefined }}>
                          {st?.last === null ? `× ${st.lossStreak}回連続` : fmtMs(st?.last)}
                        </td>
                        <td className="num">{st && st.recv ? fmtMs(st.sum / st.recv) : "—"}</td>
                        <td className="num">{st && st.min !== null ? `${fmtMs(st.min)} / ${fmtMs(st.max)}` : "—"}</td>
                        <td style={{ whiteSpace: "nowrap", color: "var(--color-muted)" }}>{st ? ago(st.lastOkAt, now) : "—"}</td>
                        <td><HistoryBar history={st?.history ?? []} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ))}
        <p style={{ marginTop: 12, fontSize: 12, color: "var(--color-muted)" }}>
          PING はサーバーから送信します（踏み台の先にある機器など、サーバーから直接届かない宛先は「応答なし」になります）。
          統計はこの画面で集計しており、画面を離れるとリセットされます。
        </p>
      </div>
    </div>
  );
}
