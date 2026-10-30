/** 監査ログ（管理者のみ）: 操作履歴とターミナルの記録 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { api, errorMessage } from "../api/client";

interface AuditLog {
  id: string;
  at: string;
  username: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  target_name: string | null;
  detail: string | null;
  ip: string | null;
  success: boolean;
}

interface TerminalSessionItem {
  id: string;
  username: string | null;
  device_id: string | null;
  device_name: string | null;
  device_host: string | null;
  via: string | null;
  ip: string | null;
  started_at: string;
  ended_at: string | null;
  end_reason: string | null;
  bytes_out: number;
  truncated: boolean;
  has_recording: boolean;
}

interface Page<T> { items: T[]; total: number; }

const PAGE_SIZE = 100;

// 操作の分類（API の action の前方一致で絞り込む）
const CATEGORIES: [string, string][] = [
  ["", "すべて"],
  ["auth.", "ログイン・パスワード"],
  ["user.", "ユーザー管理"],
  ["device.", "機器"],
  ["jump_host.", "踏み台"],
  ["schedule.", "スケジュール"],
  ["collect.", "収集"],
  ["terminal.", "ターミナル"],
  ["topology.", "構成図"],
  ["compliance.", "コンプライアンス"],
  ["audit.", "監査ログの閲覧"],
];

const FIELD_LABELS: Record<string, string> = {
  hostname: "ホスト", platform: "プラットフォーム", port: "ポート", username: "ユーザー名",
  password: "パスワード", private_key: "秘密鍵", key_passphrase: "パスフレーズ", enable_secret: "Enable",
  description: "説明", is_active: "有効", jump_host_id: "踏み台", read_timeout: "応答待ち時間",
  clear_password: "パスワード削除", clear_private_key: "秘密鍵削除", clear_enable_secret: "Enable削除",
  auth: "認証方式", role: "ロール", changes: "変更", changed: "変更", reason: "理由", error: "エラー",
  session_id: "セッション", seconds: "接続時間（秒）", via: "踏み台", cron: "cron", target: "対象",
  copy_from: "複製元", version: "版", name: "名前", severity: "重要度", pattern: "パターン", platforms: "対象機種",
  match_type: "一致方法", expect: "期待", scope: "範囲", section_pattern: "セクション", enabled: "有効",
  devices: "機器数", rules: "ルール数", checked: "検査件数",
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fmtValue(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "はい" : "いいえ";
  if (Array.isArray(v)) return v.length ? v.map(fmtValue).join(", ") : "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function DetailText({ detail }: { detail: string | null }) {
  if (!detail) return <span className="topo-muted">—</span>;
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(detail);
  } catch {
    return <span>{detail}</span>;
  }
  return (
    <span className="audit-detail">
      {Object.entries(obj).map(([k, v]) => (
        <span key={k}><span className="topo-muted">{FIELD_LABELS[k] ?? k}:</span> {fmtValue(v)}</span>
      ))}
    </span>
  );
}

function duration(a: string, b: string | null): string {
  if (!b) return "—";
  const s = Math.max(0, Math.round((new Date(b + "Z").getTime() - new Date(a + "Z").getTime()) / 1000));
  if (s < 60) return `${s}秒`;
  if (s < 3600) return `${Math.floor(s / 60)}分${s % 60}秒`;
  return `${Math.floor(s / 3600)}時間${Math.floor((s % 3600) / 60)}分`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Pager({ total, offset, onChange }: { total: number; offset: number; onChange: (o: number) => void }) {
  if (total <= PAGE_SIZE) return <span className="topo-muted topo-small">{total} 件</span>;
  return (
    <div className="audit-pager">
      <span className="topo-muted topo-small">
        {total} 件中 {offset + 1}–{Math.min(offset + PAGE_SIZE, total)}
      </span>
      <button className="btn" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - PAGE_SIZE))}>前へ</button>
      <button className="btn" disabled={offset + PAGE_SIZE >= total} onClick={() => onChange(offset + PAGE_SIZE)}>次へ</button>
    </div>
  );
}

// ============================================================ 操作履歴

function LogsTab({ actions }: { actions: Record<string, string> }) {
  const [username, setUsername] = useState("");
  const [category, setCategory] = useState("");
  const [q, setQ] = useState("");
  const [failedOnly, setFailedOnly] = useState(false);
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<AuditLog> | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async (o: number) => {
    setError("");
    try {
      const r = await api.get<Page<AuditLog>>("/audit/logs", {
        params: {
          username: username.trim() || undefined, action: category || undefined, q: q.trim() || undefined,
          failed_only: failedOnly || undefined,
          // 日付はローカル時刻の 0:00 として扱い、UTC に変換して渡す
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
  }, [username, category, q, failedOnly, since, until]);

  useEffect(() => {
    load(0);
    // 絞り込みを変えたら先頭から
  }, [category, failedOnly, since, until]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <form className="audit-filters" onSubmit={(e) => { e.preventDefault(); load(0); }}>
        <label className="audit-field">
          <span className="form-label">操作</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            {CATEGORIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="audit-field">
          <span className="form-label">ユーザー</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="完全一致" />
        </label>
        <label className="audit-field audit-field-wide">
          <span className="form-label">キーワード（対象・詳細・IP）</span>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="例: Core-SW01 / 10.20.0." />
        </label>
        <label className="audit-field">
          <span className="form-label">期間（から）</span>
          <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
        </label>
        <label className="audit-field">
          <span className="form-label">期間（まで）</span>
          <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
        </label>
        <label className="form-check audit-check">
          <input type="checkbox" checked={failedOnly} onChange={(e) => setFailedOnly(e.target.checked)} />
          失敗のみ
        </label>
        <button className="btn btn-primary" type="submit">検索</button>
      </form>
      {error && <p className="form-error">{error}</p>}
      {page && (
        <>
          <div className="audit-bar"><Pager total={page.total} offset={offset} onChange={load} /></div>
          <div className="table-scroll">
            <table className="data-table audit-table">
              <thead>
                <tr><th>日時</th><th>ユーザー</th><th>操作</th><th>対象</th><th>詳細</th><th>IP</th><th>結果</th></tr>
              </thead>
              <tbody>
                {page.items.map((x) => (
                  <tr key={x.id}>
                    <td className="nowrap mono topo-small">{fmtDate(x.at)}</td>
                    <td className="nowrap">{x.username ?? "—"}</td>
                    <td className="nowrap">{actions[x.action] ?? x.action}</td>
                    <td>{x.target_name ?? "—"}</td>
                    <td><DetailText detail={x.detail} /></td>
                    <td className="nowrap mono topo-small">{x.ip ?? "—"}</td>
                    <td>{x.success ? <span className="badge badge-success">成功</span> : <span className="badge badge-danger">失敗</span>}</td>
                  </tr>
                ))}
                {!page.items.length && (
                  <tr><td colSpan={7} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>該当する記録はありません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

// ============================================================ ターミナルの記録

type CastEvent = [number, string, string];

function parseCast(text: string): { header: { width: number; height: number; title?: string }; events: CastEvent[] } {
  const lines = text.split("\n").filter((l) => l.trim());
  const header = JSON.parse(lines[0]);
  const events: CastEvent[] = [];
  for (const l of lines.slice(1)) {
    try {
      events.push(JSON.parse(l));
    } catch {
      /* 途中で切れた行は無視 */
    }
  }
  return { header, events };
}

const MAX_IDLE = 1.0; // 「待ち時間を短縮」時の最大の待ち（秒）

function fmtClock(sec: number): string {
  const s = Math.floor(sec);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function Player({ session, onClose }: { session: TerminalSessionItem; onClose: () => void }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const castRef = useRef<{ events: CastEvent[]; text: string } | null>(null);
  const idxRef = useRef(0);
  const timerRef = useRef<number | undefined>(undefined);
  const [error, setError] = useState("");
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(2);
  const [skipIdle, setSkipIdle] = useState(true);
  const [pos, setPos] = useState(0);
  const [total, setTotal] = useState(0);
  const [done, setDone] = useState(false);
  const speedRef = useRef(speed);
  const skipRef = useRef(skipIdle);
  speedRef.current = speed;
  skipRef.current = skipIdle;

  const stop = () => {
    window.clearTimeout(timerRef.current);
    setPlaying(false);
  };

  const apply = (ev: CastEvent) => {
    const term = termRef.current;
    if (!term) return;
    if (ev[1] === "o") term.write(ev[2]);
    else if (ev[1] === "r") {
      const [c, r] = ev[2].split("x").map(Number);
      if (c > 0 && r > 0) term.resize(c, r);
    }
  };

  const step = () => {
    const cast = castRef.current;
    if (!cast) return;
    const i = idxRef.current;
    if (i >= cast.events.length) {
      setPlaying(false);
      setDone(true);
      return;
    }
    apply(cast.events[i]);
    setPos(cast.events[i][0]);
    idxRef.current = i + 1;
    if (i + 1 >= cast.events.length) {
      setPlaying(false);
      setDone(true);
      return;
    }
    let wait = cast.events[i + 1][0] - cast.events[i][0];
    if (skipRef.current) wait = Math.min(wait, MAX_IDLE);
    timerRef.current = window.setTimeout(step, (wait * 1000) / speedRef.current);
  };

  const play = () => {
    if (done) restart(false);
    setPlaying(true);
    step();
  };

  const restart = (autoplay = true) => {
    stop();
    termRef.current?.reset();
    const cast = castRef.current;
    idxRef.current = 0;
    setPos(0);
    setDone(false);
    if (cast && autoplay) {
      setPlaying(true);
      timerRef.current = window.setTimeout(step, 50);
    }
  };

  const showAll = () => {
    stop();
    const cast = castRef.current;
    if (!cast) return;
    for (let i = idxRef.current; i < cast.events.length; i++) apply(cast.events[i]);
    idxRef.current = cast.events.length;
    setPos(total);
    setDone(true);
  };

  const download = () => {
    const cast = castRef.current;
    if (!cast) return;
    const url = URL.createObjectURL(new Blob([cast.text], { type: "application/x-asciicast" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `terminal_${session.device_name ?? "device"}_${session.started_at.slice(0, 19).replace(/[:T]/g, "-")}.cast`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
  };

  useEffect(() => {
    let disposed = false;
    let term: Terminal | null = null;
    // StrictMode の二重マウント対策で生成を1フレーム遅らせる（TerminalPage と同じ）
    const raf = requestAnimationFrame(async () => {
      try {
        const r = await api.get<string>(`/audit/terminal-sessions/${session.id}/recording`, {
          responseType: "text", transformResponse: (d) => d,
        });
        if (disposed || !mountRef.current) return;
        const parsed = parseCast(r.data);
        castRef.current = { events: parsed.events, text: r.data };
        setTotal(parsed.events.length ? parsed.events[parsed.events.length - 1][0] : 0);
        term = new Terminal({
          cols: parsed.header.width || 120, rows: parsed.header.height || 40,
          theme: { background: "#0d1117", foreground: "#c9d1d9" },
          fontFamily: '"JetBrains Mono", "Fira Code", monospace', fontSize: 12, scrollback: 5000,
          disableStdin: true, cursorBlink: false,
        });
        term.open(mountRef.current);
        termRef.current = term;
        setPlaying(true);
        timerRef.current = window.setTimeout(step, 100);
      } catch (e) {
        if (!disposed) setError(errorMessage(e));
      }
    });
    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      window.clearTimeout(timerRef.current);
      term?.dispose();
      termRef.current = null;
    };
  }, [session.id]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal audit-player" onClick={(e) => e.stopPropagation()}>
        <div className="audit-player-head">
          <div>
            <p className="modal-title" style={{ marginBottom: 2 }}>
              ターミナルの記録: {session.username} → {session.device_name}（{session.device_host}）
            </p>
            <p className="topo-muted topo-small">
              {fmtDate(session.started_at)} 〜 {session.ended_at ? fmtDate(session.ended_at) : "（終了時刻なし）"}
              {session.truncated ? " ・上限に達したため途中までの記録です" : ""}
            </p>
          </div>
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
        {error ? <p className="form-error">{error}</p> : <div ref={mountRef} className="audit-player-term" />}
        <div className="audit-player-controls">
          {playing ? (
            <button className="btn" onClick={stop}>⏸ 一時停止</button>
          ) : (
            <button className="btn btn-primary" onClick={play} disabled={!!error}>▶ {done ? "もう一度" : "再生"}</button>
          )}
          <button className="btn" onClick={() => restart()} disabled={!!error}>最初から</button>
          <button className="btn" onClick={showAll} disabled={!!error || done}>最後まで表示</button>
          <label className="form-check">
            速度
            <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} style={{ width: "auto", marginLeft: 4 }}>
              {[1, 2, 4, 8].map((s) => <option key={s} value={s}>{s}倍</option>)}
            </select>
          </label>
          <label className="form-check">
            <input type="checkbox" checked={skipIdle} onChange={(e) => setSkipIdle(e.target.checked)} />
            待ち時間を短縮
          </label>
          <span className="topo-muted topo-small mono" style={{ marginLeft: "auto" }}>{fmtClock(pos)} / {fmtClock(total)}</span>
          <button className="btn" onClick={download} disabled={!!error}>ダウンロード（.cast）</button>
        </div>
      </div>
    </div>
  );
}

function SessionsTab() {
  const [username, setUsername] = useState("");
  const [device, setDevice] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<TerminalSessionItem> | null>(null);
  const [error, setError] = useState("");
  const [playing, setPlaying] = useState<TerminalSessionItem | null>(null);

  const load = useCallback(async (o: number) => {
    setError("");
    try {
      const r = await api.get<Page<TerminalSessionItem>>("/audit/terminal-sessions", {
        params: { username: username.trim() || undefined, device: device.trim() || undefined, limit: PAGE_SIZE, offset: o },
      });
      setPage(r.data);
      setOffset(o);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [username, device]);

  useEffect(() => {
    load(0);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      {playing && <Player session={playing} onClose={() => setPlaying(null)} />}
      <form className="audit-filters" onSubmit={(e) => { e.preventDefault(); load(0); }}>
        <label className="audit-field">
          <span className="form-label">ユーザー</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="完全一致" />
        </label>
        <label className="audit-field audit-field-wide">
          <span className="form-label">機器（名前・IP）</span>
          <input value={device} onChange={(e) => setDevice(e.target.value)} />
        </label>
        <button className="btn btn-primary" type="submit">検索</button>
      </form>
      <p className="topo-muted topo-small" style={{ marginBottom: 8 }}>
        画面に表示された内容を記録しています（入力したコマンドは機器のエコーとして残ります）。キー入力そのものは、パスワードなどが含まれるため記録しません。
      </p>
      {error && <p className="form-error">{error}</p>}
      {page && (
        <>
          <div className="audit-bar"><Pager total={page.total} offset={offset} onChange={load} /></div>
          <div className="table-scroll">
            <table className="data-table audit-table">
              <thead>
                <tr><th>開始</th><th>接続時間</th><th>ユーザー</th><th>機器</th><th>経由</th><th>終了</th><th>記録</th><th /></tr>
              </thead>
              <tbody>
                {page.items.map((s) => (
                  <tr key={s.id}>
                    <td className="nowrap mono topo-small">{fmtDate(s.started_at)}</td>
                    <td className="nowrap">{duration(s.started_at, s.ended_at)}</td>
                    <td className="nowrap">{s.username}</td>
                    <td>{s.device_name}<div className="topo-muted topo-small mono">{s.device_host}</div></td>
                    <td>{s.via ?? "直接"}</td>
                    <td className="nowrap">{s.end_reason ?? (s.ended_at ? "—" : "接続中または不明")}</td>
                    <td className="nowrap topo-small">{fmtBytes(s.bytes_out)}{s.truncated ? "（上限）" : ""}</td>
                    <td>
                      <button className="btn" disabled={!s.has_recording} onClick={() => setPlaying(s)}>再生</button>
                    </td>
                  </tr>
                ))}
                {!page.items.length && (
                  <tr><td colSpan={8} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>記録はありません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

export default function AuditPage() {
  const [tab, setTab] = useState<"logs" | "sessions">("logs");
  const [actions, setActions] = useState<Record<string, string>>({});
  useEffect(() => {
    api.get<Record<string, string>>("/audit/actions").then((r) => setActions(r.data)).catch(() => {});
  }, []);
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">監査ログ</span>
        <div className="seg-tabs" role="tablist">
          <button role="tab" aria-selected={tab === "logs"} className={`seg-tab${tab === "logs" ? " active" : ""}`} onClick={() => setTab("logs")}>操作履歴</button>
          <button role="tab" aria-selected={tab === "sessions"} className={`seg-tab${tab === "sessions" ? " active" : ""}`} onClick={() => setTab("sessions")}>ターミナルの記録</button>
        </div>
      </div>
      <div className="page-body">
        {tab === "logs" ? <LogsTab actions={actions} /> : <SessionsTab />}
      </div>
    </div>
  );
}
