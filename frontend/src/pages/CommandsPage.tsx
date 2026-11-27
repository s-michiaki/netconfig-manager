import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import axios from "axios";
import { api, errorMessage } from "../api/client";
import { downloadFile } from "../components/CsvButton";
import { usePlatforms } from "../platforms";
import HelpLink from "../components/HelpLink";

/**
 * コマンド実行: 複数の機器へ、表示コマンド（show / display など。設定を変えないもの）を一括で送り、
 * 機器ごと・同じ出力ごとに結果を見る。送れるコマンドの検証は backend（services/command_run.py）が行う。
 * この画面は、入力中に /commands/check で理由を見せるだけで、許可の判断はしない
 */

type Status = "queued" | "running" | "ok" | "failed" | "skipped";
interface Device { id: string; name: string; hostname: string; platform: string; is_active: boolean; group_id: string | null; group_name: string | null; }
interface Group { id: string; name: string; }
interface Limits { enabled: boolean; max_devices: number; max_commands: number; max_command_length: number; max_output: number; retention_days: number; heads: Record<string, string>; }
interface OutputItem { command: string; output: string; truncated: boolean; chars: number; }
interface ResultRow {
  id: string; device_id: string | null; device_name: string; platform: string; platform_label: string; status: Status;
  error: string | null; started_at: string | null; finished_at: string | null; outputs: OutputItem[] | null;
}
interface GroupItem { result_id: string; truncated: boolean; count: number; devices: { id: string | null; name: string; result_id: string }[]; }
interface CommandGroups { index: number; command: string; groups: GroupItem[]; }
interface Run {
  id: string; commands: string[]; target: string; target_name: string | null; created_by: string | null; created_at: string;
  total: number; finished_at: string | null; finished: boolean; counts: Record<Status, number>;
  results?: ResultRow[]; groups?: CommandGroups[];
}
interface LineCheck { n: number; command: string; universal: string | null; platforms: { platform: string; reason: string }[]; }

const UNGROUPED = "__none__";
const MAX_POLL_ERRORS = 5;
const POLL_MS = 2000;
const STATUS_LABEL: Record<Status, string> = { queued: "待機中", running: "実行中", ok: "完了", failed: "失敗", skipped: "対象外" };
const STATUS_BADGE: Record<Status, string> = { queued: "badge-neutral", running: "badge-warning", ok: "badge-success", failed: "badge-danger", skipped: "badge-neutral" };
const MAX_CHECK_PLATFORMS = 10;

const fmt = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
const linesOf = (text: string) => text.split("\n").map((l) => l.trim()).filter((l) => l !== "");
const countText = (c: Record<Status, number>) =>
  `完了 ${c.ok} / 失敗 ${c.failed} / 対象外 ${c.skipped}${c.queued + c.running ? ` / 実行中・待機中 ${c.queued + c.running}` : ""}`;

/** クリップボードへコピーする（https でない環境でも動くよう、古い方法に戻せるようにしておく） */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

function CopyButton({ text, label = "コピー" }: { text: string; label?: string }) {
  const [done, setDone] = useState<boolean | null>(null);
  return (
    <button className="btn btn-sm" type="button" onClick={async () => {
      setDone(await copyText(text));
      window.setTimeout(() => setDone(null), 2000);
    }}>
      {done === null ? label : done ? "コピーしました" : "コピーできませんでした"}
    </button>
  );
}

function OutputBlock({ item }: { item: OutputItem }) {
  return (
    <div className="cmd-output-block">
      <div className="cmd-output-head">
        <span className="mono cmd-command">{item.command}</span>
        <CopyButton text={item.output} />
      </div>
      <pre className="cmd-output" aria-label={`出力: ${item.command}`}>{item.output === "" ? "（出力なし）" : item.output}</pre>
      {item.truncated && (
        <p className="topo-muted topo-small">出力が長いため、{item.output.length.toLocaleString()} 文字で切り捨てています（全体は {item.chars.toLocaleString()} 文字）</p>
      )}
    </div>
  );
}

/** 開いたときだけ中身を作る <details>。台数が多い実行でも、閉じている機器の出力は画面に作らない */
function LazyDetails({ summary, open, children }: { summary: ReactNode; open: boolean; children: () => ReactNode }) {
  const [isOpen, setIsOpen] = useState(open);
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.open = open;
    setIsOpen(open);
  }, [open]);
  return (
    <details ref={ref} className="cmd-device" open={open} onToggle={(e) => setIsOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary>{summary}</summary>
      {isOpen && <div className="cmd-device-body">{children()}</div>}
    </details>
  );
}

function ByDevice({ run }: { run: Run }) {
  const results = run.results ?? [];
  return (
    <div>
      {results.map((r) => (
        <LazyDetails key={r.id} open={results.length <= 3 && r.status === "ok"} summary={
          <>
            <span className={`badge ${STATUS_BADGE[r.status]}`}>{STATUS_LABEL[r.status]}</span>
            <span className="cmd-device-name">{r.device_name}</span>
            <span className="topo-muted topo-small">{r.platform_label}</span>
            {r.error && <span className="cmd-device-error">{r.error}</span>}
          </>
        }>
          {() => (
            <>
              {(r.outputs ?? []).map((o, i) => <OutputBlock key={i} item={o} />)}
              {(r.outputs ?? []).length === 0 && <p className="topo-muted topo-small">{r.error ?? "出力はありません"}</p>}
            </>
          )}
        </LazyDetails>
      ))}
    </div>
  );
}

function ByOutput({ run }: { run: Run }) {
  const groups = run.groups ?? [];
  const byId = new Map((run.results ?? []).map((r) => [r.id, r]));
  const others = (run.results ?? []).filter((r) => r.status !== "ok");
  return (
    <div>
      {groups.map((cg) => (
        <div key={cg.index} className="cmd-cmd-group">
          <p className="section-label mono" style={{ textTransform: "none" }}>{cg.command}</p>
          {cg.groups.length === 0 && <p className="topo-muted topo-small">出力を取得できた機器がありません</p>}
          {cg.groups.map((g, i) => {
            const item = byId.get(g.result_id)?.outputs?.[cg.index];
            const names = g.devices.map((d) => d.name).join("、");
            return (
              <LazyDetails key={i} open={cg.groups.length === 1} summary={
                <>
                  <span className="badge badge-success">{g.count} 台</span>
                  <span className="cmd-device-name">{names}</span>
                  {i > 0 && <span className="topo-muted topo-small">（1 つ目と出力が違います）</span>}
                </>
              }>
                {() => (
                  <>
                    <div className="cmd-output-head">
                      <span className="topo-muted topo-small">同じ出力の機器: {names}</span>
                      <CopyButton text={item?.output ?? ""} />
                    </div>
                    <pre className="cmd-output" aria-label={`出力: ${cg.command}`}>{!item || item.output === "" ? "（出力なし）" : item.output}</pre>
                    {g.truncated && <p className="topo-muted topo-small">出力が長いため、途中で切り捨てています</p>}
                  </>
                )}
              </LazyDetails>
            );
          })}
        </div>
      ))}
      {others.length > 0 && (
        <div className="cmd-cmd-group">
          <p className="section-label">出力を取得できなかった機器</p>
          {others.map((r) => (
            <div key={r.id} className="cmd-other">
              <span className={`badge ${STATUS_BADGE[r.status]}`}>{STATUS_LABEL[r.status]}</span>
              <span className="cmd-device-name">{r.device_name}</span>
              <span className="cmd-device-error">{r.error}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function CommandsPage() {
  const { label: platformLabel } = usePlatforms();
  const [limits, setLimits] = useState<Limits | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesLoaded, setDevicesLoaded] = useState(false); // 機器の一覧が届くまで「グループで選ぶ」を使えなくする
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupFilter, setGroupFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [text, setText] = useState("");
  const [checks, setChecks] = useState<LineCheck[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [run, setRun] = useState<Run | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [view, setView] = useState<"device" | "output">("device");
  const [exportError, setExportError] = useState("");
  const resultsRef = useRef<HTMLDivElement>(null);

  const loadRuns = useCallback(() => {
    api.get<Run[]>("/commands/runs").then((r) => setRuns(r.data)).catch(() => undefined);
  }, []);

  useEffect(() => {
    api.get<Limits>("/commands/limits").then((r) => setLimits(r.data)).catch((e) => setError(errorMessage(e)));
    api.get<Device[]>("/devices/").then((r) => { setDevices(r.data); setDevicesLoaded(true); }).catch((e) => setError(errorMessage(e)));
    api.get<Group[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
    loadRuns();
  }, [loadRuns]);

  // ---- 入力中の確認（理由の表示だけ。許可の判断は backend）
  const selectedDevices = useMemo(() => devices.filter((d) => selected.has(d.id)), [devices, selected]);
  const platformKey = useMemo(() => [...new Set(selectedDevices.map((d) => d.platform))].sort().slice(0, MAX_CHECK_PLATFORMS).join(","), [selectedDevices]);
  useEffect(() => {
    const lines = linesOf(text).slice(0, limits?.max_commands ?? 5);
    if (lines.length === 0) {
      setChecks([]);
      return;
    }
    let cancelled = false;
    const t = window.setTimeout(async () => {
      const platforms = platformKey ? platformKey.split(",") : [];
      const get = (command: string, platform?: string) =>
        api.get<{ ok: boolean; reason: string | null }>("/commands/check", { params: { command, platform } }).then((r) => r.data.reason).catch(() => null);
      const out = await Promise.all(lines.map(async (command, i): Promise<LineCheck> => {
        const universal = await get(command);
        const per = universal ? [] : (await Promise.all(platforms.map(async (p) => ({ platform: p, reason: await get(command, p) })))).filter((x): x is { platform: string; reason: string } => !!x.reason);
        return { n: i + 1, command, universal, platforms: per };
      }));
      if (!cancelled) setChecks(out);
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [text, platformKey, limits?.max_commands]);

  // ---- 実行の進み具合（終わるまで 2 秒ごとに確認し、終わったら出力つきで読み直す）
  const runId = run?.id;
  const runFinished = run?.finished;
  useEffect(() => {
    if (!runId || runFinished) return;
    let stopped = false;
    let timer: number | undefined;
    let errors = 0;
    // 応答が返ってから次の確認を予約する（遅い応答が重ならない）。実行が見つからない・権限がないときは止め、
    // それ以外のエラーは MAX_POLL_ERRORS 回続いたら止めて、理由を表示する
    const tick = async () => {
      let again = true;
      try {
        const r = await api.get<Run>(`/commands/runs/${runId}`, { params: { outputs: false } });
        if (stopped) return;
        errors = 0;
        if (r.data.finished) {
          const full = await api.get<Run>(`/commands/runs/${runId}`);
          if (stopped) return;
          setRun(full.data);
          loadRuns();
          again = false;
        } else {
          setRun(r.data);
        }
      } catch (e) {
        if (stopped) return;
        const code = axios.isAxiosError(e) ? e.response?.status : undefined;
        errors += 1;
        if (code === 404 || code === 403) {
          setError(`${errorMessage(e)}（実行の状況の確認を止めました）`);
          again = false;
        } else if (errors >= MAX_POLL_ERRORS) {
          setError(`${errorMessage(e)}（${MAX_POLL_ERRORS} 回続けて確認できなかったため、状況の確認を止めました。実行を開き直してください）`);
          again = false;
        }
      }
      if (again && !stopped) timer = window.setTimeout(tick, POLL_MS);
    };
    timer = window.setTimeout(tick, POLL_MS);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [runId, runFinished, loadRuns]);

  const lines = linesOf(text);
  const universalErrors = checks.filter((c) => c.universal);
  const tooMany = limits ? lines.length > limits.max_commands : false;
  const maxDevices = limits?.max_devices ?? 100;
  const inGroup = (d: Device) => !groupFilter || (groupFilter === UNGROUPED ? !d.group_id : d.group_id === groupFilter);
  const shown = devices.filter(inGroup);
  const pickable = (d: Device) => d.is_active;
  const overDevices = selected.size > maxDevices;
  // 選んだ機種のすべてで、どれかの行が送れないなら、実行しても送れる機器が無い（一部の機種だけなら、その機器は対象外になる）
  const checkedPlatforms = platformKey ? platformKey.split(",") : [];
  const nothingSendable = checkedPlatforms.length > 0 && checks.length > 0
    && checkedPlatforms.every((p) => checks.some((c) => c.platforms.some((x) => x.platform === p)));
  const canRun = !!limits?.enabled && !nothingSendable && !starting && lines.length > 0 && !tooMany && universalErrors.length === 0 && selected.size > 0 && !overDevices
    && !(run && !run.finished);

  const toggleAll = (checked: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      shown.filter(pickable).forEach((d) => (checked ? next.add(d.id) : next.delete(d.id)));
      return next;
    });
  const pickGroup = (g: string) => {
    setGroupFilter(g);
    if (g) setSelected(new Set(devices.filter((d) => d.is_active && (g === UNGROUPED ? !d.group_id : d.group_id === g)).map((d) => d.id)));
  };
  const toggleDevice = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const open = async (id: string) => {
    setError("");
    try {
      const r = await api.get<Run>(`/commands/runs/${id}`, { params: { outputs: true } });
      setRun(r.data);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const start = async () => {
    setStarting(true);
    setError("");
    try {
      const r = await api.post<{ id: string }>("/commands/runs", { device_ids: [...selected], commands: lines });
      setRun(null);
      const first = await api.get<Run>(`/commands/runs/${r.data.id}`, { params: { outputs: false } });
      setRun(first.data);
      setView("device");
      loadRuns();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setStarting(false);
    }
  };

  const exportRun = async (format: "txt" | "csv") => {
    if (!run) return;
    setExportError("");
    try {
      await downloadFile(`/commands/runs/${run.id}/export`, { format }, `command-run.${format}`);
    } catch (e) {
      setExportError(errorMessage(e));
    }
  };
  const setAllOpen = (v: boolean) => resultsRef.current?.querySelectorAll("details").forEach((d) => { d.open = v; });
  const count = (n: number) => `${n} 台`;
  const platformsInSelection = [...new Set(selectedDevices.map((d) => d.platform))];

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">コマンド実行<HelpLink topic="commands" /></span>
        <button className="btn btn-primary" onClick={start} disabled={!canRun}>
          {starting ? "投入中..." : run && !run.finished ? "実行中..." : "▶ 実行"}
        </button>
      </div>

      <div className="page-body">
        <p className="cmd-note" role="note">
          表示コマンドだけ送れます（show / display など、設定を変えないもの）。出力には設定の中身が含まれることがあります。
          結果は {limits?.retention_days ?? 30} 日で削除されます。
        </p>
        {limits && !limits.enabled && <p className="form-error">コマンド実行は無効に設定されています（管理者が .env の COMMAND_RUN_ENABLED を変更すると使えます）。</p>}
        {error && <p className="form-error" role="alert">{error}</p>}

        <div className="cmd-grid">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <p className="section-label" style={{ margin: 0 }}>対象の機器</p>
              <select value={groupFilter} onChange={(e) => pickGroup(e.target.value)} disabled={!devicesLoaded} style={{ width: 220, marginLeft: "auto" }} aria-label="グループで選ぶ">
                <option value="">すべてのグループ</option>
                {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                <option value={UNGROUPED}>未分類</option>
              </select>
              <span className={`topo-small ${overDevices ? "cmd-over" : "topo-muted"}`}>{count(selected.size)}を選択中（上限 {maxDevices} 台）</span>
            </div>
            <div className="cmd-devices">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>
                      <input type="checkbox" aria-label="表示中の機器をすべて選ぶ"
                        checked={shown.filter(pickable).length > 0 && shown.filter(pickable).every((d) => selected.has(d.id))}
                        onChange={(e) => toggleAll(e.target.checked)} />
                    </th>
                    <th>ホスト名</th>
                    <th>IPアドレス</th>
                    <th>プラットフォーム</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((d) => (
                    <tr key={d.id} style={d.is_active ? undefined : { opacity: 0.5 }}>
                      <td><input type="checkbox" aria-label={`${d.name} を選ぶ`} checked={selected.has(d.id)} disabled={!d.is_active} onChange={() => toggleDevice(d.id)} /></td>
                      <td style={{ fontWeight: 500 }}>{d.name}{d.group_name && <span className="topo-muted topo-small"> · {d.group_name}</span>}</td>
                      <td className="mono" style={{ fontSize: 12, color: "var(--color-muted)" }}>{d.hostname}</td>
                      <td style={{ fontSize: 12, color: "var(--color-muted)" }}>{platformLabel(d.platform)}</td>
                    </tr>
                  ))}
                  {shown.length === 0 && <tr><td colSpan={4} className="topo-muted">機器がありません</td></tr>}
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <label className="section-label" htmlFor="cmd-input">コマンド（1 行に 1 つ。{limits?.max_commands ?? 5} 個まで）</label>
            <textarea id="cmd-input" className="mono cmd-input" rows={6} value={text} spellCheck={false} autoComplete="off"
              placeholder={"show version\nshow ip interface brief | include up"} onChange={(e) => setText(e.target.value)} />
            <p className="topo-muted topo-small">
              {lines.length} / {limits?.max_commands ?? 5} 個。1 個 {limits?.max_command_length ?? 200} 文字まで。パイプ（|）の後ろは、include / exclude などの絞り込みだけ使えます。
              {platformsInSelection.length > 0 && limits && (
                <> 先頭に使える語: {platformsInSelection.slice(0, 4).map((p) => `${platformLabel(p)}（${limits.heads[p] ?? "show"}）`).join("、")}{platformsInSelection.length > 4 ? " ほか" : ""}</>
              )}
            </p>
            {tooMany && <p className="form-error" role="alert">コマンドは {limits?.max_commands} 個までです（{lines.length} 個あります）</p>}
            {nothingSendable && <p className="form-error" role="alert">選んだ機器のすべてに、送れないコマンドが含まれています</p>}
            {(universalErrors.length > 0 || checks.some((c) => c.platforms.length > 0)) && (
              <ul className="cmd-errors" aria-label="コマンドの確認結果">
                {checks.map((c) => c.universal && (
                  <li key={`u${c.n}`} className="cmd-error">{c.n} 行目「{c.command}」: {c.universal}</li>
                ))}
                {checks.map((c) => c.platforms.map((p) => (
                  <li key={`${c.n}-${p.platform}`} className="cmd-warn">
                    {c.n} 行目: {platformLabel(p.platform)} の機器（{selectedDevices.filter((d) => d.platform === p.platform).length} 台）には送れず、対象外になります — {p.reason}
                  </li>
                )))}
              </ul>
            )}
          </div>
        </div>

        {run && (
          <div className="card cmd-run" aria-label="実行結果">
            <div className="cmd-run-head">
              <div>
                <span className="section-label" style={{ margin: 0 }}>{run.finished ? "実行結果" : "実行中"}</span>
                <span className="topo-muted topo-small"> {fmt(run.created_at)} · {run.created_by} · {run.target_name}</span>
              </div>
              <span className="cmd-count" role="status">{countText(run.counts)}</span>
            </div>
            <div className="progress-wrap" style={{ margin: "8px 0 12px" }}>
              <div className="progress-bar" style={{ width: `${run.total ? Math.round(((run.total - run.counts.queued - run.counts.running) / run.total) * 100) : 0}%` }} />
            </div>
            {!run.finished && (
              <p className="topo-muted topo-small" style={{ margin: "0 0 10px" }}>機器への接続に時間がかかる機種では 1 分ほどかかることがあります</p>
            )}
            <p className="topo-muted topo-small mono">{run.commands.join("  /  ")}</p>
            {!run.finished && (
              <div>
                {(run.results ?? []).map((r) => (
                  <div key={r.id} className="cmd-other">
                    <span className={`badge ${STATUS_BADGE[r.status]}`}>{STATUS_LABEL[r.status]}</span>
                    <span className="cmd-device-name">{r.device_name}</span>
                    {r.error && <span className="cmd-device-error">{r.error}</span>}
                  </div>
                ))}
              </div>
            )}
            {run.finished && (
              <>
                <div className="cmd-toolbar">
                  <div className="seg-tabs" role="tablist" aria-label="表示の切り替え">
                    <button role="tab" aria-selected={view === "device"} className={`seg-tab${view === "device" ? " active" : ""}`} onClick={() => setView("device")}>機器ごと</button>
                    <button role="tab" aria-selected={view === "output"} className={`seg-tab${view === "output" ? " active" : ""}`} onClick={() => setView("output")}>同じ出力ごと</button>
                  </div>
                  <button className="btn btn-sm" onClick={() => setAllOpen(true)}>すべて開く</button>
                  <button className="btn btn-sm" onClick={() => setAllOpen(false)}>すべて閉じる</button>
                  <span style={{ marginLeft: "auto" }} />
                  <button className="btn btn-sm" onClick={() => exportRun("txt")}>テキスト保存</button>
                  <button className="btn btn-sm" onClick={() => exportRun("csv")}>CSV 保存</button>
                </div>
                {exportError && <p className="form-error" role="alert">{exportError}</p>}
                <div ref={resultsRef} key={`${run.id}-${view}`}>
                  {view === "device" ? <ByDevice run={run} /> : <ByOutput run={run} />}
                </div>
              </>
            )}
          </div>
        )}

        <p className="section-label" style={{ marginTop: 20 }}>過去の実行</p>
        <table className="data-table" aria-label="過去の実行">
          <thead>
            <tr><th>日時</th><th>実行者</th><th>コマンド</th><th>対象</th><th>結果</th><th /></tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id} className={run?.id === r.id ? "cmd-row-active" : undefined}>
                <td style={{ whiteSpace: "nowrap" }}>{fmt(r.created_at)}</td>
                <td>{r.created_by}</td>
                <td className="mono cmd-cell-commands">{r.commands.join("  /  ")}</td>
                <td>{r.target_name}</td>
                <td className="topo-small">{r.finished ? countText(r.counts) : `実行中（${countText(r.counts)}）`}</td>
                <td><button className="btn btn-sm" onClick={() => open(r.id)}>開く</button></td>
              </tr>
            ))}
            {runs.length === 0 && <tr><td colSpan={6} className="topo-muted">まだ実行していません</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
