/** コンプライアンスチェック: 違反一覧・機器別・ルール管理 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import { usePlatforms } from "../platforms";

type Severity = "high" | "medium" | "low";
type Status = "pass" | "fail" | "error";

interface Rule {
  id: string;
  name: string;
  description: string | null;
  platforms: string[];
  match_type: "contains" | "regex";
  expect: "present" | "absent";
  pattern: string;
  scope: "config" | "section";
  section_pattern: string | null;
  severity: Severity;
  enabled: boolean;
  updated_by: string | null;
  updated_at: string | null;
  pass_count: number;
  fail_count: number;
  error_count: number;
}
type RuleInput = Omit<Rule, "id" | "updated_by" | "updated_at" | "pass_count" | "fail_count" | "error_count">;

interface Result {
  device_id: string;
  device_name: string;
  platform: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: Status;
  details: string[];
  commit_hash: string | null;
  checked_at: string;
}

interface DeviceSummary {
  device_id: string;
  name: string;
  hostname: string;
  platform: string;
  checked: boolean;
  pass_count: number;
  fail_count: number;
  error_count: number;
  worst_severity: Severity | null;
  checked_at: string | null;
}
interface Summary { rules: number; devices: DeviceSummary[]; fail_by_severity: Record<Severity, number>; }
interface Device { id: string; name: string; platform: string; }

const SEV_LABEL: Record<Severity, string> = { high: "高", medium: "中", low: "低" };
const SEV_BADGE: Record<Severity, string> = { high: "badge-danger", medium: "badge-warning", low: "badge-neutral" };
function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function SevBadge({ s }: { s: Severity | null }) {
  if (!s) return <span className="topo-muted">—</span>;
  return <span className={`badge ${SEV_BADGE[s]}`}>{SEV_LABEL[s]}</span>;
}

/** ルールの条件を1行の文章にする */
function describe(r: RuleInput): string {
  const how = r.match_type === "regex" ? `正規表現 /${r.pattern}/ に一致する行` : `「${r.pattern}」を含む行`;
  const exp = r.expect === "present" ? "があること" : "がないこと";
  const where = r.scope === "section" ? `/${r.section_pattern}/ の各セクションに` : "コンフィグに";
  return `${where}${how}${exp}`;
}

function Details({ items }: { items: string[] }) {
  const [open, setOpen] = useState(false);
  if (!items.length) return <span className="topo-muted">—</span>;
  const shown = open ? items : items.slice(0, 3);
  return (
    <div className="cmp-details">
      {shown.map((d, i) => <div key={i} className="mono">{d}</div>)}
      {items.length > 3 && (
        <button className="link-btn" onClick={() => setOpen(!open)}>{open ? "閉じる" : `ほか ${items.length - 3} 件を表示`}</button>
      )}
    </div>
  );
}

// ============================================================ ルールの編集

const EMPTY_RULE: RuleInput = {
  name: "", description: "", platforms: [], match_type: "contains", expect: "present", pattern: "",
  scope: "config", section_pattern: "", severity: "medium", enabled: true,
};

function RuleModal({
  rule, devices, onClose, onSaved,
}: { rule: Rule | RuleInput | null; devices: Device[]; onClose: () => void; onSaved: () => void }) {
  const { groups: platformGroups } = usePlatforms();
  const isEdit = !!rule && "id" in rule;
  const [form, setForm] = useState<RuleInput>(() => ({ ...EMPTY_RULE, ...(rule ?? {}) }));
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [testDevice, setTestDevice] = useState("");
  const [testResult, setTestResult] = useState<null | { applicable: boolean; has_config: boolean; status: Status | null; details: string[] }>(null);
  const [testing, setTesting] = useState(false);
  const set = <K extends keyof RuleInput>(k: K, v: RuleInput[K]) => {
    setForm((f) => ({ ...f, [k]: v }));
    setTestResult(null);
  };
  const body = () => ({
    ...form,
    description: form.description || null,
    section_pattern: form.scope === "section" ? form.section_pattern || null : null,
  });
  const canSave = form.name.trim() && form.pattern && (form.scope === "config" || form.section_pattern);
  const candidates = devices.filter((d) => !form.platforms.length || form.platforms.includes(d.platform));

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      if (isEdit) await api.put(`/compliance/rules/${(rule as Rule).id}`, body());
      else await api.post("/compliance/rules", body());
      onSaved();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setError("");
    try {
      const r = await api.post("/compliance/rules/test", { rule: { ...body(), name: form.name || "test" }, device_id: testDevice });
      setTestResult(r.data);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal cmp-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? "ルールの編集" : "ルールの追加"}</p>
        <div className="form-group">
          <label className="form-label" htmlFor="r-name">名前</label>
          <input id="r-name" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="例: SSH バージョン2" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="r-desc">説明（任意）</label>
          <input id="r-desc" value={form.description ?? ""} onChange={(e) => set("description", e.target.value)} />
        </div>
        <div className="form-group">
          <span className="form-label">対象のプラットフォーム（未選択なら全機種）</span>
          <div className="cmp-platforms">
            {platformGroups.map(([vendor, list]) => (
              <div key={vendor} className="cmp-platform-group">
                <div className="cmp-platform-vendor">{vendor}</div>
                {list.map((p) => (
                  <label key={p.id} className="form-check">
                    <input type="checkbox" checked={form.platforms.includes(p.id)}
                      onChange={(e) => set("platforms", e.target.checked ? [...form.platforms, p.id] : form.platforms.filter((x) => x !== p.id))} />
                    {p.label}
                  </label>
                ))}
              </div>
            ))}
          </div>
        </div>
        <div className="cmp-row3">
          <div className="form-group">
            <label className="form-label" htmlFor="r-expect">条件</label>
            <select id="r-expect" value={form.expect} onChange={(e) => set("expect", e.target.value as RuleInput["expect"])}>
              <option value="present">一致する行が必要</option>
              <option value="absent">一致する行があってはいけない</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="r-match">一致方法</label>
            <select id="r-match" value={form.match_type} onChange={(e) => set("match_type", e.target.value as RuleInput["match_type"])}>
              <option value="contains">文字列を含む</option>
              <option value="regex">正規表現</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="r-sev">重要度</label>
            <select id="r-sev" value={form.severity} onChange={(e) => set("severity", e.target.value as Severity)}>
              <option value="high">高</option><option value="medium">中</option><option value="low">低</option>
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="r-pattern">{form.match_type === "regex" ? "正規表現（1行ごとに判定）" : "含む文字列（1行ごとに判定）"}</label>
          <input id="r-pattern" className="mono" value={form.pattern} onChange={(e) => set("pattern", e.target.value)}
            placeholder={form.match_type === "regex" ? "例: ^ip ssh version 2" : "例: service password-encryption"} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="r-scope">範囲</label>
          <select id="r-scope" value={form.scope} onChange={(e) => set("scope", e.target.value as RuleInput["scope"])}>
            <option value="config">コンフィグ全体</option>
            <option value="section">セクションごと（interface・line など）</option>
          </select>
        </div>
        {form.scope === "section" && (
          <div className="form-group">
            <label className="form-label" htmlFor="r-section">セクションの見出し（正規表現）</label>
            <input id="r-section" className="mono" value={form.section_pattern ?? ""} onChange={(e) => set("section_pattern", e.target.value)}
              placeholder="例: ^interface GigabitEthernet" />
            <p className="topo-muted topo-small" style={{ marginTop: 4 }}>
              行頭に空白の無い行を見出し、続く字下げされた行を中身として、見出しが一致する各セクションを検査します。
            </p>
          </div>
        )}
        <label className="form-check" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          有効（無効にすると検査しません）
        </label>
        {form.pattern && (
          <p className="cmp-sentence">{describe({ ...form, section_pattern: form.section_pattern || "（未入力）" })}</p>
        )}

        <div className="cmp-test">
          <span className="form-label">保存前に試す（機器の最新のコンフィグで判定）</span>
          <div style={{ display: "flex", gap: 8 }}>
            <select value={testDevice} onChange={(e) => { setTestDevice(e.target.value); setTestResult(null); }} aria-label="試す機器">
              <option value="">機器を選択</option>
              {candidates.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
            <button className="btn" onClick={test} disabled={!testDevice || !form.pattern || testing}>{testing ? "判定中..." : "試す"}</button>
          </div>
          {testResult && (
            <div className="cmp-test-result">
              {!testResult.applicable ? "この機器のプラットフォームは対象外です"
                : !testResult.has_config ? "この機器はまだ収集されていません"
                : (
                  <>
                    {testResult.status === "pass" && <span className="badge badge-success">合格</span>}
                    {testResult.status === "fail" && <span className="badge badge-danger">違反</span>}
                    {testResult.status === "error" && <span className="badge badge-warning">エラー</span>}
                    <Details items={testResult.details} />
                  </>
                )}
            </div>
          )}
        </div>
        {error && <p className="form-error" style={{ marginTop: 10 }}>{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={saving || !canSave}>{saving ? "保存・検査中..." : "保存して検査"}</button>
        </div>
      </div>
    </div>
  );
}

function TemplateModal({
  existing, onClose, onAdded,
}: { existing: Set<string>; onClose: () => void; onAdded: (n: number) => void }) {
  const { label: platformLabel } = usePlatforms();
  const [templates, setTemplates] = useState<(RuleInput & { description: string })[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.get("/compliance/templates").then((r) => setTemplates(r.data)).catch((e) => setError(errorMessage(e)));
  }, []);
  const add = async () => {
    setBusy(true);
    setError("");
    let n = 0;
    try {
      for (const t of templates.filter((x) => picked.has(x.name))) {
        await api.post("/compliance/rules", { ...EMPTY_RULE, ...t, section_pattern: t.section_pattern ?? null });
        n++;
      }
      onAdded(n);
      onClose();
    } catch (e) {
      setError(`${n}件追加したところでエラー: ${errorMessage(e)}`);
      if (n) onAdded(n);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal cmp-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">テンプレートから追加</p>
        <p className="topo-muted topo-small" style={{ marginBottom: 10 }}>よく使う設定基準のひな形です。追加後に編集できます。</p>
        <ul className="cmp-templates">
          {templates.map((t) => {
            const exists = existing.has(t.name);
            return (
              <li key={t.name}>
                <label className="form-check">
                  <input type="checkbox" disabled={exists} checked={picked.has(t.name)}
                    onChange={(e) => {
                      const s = new Set(picked);
                      if (e.target.checked) s.add(t.name); else s.delete(t.name);
                      setPicked(s);
                    }} />
                  <span>
                    <b>{t.name}</b> <SevBadge s={t.severity} />{exists ? <span className="topo-muted">（登録済み）</span> : null}
                    <span className="topo-muted topo-small" style={{ display: "block" }}>
                      {t.description} ／ {t.platforms.length ? t.platforms.map((p) => platformLabel(p)).join("・") : "全機種"}
                    </span>
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={add} disabled={busy || !picked.size}>{busy ? "追加・検査中..." : `${picked.size}件を追加`}</button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ ページ

type Tab = "violations" | "devices" | "rules";

export default function CompliancePage() {
  const { can } = useAuth();
  const { label: platformLabel } = usePlatforms();
  const canWrite = can(PERM.COMPLIANCE_WRITE);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const deviceFilter = params.get("device") ?? "";
  const [tab, setTab] = useState<Tab>("violations");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [results, setResults] = useState<Result[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [sevFilter, setSevFilter] = useState<"" | Severity>("");
  const [editing, setEditing] = useState<Rule | RuleInput | null | undefined>(undefined);
  const [showTemplates, setShowTemplates] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [running, setRunning] = useState(false);

  const load = useCallback(async () => {
    setError("");
    try {
      const [s, r, ru] = await Promise.all([
        api.get<Summary>("/compliance/summary"),
        api.get<Result[]>("/compliance/results", { params: { status: "fail" } }),
        api.get<Rule[]>("/compliance/rules"),
      ]);
      setSummary(s.data);
      setResults(r.data);
      setRules(ru.data);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    load();
    api.get<Device[]>("/devices/").then((r) => setDevices(r.data)).catch(() => {});
  }, [load]);

  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(""), 4000);
    return () => window.clearTimeout(t);
  }, [notice]);

  const runAll = async () => {
    setRunning(true);
    try {
      const r = await api.post("/compliance/run");
      setNotice(`${r.data.devices}台 × ${r.data.rules}ルールを検査しました`);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRunning(false);
    }
  };

  const removeRule = async (r: Rule) => {
    if (!window.confirm(`ルール「${r.name}」を削除しますか？（検査結果も削除されます）`)) return;
    try {
      await api.delete(`/compliance/rules/${r.id}`);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const shown = useMemo(
    () => results.filter((x) => (!deviceFilter || x.device_id === deviceFilter) && (!sevFilter || x.severity === sevFilter)),
    [results, deviceFilter, sevFilter]
  );
  const deviceName = summary?.devices.find((d) => d.device_id === deviceFilter)?.name;
  const violatingDevices = summary?.devices.filter((d) => d.fail_count > 0).length ?? 0;
  const unchecked = summary?.devices.filter((d) => !d.checked).length ?? 0;

  return (
    <div className="page">
      {editing !== undefined && (
        <RuleModal rule={editing} devices={devices} onClose={() => setEditing(undefined)} onSaved={load} />
      )}
      {showTemplates && (
        <TemplateModal existing={new Set(rules.map((r) => r.name))} onClose={() => setShowTemplates(false)}
          onAdded={(n) => { setNotice(`${n}件のルールを追加しました`); load(); }} />
      )}
      <div className="page-header">
        <span className="page-title">コンプライアンス</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {notice && <span className="topo-notice">{notice}</span>}
          {canWrite && (
            <>
              <button className="btn" onClick={runAll} disabled={running}>{running ? "検査中..." : "全機器を再検査"}</button>
              <button className="btn" onClick={() => setShowTemplates(true)}>テンプレートから追加</button>
              <button className="btn btn-primary" onClick={() => setEditing(null)}>＋ ルール追加</button>
            </>
          )}
        </div>
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {summary && (
          <div className="cmp-cards">
            <div className="card cmp-card"><span className="cmp-card-label">有効なルール</span><span className="cmp-card-value">{summary.rules}</span></div>
            <div className="card cmp-card"><span className="cmp-card-label">違反のある機器</span>
              <span className="cmp-card-value" style={{ color: violatingDevices ? "var(--color-danger)" : undefined }}>
                {violatingDevices}<span className="cmp-card-sub"> / {summary.devices.length}台</span>
              </span>
            </div>
            <div className="card cmp-card"><span className="cmp-card-label">違反（重要度別）</span>
              <span className="cmp-card-sev">
                <span><SevBadge s="high" /> {summary.fail_by_severity.high ?? 0}</span>
                <span><SevBadge s="medium" /> {summary.fail_by_severity.medium ?? 0}</span>
                <span><SevBadge s="low" /> {summary.fail_by_severity.low ?? 0}</span>
              </span>
            </div>
            <div className="card cmp-card"><span className="cmp-card-label">未検査の機器</span>
              <span className="cmp-card-value">{unchecked}</span>
              <span className="topo-muted topo-small">未収集、または対象のルールなし</span>
            </div>
          </div>
        )}

        <div className="seg-tabs" role="tablist" style={{ marginBottom: 12 }}>
          {([["violations", `違反一覧（${results.length}）`], ["devices", "機器別"], ["rules", `ルール（${rules.length}）`]] as [Tab, string][]).map(([k, l]) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`seg-tab${tab === k ? " active" : ""}`} onClick={() => setTab(k)}>{l}</button>
          ))}
        </div>

        {tab === "violations" && (
          <>
            <div className="audit-filters">
              <label className="audit-field">
                <span className="form-label">機器</span>
                <select value={deviceFilter} onChange={(e) => setParams(e.target.value ? { device: e.target.value } : {})}>
                  <option value="">すべて</option>
                  {summary?.devices.filter((d) => d.fail_count).map((d) => <option key={d.device_id} value={d.device_id}>{d.name}</option>)}
                  {deviceFilter && !summary?.devices.some((d) => d.device_id === deviceFilter && d.fail_count) && (
                    <option value={deviceFilter}>{deviceName ?? "（選択中の機器）"}</option>
                  )}
                </select>
              </label>
              <label className="audit-field">
                <span className="form-label">重要度</span>
                <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as "" | Severity)}>
                  <option value="">すべて</option><option value="high">高</option><option value="medium">中</option><option value="low">低</option>
                </select>
              </label>
            </div>
            <div className="table-scroll">
              <table className="data-table">
                <thead><tr><th>重要度</th><th>機器</th><th>ルール</th><th>違反箇所</th><th>検査</th></tr></thead>
                <tbody>
                  {shown.map((x) => (
                    <tr key={`${x.device_id}:${x.rule_id}`}>
                      <td><SevBadge s={x.severity} /></td>
                      <td className="nowrap">
                        <button className="link-btn" onClick={() => navigate(`/history?device=${x.device_id}`)} title="コンフィグの世代を見る">{x.device_name}</button>
                        <div className="topo-muted topo-small">{platformLabel(x.platform)}</div>
                      </td>
                      <td>{x.rule_name}</td>
                      <td><Details items={x.details} /></td>
                      <td className="nowrap topo-small">{fmtDate(x.checked_at)}{x.commit_hash ? <div className="topo-muted mono">{x.commit_hash.slice(0, 8)}</div> : null}</td>
                    </tr>
                  ))}
                  {!shown.length && (
                    <tr><td colSpan={5} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>
                      {rules.length ? "違反はありません" : "ルールが登録されていません。「テンプレートから追加」で始められます"}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "devices" && summary && (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>機器</th><th>プラットフォーム</th><th>違反</th><th>合格</th><th>エラー</th><th>最も重い違反</th><th>検査</th></tr></thead>
              <tbody>
                {summary.devices.map((d) => (
                  <tr key={d.device_id}>
                    <td>{d.name}<div className="topo-muted topo-small mono">{d.hostname}</div></td>
                    <td>{platformLabel(d.platform)}</td>
                    <td>
                      {d.fail_count ? (
                        <button className="link-btn" onClick={() => { setParams({ device: d.device_id }); setTab("violations"); }}>
                          {d.fail_count}件
                        </button>
                      ) : d.checked ? "0" : "—"}
                    </td>
                    <td>{d.checked ? d.pass_count : "—"}</td>
                    <td>{d.error_count || (d.checked ? "0" : "—")}</td>
                    <td><SevBadge s={d.worst_severity} /></td>
                    <td className="nowrap topo-small">{d.checked ? fmtDate(d.checked_at) : <span className="topo-muted">未検査</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "rules" && (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>ルール</th><th>重要度</th><th>対象</th><th>結果</th>{canWrite && <th />}</tr></thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                    <td>
                      <b>{r.name}</b>{!r.enabled && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>無効</span>}
                      <div className="topo-muted topo-small">{r.description}</div>
                      <div className="topo-small mono cmp-cond">{describe(r)}</div>
                    </td>
                    <td><SevBadge s={r.severity} /></td>
                    <td className="topo-small">{r.platforms.length ? r.platforms.map((p) => platformLabel(p)).join("・") : "全機種"}</td>
                    <td className="nowrap topo-small">
                      <span style={{ color: r.fail_count ? "var(--color-danger)" : undefined }}>違反 {r.fail_count}</span> / 合格 {r.pass_count}
                      {r.error_count ? <span style={{ color: "var(--color-warning)" }}> / エラー {r.error_count}</span> : null}
                    </td>
                    {canWrite && (
                      <td className="nowrap">
                        <button className="btn" onClick={() => setEditing(r)}>編集</button>{" "}
                        <button className="btn btn-danger" onClick={() => removeRule(r)}>削除</button>
                      </td>
                    )}
                  </tr>
                ))}
                {!rules.length && (
                  <tr><td colSpan={5} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>ルールが登録されていません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
