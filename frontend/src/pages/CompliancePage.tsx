/** コンプライアンスチェック: 違反一覧・機器別・ルール管理・例外 */
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import { usePlatforms } from "../platforms";

type Severity = "high" | "medium" | "low";
type Status = "pass" | "fail" | "error" | "exempt";

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
  /** 違反したときの直し方（設定の例）・根拠・分野。機器へは送らず、画面で見る・コピーするだけ */
  remediation: string | null;
  reference: string | null;
  category: string | null;
  updated_by: string | null;
  updated_at: string | null;
  pass_count: number;
  fail_count: number;
  error_count: number;
  exempt_count: number;
  exception_count: number;
}
type RuleInput = Omit<Rule, "id" | "updated_by" | "updated_at" | "pass_count" | "fail_count" | "error_count" | "exempt_count" | "exception_count">;

/** 例外（承認済みの逸脱） */
interface CmpException {
  id: string;
  rule_id: string;
  rule_name: string;
  device_id: string | null;
  device_name: string | null;
  ignore_pattern: string | null;
  reason: string;
  expires_at: string | null;
  expired: boolean;
  created_by: string | null;
  created_at: string;
}

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
  exempt_count: number;
  worst_severity: Severity | null;
  checked_at: string | null;
}
interface Summary { rules: number; devices: DeviceSummary[]; fail_by_severity: Record<Severity, number>; }
interface Device { id: string; name: string; platform: string; group_id: string | null; }
const UNGROUPED = "__none__";

/** 分野（backend/app/services/compliance_templates/_base.py の CATEGORIES と合わせる） */
const CATEGORIES = ["管理アクセス", "認証", "ログ", "時刻", "SNMP", "暗号", "サービス", "バナー", "そのほか"];
const MAX_REMEDIATION = 4000;

/** クリップボードへコピーする。http・権限なしなど Clipboard API が使えないときは execCommand で試し、だめなら false */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // 権限なしなど。下の方法へ
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:0;left:0;opacity:0;";
    document.body.appendChild(ta);
    ta.select();
    const ok = typeof document.execCommand === "function" && document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

const axiosStatus = (e: unknown) => (e as { response?: { status?: number } }).response?.status;

/** 説明の行（「# 」＝# と空白で始まる行）。「#」だけの行や「#」に文字が続く行は、命令として残す */
const isCommentLine = (l: string) => l.trimStart().startsWith("# ");

/** 直し方のうち、機器に入れる行だけ（説明の行は除く） */
function commandsOf(text: string): string {
  return text.split("\n").filter((l) => !isCommentLine(l)).join("\n").trim();
}

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

// ============================================================ 例外の登録

/** 該当箇所単位の例外を使えるルールか（コンフィグ全体に「必要」なルールは外す箇所が無い） */
const patternAllowed = (r: RuleInput) => r.scope === "section" || r.expect === "absent";
const escapeRe = (t: string) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** 違反箇所（「10行目: interface Gi0/2（…）」「4行目: ip http server」）から除外用の正規表現を作る */
function patternFromDetail(rule: RuleInput, detail: string): string | null {
  const m = detail.match(/^\d+行目: (.+)$/);
  if (!m) return null;
  let text = m[1];
  if (rule.scope === "section") text = text.replace(/（一致する行がありません）$/, "").replace(/ → .*$/, "");
  return `^${escapeRe(text.trim())}$`;
}

function ExceptionModal({
  rule, device, details, devices, onClose, onSaved,
}: {
  rule: Rule; device: { id: string; name: string } | null; details: string[]; devices: Device[];
  onClose: () => void; onSaved: (msg: string) => void;
}) {
  const allowPattern = patternAllowed(rule);
  const [deviceId, setDeviceId] = useState(device?.id ?? "");
  const [mode, setMode] = useState<"device" | "pattern">(allowPattern && details.length ? "pattern" : "device");
  const [pattern, setPattern] = useState("");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const candidates = devices.filter((d) => !rule.platforms.length || rule.platforms.includes(d.platform));
  const suggestions = allowPattern
    ? Array.from(new Set(details.map((d) => patternFromDetail(rule, d)).filter((x): x is string => !!x)))
    : [];
  const effectiveMode = !deviceId ? "pattern" : mode;
  const canSave = reason.trim() && (effectiveMode === "device" || pattern.trim());

  const addSuggestion = (p: string) => {
    const parts = pattern ? pattern.split("|") : [];
    if (!parts.includes(p)) setPattern([...parts, p].join("|"));
  };

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      await api.post("/compliance/exceptions", {
        rule_id: rule.id,
        device_id: deviceId || null,
        ignore_pattern: effectiveMode === "pattern" ? pattern.trim() : null,
        reason: reason.trim(),
        expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : null,
      });
      onSaved("例外を登録して再検査しました");
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal cmp-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">例外の登録</p>
        <p className="topo-muted topo-small" style={{ marginBottom: 10 }}>
          承認済みの逸脱を登録すると、違反ではなく「除外」として扱います（違反の件数に数えません）。
        </p>
        <div className="form-group">
          <span className="form-label">ルール</span>
          <div><b>{rule.name}</b> <SevBadge s={rule.severity} /></div>
          <div className="topo-small mono cmp-cond">{describe(rule)}</div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="x-device">対象の機器</label>
          <select id="x-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            {allowPattern && <option value="">全機器（該当箇所の指定が必要）</option>}
            {candidates.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
        <div className="form-group">
          <span className="form-label">除外の範囲</span>
          <label className="form-check">
            <input type="radio" name="x-mode" checked={effectiveMode === "device"} disabled={!deviceId}
              onChange={() => setMode("device")} />
            この機器ではルールの違反をすべて除外する
          </label>
          <label className="form-check">
            <input type="radio" name="x-mode" checked={effectiveMode === "pattern"} disabled={!allowPattern}
              onChange={() => setMode("pattern")} />
            該当箇所だけ除外する
            {!allowPattern && <span className="topo-muted topo-small">（コンフィグ全体に「必要」なルールでは使えません）</span>}
          </label>
        </div>
        {effectiveMode === "pattern" && (
          <div className="form-group">
            <label className="form-label" htmlFor="x-pattern">
              {rule.scope === "section" ? "除外するセクションの見出し（正規表現）" : "除外する行（正規表現）"}
            </label>
            <input id="x-pattern" className="mono" value={pattern} onChange={(e) => setPattern(e.target.value)}
              placeholder={rule.scope === "section" ? "例: ^interface GigabitEthernet0/(2|3)$" : "例: ^ntp server 10\\.0\\.0\\.100$"} />
            {suggestions.length > 0 && (
              <div className="cmp-suggest">
                <span className="topo-muted topo-small">違反箇所から追加:</span>
                {suggestions.map((p) => (
                  <button key={p} type="button" className="btn btn-sm mono" onClick={() => addSuggestion(p)}>{p}</button>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="x-reason">理由</label>
          <input id="x-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="例: 予備ポートのため / 機器更改まで（チケット #123）" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="x-expires">期限（任意。この日の終わりまで有効）</label>
          <input id="x-expires" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={saving || !canSave}>{saving ? "登録・検査中..." : "登録して再検査"}</button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ ルールの編集

const EMPTY_RULE: RuleInput = {
  name: "", description: "", platforms: [], match_type: "contains", expect: "present", pattern: "",
  scope: "config", section_pattern: "", severity: "medium", enabled: true,
  remediation: "", reference: "", category: "",
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
    remediation: form.remediation?.trim() ? form.remediation : null,
    reference: form.reference?.trim() || null,
    category: form.category || null,
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
        <div className="cmp-row2">
          <div className="form-group">
            <label className="form-label" htmlFor="r-category">分野（任意）</label>
            <select id="r-category" value={form.category ?? ""} onChange={(e) => set("category", e.target.value)}>
              <option value="">指定しない</option>
              {form.category && !CATEGORIES.includes(form.category) && <option value={form.category}>{form.category}</option>}
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="r-ref">根拠（任意。例: 社内標準、一般的な堅牢化の推奨）</label>
            <input id="r-ref" value={form.reference ?? ""} maxLength={255} onChange={(e) => set("reference", e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="r-fix">直し方（任意。設定の例）</label>
          <textarea id="r-fix" className="mono cmp-fix-input" rows={5} maxLength={MAX_REMEDIATION}
            value={form.remediation ?? ""} onChange={(e) => set("remediation", e.target.value)}
            placeholder={"例:\n# 変更前に、別のセッションで SSH ログインできることを確かめてください\nno ip http server"} />
          <p className="topo-muted topo-small" style={{ marginTop: 4 }}>
            違反の一覧で表示・コピーできます。機器へは送りません。パスワードなどの秘密の値は書かず、<code>&lt;パスワード&gt;</code> のようなプレースホルダにしてください。
            「# 」（# と空白）で始まる行は説明として扱い、コピーでは除きます（{(form.remediation ?? "").length} / {MAX_REMEDIATION} 文字）
          </p>
        </div>
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

type Template = RuleInput & { description: string };

function TemplateModal({
  existing, onClose, onAdded,
}: { existing: Set<string>; onClose: () => void; onAdded: (n: number, skipped: number) => void }) {
  const { platforms, label: platformLabel } = usePlatforms();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [platformFilter, setPlatformFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [open, setOpen] = useState<string | null>(null); // 直し方を開いているひな形
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.get("/compliance/templates").then((r) => { setTemplates(r.data); setLoaded(true); }).catch((e) => setError(errorMessage(e)));
  }, []);

  // 機種の選択肢は、ひな形がある機種だけ（メーカーごとにまとめる）
  const platformOptions = useMemo(() => {
    const used = new Set(templates.flatMap((t) => t.platforms));
    const groups = new Map<string, { id: string; label: string }[]>();
    for (const p of platforms.filter((x) => used.has(x.id))) groups.set(p.vendor, [...(groups.get(p.vendor) ?? []), p]);
    return [...groups.entries()];
  }, [templates, platforms]);
  const categories = useMemo(() => CATEGORIES.filter((c) => templates.some((t) => t.category === c)), [templates]);
  const shown = useMemo(
    () => templates.filter((t) => (!platformFilter || t.platforms.length === 0 || t.platforms.includes(platformFilter))
      && (!categoryFilter || t.category === categoryFilter)),
    [templates, platformFilter, categoryFilter]
  );
  const selectable = shown.filter((t) => !existing.has(t.name));
  const pickedShown = shown.filter((t) => picked.has(t.name)).length;
  const setMany = (names: string[], on: boolean) => {
    const s = new Set(picked);
    for (const n of names) { if (on) s.add(n); else s.delete(n); }
    setPicked(s);
  };

  const add = async () => {
    setBusy(true);
    setError("");
    let n = 0;
    let skipped = 0; // 同じ名前のルールが、開いている間にできていたもの
    try {
      for (const t of templates.filter((x) => picked.has(x.name) && !existing.has(x.name))) {
        try {
          await api.post("/compliance/rules", { ...EMPTY_RULE, ...t, section_pattern: t.section_pattern ?? null });
          n++;
        } catch (e) {
          if (axiosStatus(e) === 409) skipped++;
          else throw e;
        }
      }
      onAdded(n, skipped);
      onClose();
    } catch (e) {
      setError(`${n}件追加したところでエラー: ${errorMessage(e)}`);
      if (n) onAdded(n, skipped);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal cmp-modal cmp-modal-wide" role="dialog" aria-label="テンプレートから追加" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">テンプレートから追加</p>
        <p className="topo-muted topo-small" style={{ marginBottom: 10 }}>
          よく使う設定基準のひな形です。機種と分野で絞り込み、まとめて選んで追加できます。追加後に編集できます。
          ひな形は実機では確かめていません（書式は公式ドキュメントと一部を照合したのみで、合格・違反の例は手で書いたものです）。環境に合わせて調整し、直し方は内容を確かめてから投入してください。
        </p>
        <div className="cmp-tpl-filters">
          <label className="audit-field">
            <span className="form-label">機種</span>
            <select value={platformFilter} onChange={(e) => setPlatformFilter(e.target.value)} aria-label="機種で絞り込む">
              <option value="">すべて</option>
              {platformOptions.map(([vendor, list]) => (
                <optgroup key={vendor} label={vendor}>
                  {list.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </optgroup>
              ))}
            </select>
          </label>
          <label className="audit-field">
            <span className="form-label">分野</span>
            <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} aria-label="分野で絞り込む">
              <option value="">すべて</option>
              {categories.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <div className="cmp-tpl-bulk">
            <button type="button" className="btn btn-sm" disabled={!selectable.length}
              onClick={() => setMany(selectable.map((t) => t.name), true)}>表示中をすべて選ぶ</button>
            <button type="button" className="btn btn-sm" disabled={!pickedShown}
              onClick={() => setMany(shown.map((t) => t.name), false)}>表示中の選択を外す</button>
          </div>
        </div>
        <p className="topo-muted topo-small" style={{ margin: "6px 0" }} data-testid="tpl-count">
          {shown.length}件を表示（選択中 {picked.size}件・登録済み {shown.filter((t) => existing.has(t.name)).length}件）
        </p>
        <ul className="cmp-templates" data-testid="tpl-list">
          {shown.map((t) => {
            const exists = existing.has(t.name);
            return (
              <li key={t.name} className="cmp-tpl-item">
                <label className="form-check">
                  <input type="checkbox" disabled={exists} checked={picked.has(t.name)}
                    onChange={(e) => setMany([t.name], e.target.checked)} />
                  <span className="cmp-tpl-body">
                    <span className="cmp-tpl-head">
                      <b>{t.name}</b> <SevBadge s={t.severity} />
                      {t.category && <span className="badge badge-neutral">{t.category}</span>}
                      {exists ? <span className="badge badge-success">登録済み</span> : null}
                    </span>
                    <span className="topo-muted topo-small cmp-tpl-desc">{t.description}</span>
                    <span className="topo-muted topo-small">
                      {t.platforms.length ? t.platforms.map((p) => platformLabel(p)).join("・") : "全機種"}
                    </span>
                  </span>
                </label>
                {t.remediation && (
                  <div className="cmp-tpl-fix">
                    <button type="button" className="link-btn" aria-expanded={open === t.name}
                      onClick={() => setOpen(open === t.name ? null : t.name)}>
                      {open === t.name ? "直し方を閉じる" : "直し方を見る"}
                    </button>
                    {open === t.name && <RemediationPanel remediation={t.remediation} reference={t.reference} category={null} />}
                  </div>
                )}
              </li>
            );
          })}
          {loaded && !shown.length && <li className="topo-muted" style={{ textAlign: "center", padding: 16 }}>条件に合うひな形はありません</li>}
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

/** 直し方・根拠の表示。内容は利用者が書けるので、必ずテキストとして出す（HTML として解釈しない）。機器へは送らない */
function RemediationPanel({
  remediation, reference, category,
}: { remediation: string | null; reference: string | null; category: string | null }) {
  const [msg, setMsg] = useState("");
  const preRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (!msg) return;
    const t = window.setTimeout(() => setMsg(""), 4000);
    return () => window.clearTimeout(t);
  }, [msg]);
  if (!remediation) {
    return <p className="topo-muted topo-small cmp-fix">このルールには直し方が登録されていません（ルールの編集で追加できます）</p>;
  }
  const commands = commandsOf(remediation);
  const copy = async () => {
    if (await copyText(commands)) {
      setMsg("コピーしました");
      return;
    }
    // クリップボードを使えない（http・権限なし）ときは、表示を選択して手動でコピーできるようにする
    try {
      const sel = window.getSelection();
      if (sel && preRef.current) {
        const range = document.createRange();
        range.selectNodeContents(preRef.current);
        sel.removeAllRanges();
        sel.addRange(range);
      }
    } catch {
      // 選択できなくても、表示はそのまま読める
    }
    setMsg("コピーできませんでした。表示を選択して、手動でコピーしてください（「# 」で始まる行は説明です）");
  };
  return (
    <div className="cmp-fix" data-testid="remediation-panel">
      <pre className="cmp-fix-pre mono" ref={preRef} data-testid="remediation-text">{remediation}</pre>
      <div className="cmp-fix-actions">
        <button type="button" className="btn btn-sm" onClick={copy} disabled={!commands}>コマンドをコピー</button>
        {msg && <span className="topo-notice topo-small" role="status">{msg}</span>}
      </div>
      <p className="topo-muted topo-small cmp-fix-note">
        機器へは送りません。内容を確かめてから、ご自身で投入してください。
        {remediation.split("\n").some(isCommentLine) && "「# 」で始まる行は説明で、コピーには含めません。"}
      </p>
      {(reference || category) && (
        <p className="topo-small cmp-fix-meta">
          {category && <span className="badge badge-neutral">{category}</span>}
          {reference && <span>根拠: {reference}</span>}
        </p>
      )}
    </div>
  );
}

// ============================================================ ページ

type Tab = "violations" | "devices" | "rules" | "exceptions";

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
  const [exceptions, setExceptions] = useState<CmpException[]>([]);
  const [excepting, setExcepting] = useState<{ rule: Rule; device: { id: string; name: string } | null; details: string[] } | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [groups, setGroups] = useState<{ id: string; name: string }[]>([]);
  const [groupFilter, setGroupFilter] = useState("");
  const [sevFilter, setSevFilter] = useState<"" | Severity>("");
  const [editing, setEditing] = useState<Rule | RuleInput | null | undefined>(undefined);
  const [showTemplates, setShowTemplates] = useState(false);
  const [openFix, setOpenFix] = useState<string | null>(null); // 直し方を開いている違反（機器:ルール）
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [running, setRunning] = useState(false);

  const load = useCallback(async () => {
    setError("");
    try {
      const [s, r, ru, ex] = await Promise.all([
        api.get<Summary>("/compliance/summary"),
        api.get<Result[]>("/compliance/results", { params: { status: "fail" } }),
        api.get<Rule[]>("/compliance/rules"),
        api.get<CmpException[]>("/compliance/exceptions"),
      ]);
      setSummary(s.data);
      setResults(r.data);
      setRules(ru.data);
      setExceptions(ex.data);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    load();
    api.get<Device[]>("/devices/").then((r) => setDevices(r.data)).catch(() => {});
    api.get<{ id: string; name: string }[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => {});
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

  const removeException = async (x: CmpException) => {
    if (!window.confirm(`ルール「${x.rule_name}」の例外（${x.device_name ?? "全機器"}）を削除しますか？\n削除後に再検査します。`)) return;
    try {
      await api.delete(`/compliance/exceptions/${x.id}`);
      setNotice("例外を削除して再検査しました");
      await load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const ruleById = useMemo(() => new Map(rules.map((r) => [r.id, r])), [rules]);

  const groupOf = useMemo(() => new Map(devices.map((d) => [d.id, d.group_id ?? UNGROUPED])), [devices]);
  const inGroup = (deviceId: string) => !groupFilter || groupOf.get(deviceId) === groupFilter;
  const shown = useMemo(
    () => results.filter((x) => (!deviceFilter || x.device_id === deviceFilter) && (!sevFilter || x.severity === sevFilter)
      && (!groupFilter || groupOf.get(x.device_id) === groupFilter)),
    [results, deviceFilter, sevFilter, groupFilter, groupOf]
  );
  const deviceName = summary?.devices.find((d) => d.device_id === deviceFilter)?.name;
  const violatingDevices = summary?.devices.filter((d) => d.fail_count > 0).length ?? 0;
  const unchecked = summary?.devices.filter((d) => !d.checked).length ?? 0;

  return (
    <div className="page">
      {editing !== undefined && (
        <RuleModal rule={editing} devices={devices} onClose={() => setEditing(undefined)} onSaved={load} />
      )}
      {excepting && (
        <ExceptionModal rule={excepting.rule} device={excepting.device} details={excepting.details} devices={devices}
          onClose={() => setExcepting(null)} onSaved={(m) => { setNotice(m); load(); }} />
      )}
      {showTemplates && (
        <TemplateModal existing={new Set(rules.map((r) => r.name))} onClose={() => setShowTemplates(false)}
          onAdded={(n, skipped) => {
            setNotice(`${n}件のルールを追加しました${skipped ? `（${skipped}件は同じ名前のルールがあり追加しませんでした）` : ""}`);
            load();
          }} />
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
          {([["violations", `違反一覧（${results.length}）`], ["devices", "機器別"], ["rules", `ルール（${rules.length}）`], ["exceptions", `例外（${exceptions.length}）`]] as [Tab, string][]).map(([k, l]) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`seg-tab${tab === k ? " active" : ""}`} onClick={() => setTab(k)}>{l}</button>
          ))}
        </div>

        {tab === "violations" && (
          <>
            <div className="audit-filters">
              <label className="audit-field">
                <span className="form-label">グループ</span>
                <select value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)}>
                  <option value="">すべて</option>
                  {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                  <option value={UNGROUPED}>未分類</option>
                </select>
              </label>
              <label className="audit-field">
                <span className="form-label">機器</span>
                <select value={deviceFilter} onChange={(e) => setParams(e.target.value ? { device: e.target.value } : {})}>
                  <option value="">すべて</option>
                  {summary?.devices.filter((d) => d.fail_count && inGroup(d.device_id)).map((d) => <option key={d.device_id} value={d.device_id}>{d.name}</option>)}
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
                <thead><tr><th>重要度</th><th>機器</th><th>ルール</th><th>違反箇所</th><th>検査</th><th /></tr></thead>
                <tbody>
                  {shown.map((x) => {
                    const key = `${x.device_id}:${x.rule_id}`;
                    const rule = ruleById.get(x.rule_id);
                    return (
                    <Fragment key={key}>
                    <tr>
                      <td><SevBadge s={x.severity} /></td>
                      <td className="nowrap">
                        <button className="link-btn" onClick={() => navigate(`/history?device=${x.device_id}`)} title="コンフィグの世代を見る">{x.device_name}</button>
                        <div className="topo-muted topo-small">{platformLabel(x.platform)}</div>
                      </td>
                      <td className="cmp-rule-name">{x.rule_name}</td>
                      <td><Details items={x.details} /></td>
                      <td className="nowrap topo-small">{fmtDate(x.checked_at)}{x.commit_hash ? <div className="topo-muted mono">{x.commit_hash.slice(0, 8)}</div> : null}</td>
                      <td className="nowrap">
                        <button className="btn btn-sm" aria-expanded={openFix === key} title="違反の直し方と根拠を見る"
                          onClick={() => setOpenFix(openFix === key ? null : key)}>
                          直し方
                        </button>
                        {canWrite && rule && (
                          <>
                            {" "}
                            <button className="btn btn-sm" title="承認済みの逸脱として除外する"
                              onClick={() => setExcepting({ rule, device: { id: x.device_id, name: x.device_name }, details: x.details })}>
                              例外にする
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                    {openFix === key && (
                      <tr className="cmp-fix-row">
                        <td colSpan={6}>
                          <RemediationPanel remediation={rule?.remediation ?? null} reference={rule?.reference ?? null}
                            category={rule?.category ?? null} />
                        </td>
                      </tr>
                    )}
                    </Fragment>
                    );
                  })}
                  {!shown.length && (
                    <tr><td colSpan={6} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>
                      {rules.length ? "違反はありません" : "ルールが登録されていません。「テンプレートから追加」で始められます"}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "devices" && summary && (
          <>
          <div className="audit-filters">
            <label className="audit-field">
              <span className="form-label">グループ</span>
              <select value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)}>
                <option value="">すべて</option>
                {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                <option value={UNGROUPED}>未分類</option>
              </select>
            </label>
          </div>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>機器</th><th>プラットフォーム</th><th>違反</th><th>合格</th><th>除外</th><th>エラー</th><th>最も重い違反</th><th>検査</th></tr></thead>
              <tbody>
                {summary.devices.filter((d) => inGroup(d.device_id)).map((d) => (
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
                    <td>{d.checked ? d.exempt_count : "—"}</td>
                    <td>{d.error_count || (d.checked ? "0" : "—")}</td>
                    <td><SevBadge s={d.worst_severity} /></td>
                    <td className="nowrap topo-small">{d.checked ? fmtDate(d.checked_at) : <span className="topo-muted">未検査</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </>
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
                      {r.category && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>{r.category}</span>}
                      <div className="topo-muted topo-small">{r.description}</div>
                      <div className="topo-small mono cmp-cond">{describe(r)}</div>
                    </td>
                    <td><SevBadge s={r.severity} /></td>
                    <td className="topo-small">{r.platforms.length ? r.platforms.map((p) => platformLabel(p)).join("・") : "全機種"}</td>
                    <td className="nowrap topo-small">
                      <span style={{ color: r.fail_count ? "var(--color-danger)" : undefined }}>違反 {r.fail_count}</span> / 合格 {r.pass_count}
                      {r.exempt_count ? <span> / 除外 {r.exempt_count}</span> : null}
                      {r.error_count ? <span style={{ color: "var(--color-warning)" }}> / エラー {r.error_count}</span> : null}
                      {r.exception_count ? (
                        <div><button className="link-btn" onClick={() => setTab("exceptions")}>例外 {r.exception_count}件</button></div>
                      ) : null}
                    </td>
                    {canWrite && (
                      <td className="nowrap">
                        <button className="btn" onClick={() => setEditing(r)}>編集</button>{" "}
                        <button className="btn" onClick={() => setExcepting({ rule: r, device: null, details: [] })}>例外</button>{" "}
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

        {tab === "exceptions" && (
          <>
            <p className="topo-muted topo-small" style={{ marginBottom: 8 }}>
              承認済みの逸脱です。登録・削除すると対象を再検査します。期限が切れた例外は使われなくなり、5分以内に自動で再検査します。
              追加は「違反一覧」の「例外にする」か、「ルール」の「例外」から行います。
            </p>
            <div className="table-scroll">
              <table className="data-table">
                <thead><tr><th>ルール</th><th>機器</th><th>除外する箇所</th><th>理由</th><th>期限</th><th>登録</th>{canWrite && <th />}</tr></thead>
                <tbody>
                  {exceptions.map((x) => (
                    <tr key={x.id} style={{ opacity: x.expired ? 0.6 : 1 }}>
                      <td>{x.rule_name}</td>
                      <td className="nowrap">{x.device_name ?? <span className="badge badge-neutral">全機器</span>}</td>
                      <td className="mono topo-small">{x.ignore_pattern ?? <span className="topo-muted">（機器単位で除外）</span>}</td>
                      <td>{x.reason}</td>
                      <td className="nowrap topo-small">
                        {x.expires_at ? new Date(/[zZ]|[+-]\d\d:\d\d$/.test(x.expires_at) ? x.expires_at : x.expires_at + "Z").toLocaleDateString("ja-JP") + " まで" : <span className="topo-muted">なし</span>}
                        {x.expired && <span className="badge badge-warning" style={{ marginLeft: 6 }}>期限切れ</span>}
                      </td>
                      <td className="nowrap topo-small">{x.created_by ?? "—"}<div className="topo-muted">{fmtDate(x.created_at)}</div></td>
                      {canWrite && (
                        <td className="nowrap"><button className="btn btn-danger btn-sm" onClick={() => removeException(x)}>削除</button></td>
                      )}
                    </tr>
                  ))}
                  {!exceptions.length && (
                    <tr><td colSpan={7} className="topo-muted" style={{ textAlign: "center", padding: 24 }}>例外は登録されていません</td></tr>
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
