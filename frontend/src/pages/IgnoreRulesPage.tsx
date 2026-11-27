/** 収集時に無視する行: 毎回変わる行（時刻・カウンタなど）を、機種・機器ごとの正規表現で追加して変更扱いにしない（管理者のみ） */
import { useCallback, useEffect, useState } from "react";
import axios from "axios";
import { api, errorMessage } from "../api/client";
import { usePlatforms } from "../platforms";
import HelpLink from "../components/HelpLink";

interface Rule {
  id: string; scope: "platform" | "device"; platform: string | null; platform_label: string | null;
  device_id: string | null; device_name: string | null; pattern: string; description: string | null;
  enabled: boolean; created_by: string | null; updated_by: string | null; updated_at: string | null;
}
interface DeviceItem { id: string; name: string; platform: string; }
interface PreviewDevice {
  device_id: string; device_name: string; has_config: boolean; total_lines: number; matched_lines: number;
  examples: string[]; timeout: boolean;
}
interface Preview { devices: PreviewDevice[]; timeout: boolean; warning: string | null; matched_total: number; }
interface Form { scope: "platform" | "device"; platform: string; device_id: string; pattern: string; description: string; enabled: boolean; }

const EMPTY: Form = { scope: "platform", platform: "", device_id: "", pattern: "", description: "", enabled: true };
const NOTICE = "追加後の最初の収集では、該当の行が消える変更が 1 回記録されます。過去の世代は変わりません";
const HIDDEN_NOTICE = "無視した行は保存されないため、コンプライアンスの検査・コンフィグ検索・基準との比較からも見えなくなります";
const PREVIEW_NOTICE = "保存済みの世代に当てています。すでに有効なルールで消えた行は出ません";
const BROAD_CODE = "ignore_rule_broad";

type RulePayload = { scope: string; platform: string | null; device_id: string | null; pattern: string; description: string | null; enabled: boolean };

/** 保存（追加・更新）。全行の 50% 以上が消える機器があるとサーバーが 409 を返すので、確認してから confirm_broad を付けて送り直す。
 *  確認で取りやめたら false */
async function saveRule(id: string | null, payload: RulePayload): Promise<boolean> {
  const send = (confirm_broad: boolean) => {
    const body = { ...payload, confirm_broad };
    return id ? api.put(`/ignore-rules/${id}`, body) : api.post("/ignore-rules/", body);
  };
  try {
    await send(false);
    return true;
  } catch (e) {
    const detail = axios.isAxiosError(e) && e.response?.status === 409
      ? (e.response.data as { detail?: { code?: string; message?: string } }).detail : undefined;
    if (!detail || detail.code !== BROAD_CODE) throw e;
    if (!window.confirm(`${detail.message}。保存しますか？`)) return false;
    await send(true);
    return true;
  }
}

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "");

function RuleModal({ rule, devices, onClose, onSaved }: {
  rule: Rule | null; devices: DeviceItem[]; onClose: () => void; onSaved: (msg: string) => void;
}) {
  const { groups } = usePlatforms();
  const [form, setForm] = useState<Form>(() => rule
    ? { scope: rule.scope, platform: rule.platform ?? "", device_id: rule.device_id ?? "", pattern: rule.pattern, description: rule.description ?? "", enabled: rule.enabled }
    : EMPTY);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setForm((f) => ({ ...f, [k]: v })); setPreview(null); };
  const targetOk = form.scope === "platform" ? !!form.platform : !!form.device_id;
  const body = () => ({
    scope: form.scope, platform: form.scope === "platform" ? form.platform : null,
    device_id: form.scope === "device" ? form.device_id : null, pattern: form.pattern,
  });

  const test = async () => {
    setBusy(true); setError("");
    try {
      setPreview((await api.post<Preview>("/ignore-rules/preview", body())).data);
    } catch (e) { setPreview(null); setError(errorMessage(e)); } finally { setBusy(false); }
  };
  const save = async () => {
    setBusy(true); setError("");
    try {
      const payload = { ...body(), description: form.description.trim() || null, enabled: form.enabled };
      if (!(await saveRule(rule ? rule.id : null, payload))) { setBusy(false); return; }
      onSaved(rule ? "ルールを更新しました。" : "ルールを追加しました。次の収集から効きます。");
    } catch (e) { setError(errorMessage(e)); setBusy(false); }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal cmp-modal" role="dialog" aria-label={rule ? "ルールの編集" : "ルールの追加"} onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{rule ? "無視する行の編集" : "無視する行の追加"}</p>
        <div className="cmp-row3" style={{ gridTemplateColumns: "0.7fr 1.3fr" }}>
          <div className="form-group">
            <label className="form-label" htmlFor="ig-scope">対象</label>
            <select id="ig-scope" value={form.scope} onChange={(e) => set("scope", e.target.value as Form["scope"])}>
              <option value="platform">機種</option>
              <option value="device">機器</option>
            </select>
          </div>
          <div className="form-group">
            {form.scope === "platform" ? (
              <>
                <label className="form-label" htmlFor="ig-platform">機種（この機種のすべての機器に効きます）</label>
                <select id="ig-platform" value={form.platform} onChange={(e) => set("platform", e.target.value)}>
                  <option value="">選択してください</option>
                  {groups.map(([vendor, list]) => (
                    <optgroup key={vendor} label={vendor}>{list.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}</optgroup>
                  ))}
                </select>
              </>
            ) : (
              <>
                <label className="form-label" htmlFor="ig-device">機器</label>
                <select id="ig-device" value={form.device_id} onChange={(e) => set("device_id", e.target.value)}>
                  <option value="">選択してください</option>
                  {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </>
            )}
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="ig-pattern">正規表現（1 行ごとに、一致した行を保存しません）</label>
          <input id="ig-pattern" className="mono" value={form.pattern} maxLength={500} onChange={(e) => set("pattern", e.target.value)}
            placeholder="例: ^! Last configuration change at " />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="ig-desc">説明（任意）</label>
          <input id="ig-desc" value={form.description} maxLength={200} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            placeholder="例: 時刻の同期のたびに変わる行" />
        </div>
        <label className="form-check" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
          有効（無効にすると収集で使いません）
        </label>

        <div className="cmp-test">
          <span className="form-label">保存前に試す（対象の機器の最新の世代に当てます。保存はしません）</span>
          <button className="btn" onClick={test} disabled={busy || !form.pattern || !targetOk}>{busy ? "確認中..." : "試す"}</button>
          {preview && (
            <div className="ign-preview" aria-label="試した結果">
              <p className="topo-muted topo-small">{PREVIEW_NOTICE}</p>
              {preview.warning && <p className="form-error" role="alert">{preview.warning}</p>}
              {preview.timeout && <p className="form-error">照合が時間切れになった機器があります。正規表現を単純にしてください。</p>}
              {!preview.devices.length && <p className="topo-muted topo-small">対象の機器がありません。</p>}
              {preview.devices.map((d) => (
                <div key={d.device_id} className="ign-preview-dev">
                  <div>
                    <b>{d.device_name}</b>{" "}
                    {!d.has_config ? <span className="topo-muted topo-small">まだ収集されていません</span>
                      : d.timeout ? <span className="badge badge-warning">時間切れ</span>
                      : <span className={`badge ${d.matched_lines ? "badge-success" : "badge-neutral"}`}>{d.matched_lines} / {d.total_lines} 行が一致</span>}
                  </div>
                  {d.examples.length > 0 && (
                    <pre className="ign-examples">{d.examples.join("\n")}</pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
        <p className="topo-muted topo-small" style={{ marginTop: 10 }}>{NOTICE}。{HIDDEN_NOTICE}。</p>
        {error && <p className="form-error" style={{ marginTop: 10 }}>{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={busy || !form.pattern || !targetOk}>保存</button>
        </div>
      </div>
    </div>
  );
}

export default function IgnoreRulesPage() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [modal, setModal] = useState<{ rule: Rule | null } | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(() => {
    api.get<Rule[]>("/ignore-rules/").then((r) => { setRules(r.data); setError(""); }).catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(() => {
    load();
    api.get<DeviceItem[]>("/devices/").then((r) => setDevices(r.data)).catch(() => undefined);
  }, [load]);

  const remove = async (r: Rule) => {
    if (!window.confirm(`「${r.pattern}」を削除しますか？\n削除後の最初の収集では、これまで消していた行が戻る変更が 1 回記録されます。`)) return;
    try { await api.delete(`/ignore-rules/${r.id}`); setError(""); setMessage("削除しました。"); load(); } catch (e) { setError(errorMessage(e)); }
  };
  const toggle = async (r: Rule) => {
    try {
      // 有効にするときも、全行の 50% 以上が消える機器があれば確認する
      if (!(await saveRule(r.id, { scope: r.scope, platform: r.platform, device_id: r.device_id, pattern: r.pattern, description: r.description, enabled: !r.enabled }))) return;
      setError("");
      load();
    } catch (e) { setError(errorMessage(e)); }
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">無視する行<HelpLink topic="ignore-rules" /></span>
        <span className="topo-muted topo-small">毎回変わる行（時刻・カウンタなど）を、正規表現で収集の対象から外します</span>
        <button className="btn btn-primary" style={{ marginLeft: "auto" }} onClick={() => { setMessage(""); setModal({ rule: null }); }}>ルールを追加</button>
      </div>
      <div className="page-body">
        <p className="topo-muted topo-small" style={{ marginBottom: 10 }}>
          一致した行は、収集のたびに保存前に取り除きます（機種ごとの組み込みの除外に加えて適用）。{NOTICE}。{HIDDEN_NOTICE}。
        </p>
        {error && <p className="form-error">{error}</p>}
        {message && <p className="review-message">{message}</p>}
        {rules && !rules.length ? (
          <p className="topo-muted">ルールはまだありません。「ルールを追加」から登録してください。</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>対象</th><th>正規表現</th><th>説明</th><th>状態</th><th>更新</th><th>操作</th></tr></thead>
            <tbody>
              {(rules ?? []).map((r) => (
                <tr key={r.id}>
                  <td>
                    <span className={`badge ${r.scope === "platform" ? "badge-neutral" : "badge-success"}`}>{r.scope === "platform" ? "機種" : "機器"}</span>{" "}
                    {r.scope === "platform" ? r.platform_label : r.device_name}
                  </td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>{r.pattern}</td>
                  <td className="topo-small">{r.description}</td>
                  <td>
                    <button className={`badge review-badge-btn ${r.enabled ? "badge-success" : "badge-neutral"}`} title="クリックで有効・無効を切り替え" onClick={() => toggle(r)}>
                      {r.enabled ? "有効" : "無効"}
                    </button>
                  </td>
                  <td className="nowrap topo-small">{fmt(r.updated_at)}{r.updated_by ? ` · ${r.updated_by}` : ""}</td>
                  <td>
                    <div className="hist-actions">
                      <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => { setMessage(""); setModal({ rule: r }); }}>編集</button>
                      <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => remove(r)}>削除</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {modal && (
        <RuleModal rule={modal.rule} devices={devices} onClose={() => setModal(null)}
          onSaved={(m) => { setModal(null); setMessage(m); load(); }} />
      )}
    </div>
  );
}
