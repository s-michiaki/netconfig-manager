import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import { CsvButton, downloadCsv } from "../components/CsvButton";

/**
 * 脆弱性・サポート期限: 機器の OS バージョンを、ベンダーの勧告（Palo Alto・Fortinet）・悪用確認済み一覧（CISA KEV）・
 * サポート終了日（endoflife.date と手入力）と照合した結果。.env の VULN_ENABLED=true のときだけメニューに出る。
 * 外部から来た文字列（勧告の題・URL）はテキストとして表示し、リンクは https のものだけ rel="noopener noreferrer" の新しいタブで開く。
 * 画面はタブで分ける: 脆弱性 / 機器別 / サポート期限 / 判定できない機器
 */

type Severity = "critical" | "high" | "medium" | "low" | "none";
type State = "open" | "ack" | "fixed";
interface Advisory {
  id: string; ext_id: string; cve_ids: string[]; title: string; severity: Severity; cvss: number | null;
  url: string | null; kev: boolean; kev_due: string | null; published_at: string | null; rejected?: boolean;
  provisional?: boolean; // final でない文書（暫定の勧告）
}
interface Notice { ext_id: string; title: string; published_at: string | null; modified_at: string | null; url: string | null; }
interface Match {
  id: string; device_id: string; device_name: string; group_name: string | null; os_version: string | null;
  confidence: "confirmed" | "candidate"; state: State; note: string | null; acked_by: string | null; acked_at: string | null;
  first_seen: string | null; advisory: Advisory; candidate_reason: string | null; candidate_code?: string | null;
}
interface MatchList { total: number; limit: number; offset: number; items: Match[]; }
interface SourceInfo { source: string; label: string; last_at: string | null; last_ok_at: string | null; last_error: string | null; last_count: number | null; skipped: number | null; }
interface Coverage {
  source: string; label: string; count: number; documents: number; pending: number; oldest: string | null; newest: string | null;
}
interface Summary {
  counts: Record<Severity, number> & { kev: number; candidate: number; acked: number; candidate_not_listed?: number };
  coverage?: Coverage[];
  notices?: { count: number; recent: number; items: Notice[] }; // 要確認の告知（製品の記載が無く、機器を特定できない勧告）
  eol: { ended: number; soon: number }; devices: number; unknown_devices: number;
  sources: SourceInfo[]; unknown_sources: string[]; fetch_hour: number;
  range_unreadable: { devices: number; pairs: number; advisories: number; stale?: number };
}
interface DeviceRow {
  device_id: string; name: string; group_name: string | null; model: string | null; os_version: string | null;
  open: number; acked: number; kev: number; critical: number; high: number; medium: number; low: number; none: number;
}
interface Eol {
  id: string; eol_date: string; days_left: number; source: string; url: string | null; note: string | null;
  branch: string; model: string; eos_date: string | null;
}
interface EolDevice {
  device_id: string; name: string; group_name: string | null; platform: string; model: string | null; os_version: string | null;
  branch: string | null; os: Eol | null; hardware: Eol | null; reason: string | null; days_left: number | null;
}
interface StaleMatch { advisory: string; previous_version: string | null; state: string; note: string | null; label: string; }
interface RangeUnreadable {
  device_id: string; name: string; group_name: string | null; os_version: string | null; count: number; advisories: string[];
  stale?: StaleMatch[]; stale_count?: number;
}
interface UnknownDevice { device_id: string; name: string; group_name: string | null; platform_label: string; model: string | null; os_version: string | null; reason: string; reason_label: string; }
interface Group { id: string; name: string; }

const TABS = [
  { key: "matches", label: "脆弱性" }, { key: "devices", label: "機器別" },
  { key: "eol", label: "サポート期限" }, { key: "unknown", label: "判定できない機器" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const SEV_LABEL: Record<Severity, string> = { critical: "重大", high: "高", medium: "中", low: "低", none: "不明" };
const SEV_BADGE: Record<Severity, string> = {
  critical: "badge-danger", high: "badge-danger", medium: "badge-warning", low: "badge-neutral", none: "badge-neutral",
};
const STATES: { key: State | "all"; label: string }[] = [
  { key: "open", label: "未確認" }, { key: "ack", label: "確認済み" }, { key: "fixed", label: "解消" }, { key: "all", label: "すべて" },
];
const PAGE = 50;
const NOTE_MAX = 500;

const fmt = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";
const fmtDay = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleDateString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit" }) : "—";
// 勧告に載っていない系列による候補（勧告に載っていない系列・勧告より新しい系列）。既定で折りたたむ
const NOT_LISTED = ["not_listed", "newer_branch"];

/** 配列は同じ名前を繰り返す形（reason=a&reason=b）で送る（axios の既定の reason[]= は API が読まない） */
function toQuery(params: Record<string, unknown>): URLSearchParams {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    for (const x of Array.isArray(v) ? v : [v]) q.append(k, String(x));
  }
  return q;
}

// 出典としてリンクにしてよいホスト（サーバーの許可リストと同じ。https だけ）
const LINK_HOSTS = ["security.paloaltonetworks.com", "www.fortiguard.com", "www.cisa.gov", "endoflife.date"];

/** 出典へのリンク。https で、決まったホストの URL だけ（それ以外はリンクにしない） */
function SafeLink({ url, children }: { url: string | null; children: React.ReactNode }) {
  let ok = false;
  try {
    const u = url ? new URL(url) : null;
    ok = !!u && u.protocol === "https:" && LINK_HOSTS.includes(u.hostname) && !u.username && !u.password && !u.port;
  } catch {
    ok = false;
  }
  if (ok && url) return <a href={url} target="_blank" rel="noopener noreferrer">{children}</a>;
  return <>{children}</>;
}

function DaysBadge({ days }: { days: number | null }) {
  if (days === null) return <span className="topo-muted">—</span>;
  if (days < 0) return <span className="badge badge-danger">終了済み（{-days} 日前）</span>;
  const cls = days <= 90 ? "badge-danger" : days <= 365 ? "badge-warning" : "badge-neutral";
  return <span className={`badge ${cls}`}>あと {days} 日</span>;
}

// ---------------------------------------------------------------- 確認済みにする（メモ必須）

function AckModal({ match, onClose, onDone }: { match: Match; onClose: () => void; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await api.post(`/vulns/matches/${match.id}/ack`, { note: note.trim() });
      onDone();
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" role="dialog" aria-label="確認済みにする" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">確認済みにする</p>
        <p className="hist-note">
          <b>{match.device_name}</b>（{match.os_version ?? "—"}）の <span className="mono">{match.advisory.ext_id}</span> を、
          対応不要・対応済みの予定として「確認済み」にします。誰がいつ付けたかは監査ログに残ります。バージョンが上がって影響範囲から外れると「解消」になります。
        </p>
        <div className="form-group">
          <label className="form-label" htmlFor="vuln-ack-note">メモ（必須・{NOTE_MAX} 文字まで）</label>
          <textarea id="vuln-ack-note" rows={4} maxLength={NOTE_MAX} value={note} onChange={(e) => setNote(e.target.value)}
            placeholder="例: 管理画面は社内の管理用ネットワークからしか届かないため。次回のメンテナンスで修正版へ上げる" />
          <p className="hist-note" style={{ marginTop: 4 }}>{note.length} / {NOTE_MAX} 文字。パスワードなどの秘密情報は書かないでください</p>
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" disabled={busy || !note.trim()} onClick={submit}>確認済みにする</button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- 脆弱性の一覧

function MatchesTab({ groups, canWrite, deviceId, onDevice, notListed }: {
  groups: Group[]; canWrite: boolean; deviceId: string; onDevice: (id: string) => void; notListed: number;
}) {
  const [state, setState] = useState<State | "all">("open");
  const [severity, setSeverity] = useState("");
  const [groupId, setGroupId] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  // 判定: すべて / 該当だけ / 候補だけ / 候補のうち「勧告に載っていない系列」だけ
  const [judge, setJudge] = useState<"" | "confirmed" | "candidate" | "not_listed">("");
  // 「勧告に載っていない系列」による候補は、既定で折りたたむ（多くなりやすいため。件数は出す）
  const [showNotListed, setShowNotListed] = useState(false);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<MatchList | null>(null);
  const [ack, setAck] = useState<Match | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const hideNotListed = !showNotListed && judge !== "not_listed" && judge !== "confirmed";
  const params = useCallback(() => ({
    state, severity: severity || undefined, group_id: groupId || undefined, device_id: deviceId || undefined,
    kev: kevOnly ? true : undefined,
    confidence: judge === "confirmed" ? "confirmed" : judge ? "candidate" : undefined,
    reason: judge === "not_listed" ? NOT_LISTED : undefined,
    hide_reason: hideNotListed ? NOT_LISTED : undefined,
  }), [state, severity, groupId, deviceId, kevOnly, judge, hideNotListed]);
  const load = useCallback(() => {
    api.get<MatchList>("/vulns/matches", { params: toQuery({ ...params(), limit: PAGE, offset }) })
      .then((r) => { setData(r.data); setError(""); })
      .catch((e) => setError(errorMessage(e)));
  }, [params, offset]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { setOffset(0); }, [state, severity, groupId, deviceId, kevOnly, judge, showNotListed]);

  const unack = async (m: Match) => {
    setError("");
    try {
      await api.post(`/vulns/matches/${m.id}/unack`);
      setMessage(`${m.device_name} の ${m.advisory.ext_id} を未確認に戻しました`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const items = data?.items ?? [];
  return (
    <>
      <div className="review-filters">
        <div className="seg-tabs" role="tablist" aria-label="状態">
          {STATES.map((s) => (
            <button key={s.key} role="tab" aria-selected={state === s.key} className={`seg-tab${state === s.key ? " active" : ""}`}
              onClick={() => setState(s.key)}>{s.label}</button>
          ))}
        </div>
        <label className="audit-field">
          <span className="form-label">重大度</span>
          <select aria-label="重大度" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">すべて</option>
            {(["critical", "high", "medium", "low"] as Severity[]).map((s) => <option key={s} value={s}>{SEV_LABEL[s]}</option>)}
          </select>
        </label>
        <label className="audit-field">
          <span className="form-label">機器グループ</span>
          <select aria-label="機器グループ" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">すべて</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </label>
        <label className="audit-field">
          <span className="form-label">判定</span>
          <select aria-label="判定" value={judge} onChange={(e) => setJudge(e.target.value as typeof judge)}>
            <option value="">すべて</option>
            <option value="confirmed">該当だけ</option>
            <option value="candidate">候補だけ</option>
            <option value="not_listed">候補（勧告に載っていない系列・勧告より新しい系列）だけ</option>
          </select>
        </label>
        <label className="vuln-check">
          <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> 悪用確認済みだけ
        </label>
        {deviceId && (
          <button className="btn btn-sm" onClick={() => onDevice("")} title="機器の絞り込みを外す">
            機器で絞り込み中: {items[0]?.device_name ?? "…"} ×
          </button>
        )}
        <span style={{ flex: 1 }} />
        <CsvButton onClick={() => downloadCsv("/vulns/matches/export", toQuery(params()) as unknown as Record<string, unknown>, "vulns.csv")} />
      </div>
      {error && <p className="form-error">{error}</p>}
      {message && <p className="review-message">{message}</p>}
      {hideNotListed && notListed > 0 && state === "open" && (
        <p className="hist-note vuln-folded" data-testid="vuln-not-listed-folded">
          勧告のデータに機器の系列が載っていない（勧告より新しい系列を含む）ための「候補」{notListed} 件を折りたたんでいます
          （新しい系列の機器に、古い勧告が当たることが多いものです）。
          <button className="btn btn-sm" style={{ marginLeft: 8 }} onClick={() => setShowNotListed(true)}>表示する</button>
        </p>
      )}
      {showNotListed && judge !== "not_listed" && (
        <p className="hist-note">
          勧告に載っていない系列による候補も表示しています。
          <button className="btn btn-sm" style={{ marginLeft: 8 }} onClick={() => setShowNotListed(false)}>折りたたむ</button>
        </p>
      )}
      {data && !items.length ? (
        <p className="topo-muted">{state === "open" ? "未確認の該当はありません。" : "該当する記録はありません。"}</p>
      ) : (
        // 幅が狭いときは表を横にスクロールさせる（折り返せる列が 1 文字幅まで潰れないよう、機器・勧告の列に最小幅を付ける）
        <div className="table-scroll">
        <table className="data-table vuln-table">
          <thead>
            <tr><th>機器</th><th>勧告</th><th>重大度</th><th>悪用確認済み</th><th>判定</th><th>状態・メモ</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.id} className="vuln-row">
                <td style={{ minWidth: "9em" }}>
                  <b>{m.device_name}</b>
                  <div className="topo-muted topo-small">{m.os_version ?? "—"}{m.group_name ? `・${m.group_name}` : ""}</div>
                </td>
                <td className="vuln-title" style={{ minWidth: "14em" }}>
                  <SafeLink url={m.advisory.url}><span className="mono">{m.advisory.ext_id}</span></SafeLink>
                  {m.advisory.provisional && (
                    <span className="badge badge-warning" data-testid="vuln-provisional" style={{ marginLeft: 6 }}
                      title="勧告の文書が確定版（final）ではありません。内容が変わることがあります">暫定の勧告</span>
                  )}
                  {m.advisory.rejected && (
                    <span className="badge badge-neutral" data-testid="vuln-rejected" style={{ marginLeft: 6 }}
                      title="ベンダーが勧告を取り下げました。照合には使わず、この勧告の判定は解消にしています">取り下げ</span>
                  )}
                  <div>{m.advisory.title}</div>
                  {m.advisory.cve_ids.length > 0 && m.advisory.cve_ids[0] !== m.advisory.ext_id && (
                    <div className="topo-muted topo-small">{m.advisory.cve_ids.join(" ")}</div>
                  )}
                </td>
                <td className="nowrap">
                  <span className={`badge ${SEV_BADGE[m.advisory.severity]}`}>{SEV_LABEL[m.advisory.severity]}</span>
                  {m.advisory.cvss !== null && <span className="topo-muted topo-small"> {m.advisory.cvss.toFixed(1)}</span>}
                </td>
                <td>
                  {m.advisory.kev
                    ? <>
                      <span className="badge badge-danger nowrap" title="CISA が、実際に悪用されていることを確認している脆弱性です">悪用確認済み</span>
                      {m.advisory.kev_due && <div className="topo-muted topo-small nowrap">期限 {m.advisory.kev_due}</div>}
                    </>
                    : <span className="topo-muted">—</span>}
                </td>
                <td>
                  <span className="nowrap">
                    {m.confidence === "confirmed"
                      ? <span className="badge badge-neutral" title="ベンダーの勧告の影響範囲と、機器の OS バージョンの照合で判定しました">該当</span>
                      : <span className="badge badge-warning" title={m.candidate_reason ?? "候補です。該当しない場合があります"}>候補</span>}
                  </span>
                  {/* 理由の文は折り返す（nowrap の中に入れると、列が文の長さまで広がって表が崩れる） */}
                  {m.confidence === "candidate" && m.candidate_reason && (
                    <div className="topo-muted topo-small" style={{ maxWidth: "20em", minWidth: "12em", whiteSpace: "normal" }}>{m.candidate_reason}</div>
                  )}
                </td>
                <td>
                  <span className={`badge nowrap ${m.state === "open" ? "badge-warning" : m.state === "ack" ? "badge-success" : "badge-neutral"}`}>
                    {STATES.find((s) => s.key === m.state)?.label}</span>
                  {m.state === "fixed" && m.advisory.rejected && <div className="topo-muted topo-small">勧告の取り下げで解消</div>}
                  {m.note && <div className="review-comment" title={m.note}>{m.note}</div>}
                  {m.acked_by && <div className="topo-muted topo-small">{m.acked_by}・{fmt(m.acked_at)}</div>}
                </td>
                <td>
                  <div className="hist-actions">
                    <button className="btn btn-sm" onClick={() => onDevice(m.device_id)}>この機器だけ</button>
                    {canWrite && m.state === "open" && <button className="btn btn-sm" onClick={() => setAck(m)}>確認済みにする</button>}
                    {canWrite && m.state === "ack" && <button className="btn btn-sm" onClick={() => unack(m)}>未確認に戻す</button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {data && data.total > PAGE && (
        <div className="btn-row" style={{ justifyContent: "flex-start", alignItems: "center", marginTop: 10 }}>
          <button className="btn btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>前へ</button>
          <span className="topo-muted topo-small">{offset + 1}〜{Math.min(offset + PAGE, data.total)} / {data.total} 件</span>
          <button className="btn btn-sm" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>次へ</button>
        </div>
      )}
      {ack && <AckModal match={ack} onClose={() => setAck(null)}
        onDone={() => { setMessage(`${ack.device_name} の ${ack.advisory.ext_id} を確認済みにしました`); setAck(null); load(); }} />}
    </>
  );
}

// ---------------------------------------------------------------- 機器別

function DevicesTab({ onOpen }: { onOpen: (deviceId: string) => void }) {
  const [rows, setRows] = useState<DeviceRow[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.get<{ items: DeviceRow[] }>("/vulns/devices").then((r) => setRows(r.data.items)).catch((e) => setError(errorMessage(e)));
  }, []);
  return (
    <>
      {error && <p className="form-error">{error}</p>}
      {rows && !rows.length && <p className="topo-muted">脆弱性を判定できた機器がありません（OS バージョンが読み取れている Palo Alto・Fortinet の機器が対象です）。</p>}
      {rows && rows.length > 0 && (
        <table className="data-table">
          <thead><tr><th>機器</th><th>OS バージョン</th><th>重大</th><th>高</th><th>中</th><th>低</th><th>悪用確認済み</th><th>確認済み</th><th /></tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.device_id}>
                <td><b>{d.name}</b><div className="topo-muted topo-small">{d.group_name ?? ""}{d.model ? `${d.group_name ? "・" : ""}${d.model}` : ""}</div></td>
                <td className="mono">{d.os_version}</td>
                <td>{d.critical || "—"}</td><td>{d.high || "—"}</td><td>{d.medium || "—"}</td><td>{d.low + d.none || "—"}</td>
                <td>{d.kev ? <span className="badge badge-danger">{d.kev}</span> : "—"}</td>
                <td>{d.acked || "—"}</td>
                <td><button className="btn btn-sm" disabled={!d.open && !d.acked} onClick={() => onOpen(d.device_id)}>一覧を見る</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// ---------------------------------------------------------------- サポート期限（手入力を含む）

interface EolEdit { device: EolDevice; kind: "os" | "hardware"; }

function EolModal({ edit, onClose, onDone }: { edit: EolEdit; onClose: () => void; onDone: () => void }) {
  const d = edit.device;
  const cur = edit.kind === "os" ? d.os : d.hardware;
  const [branch, setBranch] = useState(edit.kind === "os" ? (d.branch ?? "*") : "");
  const [model, setModel] = useState(edit.kind === "hardware" ? (d.model ?? "") : "");
  const [eol, setEol] = useState(cur?.eol_date ?? "");
  const [eos, setEos] = useState(cur?.eos_date ?? "");
  const [note, setNote] = useState(cur?.source === "manual" ? (cur.note ?? "") : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await api.put("/vulns/eol", {
        platform: d.platform, kind: edit.kind, branch: edit.kind === "os" ? branch : "", model: edit.kind === "hardware" ? model : "",
        eol_date: eol, eos_date: eos || null, note: note.trim() || null,
      });
      onDone();
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" role="dialog" aria-label="サポート終了日の手入力" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">サポート終了日を手入力する（{edit.kind === "os" ? "OS" : "ハードウェア"}）</p>
        <p className="hist-note">
          手入力した日付は、自動取得した日付より優先します（同じ機種・{edit.kind === "os" ? "リリース系列" : "モデル"}の機器すべてに使います）。
          ベンダーの案内（延長保守の契約など）で日付が分かっているときに入れてください。
        </p>
        {edit.kind === "os" ? (
          <div className="form-group">
            <label className="form-label" htmlFor="eol-branch">リリース系列（例: 10.2。その機種のすべては *）</label>
            <input id="eol-branch" value={branch} maxLength={32} onChange={(e) => setBranch(e.target.value)} />
          </div>
        ) : (
          <div className="form-group">
            <label className="form-label" htmlFor="eol-model">モデル</label>
            <input id="eol-model" value={model} maxLength={128} onChange={(e) => setModel(e.target.value)} />
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="eol-date">サポート終了日</label>
          <input id="eol-date" type="date" value={eol} onChange={(e) => setEol(e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="eos-date">販売終了・セキュリティ修正の終了日（任意）</label>
          <input id="eos-date" type="date" value={eos} onChange={(e) => setEos(e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="eol-note">メモ（任意）</label>
          <input id="eol-note" value={note} maxLength={NOTE_MAX} onChange={(e) => setNote(e.target.value)} placeholder="例: 延長保守契約（〜2028/1）" />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" disabled={busy || !eol || (edit.kind === "os" ? !branch.trim() : !model.trim())} onClick={submit}>保存</button>
        </div>
      </div>
    </div>
  );
}

function EolCell({ e, canWrite, onEdit, onRemove }: { e: Eol | null; canWrite: boolean; onEdit: () => void; onRemove: () => void }) {
  return (
    <div>
      {e ? (
        <>
          <span className="nowrap">{e.eol_date}</span> <DaysBadge days={e.days_left} />
          <div className="topo-muted topo-small">
            {e.source === "manual" ? "手入力" : <SafeLink url={e.url}>自動取得（endoflife.date）</SafeLink>}{e.note ? `・${e.note}` : ""}
          </div>
        </>
      ) : <span className="topo-muted">—</span>}
      {canWrite && (
        <div className="hist-actions">
          <button className="btn btn-sm" onClick={onEdit}>{e ? "手入力で上書き" : "手入力する"}</button>
          {e?.source === "manual" && <button className="btn btn-sm" onClick={onRemove}>手入力を消す</button>}
        </div>
      )}
    </div>
  );
}

function EolTab({ canWrite }: { canWrite: boolean }) {
  const [rows, setRows] = useState<EolDevice[] | null>(null);
  const [edit, setEdit] = useState<EolEdit | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const load = useCallback(() => {
    api.get<{ items: EolDevice[] }>("/vulns/eol/devices").then((r) => { setRows(r.data.items); setError(""); }).catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(() => { load(); }, [load]);
  const remove = async (id: string) => {
    setError("");
    try {
      await api.delete(`/vulns/eol/${id}`);
      setMessage("手入力のサポート終了日を消しました（自動取得の日付があればそちらを使います）");
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  return (
    <>
      <p className="hist-note">
        機器の OS のリリース系列ごとのサポート終了日です（残りが短い順）。自動取得は PAN-OS・FortiOS・Cisco IOS XE が対象で、
        それ以外の機種（Junos・NX-OS・EOS など）や、ベンダーの案内と違うときは手入力で登録できます。バージョンを読み取れない機種は、系列に * を入れて「その機種のすべて」として登録できます。ハードウェア（モデル）のサポート終了日は手入力だけです。
      </p>
      {error && <p className="form-error">{error}</p>}
      {message && <p className="review-message">{message}</p>}
      {rows && (
        <table className="data-table">
          <thead><tr><th>機器</th><th>OS バージョン</th><th>OS のサポート終了日</th><th>ハードウェアのサポート終了日</th></tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.device_id} className="eol-row">
                <td><b>{d.name}</b><div className="topo-muted topo-small">{d.group_name ?? ""}{d.model ? `${d.group_name ? "・" : ""}${d.model}` : ""}</div></td>
                <td><span className="mono">{d.os_version ?? "—"}</span>{d.branch && <div className="topo-muted topo-small">系列 {d.branch}</div>}</td>
                <td>
                  {/* バージョンを読み取れない機種も、系列「*」（その機種のすべて）で手入力できる */}
                  <EolCell e={d.os} canWrite={canWrite} onEdit={() => setEdit({ device: d, kind: "os" })} onRemove={() => d.os && remove(d.os.id)} />
                </td>
                <td>
                  {d.model
                    ? <EolCell e={d.hardware} canWrite={canWrite} onEdit={() => setEdit({ device: d, kind: "hardware" })} onRemove={() => d.hardware && remove(d.hardware.id)} />
                    : <span className="topo-muted">モデルを読み取れていません</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {edit && <EolModal edit={edit} onClose={() => setEdit(null)} onDone={() => { setEdit(null); setMessage("サポート終了日を保存しました"); load(); }} />}
    </>
  );
}

// ---------------------------------------------------------------- 判定できない機器

function UnknownTab() {
  const [rows, setRows] = useState<UnknownDevice[] | null>(null);
  const [ranges, setRanges] = useState<RangeUnreadable[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api.get<{ items: UnknownDevice[]; range_unreadable: RangeUnreadable[] }>("/vulns/unknown")
      .then((r) => { setRows(r.data.items); setRanges(r.data.range_unreadable ?? []); })
      .catch((e) => setError(errorMessage(e)));
  }, []);
  return (
    <>
      <p className="hist-note">脆弱性を判定できていない機器です。誤って「該当」「非該当」にしないよう、読み取れないバージョン・対象外の機種は照合していません。</p>
      {error && <p className="form-error">{error}</p>}
      {rows && !rows.length && !ranges.length && <p className="topo-muted">判定できない機器はありません。</p>}
      {ranges.length > 0 && (
        <>
          <p className="hist-note">
            勧告の影響範囲を読み取れなかったため、その勧告を該当・非該当のどちらにも判定していない機器です（勧告の書き方が想定と違うとき。
            ベンダーの公式の案内で確認してください）。
          </p>
          <table className="data-table" data-testid="vuln-range-unreadable">
            <thead><tr><th>機器</th><th>OS バージョン</th><th>範囲を読み取れなかった勧告</th></tr></thead>
            <tbody>
              {ranges.map((r) => (
                <tr key={r.device_id}>
                  <td><b>{r.name}</b><div className="topo-muted topo-small">{r.group_name ?? ""}</div></td>
                  <td className="mono">{r.os_version ?? "—"}</td>
                  <td>
                    {r.count > 0 && <>範囲を読み取れなかった勧告が {r.count} 件あります<div className="topo-muted topo-small mono">{r.advisories.join(" ")}{r.count > r.advisories.length ? " …" : ""}</div></>}
                    {(r.stale ?? []).map((x) => (
                      <div key={x.advisory} className="topo-small" data-testid="vuln-stale">
                        <span className="mono">{x.advisory}</span>: {x.label}
                        {x.state === "ack" && <span className="topo-muted">（確認済み{x.note ? `: ${x.note}` : ""}）</span>}
                      </div>
                    ))}
                    {(r.stale_count ?? 0) > (r.stale ?? []).length && (
                      <div className="topo-muted topo-small">ほか {(r.stale_count ?? 0) - (r.stale ?? []).length} 件</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {rows && rows.length > 0 && (
        <table className="data-table">
          <thead><tr><th>機器</th><th>機種</th><th>OS バージョン</th><th>理由</th></tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.device_id}>
                <td><b>{d.name}</b><div className="topo-muted topo-small">{d.group_name ?? ""}</div></td>
                <td>{d.platform_label}{d.model ? <div className="topo-muted topo-small">{d.model}</div> : null}</td>
                <td className="mono">{d.os_version ?? "—"}</td>
                <td>{d.reason_label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// ---------------------------------------------------------------- 取得済みの範囲・過去の勧告の取り込み（Fortinet）

interface ImportResult { ext_id: string; ok: boolean; result: string; message: string; }
interface ImportState {
  status: "queued" | "done" | "busy" | "error"; by?: string | null; ids?: string[]; at?: string; finished_at?: string;
  message?: string; results?: ImportResult[];
}

/** 要確認の告知: 製品の記載が無く、機器を特定できない勧告（NGINX・Java などの告知）。機器ごとの件数には入れない */
function NoticesPanel({ notices }: { notices: { count: number; recent: number; items: Notice[] } }) {
  const [open, setOpen] = useState(false);
  if (!notices.count) return null;
  return (
    <div className="hist-note vuln-notices" data-testid="vuln-notices">
      <span>
        要確認の告知（製品の記載が無く、機器を特定できない勧告）が <b>{notices.count} 件</b>あります
        {notices.recent ? `（直近 30 日に公開 ${notices.recent} 件）` : ""}。機器ごとの件数には数えていません。勧告のページで、自分の機器に関係するかを確かめてください。
      </span>
      <button className="btn btn-sm" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "閉じる" : "一覧を見る"}</button>
      {open && (
        <ul className="vuln-notice-list">
          {notices.items.map((n) => (
            <li key={n.ext_id}>
              <SafeLink url={n.url}><span className="mono">{n.ext_id}</span></SafeLink>
              <span className="vuln-notice-title"> {n.title}</span>
              <span className="topo-muted topo-small">（公開 {fmtDay(n.published_at)}）</span>
            </li>
          ))}
          {notices.count > notices.items.length && <li className="topo-muted">ほか {notices.count - notices.items.length} 件</li>}
        </ul>
      )}
    </div>
  );
}

function CoveragePanel({ coverage }: { coverage: Coverage[] }) {
  if (!coverage.length) return null;
  return (
    <div className="vuln-coverage" data-testid="vuln-coverage">
      <span className="form-label">取得済みの範囲</span>
      {coverage.map((c) => (
        <span key={c.source} className="vuln-source">
          {c.label}: {c.count} 件
          {c.count > 0 && <>（公開日 {fmtDay(c.oldest)} 〜 {fmtDay(c.newest)}）</>}
          {c.source === "fortinet" && c.documents > c.count && <span className="topo-muted">　ほかの製品の勧告 {c.documents - c.count} 件</span>}
          {c.pending > 0 && <span className="topo-muted">　取得待ち {c.pending} 件（次回の取得で取ります）</span>}
        </span>
      ))}
      <span className="topo-muted topo-small">
        取得済みの範囲より前の勧告は照合していません。<b>勧告が見つからないことは、安全であることを意味しません。</b>
      </span>
    </div>
  );
}

function ImportPanel({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [max, setMax] = useState(20);
  const [st, setSt] = useState<ImportState | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    api.get<{ state: ImportState | null; max: number }>("/vulns/fortinet/import")
      .then((r) => { setSt(r.data.state); setMax(r.data.max); })
      .catch(() => undefined);
  }, []);
  useEffect(() => { if (open) load(); }, [open, load]);
  // 依頼中は 3 秒ごとに状態を見る（worker が結果を書いたら止める）
  useEffect(() => {
    if (!open || st?.status !== "queued") return;
    const t = window.setInterval(load, 3000);
    return () => window.clearInterval(t);
  }, [open, st?.status, load]);
  const prev = st?.status;
  useEffect(() => { if (prev === "done") onDone(); }, [prev, onDone]);
  const ids = text.split(/[\s,、]+/).filter(Boolean);
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await api.post("/vulns/fortinet/import", { ids: text });
      load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="vuln-import">
      <button className="btn btn-sm" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} Fortinet の過去の勧告を取り込む
      </button>
      {open && (
        <div className="card vuln-import-body" data-testid="vuln-import">
          <p className="hist-note">
            毎日の取得は、Fortinet の RSS に出ている最新の 50 件だけを新しく見つけます。それより前の勧告は、勧告の ID
            （FG-IR-YY-NNN の形）を指定して取り込めます。改行かカンマで区切り、1 回に {max} 件まで。1 件ごとに 2 秒以上あけて取りに行きます。
            2021 年以前の勧告など、機械で読める形式（CSAF）の文書が無い勧告は取り込めません。
          </p>
          <div className="form-group">
            <label className="form-label" htmlFor="vuln-import-ids">勧告の ID</label>
            <textarea id="vuln-import-ids" rows={3} maxLength={4000} value={text} onChange={(e) => setText(e.target.value)}
              placeholder={"FG-IR-24-015\nFG-IR-22-398"} className="mono" />
            <p className="hist-note" style={{ marginTop: 4 }}>{ids.length} 件</p>
          </div>
          {error && <p className="form-error">{error}</p>}
          <div className="btn-row" style={{ justifyContent: "flex-start" }}>
            <button className="btn btn-primary" disabled={busy || !ids.length || st?.status === "queued"} onClick={submit}>取り込む</button>
          </div>
          {st && (
            <div className="vuln-import-state" data-testid="vuln-import-state">
              <p className="topo-small">
                {st.status === "queued" ? "取り込み中です…" : st.status === "done" ? `取り込みが終わりました（${fmt(st.finished_at ?? st.at)}）`
                  : st.message}
                {st.by ? <span className="topo-muted">　依頼: {st.by}</span> : null}
              </p>
              {st.results && st.results.length > 0 && (
                <table className="data-table">
                  <thead><tr><th>勧告</th><th>結果</th></tr></thead>
                  <tbody>
                    {st.results.map((r) => (
                      <tr key={r.ext_id}>
                        <td className="mono nowrap">{r.ext_id}</td>
                        <td><span className={`badge ${r.ok ? "badge-success" : "badge-warning"}`}>{r.ok ? "成功" : "取り込めません"}</span>
                          <span className="vuln-import-msg"> {r.message}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- 画面

export default function VulnsPage() {
  const { can } = useAuth();
  const canWrite = can(PERM.VULN_WRITE);
  const canFetch = can(PERM.SYSTEM_READ); // 「いま取得」は管理者だけ
  const [params, setParams] = useSearchParams();
  const tab: TabKey = TABS.some((t) => t.key === params.get("tab")) ? (params.get("tab") as TabKey) : "matches";
  const deviceId = params.get("device") ?? "";
  const [summary, setSummary] = useState<Summary | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [error, setError] = useState("");
  const [fetchNote, setFetchNote] = useState("");

  const loadSummary = useCallback(() => {
    api.get<Summary>("/vulns/summary").then((r) => { setSummary(r.data); setError(""); }).catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(() => {
    loadSummary();
    api.get<Group[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  }, [loadSummary]);
  const setTab = (t: TabKey, device = "") => setParams({ ...(t === "matches" ? {} : { tab: t }), ...(device ? { device } : {}) }, { replace: true });
  const fetchNow = async () => {
    setFetchNote("");
    try {
      await api.post("/vulns/fetch");
      setFetchNote("取得を依頼しました。数分後に画面を開き直すと、情報源の最後の取得が更新されます");
    } catch (e) {
      setFetchNote(errorMessage(e));
    }
  };
  const c = summary?.counts;
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">脆弱性・サポート期限</span>
        <span className="topo-muted topo-small">機器の OS バージョンを、公開されている脆弱性情報・サポート終了日と照合します</span>
        <span style={{ flex: 1 }} />
        {canFetch && <button className="btn" onClick={fetchNow}>いま取得</button>}
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {fetchNote && <p className="review-message">{fetchNote}</p>}
        <div className="vuln-notice" role="note">
          <p>
            「該当」は、ベンダーの勧告の影響範囲と機器の OS バージョンを照合した結果です（機能の設定・構成までは見ていません）。
            <b>載っていない脆弱性がありえます</b>（情報源の公開の遅れ・対象外の機種・読み取れないバージョン）。見つからないことは、安全を意味しません。
            機器名・IP・OS バージョンは外部へ送らず、製品単位の公開情報を取得して、サーバーの中で照合しています。
          </p>
          <p className="topo-muted topo-small">
            出典: Palo Alto Networks Security Advisories（security.paloaltonetworks.com）／ Fortinet PSIRT Advisories（www.fortiguard.com・
            filestore.fortinet.com）／ CISA Known Exploited Vulnerabilities Catalog（www.cisa.gov）／ endoflife.date。
            各情報の権利は、それぞれの提供元に帰属します。
          </p>
        </div>
        {summary && c && (
          <>
            <div className="cmp-cards" data-testid="vuln-summary">
              <div className="card cmp-card"><span className="cmp-card-label">重大</span><span className="cmp-card-value" style={{ color: c.critical ? "var(--color-danger)" : undefined }}>{c.critical}</span></div>
              <div className="card cmp-card"><span className="cmp-card-label">高</span><span className="cmp-card-value" style={{ color: c.high ? "var(--color-danger)" : undefined }}>{c.high}</span></div>
              <div className="card cmp-card"><span className="cmp-card-label">悪用確認済み</span><span className="cmp-card-value" style={{ color: c.kev ? "var(--color-danger)" : undefined }}>{c.kev}</span></div>
              <div className="card cmp-card"><span className="cmp-card-label">候補</span><span className="cmp-card-value">{c.candidate}</span><span className="topo-muted topo-small">機種・系列を自動では決められない勧告に当たるもの（Panorama だけ・特定の機種だけ・記載のない系列も影響あり・勧告に機器の系列が載っていない）</span></div>
              <div className="card cmp-card"><span className="cmp-card-label">サポート終了済み</span><span className="cmp-card-value" style={{ color: summary.eol.ended ? "var(--color-danger)" : undefined }}>{summary.eol.ended}<span className="cmp-card-sub"> 台</span></span></div>
              <div className="card cmp-card"><span className="cmp-card-label">1 年以内に終了</span><span className="cmp-card-value" style={{ color: summary.eol.soon ? "var(--color-warning)" : undefined }}>{summary.eol.soon}<span className="cmp-card-sub"> 台</span></span></div>
            </div>
            <div className="vuln-sources" data-testid="vuln-sources">
              {summary.sources.map((s) => (
                <span key={s.source} className="vuln-source" title={s.last_error ?? ""}>
                  <span className={`sys-dot sys-dot-${s.last_error ? "warn" : s.last_ok_at ? "ok" : "unknown"}`} aria-hidden="true" />
                  {s.label}: {s.last_ok_at ? `最後の取得 ${fmt(s.last_ok_at)}${s.last_count !== null ? `（${s.last_count} 件）` : ""}` : "まだ取得していません"}
                  {s.skipped ? <span className="topo-muted">　範囲を読み取れなかった行 {s.skipped} 件</span> : null}
                  {s.source === "fortinet" && summary.notices?.count ? <span className="topo-muted">　要確認の告知 {summary.notices.count} 件</span> : null}
                  {s.last_error && <span className="vuln-source-error">　失敗: {s.last_error}</span>}
                </span>
              ))}
              {!summary.sources.length && <span className="topo-muted">使う情報源がありません（VULN_SOURCES）</span>}
              {summary.unknown_sources.length > 0 && (
                <span className="topo-muted">この版では使えない情報源の指定があります: {summary.unknown_sources.join("、")}</span>
              )}
              <span className="topo-muted topo-small">毎日 {summary.fetch_hour} 時以降に取得します</span>
            </div>
            <CoveragePanel coverage={summary.coverage ?? []} />
            {summary.notices && <NoticesPanel notices={summary.notices} />}
            {canFetch && (summary.coverage ?? []).some((x) => x.source === "fortinet") && <ImportPanel onDone={loadSummary} />}
            {(summary.range_unreadable.stale ?? 0) > 0 && (
              <p className="hist-note" data-testid="vuln-stale-note">
                前回は該当だった勧告のうち {summary.range_unreadable.stale} 件は、機器の版が変わり、いまの版では判定できません（該当の件数からは外しています）。「判定できない機器」のタブで確認してください。
              </p>
            )}
            {summary.range_unreadable.pairs > 0 && (
              <p className="hist-note" data-testid="vuln-range-note">
                範囲を読み取れなかった勧告が {summary.range_unreadable.advisories} 件あります（{summary.range_unreadable.devices} 台の機器が関係）。
                該当・非該当のどちらにも判定していません。「判定できない機器」のタブで確認してください。
              </p>
            )}
          </>
        )}
        <div className="seg-tabs" role="tablist" style={{ margin: "4px 0 12px", alignSelf: "flex-start" }}>
          {TABS.map((t) => (
            <button key={t.key} role="tab" aria-selected={tab === t.key} className={`seg-tab${tab === t.key ? " active" : ""}`}
              onClick={() => setTab(t.key)}>
              {t.label}{t.key === "unknown" && summary ? `（${summary.unknown_devices}）` : ""}
            </button>
          ))}
        </div>
        {tab === "matches" && (
          <MatchesTab groups={groups} canWrite={canWrite} deviceId={deviceId}
            onDevice={(id) => setTab("matches", id)} notListed={c?.candidate_not_listed ?? 0} />
        )}
        {tab === "devices" && <DevicesTab onOpen={(id) => setTab("matches", id)} />}
        {tab === "eol" && <EolTab canWrite={canWrite} />}
        {tab === "unknown" && <UnknownTab />}
      </div>
    </div>
  );
}
