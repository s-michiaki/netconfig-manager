import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { CsvButton, downloadFilePost } from "../components/CsvButton";
import { usePlatforms } from "../platforms";

/**
 * コンフィグ検索: 全機器の最新コンフィグを文字列・正規表現で横断検索する。
 * 「この IP・VLAN・ACL はどの機器にあるか」「この設定が入っていない機器はどれか」を調べる
 */

interface Target { id: string; name: string; hostname: string; platform: string; group: string | null; }
interface Line { line: number; text: string; ranges: [number, number][]; before: string[]; after: string[]; }
interface Hit extends Target { count: number; commit: string | null; lines: Line[]; }
interface Result {
  searched: number; matched: number; total_lines: number; max_lines_per_device: number;
  devices: Hit[]; unmatched: Target[]; not_collected: Target[]; timed_out: Target[];
}
interface Group { id: string; name: string; }
interface SearchRequest {
  query: string; mode: string; case_sensitive: boolean; context: number; group_id: string | null; platform: string | null;
}

/** 一致した部分を強調して1行を表示する */
function Highlighted({ text, ranges }: { text: string; ranges: [number, number][] }) {
  const parts: React.ReactNode[] = [];
  let pos = 0;
  ranges.forEach(([s, e], i) => {
    if (s < pos) return;
    parts.push(text.slice(pos, s), <mark key={i}>{text.slice(s, e)}</mark>);
    pos = e;
  });
  parts.push(text.slice(pos));
  return <>{parts}</>;
}

function Names({ items }: { items: Target[] }) {
  return (
    <div className="srch-names">
      {items.map((t) => <span key={t.id} className="badge badge-neutral" title={t.hostname}>{t.name}</span>)}
    </div>
  );
}

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [mode, setMode] = useState("contains");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [context, setContext] = useState(0);
  const [groupId, setGroupId] = useState("");
  const [platform, setPlatform] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const { groups: platformGroups, label: platformLabel } = usePlatforms();
  const [result, setResult] = useState<Result | null>(null);
  // 最後に検索したときの条件（CSV はこの条件で出力する。入力欄を変えてから押しても結果とずれないように）
  const [lastRequest, setLastRequest] = useState<SearchRequest | null>(null);
  const [csvNote, setCsvNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Group[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  }, []);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setBusy(true);
    setError("");
    setCsvNote("");
    const req: SearchRequest = {
      query, mode, case_sensitive: caseSensitive, context, group_id: groupId || null, platform: platform || null,
    };
    try {
      const r = await api.post<Result>("/configs/search", req);
      setResult(r.data);
      setLastRequest(req);
    } catch (err) {
      setError(errorMessage(err));
      setResult(null);
      setLastRequest(null);
    } finally {
      setBusy(false);
    }
  };

  // 検索結果の CSV（一致した行をすべて。検索語は URL に載せないよう POST で送る）
  const exportCsv = async () => {
    if (!lastRequest) return;
    setError("");
    setCsvNote("");
    try {
      const h = await downloadFilePost("/configs/search/export", lastRequest, "config_search.csv");
      const rows = Number(h["x-search-rows"] ?? 0);
      const total = Number(h["x-search-total-lines"] ?? 0);
      const timedOut = Number(h["x-search-timed-out"] ?? 0);
      const notes = [];
      if (total > rows) notes.push(`上限のため ${total} 行のうち ${rows} 行だけを出力しました`);
      if (timedOut) notes.push(`時間内に調べきれなかった機器が ${timedOut} 台あり、その機器の行は含まれていません`);
      setCsvNote(notes.join("。"));
    } catch (err) {
      setError(errorMessage(err, "CSV を出力できませんでした"));
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">コンフィグ検索</span>
        <span className="topo-muted topo-small">各機器の最後に収集したコンフィグから探します（過去の世代は対象外）</span>
      </div>
      <div className="page-body">
        <form className="audit-filters" onSubmit={run}>
          <label className="audit-field audit-field-wide">
            <span className="form-label">探す文字列</span>
            <input className="mono" value={query} onChange={(e) => setQuery(e.target.value)} maxLength={200} autoFocus
                   placeholder={mode === "regex" ? "例: ^ip route 0\\.0\\.0\\.0 " : "例: 192.168.10.1 / vlan 120"} />
          </label>
          <label className="audit-field srch-field-narrow">
            <span className="form-label">探し方</span>
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="contains">文字列を含む</option>
              <option value="regex">正規表現</option>
            </select>
          </label>
          <label className="audit-field">
            <span className="form-label">機器グループ</span>
            <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">すべて</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              <option value="none">グループなし</option>
            </select>
          </label>
          <label className="audit-field">
            <span className="form-label">機種</span>
            <select value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="">すべて</option>
              {platformGroups.map(([vendor, list]) => (
                <optgroup key={vendor} label={vendor}>
                  {list.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </optgroup>
              ))}
            </select>
          </label>
          <label className="audit-field srch-field-narrow">
            <span className="form-label">前後の行</span>
            <select value={context} onChange={(e) => setContext(Number(e.target.value))}>
              <option value={0}>表示しない</option>
              <option value={1}>1 行</option>
              <option value={2}>2 行</option>
              <option value={3}>3 行</option>
            </select>
          </label>
          <label className="srch-check">
            <input type="checkbox" checked={caseSensitive} onChange={(e) => setCaseSensitive(e.target.checked)} />
            大文字と小文字を区別
          </label>
          <button className="btn btn-primary" type="submit" disabled={busy || !query.trim()}>{busy ? "検索中…" : "検索"}</button>
        </form>
        {error && <p className="form-error">{error}</p>}

        {result && (
          <>
            <div className="srch-summary-row">
              <p className="srch-summary">
                <b>{result.matched}</b> 台で <b>{result.total_lines}</b> 行が一致（{result.searched} 台を検索）
                <span className="topo-muted">　「<span className="mono">{lastRequest?.query}</span>」</span>
              </p>
              <CsvButton onClick={exportCsv} disabled={!result.total_lines}
                title="この検索で一致した行をすべて CSV で出力します（表示の 50 行の制限とは別。最大10万行）" />
            </div>
            {csvNote && <div className="srch-note srch-note-warn">{csvNote}</div>}
            {result.timed_out.length > 0 && (
              <div className="srch-note srch-note-warn">
                時間内に調べきれなかった機器が {result.timed_out.length} 台あります。正規表現を単純にするか、機器グループで絞ってください。
                <Names items={result.timed_out} />
              </div>
            )}
            {result.devices.map((d) => (
              <section key={d.id} className="card srch-device">
                <header>
                  <b>{d.name}</b> <span className="topo-muted mono">{d.hostname}</span>
                  <span className="topo-muted topo-small">{platformLabel(d.platform)}</span>
                  {d.group && <span className="badge badge-neutral">{d.group}</span>}
                  <span className="topo-muted topo-small">{d.count} 行</span>
                  <span style={{ flex: 1 }} />
                  <Link to={`/history?device=${d.id}`} className="topo-small">世代管理で開く →</Link>
                </header>
                <div className="srch-lines mono">
                  {d.lines.map((l, i) => (
                    <div key={l.line} className={`srch-block${i && (l.before.length || l.after.length) ? " srch-sep" : ""}`}>
                      {l.before.map((t, j) => (
                        <div key={`b${j}`} className="srch-line srch-ctx"><span className="srch-no">{l.line - l.before.length + j}</span><span>{t}</span></div>
                      ))}
                      <div className="srch-line"><span className="srch-no">{l.line}</span><span><Highlighted text={l.text} ranges={l.ranges} /></span></div>
                      {l.after.map((t, j) => (
                        <div key={`a${j}`} className="srch-line srch-ctx"><span className="srch-no">{l.line + 1 + j}</span><span>{t}</span></div>
                      ))}
                    </div>
                  ))}
                </div>
                {d.count > d.lines.length && (
                  <p className="topo-muted topo-small srch-more">ほかに {d.count - d.lines.length} 行あります（表示は機器ごとに {result.max_lines_per_device} 行まで）</p>
                )}
              </section>
            ))}
            {result.matched === 0 && result.searched > 0 && <p className="topo-muted">一致する行はありませんでした。</p>}
            {result.unmatched.length > 0 && (
              <details className="srch-note" open={result.matched === 0 ? undefined : false}>
                <summary>一致しなかった機器（{result.unmatched.length} 台）— この設定が入っていない機器の確認に使えます</summary>
                <Names items={result.unmatched} />
              </details>
            )}
            {result.not_collected.length > 0 && (
              <details className="srch-note">
                <summary>未収集のため検索していない機器（{result.not_collected.length} 台）</summary>
                <Names items={result.not_collected} />
              </details>
            )}
          </>
        )}
      </div>
    </div>
  );
}
