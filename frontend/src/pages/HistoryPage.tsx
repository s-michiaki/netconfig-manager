import { Fragment, useEffect, useRef, useState, type CSSProperties } from "react";
import { useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import { downloadFile } from "../components/CsvButton";

interface Device { id: string; name: string; group_name: string | null; }
/** 世代へのコメント（作業内容のメモ） */
interface Comment {
  body: string; created_by: string | null; created_by_id: string | null; created_at: string | null;
  updated_by: string | null; updated_at: string | null;
}
interface Commit { hash: string; full_hash: string; message: string; date: string; author: string; comment: Comment | null; }
interface Side { device_id: string; name: string; hash: string; full_hash: string; date: string; }
interface CompareResult { diff: string; message?: string; truncated: boolean; a: Side; b: Side; }

const HISTORY_LIMIT = 500; // 一覧に出す世代の数（API の上限）
const COMMENT_MAX = 1000;

const fmt = (iso: string) => new Date(iso).toLocaleString("ja-JP");
const optionLabel = (c: Commit) => `${c.hash}  ${fmt(c.date)}`;

function parseDiff(diff: string) {
  // 最初の @@ より前（--- / +++ などの見出し）と @@ の行だけを灰色にする。
  // 設定の行が "--" で始まる場合も、削除した行は赤で表示される
  let inHunk = false;
  return diff.split("\n").map((line, i) => {
    let cls = "diff-meta";
    if (line.startsWith("@@")) inHunk = true;
    else if (line.startsWith("diff ")) inHunk = false;
    else if (inHunk && line.startsWith("+")) cls = "diff-add";
    else if (inHunk && line.startsWith("-")) cls = "diff-del";
    return <div key={i} className={cls}>{line || " "}</div>;
  });
}

/** グループごとにまとめた機器の選択肢（グループの並び順。未分類は最後） */
function DeviceSelect({ devices, groupOrder, value, onChange, placeholder, exclude, style, label }: {
  devices: Device[]; groupOrder: string[]; value: string; onChange: (id: string) => void;
  placeholder: string; exclude?: string; style?: CSSProperties; label?: string;
}) {
  const rank = (name: string) => {
    const i = groupOrder.indexOf(name);
    return i < 0 ? groupOrder.length : i;
  };
  const list = devices.filter((d) => d.id !== exclude);
  return (
    <select aria-label={label} style={style} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{placeholder}</option>
      {[...new Set(list.map((d) => d.group_name ?? ""))]
        .sort((a, b) => (a === "" ? 1 : b === "" ? -1 : rank(a) - rank(b) || a.localeCompare(b, "ja")))
        .map((g) => (
          <optgroup key={g || "__none__"} label={g || "未分類"}>
            {list.filter((d) => (d.group_name ?? "") === g).map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </optgroup>
        ))}
    </select>
  );
}

const smallBtn: CSSProperties = { padding: "2px 8px", fontSize: 11 };

const commentBy = (c: Comment) => {
  const who = c.updated_by && c.updated_by !== c.created_by ? `${c.created_by}（更新: ${c.updated_by}）` : c.created_by;
  return `${who ?? ""}${c.updated_at ? ` · ${fmt(c.updated_at)}` : ""}`;
};

/** 差分・コンフィグの見出しの下に出すコメント */
function CommentNotes({ items }: { items: { label: string; comment: Comment | null }[] }) {
  const shown = items.filter((x) => x.comment);
  if (!shown.length) return null;
  return (
    <div className="hist-comments">
      {shown.map((x) => (
        <div key={x.label} className="hist-comment-note">
          <span className="hist-side">{x.label}</span>
          <span className="hist-comment-body">{x.comment!.body}</span>
          <span className="hist-comment-by">{commentBy(x.comment!)}</span>
        </div>
      ))}
    </div>
  );
}

/** コメントの入力（オペレーター以上）。他の人のコメントは本人か管理者だけが変更できる */
function CommentModal({ deviceId, commit, editable, onClose, onSaved }: {
  deviceId: string; commit: Commit; editable: boolean; onClose: () => void; onSaved: (c: Comment | null) => void;
}) {
  const [body, setBody] = useState(commit.comment?.body ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const url = `/configs/${encodeURIComponent(deviceId)}/comments/${commit.full_hash}`;
  const run = async (f: () => Promise<Comment | null>) => {
    setBusy(true);
    setError("");
    try {
      onSaved(await f());
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  const save = () => run(async () => (await api.put<Comment>(url, { body })).data);
  const remove = () => {
    if (!window.confirm("このコメントを削除しますか？")) return;
    void run(async () => {
      await api.delete(url);
      return null;
    });
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">変更へのコメント</p>
        <p className="hist-note">
          世代 <span className="mono">{commit.hash}</span>（{fmt(commit.date)}）に、作業内容や依頼番号など、後から見て意図した変更か分かるメモを残します。
        </p>
        {commit.comment && <p className="hist-note">書いた人: {commentBy(commit.comment)}</p>}
        <div className="form-group">
          <label className="form-label" htmlFor="hist-comment">メモ（{COMMENT_MAX} 文字まで）</label>
          <textarea id="hist-comment" rows={6} maxLength={COMMENT_MAX} value={body} disabled={!editable}
            placeholder="例: CHG-1234 VLAN 30 を追加（夜間作業・山田）" onChange={(e) => setBody(e.target.value)} />
          <p className="hist-note" style={{ marginTop: 4 }}>
            {body.length} / {COMMENT_MAX} 文字。パスワードなどの秘密情報は書かないでください（変更・削除は監査ログに残ります）
          </p>
        </div>
        {!editable && <p className="hist-note">他の人が書いたコメントは、書いた本人か管理者だけが変更できます。</p>}
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          {editable && commit.comment && <button className="btn btn-danger" disabled={busy} onClick={remove}>削除</button>}
          {editable && <button className="btn btn-primary" disabled={busy || !body.trim()} onClick={save}>保存</button>}
        </div>
      </div>
    </div>
  );
}

export default function HistoryPage() {
  const { me, can } = useAuth();
  const canComment = can(PERM.CONFIG_COMMENT);
  const isAdmin = can(PERM.USER_ADMIN);
  const [devices, setDevices] = useState<Device[]>([]);
  const [groupOrder, setGroupOrder] = useState<string[]>([]);
  const [searchParams] = useSearchParams();
  // 構成図などから ?device=<id> 付きで開かれた場合は、その機器を選択した状態にする
  const [selectedDevice, setSelectedDevice] = useState(searchParams.get("device") ?? "");
  // ダッシュボードなどから ?commit=<hash> 付きで開かれた場合は、その世代の変更（1 つ前との差分）を表示する（最初の 1 回だけ）
  const initialCommit = useRef(searchParams.get("commit") ?? "");
  const [history, setHistory] = useState<Commit[]>([]);
  // 比べ方: 同じ機器の 2 世代 / 別の機器と
  const [mode, setMode] = useState<"self" | "other">("self");
  const [selectedA, setSelectedA] = useState("");
  const [selectedB, setSelectedB] = useState("");
  // 別の機器と比べるとき（世代の "" は最新）
  const [selfHash, setSelfHash] = useState("");
  const [otherDevice, setOtherDevice] = useState("");
  const [otherHistory, setOtherHistory] = useState<Commit[]>([]);
  const [otherHash, setOtherHash] = useState("");

  const [diff, setDiff] = useState("");
  const [diffTitle, setDiffTitle] = useState("");
  const [diffComments, setDiffComments] = useState<{ label: string; full_hash: string; comment: Comment | null }[]>([]);
  const [editing, setEditing] = useState<Commit | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [content, setContent] = useState<string | null>(null);
  const [contentCommit, setContentCommit] = useState<Commit | null>(null);
  const [view, setView] = useState<"diff" | "content">("diff");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState("");

  useEffect(() => {
    api.get("/devices/").then((r) => setDevices(r.data)).catch((e) => setError(errorMessage(e)));
    api.get<{ name: string }[]>("/device-groups/").then((r) => setGroupOrder(r.data.map((g) => g.name))).catch(() => undefined);
  }, []);

  const deviceName = (id: string) => devices.find((d) => d.id === id)?.name ?? "";

  useEffect(() => {
    // デバイスを切り替えたら前のデバイスの選択・表示内容をすべてリセットする（比較先の機器は残す）
    setHistory([]);
    setSelectedA("");
    setSelectedB("");
    setSelfHash("");
    setDiff("");
    setDiffTitle("");
    setDiffComments([]);
    setTruncated(false);
    setContent(null);
    setContentCommit(null);
    setView("diff");
    setError("");
    setOtherDevice((o) => (o === selectedDevice ? "" : o));
    if (!selectedDevice) return;

    let cancelled = false;
    api
      .get<Commit[]>(`/configs/${encodeURIComponent(selectedDevice)}/history`, { params: { limit: HISTORY_LIMIT } })
      .then((r) => {
        if (cancelled) return;
        setHistory(r.data);
        if (r.data.length >= 2) {
          setSelectedA(r.data[1].full_hash);
          setSelectedB(r.data[0].full_hash);
        }
        const want = initialCommit.current.toLowerCase();
        initialCommit.current = "";
        const i = want ? r.data.findIndex((c) => c.full_hash.startsWith(want)) : -1;
        if (i >= 0 && i + 1 < r.data.length) {
          setSelectedA(r.data[i + 1].full_hash);
          setSelectedB(r.data[i].full_hash);
          void loadDiff(selectedDevice, r.data[i + 1], r.data[i]);
        } else if (i >= 0) {
          void showContent(r.data[i], selectedDevice);
        }
      })
      .catch((e) => !cancelled && setError(errorMessage(e)));
    return () => {
      cancelled = true;
    };
  }, [selectedDevice]);

  useEffect(() => {
    setOtherHistory([]);
    setOtherHash("");
    if (!otherDevice) return;
    let cancelled = false;
    api
      .get<Commit[]>(`/configs/${encodeURIComponent(otherDevice)}/history`, { params: { limit: HISTORY_LIMIT } })
      .then((r) => !cancelled && setOtherHistory(r.data))
      .catch((e) => !cancelled && setError(errorMessage(e)));
    return () => {
      cancelled = true;
    };
  }, [otherDevice]);

  const loadDiff = async (deviceId: string, a: Commit, b: Commit) => {
    setError("");
    try {
      const r = await api.get(`/configs/${encodeURIComponent(deviceId)}/diff`, {
        params: { from_hash: a.full_hash, to_hash: b.full_hash },
      });
      setDiff(r.data.diff || "差分なし");
      setDiffTitle(`${a.hash}（${fmt(a.date)}）→ ${b.hash}（${fmt(b.date)}）`);
      setDiffComments([{ label: "A", full_hash: a.full_hash, comment: a.comment }, { label: "B", full_hash: b.full_hash, comment: b.comment }]);
      setTruncated(false);
      setView("diff");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const showDiff = async () => {
    const a = history.find((c) => c.full_hash === selectedA);
    const b = history.find((c) => c.full_hash === selectedB);
    if (!selectedDevice || !a || !b) return;
    await loadDiff(selectedDevice, a, b);
  };

  const compareOther = async () => {
    if (!selectedDevice || !otherDevice) return;
    setError("");
    try {
      const r = await api.get<CompareResult>("/configs/compare", {
        params: { device_a: selectedDevice, hash_a: selfHash || undefined, device_b: otherDevice, hash_b: otherHash || undefined },
      });
      const { a, b } = r.data;
      setDiff(r.data.diff || "差分なし");
      setDiffTitle(`${a.name} ${a.hash}（${fmt(a.date)}）→ ${b.name} ${b.hash}（${fmt(b.date)}）`);
      setDiffComments([
        { label: "A", full_hash: a.full_hash, comment: history.find((c) => c.full_hash === a.full_hash)?.comment ?? null },
        { label: "B", full_hash: b.full_hash, comment: otherHistory.find((c) => c.full_hash === b.full_hash)?.comment ?? null },
      ]);
      setTruncated(r.data.truncated);
      setView("diff");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const showContent = async (c: Commit, deviceId = selectedDevice) => {
    if (!deviceId) return;
    setError("");
    try {
      const r = await api.get<string>(`/configs/${encodeURIComponent(deviceId)}/content/${c.full_hash}`, {
        responseType: "text",
      });
      setContent(r.data);
      setContentCommit(c);
      setView("content");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const save = async (c: Commit) => {
    if (!selectedDevice) return;
    setError("");
    setSaving(c.full_hash);
    try {
      await downloadFile(`/configs/${encodeURIComponent(selectedDevice)}/download/${c.full_hash}`, {}, `config_${c.hash}.txt`);
    } catch (e) {
      // blob で受けたエラーは本文を読めないため、よくある理由だけ文言を分ける
      const status = (e as { response?: { status?: number } }).response?.status;
      setError(status === 404 ? "コンフィグが見つかりません" : status === 403 ? "権限がありません" : errorMessage(e));
    } finally {
      setSaving("");
    }
  };

  // コメントを保存・削除したら、一覧と表示中の見出しだけを書き換える（一覧は取り直さない）
  const commentSaved = (full: string, comment: Comment | null) => {
    setHistory((h) => h.map((c) => (c.full_hash === full ? { ...c, comment } : c)));
    setContentCommit((c) => (c && c.full_hash === full ? { ...c, comment } : c));
    // 別の機器と比べているときの B は別の機器の世代なので、A だけが対象
    setDiffComments((d) => d.map((x) => (x.full_hash === full && (mode === "self" || x.label === "A") ? { ...x, comment } : x)));
    setEditing(null);
  };
  const editable = (c: Commit) => !c.comment || isAdmin || c.comment.created_by_id === me?.id;

  // 一覧の「A」: 比べる元の世代にする（別の機器と比べるときは、この機器の側の世代）
  const pickA = (c: Commit) => (mode === "self" ? setSelectedA(c.full_hash) : setSelfHash(c.full_hash));
  const markOf = (c: Commit) => {
    if (mode === "self") {
      return [c.full_hash === selectedA && "A", c.full_hash === selectedB && "B"].filter(Boolean).join("・");
    }
    return (selfHash ? c.full_hash === selfHash : c.full_hash === history[0]?.full_hash) ? "A" : "";
  };

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">世代管理 (Git)</span>
        <div style={{ display: "flex", gap: 8 }}>
          <DeviceSelect devices={devices} groupOrder={groupOrder} value={selectedDevice} onChange={setSelectedDevice}
            placeholder="デバイスを選択..." style={{ width: 200 }} />
        </div>
      </div>

      <div className="page-body" style={{ display: "flex", gap: 16, height: "100%", paddingBottom: 0 }}>
        {/* 左: コミット一覧 */}
        <div style={{ width: 440, flexShrink: 0, display: "flex", flexDirection: "column" }}>
          <p className="section-label">コミット履歴</p>
          {history.length === 0 ? (
            <p style={{ color: "var(--color-muted)", fontSize: 13 }}>
              {selectedDevice ? "履歴なし" : "デバイスを選択してください"}
            </p>
          ) : (
            <div style={{ overflow: "auto", flex: 1 }}>
              <table className="data-table hist-table">
                <thead>
                  <tr>
                    <th>ハッシュ</th>
                    <th>日時</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((c) => {
                    const mark = markOf(c);
                    return (
                      <Fragment key={c.full_hash}>
                      <tr title={c.message} className={`hist-row${mark ? " hist-picked" : ""}${c.comment ? " hist-has-comment" : ""}`}>
                        <td>
                          <span className="mono" style={{ fontSize: 12, color: "var(--color-accent)" }}>
                            {c.hash}
                          </span>
                          {mark && <span className="hist-mark">{mark}</span>}
                        </td>
                        <td style={{ fontSize: 11, color: "var(--color-muted)" }}>
                          {fmt(c.date)}
                        </td>
                        <td>
                          <div className="hist-actions">
                            <button className="btn" style={smallBtn} onClick={() => showContent(c)}>
                              表示
                            </button>
                            <button className="btn" style={smallBtn} disabled={saving === c.full_hash}
                              title="この世代のコンフィグをテキストファイルで保存します（監査ログに残ります）" onClick={() => save(c)}>
                              {saving === c.full_hash ? "保存中..." : "保存"}
                            </button>
                            <button className="btn" style={smallBtn} title="比べる元（A）にする" onClick={() => pickA(c)}>A</button>
                            {mode === "self" && (
                              <button className="btn" style={smallBtn} title="比べる先（B）にする" onClick={() => setSelectedB(c.full_hash)}>B</button>
                            )}
                            {canComment && (
                              <button className="btn" style={smallBtn} title="作業内容のメモを書きます" onClick={() => setEditing(c)}>メモ</button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {c.comment && (
                        <tr className={`hist-comment-row${mark ? " hist-picked" : ""}`}>
                          <td colSpan={3}>
                            <div className="hist-comment" title={`${c.comment.body}\n— ${commentBy(c.comment)}`}>
                              <span className="hist-comment-body">{c.comment.body}</span>
                              <span className="hist-comment-by">{c.comment.updated_by ?? c.comment.created_by}</span>
                            </div>
                          </td>
                        </tr>
                      )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
              {history.length >= HISTORY_LIMIT && (
                <p style={{ color: "var(--color-muted)", fontSize: 11, margin: "6px 0" }}>新しい {HISTORY_LIMIT} 世代までを表示しています</p>
              )}
            </div>
          )}
        </div>

        {/* 右: 差分・コンテンツビュー */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {history.length >= 1 && (
            <div className="seg-tabs" role="tablist" style={{ marginBottom: 10, alignSelf: "flex-start" }}>
              <button role="tab" aria-selected={mode === "self"} className={`seg-tab${mode === "self" ? " active" : ""}`}
                onClick={() => setMode("self")}>同じ機器の世代を比べる</button>
              <button role="tab" aria-selected={mode === "other"} className={`seg-tab${mode === "other" ? " active" : ""}`}
                onClick={() => setMode("other")}>別の機器と比べる</button>
            </div>
          )}

          {mode === "self" && history.length >= 2 && (
            <div className="hist-compare">
              <span className="hist-side">A</span>
              <select aria-label="比べる元の世代" value={selectedA} onChange={(e) => setSelectedA(e.target.value)} style={{ width: 230 }}>
                {history.map((c) => <option key={c.full_hash} value={c.full_hash}>{optionLabel(c)}</option>)}
              </select>
              <span style={{ color: "var(--color-muted)" }}>→</span>
              <span className="hist-side">B</span>
              <select aria-label="比べる先の世代" value={selectedB} onChange={(e) => setSelectedB(e.target.value)} style={{ width: 230 }}>
                {history.map((c) => <option key={c.full_hash} value={c.full_hash}>{optionLabel(c)}</option>)}
              </select>
              <button className="btn btn-primary" onClick={showDiff}>差分を表示</button>
            </div>
          )}
          {mode === "self" && history.length === 1 && (
            <p className="hist-note">世代が 1 つだけのため、比べる世代がありません。「別の機器と比べる」で他の機器と比べられます。</p>
          )}

          {mode === "other" && history.length >= 1 && (
            <>
              <div className="hist-compare-grid">
                <span className="hist-side">A</span>
                <span className="hist-devname">{deviceName(selectedDevice)}</span>
                <select aria-label="この機器の世代" value={selfHash} onChange={(e) => setSelfHash(e.target.value)} style={{ width: 230 }}>
                  <option value="">最新</option>
                  {history.map((c) => <option key={c.full_hash} value={c.full_hash}>{optionLabel(c)}</option>)}
                </select>
                <span />
                <span className="hist-side">B</span>
                <DeviceSelect devices={devices} groupOrder={groupOrder} value={otherDevice} onChange={setOtherDevice}
                  placeholder="比べる機器を選択..." label="比べる機器" exclude={selectedDevice} style={{ width: 200 }} />
                <select aria-label="比べる機器の世代" value={otherHash} onChange={(e) => setOtherHash(e.target.value)}
                  style={{ width: 230 }} disabled={!otherDevice}>
                  <option value="">最新</option>
                  {otherHistory.map((c) => <option key={c.full_hash} value={c.full_hash}>{optionLabel(c)}</option>)}
                </select>
                <button className="btn btn-primary" onClick={compareOther} disabled={!otherDevice}>比較する</button>
              </div>
              <p className="hist-note">冗長構成の 2 台などを比べます。hostname や管理 IP など、機器ごとに違って当然の行も差分に出ます。</p>
            </>
          )}

          {error && <p className="form-error">{error}</p>}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <p className="section-label">{view === "diff" ? "差分ビュー" : "コンフィグ内容"}</p>
            {view === "diff" && diffTitle && <span className="hist-title mono">{diffTitle}</span>}
            {view === "content" && contentCommit && (
              <>
                <span className="hist-title mono">{contentCommit.hash}（{fmt(contentCommit.date)}）</span>
                <button className="btn" style={{ ...smallBtn, marginLeft: "auto" }} disabled={saving === contentCommit.full_hash}
                  onClick={() => save(contentCommit)}>ファイルに保存</button>
              </>
            )}
          </div>
          {view === "diff" && diff && <CommentNotes items={diffComments} />}
          {view === "content" && contentCommit && <CommentNotes items={[{ label: contentCommit.hash, comment: contentCommit.comment }]} />}
          {view === "diff" && truncated && (
            <p className="hist-note">差分が大きいため、先頭の部分だけを表示しています。</p>
          )}
          <div className="diff-view" style={{ flex: 1, maxHeight: "none" }}>
            {view === "diff"
              ? (diff ? parseDiff(diff) : <span style={{ color: "var(--color-muted)" }}>コミットを選択して差分表示</span>)
              : (content !== null
                ? <pre style={{ whiteSpace: "pre-wrap", color: "#c9d1d9", fontSize: 12 }}>{content || "(空のコンフィグ)"}</pre>
                : <span style={{ color: "var(--color-muted)" }}>コミットを選択してコンフィグを表示</span>)
            }
          </div>
        </div>
      </div>
      {editing && (
        <CommentModal deviceId={selectedDevice} commit={editing} editable={editable(editing)} onClose={() => setEditing(null)}
          onSaved={(c) => commentSaved(editing.full_hash, c)} />
      )}
    </div>
  );
}
