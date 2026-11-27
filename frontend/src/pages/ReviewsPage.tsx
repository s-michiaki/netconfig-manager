import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import BaselineModal, { LATEST, type Baseline } from "../components/BaselineModal";
import ReviewModal, { ReviewBadge, bulkMessage, bulkReview, clearReview, reviewError, setReview, type Review, type ReviewTarget } from "../components/ReviewModal";
import HelpLink from "../components/HelpLink";

/**
 * 変更の確認: 検出した変更（世代）に「確認済み」「想定外」を付け、未確認の変更を一覧にする。
 * 画面はタブで分ける（変更の一覧 / 基準からのずれ。TABS に足すと増やせる）
 */

interface Change {
  device_id: string; device_name: string; group_id: string | null; group_name: string | null;
  commit_hash: string; hash: string; collected_at: string; added: number; removed: number; triggered_by: string;
  review: Review | null; comment: string | null;
}
interface ListResult { total: number; limit: number; days: number; counts: Record<State, number>; items: Change[]; }
interface Group { id: string; name: string; }
type State = "unreviewed" | "unexpected" | "confirmed";

const TABS = [{ key: "changes", label: "変更の一覧" }, { key: "drift", label: "基準からのずれ" }] as const;
type TabKey = (typeof TABS)[number]["key"];

const STATES: { key: State | "all"; label: string }[] = [
  { key: "unreviewed", label: "未確認" }, { key: "unexpected", label: "想定外" }, { key: "confirmed", label: "確認済み" }, { key: "all", label: "すべて" },
];
const PERIODS = [{ days: 7, label: "7 日" }, { days: 30, label: "30 日" }, { days: 90, label: "90 日" }, { days: 0, label: "すべて" }];
const TRIGGER: Record<string, string> = { manual: "手動", schedule: "スケジュール" };

const fmt = (iso: string) => new Date(iso).toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
const keyOf = (c: Change) => `${c.device_id}:${c.commit_hash}`;
const target = (c: Change): ReviewTarget => ({ device_id: c.device_id, commit_hash: c.commit_hash, label: `${c.device_name} ${c.hash}` });

function ChangesTab() {
  const { can } = useAuth();
  const canReview = can(PERM.CONFIG_REVIEW);
  const [params, setParams] = useSearchParams();
  // URL の値が不正なら既定にする
  const [state, setState] = useState<State | "all">(STATES.some((x) => x.key === params.get("state")) ? (params.get("state") as State | "all") : "unreviewed");
  const rawDays = Number(params.get("days"));
  const [days, setDays] = useState(params.get("days") !== null && Number.isInteger(rawDays) && rawDays >= 0 && rawDays <= 3650 ? rawDays : -1); // -1: サーバーの既定（CHANGE_REVIEW_DAYS）
  const [groupId, setGroupId] = useState(params.get("group") ?? "");
  const [groups, setGroups] = useState<Group[]>([]);
  const [data, setData] = useState<ListResult | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [modal, setModal] = useState<{ targets: ReviewTarget[]; current?: Review | null; status?: Review["status"] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Group[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  }, []);

  const load = useCallback(() => {
    api.get<ListResult>("/configs/reviews", { params: { state, days: days < 0 ? undefined : days, group_id: groupId || undefined } })
      .then((r) => {
        setData(r.data);
        // 一覧から消えた行は選択から外す
        setSelected((s) => new Set([...s].filter((k) => r.data.items.some((c) => keyOf(c) === k))));
        setError("");
      })
      .catch((e) => setError(errorMessage(e)));
  }, [state, days, groupId]);
  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    // URL にも残す（ダッシュボードからのリンク・再読み込みで同じ絞り込みになる）
    const p = new URLSearchParams();
    if (state !== "unreviewed") p.set("state", state);
    if (days >= 0) p.set("days", String(days));
    if (groupId) p.set("group", groupId);
    setParams(p, { replace: true });
  }, [state, days, groupId, setParams]);

  const act = async (f: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await f();
      if (done) setMessage(done);
    } catch (e) {
      setError(reviewError(e));
    } finally {
      setBusy(false);
      load(); // 途中で失敗しても、付いたところまでを一覧に反映する
    }
  };
  const items = data?.items ?? [];
  const shownDays = days >= 0 ? days : (data?.days ?? 30); // 指定が無いときはサーバーの既定（CHANGE_REVIEW_DAYS）
  const chosen = items.filter((c) => selected.has(keyOf(c)));
  const allChecked = items.length > 0 && chosen.length === items.length;
  const toggle = (c: Change) => setSelected((s) => { const n = new Set(s); if (n.has(keyOf(c))) n.delete(keyOf(c)); else n.add(keyOf(c)); return n; });
  const bulkConfirm = () => act(async () => {
    const r = await bulkReview(chosen.map(target), "confirmed");
    setSelected(new Set());
    setMessage(bulkMessage(r, "confirmed"));
  });

  return (
    <>
      <div className="review-filters">
        <div className="seg-tabs" role="tablist" aria-label="状態">
          {STATES.map((s) => (
            <button key={s.key} role="tab" aria-selected={state === s.key} className={`seg-tab${state === s.key ? " active" : ""}`}
              onClick={() => setState(s.key)}>
              {s.label}{data && s.key !== "all" ? `（${data.counts[s.key]}）` : ""}
            </button>
          ))}
        </div>
        <label className="audit-field">
          <span className="form-label">期間</span>
          <select aria-label="期間" value={shownDays} onChange={(e) => setDays(Number(e.target.value))}>
            {!PERIODS.some((p) => p.days === shownDays) && <option value={shownDays}>{shownDays} 日</option>}
            {PERIODS.map((p) => <option key={p.days} value={p.days}>{p.label}</option>)}
          </select>
        </label>
        <label className="audit-field">
          <span className="form-label">機器グループ</span>
          <select aria-label="機器グループ" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">すべて</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </label>
      </div>

      {error && <p className="form-error">{error}</p>}
      {message && <p className="review-message">{message}</p>}
      {canReview && chosen.length > 0 && (
        <div className="review-bulk">
          <span>{chosen.length} 件を選択中</span>
          <button className="btn btn-primary" disabled={busy} onClick={bulkConfirm}>確認済みにする</button>
          <button className="btn" disabled={busy} onClick={() => setModal({ targets: chosen.map(target), status: "unexpected" })}>想定外にする…</button>
          <button className="btn" onClick={() => setSelected(new Set())}>選択を解除</button>
        </div>
      )}

      {data && !items.length ? (
        <p className="topo-muted">{state === "unreviewed" ? "未確認の変更はありません。" : "該当する変更はありません。"}</p>
      ) : (
        <table className="data-table review-table">
          <thead>
            <tr>
              {canReview && (
                <th style={{ width: 28 }}>
                  <input type="checkbox" aria-label="すべて選択" checked={allChecked}
                    onChange={() => setSelected(allChecked ? new Set() : new Set(items.map(keyOf)))} />
                </th>
              )}
              <th>機器</th><th>世代</th><th>収集日時</th><th>変更</th><th>収集</th><th>メモ</th><th>状態</th><th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={keyOf(c)} className="review-row">
                {canReview && (
                  <td><input type="checkbox" aria-label={`${c.device_name} ${c.hash} を選択`} checked={selected.has(keyOf(c))} onChange={() => toggle(c)} /></td>
                )}
                <td>
                  <b>{c.device_name}</b>
                  {c.group_name && <div className="topo-muted topo-small">{c.group_name}</div>}
                </td>
                <td className="mono review-hash">{c.hash}</td>
                <td className="nowrap topo-small">{fmt(c.collected_at)}</td>
                <td className="nowrap"><span className="dash-add">+{c.added}</span> <span className="dash-del">-{c.removed}</span></td>
                <td className="nowrap topo-small">{TRIGGER[c.triggered_by] ?? c.triggered_by}</td>
                <td className="review-memo">
                  {c.comment && <div title={c.comment} className="review-comment">コメント: {c.comment}</div>}
                  {c.review?.note && <div title={c.review.note} className="review-comment">確認: {c.review.note}</div>}
                </td>
                <td className="nowrap">
                  <ReviewBadge review={c.review} onClick={canReview ? () => setModal({ targets: [target(c)], current: c.review }) : undefined} />
                </td>
                <td>
                  <div className="hist-actions">
                    <Link className="btn" style={{ padding: "2px 8px", fontSize: 11 }} to={`/history?device=${c.device_id}&commit=${c.commit_hash}`}>差分</Link>
                    {canReview && c.review?.status !== "confirmed" && (
                      <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} disabled={busy}
                        onClick={() => act(() => setReview(target(c), "confirmed", c.review?.note ?? undefined))}>確認済み</button>
                    )}
                    {canReview && c.review?.status !== "unexpected" && (
                      <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} disabled={busy}
                        onClick={() => setModal({ targets: [target(c)], current: c.review, status: "unexpected" })}>想定外</button>
                    )}
                    {canReview && c.review && (
                      <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} disabled={busy}
                        onClick={() => act(() => clearReview(target(c)))}>未確認に戻す</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && data.total > data.limit && (
        <p className="topo-muted topo-small">新しい {data.limit} 件までを表示しています（該当は {data.total} 件）。期間や機器グループで絞り込んでください。</p>
      )}
      {modal && (
        <ReviewModal targets={modal.targets} current={modal.current} defaultStatus={modal.status} onClose={() => setModal(null)}
          onDone={(info) => { setModal(null); setSelected(new Set()); setMessage(info.message ?? ""); load(); }} />
      )}
    </>
  );
}

interface DriftItem {
  device_id: string; device_name: string; group_id: string | null; group_name: string | null; state: "drift" | "ok" | "unknown" | "none";
  baseline: (Baseline & { collected_at: string | null }) | null;
}
interface DriftResult { total: number; counts: { drift: number; ok: number; unknown: number; none: number }; items: DriftItem[]; }

/** 基準からのずれ: 機器ごとに基準の世代を決め、最新のコンフィグとの差（ずれ）が出た機器を一覧にする */
function DriftTab() {
  const { can } = useAuth();
  const canReview = can(PERM.CONFIG_REVIEW);
  const [groupId, setGroupId] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [data, setData] = useState<DriftResult | null>(null);
  const [modal, setModal] = useState<DriftItem | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<Group[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  }, []);
  const load = useCallback(() => {
    api.get<DriftResult>("/configs/baselines", { params: { state: "all", group_id: groupId || undefined } })
      .then((r) => { setData({ ...r.data, items: r.data.items.filter((i) => i.state === "drift" || i.state === "unknown") }); setError(""); })
      .catch((e) => setError(errorMessage(e)));
  }, [groupId]);
  useEffect(() => {
    load();
  }, [load]);

  const items = data?.items ?? [];
  return (
    <>
      <div className="review-filters">
        <label className="audit-field">
          <span className="form-label">機器グループ</span>
          <select aria-label="機器グループ" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">すべて</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </label>
        {data && (
          <p className="topo-muted topo-small" style={{ margin: 0 }} data-testid="drift-counts">
            ずれている {data.counts.drift} 台・基準どおり {data.counts.ok} 台・未計算 {data.counts.unknown} 台・基準が未指定 {data.counts.none} 台
          </p>
        )}
      </div>
      {error && <p className="form-error">{error}</p>}
      {message && <p className="review-message">{message}</p>}
      {data && !items.length ? (
        <p className="topo-muted">
          {data.counts.ok + data.counts.drift + data.counts.unknown ? "基準からずれている機器はありません。" : "基準を指定した機器がありません。"}
          基準は、世代管理で承認済みの世代の「基準にする」から指定します。
        </p>
      ) : (
        <table className="data-table review-table">
          <thead>
            <tr><th>機器</th><th>基準の世代</th><th>ずれ</th><th>最新の世代</th><th>メモ</th><th>操作</th></tr>
          </thead>
          <tbody>
            {items.map((i) => {
              const b = i.baseline!;
              return (
                <tr key={i.device_id} className="drift-row">
                  <td>
                    <b>{i.device_name}</b>
                    {i.group_name && <div className="topo-muted topo-small">{i.group_name}</div>}
                  </td>
                  <td className="nowrap">
                    <span className="mono review-hash">{b.hash}</span>
                    <div className="topo-muted topo-small">{b.collected_at ? `収集 ${fmt(b.collected_at)}` : b.set_at ? `指定 ${fmt(b.set_at)}` : ""}</div>
                  </td>
                  <td className="nowrap">
                    {i.state === "unknown" ? <span className="topo-muted" title="次の収集のあとに計算します">未計算</span>
                      : <><span className="dash-add">+{b.drift_added}</span> <span className="dash-del">-{b.drift_removed}</span></>}
                  </td>
                  <td className="nowrap"><span className="mono">{b.latest ?? "—"}</span></td>
                  <td className="review-memo">
                    {b.note && <div title={b.note} className="review-comment">{b.note}</div>}
                    <div className="topo-muted topo-small">{b.set_by ? `指定: ${b.set_by}` : ""}</div>
                  </td>
                  <td>
                    <div className="hist-actions">
                      <Link className="btn" style={{ padding: "2px 8px", fontSize: 11 }} to={`/history?device=${i.device_id}&drift=1`}>差分</Link>
                      {canReview && (
                        <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setModal(i)}>最新を基準にする</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {modal && modal.baseline && (
        <BaselineModal deviceId={modal.device_id} deviceName={modal.device_name} commitHash={LATEST}
          current={modal.baseline} onClose={() => setModal(null)}
          onDone={(b) => { setModal(null); setMessage(`${modal.device_name} の基準を ${b?.hash ?? ""} に更新しました`); load(); }} />
      )}
    </>
  );
}

export default function ReviewsPage() {
  const [params, setParams] = useSearchParams();
  const tab: TabKey = params.get("tab") === "drift" ? "drift" : "changes";
  const setTab = (t: TabKey) => setParams(t === "drift" ? { tab: "drift" } : {}, { replace: true });
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">変更の確認<HelpLink topic="reviews" /></span>
        <span className="topo-muted topo-small">収集で検出した変更に「確認済み」「想定外」を付けます。付いていない変更が「未確認」です（各機器の最初の世代は対象外）。承認済みの世代（基準）からのずれも確認できます</span>
      </div>
      <div className="page-body">
        {TABS.length > 1 && (
          <div className="seg-tabs" role="tablist" style={{ marginBottom: 12, alignSelf: "flex-start" }}>
            {TABS.map((t) => (
              <button key={t.key} role="tab" aria-selected={tab === t.key} className={`seg-tab${tab === t.key ? " active" : ""}`} onClick={() => setTab(t.key)}>{t.label}</button>
            ))}
          </div>
        )}
        {tab === "changes" && <ChangesTab />}
        {tab === "drift" && <DriftTab />}
      </div>
    </div>
  );
}
