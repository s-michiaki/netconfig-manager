import { useState } from "react";
import { api, errorMessage } from "../api/client";

/** 変更（世代）の確認の状態（backend/app/api/config_reviews.py の review_dict と対応）。null は未確認 */
export interface Review { status: "confirmed" | "unexpected"; note: string | null; reviewed_by: string | null; reviewed_at: string | null; }
/** 確認を付ける対象の世代 */
export interface ReviewTarget { device_id: string; commit_hash: string; label: string; }

export const REVIEW_NOTE_MAX = 500;
const LABEL = { confirmed: "確認済み", unexpected: "想定外" } as const;

const fmt = (iso: string) => new Date(iso).toLocaleString("ja-JP");

/** 状態のバッジ（確認済み＝緑・想定外＝赤・未確認＝灰）。onClick があればボタンとして操作できる */
export function ReviewBadge({ review, onClick }: { review: Review | null; onClick?: () => void }) {
  const cls = review ? (review.status === "confirmed" ? "badge-success" : "badge-danger") : "badge-neutral";
  const text = review ? LABEL[review.status] : "未確認";
  const title = review
    ? `${text}: ${review.reviewed_by ?? ""}${review.reviewed_at ? ` · ${fmt(review.reviewed_at)}` : ""}${review.note ? `\n${review.note}` : ""}`
    : "まだ確認されていない変更です";
  if (!onClick) return <span className={`badge ${cls} review-badge`} title={title}>{text}</span>;
  return <button type="button" className={`badge ${cls} review-badge review-badge-btn`} title={`${title}\nクリックでメモの編集・付け直し`} onClick={onClick}>{text}</button>;
}

/** 1 件の確認を付ける・戻す（API を呼ぶだけ。画面の更新は呼び出し側）。付けたあとの状態を返す */
export const setReview = (t: ReviewTarget, status: Review["status"], note?: string) =>
  api.put<Review>(`/configs/${encodeURIComponent(t.device_id)}/reviews/${t.commit_hash}`, { status, note: note?.trim() || null })
    .then((r) => r.data);
export const clearReview = (t: ReviewTarget) =>
  api.delete(`/configs/${encodeURIComponent(t.device_id)}/reviews/${t.commit_hash}`);

const BULK_CHUNK = 200; // API が 1 回で受け付ける件数の上限

/** 画面に出すエラーの文言（bulkReview が途中で失敗したときの説明は、そのまま出す） */
export const reviewError = (e: unknown) => (e instanceof Error && e.name === "BulkReviewError" ? e.message : errorMessage(e));

/**
 * 複数をまとめて付ける。200 件ずつに分けて順に送る。付けられなかった（対象外の）件数を返す。
 * 途中で失敗したら、そこまでに付けた件数と理由を含むエラーにする
 */
export async function bulkReview(targets: ReviewTarget[], status: Review["status"], note?: string): Promise<{ updated: number; skipped: number }> {
  let updated = 0;
  let skipped = 0;
  for (let i = 0; i < targets.length; i += BULK_CHUNK) {
    try {
      const r = await api.post<{ updated: number; skipped: unknown[] }>("/configs/reviews/bulk", {
        items: targets.slice(i, i + BULK_CHUNK).map((t) => ({ device_id: t.device_id, commit_hash: t.commit_hash })),
        status, note: note?.trim() || null,
      });
      updated += r.data.updated;
      skipped += r.data.skipped.length;
    } catch (e) {
      const err = new Error(`${updated} 件を付けたところで失敗しました（残り ${targets.length - i} 件は付いていません）: ${errorMessage(e)}`);
      err.name = "BulkReviewError";
      throw err;
    }
  }
  return { updated, skipped };
}

/** まとめて付けた結果の文言 */
export const bulkMessage = (r: { updated: number; skipped: number }, status: Review["status"]) =>
  `${r.updated} 件を${LABEL[status]}にしました${r.skipped ? `（${r.skipped} 件は対象外）` : ""}`;

/**
 * 確認の入力（小さなモーダル）。メモ（任意）を書いて「確認済みにする」「想定外にする」を選ぶ。
 * 既に状態が付いている世代では「未確認に戻す」もできる。複数の世代を渡すとまとめて付ける
 */
export default function ReviewModal({ targets, current, defaultStatus, onClose, onDone }: {
  targets: ReviewTarget[]; current?: Review | null; defaultStatus?: Review["status"]; onClose: () => void;
  // 1 件のときは付けたあとの状態（戻したときは null）、まとめたときは結果の文言を渡す
  onDone: (info: { review?: Review | null; message?: string }) => void;
}) {
  const [note, setNote] = useState(current?.note ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const bulk = targets.length > 1;
  const run = async (f: () => Promise<{ review?: Review | null; message?: string }>) => {
    setBusy(true);
    setError("");
    try {
      onDone(await f());
    } catch (e) {
      setError(reviewError(e));
      setBusy(false);
    }
  };
  const apply = (status: Review["status"]) => run(async () => (bulk
    ? { message: bulkMessage(await bulkReview(targets, status, note), status) }
    : { review: await setReview(targets[0], status, note) }));
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">変更の確認</p>
        <p className="hist-note">
          {bulk ? `選んだ ${targets.length} 件の変更に` : <><span className="mono">{targets[0].label}</span> の変更に</>}
          「確認済み」（意図した変更）か「想定外」（身に覚えのない変更）を付けます。変更は監査ログに残ります。
        </p>
        {current && <p className="hist-note">いまの状態: <ReviewBadge review={current} />　{current.reviewed_by}{current.reviewed_at ? ` · ${fmt(current.reviewed_at)}` : ""}</p>}
        <div className="form-group">
          <label className="form-label" htmlFor="review-note">メモ（任意・{REVIEW_NOTE_MAX} 文字まで）</label>
          <textarea id="review-note" rows={4} maxLength={REVIEW_NOTE_MAX} value={note} onChange={(e) => setNote(e.target.value)}
            placeholder="例: 依頼番号 CHG-1234 の作業と一致を確認 / 依頼のない VLAN の追加。作業者に確認中" />
          <p className="hist-note" style={{ marginTop: 4 }}>{note.length} / {REVIEW_NOTE_MAX} 文字。パスワードなどの秘密情報は書かないでください</p>
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          {!bulk && current && (
            <button className="btn" disabled={busy} onClick={() => run(async () => { await clearReview(targets[0]); return { review: null }; })}>未確認に戻す</button>
          )}
          <button className={`btn ${defaultStatus === "unexpected" ? "btn-primary" : "btn-danger"}`} disabled={busy} onClick={() => apply("unexpected")}>想定外にする</button>
          <button className={`btn ${defaultStatus === "unexpected" ? "" : "btn-primary"}`} disabled={busy} onClick={() => apply("confirmed")}>確認済みにする</button>
        </div>
      </div>
    </div>
  );
}
