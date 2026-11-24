import { useState } from "react";
import { api, errorMessage } from "../api/client";

/** 機器の基準の世代とずれ（backend/app/api/config_baselines.py の baseline_dict と対応） */
export interface Baseline {
  commit_hash: string; hash: string; note: string | null; set_by: string | null; set_at: string | null;
  drift_added: number | null; drift_removed: number | null; latest_hash: string | null; latest: string | null; checked_at: string | null;
}

export const BASELINE_NOTE_MAX = 200;

/** ずれの行数（未計算なら 0） */
export const driftOf = (b: Baseline | null | undefined) => (b ? (b.drift_added ?? 0) + (b.drift_removed ?? 0) : 0);
/** ずれが未計算（計算できなかった・まだ計算していない） */
export const isUnknown = (b: Baseline | null | undefined) => !!b && b.drift_added === null;

/** 基準にする世代に渡すと、サーバーが実際の最新の世代（HEAD）を解決する */
export const LATEST = "latest";

/** 基準を指定する（付け替えも同じ）。指定後の基準とずれを返す */
export const setBaseline = (deviceId: string, commitHash: string, note?: string) =>
  api.put<Baseline>(`/configs/${encodeURIComponent(deviceId)}/baseline`, { commit_hash: commitHash, note: note?.trim() || null })
    .then((r) => r.data);
export const clearBaseline = (deviceId: string) => api.delete(`/configs/${encodeURIComponent(deviceId)}/baseline`);

const fmt = (iso: string) => new Date(iso).toLocaleString("ja-JP");

/** 世代の行に付ける「基準」のバッジ */
export function BaselineBadge({ baseline }: { baseline: Baseline | null }) {
  const title = baseline ? `基準の世代です（${baseline.set_by ?? ""}${baseline.set_at ? ` · ${fmt(baseline.set_at)}` : ""}）${baseline.note ? `\n${baseline.note}` : ""}` : "";
  return <span className="badge baseline-badge" title={title}>基準</span>;
}

/**
 * 基準にする・解除する前の確認（小さなモーダル）。基準にするときはメモ（任意）を書ける。
 * 基準にした世代との差が、そのあとの「ずれ」になる
 */
export default function BaselineModal({ deviceId, deviceName, commitHash, hash, current, onClose, onDone }: {
  deviceId: string; deviceName: string;
  commitHash: string | null; // null なら基準の解除。LATEST なら最新の世代
  hash?: string; current: Baseline | null; onClose: () => void;
  onDone: (b: Baseline | null) => void;
}) {
  const clearing = commitHash === null;
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = async () => {
    setBusy(true);
    setError("");
    try {
      if (commitHash === null) {
        await clearBaseline(deviceId);
        onDone(null);
      } else {
        onDone(await setBaseline(deviceId, commitHash, note));
      }
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{clearing ? "基準の解除" : "基準にする"}</p>
        {clearing ? (
          <p className="hist-note">
            <b>{deviceName}</b> の基準（<span className="mono">{current?.hash}</span>）を解除します。ずれの検出・通知は止まります。
          </p>
        ) : (
          <>
            <p className="hist-note">
              <b>{deviceName}</b> の{commitHash === LATEST ? "最新の世代" : <>世代 <span className="mono">{hash}</span></>} を「承認済みの状態」（基準）にします。
              最新のコンフィグとの差が「ずれ」として、変更の確認・ダッシュボード・通知に出ます。
              {current && <>　いまの基準（<span className="mono">{current.hash}</span>）は置き換わります。</>}
            </p>
            <div className="form-group">
              <label className="form-label" htmlFor="baseline-note">メモ（任意・{BASELINE_NOTE_MAX} 文字まで）</label>
              <input id="baseline-note" maxLength={BASELINE_NOTE_MAX} value={note} onChange={(e) => setNote(e.target.value)}
                placeholder="例: 2026 年度の定期見直しで承認" />
            </div>
          </>
        )}
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className={`btn ${clearing ? "btn-danger" : "btn-primary"}`} disabled={busy} onClick={run}>
            {clearing ? "基準を解除する" : "基準にする"}
          </button>
        </div>
      </div>
    </div>
  );
}
