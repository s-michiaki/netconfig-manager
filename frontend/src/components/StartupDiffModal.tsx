import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";

interface StartupDiff {
  state: "synced" | "unsaved" | "unknown" | null;
  added: number | null; removed: number | null; diff: string | null; checked_at: string | null;
}

const fmt = (iso: string) => new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z").toLocaleString("ja-JP");

/** 差分の色分け（最初の @@ より前の見出し行は灰色。HistoryPage の差分と同じ見た目） */
function lines(diff: string) {
  let inHunk = false;
  return diff.split("\n").map((line, i) => {
    let cls = "diff-meta";
    if (line.startsWith("@@")) inHunk = true;
    else if (inHunk && line.startsWith("+")) cls = "diff-add";
    else if (inHunk && line.startsWith("-")) cls = "diff-del";
    return <div key={i} className={cls}>{line || " "}</div>;
  });
}

/** 保存されていない変更（startup-config → running-config の差分）。コンフィグの中身なので、閲覧権限のある人だけが開ける */
export default function StartupDiffModal({ deviceId, deviceName, onClose }: { deviceId: string; deviceName: string; onClose: () => void }) {
  const [data, setData] = useState<StartupDiff | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.get<StartupDiff>(`/devices/${encodeURIComponent(deviceId)}/startup-diff`)
      .then((r) => setData(r.data)).catch((e) => setError(errorMessage(e)));
  }, [deviceId]);
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: "min(760px, 96vw)" }} role="dialog" aria-label="保存されていない変更" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">保存されていない変更: {deviceName}</p>
        {error && <p className="form-error">{error}</p>}
        {data && (
          <>
            <p style={{ fontSize: 12, color: "var(--color-muted)", marginBottom: 10 }}>
              {data.state === "unsaved"
                ? `running-config にあって startup-config に保存されていない変更です（+${data.added} 行 / -${data.removed} 行）。`
                  + "再起動すると、この変更は失われます。機器で保存（write memory など）してください。"
                : data.state === "synced" ? "running-config と startup-config は一致しています。"
                : data.state === "unknown" ? "startup-config を読み取れなかったため、まだ比べられていません。"
                : "この機器は保存し忘れの検出の対象外です。"}
              {data.checked_at && ` 最後に比べた日時: ${fmt(data.checked_at)}`}
            </p>
            {data.diff && <div className="diff-view" aria-label="差分">{lines(data.diff)}</div>}
          </>
        )}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
      </div>
    </div>
  );
}
