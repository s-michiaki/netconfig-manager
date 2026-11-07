import { useState } from "react";
import { api } from "../api/client";

/** 絞り込みと同じ条件で CSV をダウンロードする（認証ヘッダーが要るため blob で受け取る） */
export async function downloadCsv(path: string, params: Record<string, unknown>, fallback: string) {
  const r = await api.get<Blob>(path, { params, responseType: "blob" });
  const m = /filename="([^"]+)"/.exec(String(r.headers["content-disposition"] ?? ""));
  const url = URL.createObjectURL(r.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = m ? m[1] : fallback;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function CsvButton({ onClick }: { onClick: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  return (
    <button className="btn" disabled={busy} title="今の絞り込み条件で出力します（最大10万件）"
      onClick={async () => { setBusy(true); try { await onClick(); } finally { setBusy(false); } }}>
      {busy ? "出力中..." : "CSV 出力"}
    </button>
  );
}
