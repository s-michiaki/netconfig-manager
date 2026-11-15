import { useState } from "react";
import { api } from "../api/client";

/** Content-Disposition からファイル名を取り出す（日本語の名前は filename*=UTF-8''... に入っている） */
function filenameOf(header: string, fallback: string): string {
  const star = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      // 壊れた値なら filename="..." を使う
    }
  }
  const m = /filename="([^"]+)"/.exec(header);
  return m ? m[1] : fallback;
}

/** ファイルをダウンロードする（認証ヘッダーが要るため blob で受け取る） */
export async function downloadFile(path: string, params: Record<string, unknown>, fallback: string) {
  const r = await api.get<Blob>(path, { params, responseType: "blob" });
  const url = URL.createObjectURL(r.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filenameOf(String(r.headers["content-disposition"] ?? ""), fallback);
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** 絞り込みと同じ条件で CSV をダウンロードする */
export const downloadCsv = downloadFile;

export function CsvButton({ onClick }: { onClick: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  return (
    <button className="btn" disabled={busy} title="今の絞り込み条件で出力します（最大10万件）"
      onClick={async () => { setBusy(true); try { await onClick(); } finally { setBusy(false); } }}>
      {busy ? "出力中..." : "CSV 出力"}
    </button>
  );
}
