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

/** 受け取った blob をファイルとして保存する */
function saveBlob(data: Blob, disposition: string, fallback: string) {
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filenameOf(disposition, fallback);
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** ファイルをダウンロードする（認証ヘッダーが要るため blob で受け取る） */
export async function downloadFile(path: string, params: Record<string, unknown>, fallback: string) {
  const r = await api.get<Blob>(path, { params, responseType: "blob" });
  saveBlob(r.data, String(r.headers["content-disposition"] ?? ""), fallback);
}

/**
 * 条件を本文で送ってダウンロードする（検索語など URL・アクセスログに残したくない条件用）。
 * 応答ヘッダーを返す（件数などを画面で知らせるため）
 */
export async function downloadFilePost(path: string, body: unknown, fallback: string) {
  const r = await api.post<Blob>(path, body, { responseType: "blob" });
  saveBlob(r.data, String(r.headers["content-disposition"] ?? ""), fallback);
  return r.headers;
}

/** 絞り込みと同じ条件で CSV をダウンロードする */
export const downloadCsv = downloadFile;

export function CsvButton({ onClick, disabled = false, title = "今の絞り込み条件で出力します（最大10万件）" }: {
  onClick: () => Promise<void>; disabled?: boolean; title?: string;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <button className="btn" disabled={busy || disabled} title={title}
      onClick={async () => { setBusy(true); try { await onClick(); } finally { setBusy(false); } }}>
      {busy ? "出力中..." : "CSV 出力"}
    </button>
  );
}
