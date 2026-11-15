import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * 本番の nginx と同じ CSP の値を nginx/csp.inc から読み取る（画面テストと本番の設定がずれないようにするため）
 *   app  … 画面（既定）の CSP
 *   docs … /docs（Swagger UI）の CSP
 */
export function readCsp(): { app: string; docs: string } {
  const here = dirname(fileURLToPath(import.meta.url));
  const text = readFileSync(join(here, "..", "nginx", "csp.inc"), "utf-8");
  const value = (key: string) => {
    const m = text.match(new RegExp(`^\\s*${key.replace("/", "\\/")}\\s+"([^"]+)";`, "m"));
    if (!m) throw new Error(`nginx/csp.inc に ${key} の CSP が見つかりません`);
    return m[1];
  };
  return { app: value("default"), docs: value("/docs") };
}
