import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";

/**
 * API トークン（スクリプト・ほかのシステムから API を使うための、本人が発行するトークン）
 * - 一覧: 名前・範囲・期限・最後に使った日時と接続元。値は表示しない（先頭の数文字だけ）
 * - 発行: 名前・範囲・日数・パスワード（本人の確認）。値は発行した直後のこの画面でだけ表示する
 * - 失効: 一覧の「失効」。失効させたトークンはすぐに使えなくなる
 */

export interface ApiTokenInfo {
  id: string;
  name: string;
  prefix: string;
  scope: "read" | "full";
  status: "active" | "expired" | "revoked";
  created_at: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  last_used_ip: string | null;
  revoked_at: string | null;
}

interface TokenList { items: ApiTokenInfo[]; max_days: number; default_days: number; max_tokens: number; enabled: boolean; }

export const SCOPE_LABELS: Record<string, string> = {
  read: "閲覧だけ（read）",
  full: "ロールの権限（full）",
};
const STATUS_LABELS: Record<string, [string, string]> = {
  active: ["有効", "badge-success"],
  expired: ["期限切れ", "badge-neutral"],
  revoked: ["失効", "badge-neutral"],
};

export const fmtDateTime = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";

export function TokenTable({ items, onRevoke }: { items: ApiTokenInfo[]; onRevoke?: (t: ApiTokenInfo) => void }) {
  if (items.length === 0) return <p className="topo-muted topo-small">発行したトークンはありません</p>;
  return (
    <table className="data-table apitok-table">
      <thead>
        <tr>
          <th>名前</th>
          <th>範囲</th>
          <th>期限</th>
          <th>最後に使った日時（接続元）</th>
          <th>状態</th>
          {onRevoke && <th />}
        </tr>
      </thead>
      <tbody>
        {items.map((t) => {
          const [label, cls] = STATUS_LABELS[t.status] ?? [t.status, "badge-neutral"];
          return (
            <tr key={t.id}>
              <td>
                <div style={{ fontWeight: 500 }}>{t.name}</div>
                <div className="mono topo-muted topo-small">{t.prefix}…</div>
              </td>
              <td style={{ fontSize: 12 }}>{SCOPE_LABELS[t.scope] ?? t.scope}</td>
              <td style={{ fontSize: 12 }}>{fmtDateTime(t.expires_at)}</td>
              <td style={{ fontSize: 12 }}>
                {t.last_used_at ? <>{fmtDateTime(t.last_used_at)}{t.last_used_ip && <span className="topo-muted">（{t.last_used_ip}）</span>}</> : "未使用"}
              </td>
              <td><span className={`badge ${cls}`}>{label}</span></td>
              {onRevoke && (
                <td>
                  {t.status === "active" && (
                    <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => onRevoke(t)}>
                      失効
                    </button>
                  )}
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function CreatedToken({ token, onDone }: { token: string; onDone: () => void }) {
  const [copied, setCopied] = useState<"" | "ok" | "failed">("");
  const copy = () => {
    // クリップボードが使えない（http で開いている・ブラウザが拒否した）ときは、手でコピーしてもらう
    if (!navigator.clipboard) { setCopied("failed"); return; }
    navigator.clipboard.writeText(token).then(() => setCopied("ok")).catch(() => setCopied("failed"));
  };
  const origin = window.location.origin;
  return (
    <>
      <p style={{ marginTop: 0, marginBottom: 4 }}><b>発行した API トークン</b></p>
      <p className="form-error" style={{ marginBottom: 6 }}>この画面を閉じると二度と表示できません。いまコピーして、安全な場所に保管してください。</p>
      <p className="mfa-secret mono" data-testid="api-token-value">{token}</p>
      <div className="btn-row" style={{ marginTop: 8 }}>
        <button className="btn" onClick={copy}>{copied === "ok" ? "コピーしました" : "コピー"}</button>
      </div>
      {copied === "failed" && (
        <p className="form-error" role="alert">コピーできませんでした。上の値を選択して、手でコピーしてください。</p>
      )}
      <p className="topo-small" style={{ marginBottom: 4 }}>使い方の例（Authorization ヘッダーに付けます）</p>
      <pre className="mfa-secret mono apitok-example">{`curl -H "Authorization: Bearer ${token.slice(0, 12)}…" \\\n  ${origin}/api/devices/`}</pre>
      <div className="btn-row">
        <button className="btn btn-primary" onClick={onDone}>控えました</button>
      </div>
    </>
  );
}

export default function ApiTokenModal({ onClose }: { onClose: () => void }) {
  const [items, setItems] = useState<ApiTokenInfo[]>([]);
  const [limits, setLimits] = useState({ maxDays: 365, maxTokens: 10 });
  const [name, setName] = useState("");
  const [scope, setScope] = useState<"read" | "full">("read");
  const [days, setDays] = useState(90);
  const [password, setPassword] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = (first = false) => api.get<TokenList>("/auth/tokens").then((r) => {
    setItems(r.data.items);
    // 日数の上限などはサーバーの設定（API_TOKEN_MAX_DAYS）に合わせる
    setLimits({ maxDays: r.data.max_days, maxTokens: r.data.max_tokens });
    if (first) setDays(r.data.default_days);
  }).catch((e) => setError(errorMessage(e)));
  useEffect(() => { load(true); }, []);

  const create = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await api.post<ApiTokenInfo & { token: string }>("/auth/tokens", { name: name.trim(), scope, days, password });
      setCreated(r.data.token);
      setName("");
      setPassword("");
      load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: ApiTokenInfo) => {
    if (!confirm(`API トークン「${t.name}」を失効させますか？\nこのトークンを使っているスクリプトは、すぐに使えなくなります。`)) return;
    setError("");
    try {
      await api.delete(`/auth/tokens/${t.id}`);
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const activeCount = items.filter((t) => t.status === "active").length;

  return (
    <div className="modal-overlay" onClick={created ? undefined : onClose}>
      <div className="modal apitok-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="API トークン">
        <p className="modal-title">API トークン</p>
        {created ? (
          <CreatedToken token={created} onDone={() => setCreated(null)} />
        ) : (
          <>
            <p style={{ marginTop: 0 }} className="topo-small">
              スクリプトやほかのシステムから API を使うためのトークンです。権限は自分のロールの範囲までで、
              「閲覧だけ」は GET（読み取り）だけ使えます。「ロールの権限」は、収集・コマンド実行や、変更の確認・基準の世代・
              無視する行・コンプライアンスの例外など監視の結果を変える操作もできるので、必要なときだけ発行してください。
              トークンの発行・パスワード変更・2 段階認証・ユーザー管理・認証情報の登録や変更・ターミナルなどは、トークンでは行えません。
              漏れた疑いがあるときはすぐに失効させてください（パスワードを変えても失効しません）。
            </p>
            <TokenTable items={items} onRevoke={revoke} />

            <p className="section-label" style={{ marginTop: 18 }}>新しく発行する（有効なものは 1 人 {limits.maxTokens} 個まで。いま {activeCount} 個）</p>
            <div className="form-group">
              <label className="form-label" htmlFor="apitok-name">名前（用途）</label>
              <input id="apitok-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="例: 夜間の差分の確認" />
            </div>
            <div style={{ display: "flex", gap: 12 }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label" htmlFor="apitok-scope">範囲</label>
                <select id="apitok-scope" value={scope} onChange={(e) => setScope(e.target.value as "read" | "full")}>
                  <option value="read">{SCOPE_LABELS.read}</option>
                  <option value="full">{SCOPE_LABELS.full}</option>
                </select>
              </div>
              <div className="form-group" style={{ width: 120 }}>
                <label className="form-label" htmlFor="apitok-days">期限（日。{limits.maxDays} まで）</label>
                <input id="apitok-days" type="number" min={1} max={limits.maxDays} step={1} value={days}
                       onChange={(e) => setDays(Number(e.target.value))} />
              </div>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="apitok-pw">パスワード（本人の確認）</label>
              <input id="apitok-pw" type="password" value={password} autoComplete="current-password"
                     onChange={(e) => setPassword(e.target.value)} />
            </div>
            {error && <p className="form-error">{error}</p>}
            <div className="btn-row">
              <button className="btn" onClick={onClose}>閉じる</button>
              <button className="btn btn-primary" onClick={create}
                      disabled={busy || !name.trim() || !password || !(Number.isInteger(days) && days >= 1 && days <= limits.maxDays)}>
                発行
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
