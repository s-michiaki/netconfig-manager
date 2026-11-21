import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";

/**
 * メールサーバー（メール通知の送信設定）。管理者のみ
 * - 認証: なし / SMTP Auth（パスワード）/ Microsoft 365（OAuth 2.0）/ Google（サービスアカウント・アカウントの同意）
 * - 秘密の値（パスワード・シークレット・鍵）は表示しない。空欄なら変更なし
 */

type Auth = "none" | "password" | "microsoft" | "google_sa" | "google_user";
type Security = "starttls" | "ssl" | "none";

interface MailServer {
  enabled: boolean; auth: Auth; host: string; port: number; security: Security; verify_tls: boolean;
  username: string; from_address: string; from_name: string; subject_prefix: string; allowed_domains: string;
  ms_tenant_id: string; ms_client_id: string; google_client_id: string;
  has_password: boolean; has_ms_client_secret: boolean; has_google_client_secret: boolean; has_google_sa_json: boolean;
  google_sa_email: string | null; google_authorized: boolean; google_authorized_at: string | null; google_redirect_uri: string;
  updated_at: string | null; updated_by: string | null;
  last_result: { at: string; ok: boolean; error: string | null } | null;
}

const AUTH_OPTIONS: [Auth, string, string][] = [
  ["password", "SMTP Auth（ユーザー名＋パスワード）", "社内のメールサーバー、Gmail のアプリパスワード、送信サービスなど"],
  ["microsoft", "Microsoft 365（OAuth 2.0）", "Entra ID にアプリを登録し、クライアント ID・シークレットでトークンを取ります"],
  ["google_sa", "Google Workspace（サービスアカウント）", "ドメイン全体の委任を設定したサービスアカウントの鍵（JSON）で送ります"],
  ["google_user", "Google アカウント（OAuth 2.0・同意）", "個人の Gmail など。一度 Google にサインインして送信を許可します"],
  ["none", "認証なし", "社内のリレー（送信元の IP で許可しているサーバー）"],
];

// 認証方式を選んだときの既定値（ホスト・ポートが空か既定のままのときだけ入れる）
const PRESETS: Partial<Record<Auth, { host: string; port: number; security: Security }>> = {
  microsoft: { host: "smtp.office365.com", port: 587, security: "starttls" },
  google_sa: { host: "smtp.gmail.com", port: 587, security: "starttls" },
  google_user: { host: "smtp.gmail.com", port: 587, security: "starttls" },
};
const PRESET_HOSTS = ["", "smtp.office365.com", "smtp.gmail.com"];

function fmt(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { dateStyle: "short", timeStyle: "short" });
}

interface Form {
  enabled: boolean; auth: Auth; host: string; port: string; security: Security; verify_tls: boolean;
  username: string; from_address: string; from_name: string; subject_prefix: string; allowed_domains: string;
  ms_tenant_id: string; ms_client_id: string; google_client_id: string;
  password: string; ms_client_secret: string; google_client_secret: string; google_sa_json: string;
}

function toForm(s: MailServer): Form {
  return {
    enabled: s.enabled, auth: s.auth, host: s.host, port: String(s.port), security: s.security, verify_tls: s.verify_tls,
    username: s.username, from_address: s.from_address, from_name: s.from_name, subject_prefix: s.subject_prefix,
    allowed_domains: s.allowed_domains, ms_tenant_id: s.ms_tenant_id, ms_client_id: s.ms_client_id,
    google_client_id: s.google_client_id, password: "", ms_client_secret: "", google_client_secret: "", google_sa_json: "",
  };
}

function Secret({ id, label, has, value, onChange, multiline, placeholder }: {
  id: string; label: string; has: boolean; value: string; onChange: (v: string) => void; multiline?: boolean; placeholder?: string;
}) {
  const ph = has ? "登録済み（変更する場合のみ入力）" : placeholder ?? "";
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>{label}{has && <span className="badge badge-success" style={{ marginLeft: 6 }}>登録済み</span>}</label>
      {multiline ? (
        <textarea id={id} rows={4} value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} className="mono" spellCheck={false} />
      ) : (
        <input id={id} type="password" value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} autoComplete="new-password" />
      )}
    </div>
  );
}

export default function MailServerTab() {
  const [data, setData] = useState<MailServer | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [testTo, setTestTo] = useState("");
  const [testResult, setTestResult] = useState<{ ok: boolean; error: string | null } | null>(null);
  const [authUrl, setAuthUrl] = useState("");
  const [pasted, setPasted] = useState("");

  const apply = (s: MailServer) => { setData(s); setForm(toForm(s)); };
  const load = useCallback(async () => apply((await api.get<MailServer>("/mail/server")).data), []);
  useEffect(() => { load().catch((e) => setError(errorMessage(e))); }, [load]);

  if (!form || !data) return <p className="ntf-muted">{error || "読み込み中..."}</p>;
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm({ ...form, [k]: v });
  const isOauth = form.auth === "microsoft" || form.auth === "google_sa" || form.auth === "google_user";

  const chooseAuth = (auth: Auth) => {
    const p = PRESETS[auth];
    const next = { ...form, auth };
    if (p && PRESET_HOSTS.includes(form.host)) Object.assign(next, { host: p.host, port: String(p.port), security: p.security });
    setForm(next);
  };

  // 秘密の値の空欄は変更なし（null）
  const body = () => ({
    ...form, port: Number(form.port) || 587,
    password: form.password || null, ms_client_secret: form.ms_client_secret || null,
    google_client_secret: form.google_client_secret || null, google_sa_json: form.google_sa_json.trim() || null,
  });
  const save = async () => {
    setBusy(true); setError(""); setMsg("");
    try {
      apply((await api.put<MailServer>("/mail/server", body())).data);
      setMsg("保存しました");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const removeSecret = async (field: "password" | "ms_client_secret" | "google_client_secret" | "google_sa_json", label: string) => {
    if (!confirm(`${label}を削除しますか？`)) return;
    try {
      apply((await api.put<MailServer>("/mail/server", { ...body(), enabled: false, [field]: "" })).data);
      setMsg(`${label}を削除しました（メール送信は無効にしました）`);
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const sendTest = async () => {
    setTestResult(null); setError("");
    try {
      setTestResult((await api.post("/mail/server/test", { to: testTo })).data);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const startGoogle = async () => {
    setError(""); setAuthUrl(""); setPasted("");
    try {
      const url = (await api.post<{ url: string }>("/mail/google/authorize")).data.url;
      setAuthUrl(url);
      window.open(url, "_blank", "noopener");
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const completeGoogle = async () => {
    setError("");
    try {
      apply((await api.post<MailServer>("/mail/google/complete", { url: pasted })).data);
      setAuthUrl(""); setPasted("");
      setMsg("Google アカウントの同意を保存しました");
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const revokeGoogle = async () => {
    if (!confirm("保存している Google アカウントの同意（更新用トークン）を削除しますか？")) return;
    try {
      apply((await api.delete<MailServer>("/mail/google")).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const last = data.last_result;
  return (
    <div className="card ntf-card mail-card">
      <p className="ntf-lead">
        通知をメールで送るための設定です。宛先は「自分の通知」「ユーザーグループ」で登録します。
        パスワード・シークレット・鍵は暗号化して保存し、画面には表示しません。
      </p>

      <label className="form-check" style={{ marginBottom: 12 }}>
        <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
        <b>メール送信を有効にする</b>
      </label>

      <div className="form-group">
        <span className="form-label">認証の方式</span>
        <div className="ntf-modes" role="radiogroup">
          {AUTH_OPTIONS.map(([v, label, desc]) => (
            <label key={v} className={`ntf-mode${form.auth === v ? " active" : ""}`}>
              <input type="radio" name="mail-auth" checked={form.auth === v} onChange={() => chooseAuth(v)} />
              <span><b>{label}</b><span className="ntf-muted"> — {desc}</span></span>
            </label>
          ))}
        </div>
      </div>

      <div className="mail-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="mail-host">SMTP サーバー</label>
          <input id="mail-host" value={form.host} onChange={(e) => set("host", e.target.value)} placeholder="smtp.example.com" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="mail-port">ポート</label>
          <input id="mail-port" inputMode="numeric" value={form.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, ""))} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="mail-sec">暗号化</label>
          <select id="mail-sec" value={form.security} onChange={(e) => {
            const v = e.target.value as Security;
            setForm({ ...form, security: v, port: form.port === "587" || form.port === "465" || form.port === "25" ? (v === "ssl" ? "465" : v === "starttls" ? "587" : "25") : form.port });
          }}>
            <option value="starttls">STARTTLS（587）</option>
            <option value="ssl">SSL/TLS（465）</option>
            <option value="none" disabled={isOauth}>なし（社内のリレーのみ）</option>
          </select>
        </div>
      </div>
      {form.security !== "none" && (
        <label className="form-check" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={!form.verify_tls} onChange={(e) => set("verify_tls", !e.target.checked)} />
          サーバーの証明書を確認しない（社内の自己署名の証明書のときだけ。通信を盗み見られても気づけなくなります）
        </label>
      )}

      {form.auth !== "none" && (
        <div className="form-group">
          <label className="form-label" htmlFor="mail-user">
            {form.auth === "password" ? "ユーザー名" : "送信に使うメールアドレス（メールボックス）"}
          </label>
          <input id="mail-user" value={form.username} onChange={(e) => set("username", e.target.value)} placeholder="notify@example.com" autoComplete="off" />
        </div>
      )}

      {form.auth === "password" && (
        <>
          <Secret id="mail-pass" label="パスワード（アプリパスワード）" has={data.has_password} value={form.password} onChange={(v) => set("password", v)} />
          <p className="ntf-muted mail-hint">
            Gmail はアカウントのパスワードでは送れません（アプリパスワードを作成）。Microsoft 365 はパスワードでの送信が廃止される予定のため、OAuth 2.0 を推奨します。
          </p>
        </>
      )}

      {form.auth === "microsoft" && (
        <>
          <div className="mail-grid mail-grid-2">
            <div className="form-group">
              <label className="form-label" htmlFor="mail-tenant">テナント ID</label>
              <input id="mail-tenant" className="mono" value={form.ms_tenant_id} onChange={(e) => set("ms_tenant_id", e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="mail-msclient">アプリケーション（クライアント）ID</label>
              <input id="mail-msclient" className="mono" value={form.ms_client_id} onChange={(e) => set("ms_client_id", e.target.value)} />
            </div>
          </div>
          <Secret id="mail-mssecret" label="クライアントシークレット（値）" has={data.has_ms_client_secret} value={form.ms_client_secret} onChange={(v) => set("ms_client_secret", v)} />
          <p className="ntf-muted mail-hint">
            Entra ID のアプリに API のアクセス許可「Office 365 Exchange Online → SMTP.SendAsApp（アプリケーション）」を付けて管理者の同意を行い、
            Exchange Online でアプリのサービスプリンシパルを登録して、送信に使うメールボックスへの権限を与えてください（手順は README）。
            シークレットには有効期限があります。
          </p>
        </>
      )}

      {form.auth === "google_sa" && (
        <>
          <Secret id="mail-sa" label="サービスアカウントの鍵（JSON）" has={data.has_google_sa_json} value={form.google_sa_json}
            onChange={(v) => set("google_sa_json", v)} multiline placeholder='{"type": "service_account", "client_email": "…", "private_key": "…"}' />
          {data.google_sa_email && <p className="ntf-muted mail-hint">登録済みの鍵: <span className="mono">{data.google_sa_email}</span></p>}
          <p className="ntf-muted mail-hint">
            Google Workspace の管理コンソールで、このサービスアカウントのクライアント ID にドメイン全体の委任（スコープ https://mail.google.com/）を許可してください。
          </p>
        </>
      )}

      {form.auth === "google_user" && (
        <>
          <div className="form-group">
            <label className="form-label" htmlFor="mail-gclient">OAuth クライアント ID（種類: デスクトップ アプリ）</label>
            <input id="mail-gclient" className="mono" value={form.google_client_id} onChange={(e) => set("google_client_id", e.target.value)} placeholder="…apps.googleusercontent.com" />
          </div>
          <Secret id="mail-gsecret" label="クライアントシークレット" has={data.has_google_client_secret} value={form.google_client_secret} onChange={(v) => set("google_client_secret", v)} />
          <div className="mail-consent">
            <div>
              Google アカウントの同意:{" "}
              {data.google_authorized
                ? <span className="badge badge-success">済み（{fmt(data.google_authorized_at)}）</span>
                : <span className="badge badge-warning">まだ</span>}
            </div>
            <ol className="ntf-muted">
              <li>上の設定を保存してから「Google にサインイン」を押し、開いた画面で送信者のアカウントでサインインして許可します</li>
              <li>許可すると、ブラウザが <span className="mono">{data.google_redirect_uri}</span> を開いて「接続できません」と表示します（正常です）</li>
              <li>そのページのアドレス欄の内容をすべてコピーして、下に貼り付けてください（10 分以内）</li>
            </ol>
            <div className="btn-row" style={{ justifyContent: "flex-start" }}>
              <button className="btn" onClick={startGoogle} disabled={!data.google_client_id || !data.has_google_client_secret}>Google にサインイン</button>
              {data.google_authorized && <button className="btn btn-danger" onClick={revokeGoogle}>同意を削除</button>}
            </div>
            {authUrl && (
              <div className="form-group" style={{ marginTop: 8 }}>
                <p className="ntf-muted">新しいタブが開かない場合は <a href={authUrl} target="_blank" rel="noopener noreferrer">こちら</a> を開いてください。</p>
                <label className="form-label" htmlFor="mail-paste">許可したあとのアドレス</label>
                <input id="mail-paste" className="mono" value={pasted} onChange={(e) => setPasted(e.target.value)} placeholder="http://127.0.0.1/?state=…&code=…" />
                <div className="btn-row" style={{ justifyContent: "flex-start" }}>
                  <button className="btn btn-primary" onClick={completeGoogle} disabled={!pasted.trim()}>同意を保存</button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      <div className="mail-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="mail-from">送信元のメールアドレス</label>
          <input id="mail-from" value={form.from_address} onChange={(e) => set("from_address", e.target.value)} placeholder="notify@example.com" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="mail-fromname">送信者名</label>
          <input id="mail-fromname" value={form.from_name} onChange={(e) => set("from_name", e.target.value)} placeholder="NetConfig Manager" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="mail-prefix">件名の先頭</label>
          <input id="mail-prefix" value={form.subject_prefix} onChange={(e) => set("subject_prefix", e.target.value)} placeholder="[NetConfig]" />
        </div>
      </div>
      {isOauth && <p className="ntf-muted mail-hint">OAuth 2.0 では、送信元は送信に使うメールアドレス（または送信を許可された別名）にしてください。</p>}
      <div className="form-group">
        <label className="form-label" htmlFor="mail-domains">宛先に使えるドメイン（カンマ区切り。空なら制限しない）</label>
        <input id="mail-domains" value={form.allowed_domains} onChange={(e) => set("allowed_domains", e.target.value)} placeholder="example.com, example.co.jp" />
        <p className="ntf-muted" style={{ marginTop: 4 }}>閲覧者も自分の宛先を登録できるため、社外のアドレスへ送らせないときに指定します（サブドメインも含みます）。</p>
      </div>

      {error && <p className="form-error">{error}</p>}
      {msg && <p className="ntf-ok">{msg}</p>}
      <div className="btn-row">
        {data.has_password && form.auth !== "password" && <button className="btn btn-sm" onClick={() => removeSecret("password", "パスワード")}>保存済みのパスワードを削除</button>}
        <button className="btn btn-primary" onClick={save} disabled={busy}>保存</button>
      </div>

      <div className="ntf-section">
        <span className="form-label">テスト送信（保存済みの設定で送ります）</span>
        <div style={{ display: "flex", gap: 8 }}>
          <input aria-label="テストメールの宛先" value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder="宛先のメールアドレス" style={{ maxWidth: 360 }} />
          <button className="btn" onClick={sendTest} disabled={!testTo.trim() || !data.enabled}>テストメールを送る</button>
        </div>
        {testResult && (
          <p style={{ marginTop: 6, color: testResult.ok ? "var(--color-success)" : "var(--color-danger)" }}>
            {testResult.ok ? "送信しました。届いているか確認してください" : testResult.error}
          </p>
        )}
        {last && !testResult && (
          <p className="ntf-muted" style={{ marginTop: 6 }}>
            最後の送信: {fmt(last.at)}{" "}
            {last.ok ? <span style={{ color: "var(--color-success)" }}>成功</span> : <span style={{ color: "var(--color-danger)" }}>失敗（{last.error}）</span>}
          </p>
        )}
        {data.updated_at && <p className="ntf-muted">設定の更新: {fmt(data.updated_at)}（{data.updated_by}）</p>}
      </div>
    </div>
  );
}
