import { useState } from "react";
import { api, errorMessage } from "../api/client";

/**
 * 2 段階認証（ワンタイムパスワード）の設定。本人だけが操作する（管理者は「ユーザー管理」で解除だけできる）
 * - 未設定: 「設定を始める」→ QR コードを認証アプリで読み取る → 表示された 6 桁で確認 → 予備コードを控える
 * - 設定済み: 予備コードの作り直し、解除（パスワードとコードで確認）
 */

interface Setup { secret: string; uri: string; qr_svg: string; }

function RecoveryList({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join("\n");
  const [copied, setCopied] = useState(false);
  return (
    <>
      <p style={{ marginBottom: 4 }}><b>予備コード</b>（この画面でしか表示しません。安全な場所に控えてください）</p>
      <p className="topo-muted topo-small" style={{ marginTop: 0 }}>
        認証アプリを無くしたときに、確認コードの代わりに 1 回ずつ使えます。
      </p>
      <div className="mfa-codes mono">{codes.map((c) => <span key={c}>{c}</span>)}</div>
      <div className="btn-row">
        <button className="btn" onClick={() => { navigator.clipboard?.writeText(text).then(() => setCopied(true)).catch(() => undefined); }}>
          {copied ? "コピーしました" : "コピー"}
        </button>
        <button className="btn btn-primary" onClick={onDone}>控えました</button>
      </div>
    </>
  );
}

export default function MfaModal({ enabled, onClose, onChanged }: { enabled: boolean; onClose: () => void; onChanged: () => void }) {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [mode, setMode] = useState<"main" | "disable" | "regen">("main");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const start = () => run(async () => { setSetup((await api.post<Setup>("/auth/mfa/setup")).data); });
  const enable = () => run(async () => {
    const r = await api.post<{ recovery_codes: string[] }>("/auth/mfa/enable", { code });
    setRecovery(r.data.recovery_codes);
    setSetup(null);
    setCode("");
    onChanged();
  });
  const regen = () => run(async () => {
    const r = await api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { code });
    setRecovery(r.data.recovery_codes);
    setCode("");
    setMode("main");
  });
  const disable = () => run(async () => {
    await api.post("/auth/mfa/disable", { password, code });
    setPassword("");
    setCode("");
    setMode("main");
    setNotice("2 段階認証を解除しました。次のログインからはパスワードだけで入れます");
    onChanged();
  });

  let body: React.ReactNode;
  if (recovery) {
    body = <RecoveryList codes={recovery} onDone={() => { setRecovery(null); setNotice("2 段階認証を設定しています"); }} />;
  } else if (!enabled && setup) {
    body = (
      <>
        <p style={{ marginTop: 0 }}>1. 認証アプリ（Google Authenticator・Microsoft Authenticator など）でこの QR コードを読み取ります。</p>
        <div className="mfa-qr" dangerouslySetInnerHTML={{ __html: setup.qr_svg }} />
        <p className="topo-muted topo-small">読み取れないときは、次の文字列（秘密鍵）を手で入力します（時間ベース・6 桁）。</p>
        <p className="mfa-secret mono">{setup.secret}</p>
        <div className="form-group">
          <label className="form-label" htmlFor="mfa-enable-code">2. アプリに表示された 6 桁のコード</label>
          <input id="mfa-enable-code" className="mono" value={code} onChange={(e) => setCode(e.target.value)}
                 inputMode="numeric" autoComplete="one-time-code" maxLength={8} placeholder="123456" />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={enable} disabled={busy || code.trim().length < 6}>確認して有効にする</button>
        </div>
      </>
    );
  } else if (!enabled) {
    body = (
      <>
        {notice && <p className="topo-small">{notice}</p>}
        <p style={{ marginTop: 0 }}>
          ログインのときに、パスワードに加えて認証アプリのワンタイムパスワード（6 桁）を求めます。パスワードが漏れても、ほかの人がログインできなくなります。
        </p>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
          <button className="btn btn-primary" onClick={start} disabled={busy}>設定を始める</button>
        </div>
      </>
    );
  } else if (mode === "main") {
    body = (
      <>
        <p style={{ marginTop: 0 }}><span className="badge badge-success">設定済み</span>　ログインのときに認証アプリのコードを求めます。</p>
        {notice && notice !== "2 段階認証を設定しています" && <p className="topo-small">{notice}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
          <button className="btn" onClick={() => { setMode("regen"); setError(""); }}>予備コードを作り直す</button>
          <button className="btn btn-danger" onClick={() => { setMode("disable"); setError(""); }}>解除する</button>
        </div>
      </>
    );
  } else {
    body = (
      <>
        <p style={{ marginTop: 0 }}>
          {mode === "disable"
            ? "解除すると、ログインはパスワードだけになります。パスワードと、認証アプリのコード（または予備コード）で確認します。"
            : "新しい予備コードを作ります（以前の予備コードは使えなくなります）。認証アプリのコードで確認します。"}
        </p>
        {mode === "disable" && (
          <div className="form-group">
            <label className="form-label" htmlFor="mfa-pw">パスワード</label>
            <input id="mfa-pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </div>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor="mfa-code2">確認コード</label>
          <input id="mfa-code2" className="mono" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric"
                 autoComplete="one-time-code" maxLength={20} placeholder="123456" />
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={() => { setMode("main"); setCode(""); setPassword(""); setError(""); }}>戻る</button>
          {mode === "disable"
            ? <button className="btn btn-danger" onClick={disable} disabled={busy || !password || !code.trim()}>解除する</button>
            : <button className="btn btn-primary" onClick={regen} disabled={busy || code.trim().length < 6}>作り直す</button>}
        </div>
      </>
    );
  }

  return (
    <div className="modal-overlay" onClick={recovery ? undefined : onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 480 }}>
        <p className="modal-title">2 段階認証</p>
        {body}
      </div>
    </div>
  );
}
