import { FormEvent, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { errorMessage, IDLE_REASON, login, verifyMfa } from "../api/client";

/** ログイン。2 段階認証を設定している人は、パスワードのあとに認証アプリのコード（または予備コード）を入力する */
export default function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const done = () => {
    const next = params.get("next");
    // 外部サイトへのリダイレクトを防ぐため、同一サイト内のパスのみ許可
    navigate(next && next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard", { replace: true });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (mfaToken) {
        await verifyMfa(mfaToken, code);
        done();
        return;
      }
      const r = await login(username, password);
      if (r.mfaToken) {
        setMfaToken(r.mfaToken);
        setPassword("");
      } else {
        done();
      }
    } catch (err) {
      const msg = errorMessage(err, "ログインに失敗しました");
      setError(msg);
      // 確認コードの入力に時間がかかって印が切れたら、パスワードからやり直す
      if (mfaToken && msg.includes("もう一度ユーザー名とパスワード")) {
        setMfaToken(null);
        setCode("");
      }
    } finally {
      setBusy(false);
    }
  };

  const back = () => {
    setMfaToken(null);
    setCode("");
    setError("");
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <p className="login-title">⬡ NetConfig</p>
        {params.get("reason") === IDLE_REASON && !mfaToken && (
          <p className="login-note" role="status" data-testid="login-reason">操作が無い時間が続いたため、ログアウトしました。</p>
        )}
        {mfaToken ? (
          <>
            <p className="login-note">2 段階認証: 認証アプリに表示されている 6 桁のコードを入力してください。</p>
            <div className="form-group">
              <label className="form-label" htmlFor="mfa-code">確認コード</label>
              <input id="mfa-code" className="mono login-code" value={code} onChange={(e) => setCode(e.target.value)}
                     inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={20} placeholder="123456" />
              <p className="login-hint">認証アプリが使えないときは、設定したときに控えた予備コード（xxxx-xxxx）を入力します。</p>
            </div>
            {error && <p className="form-error">{error}</p>}
            <button className="btn btn-primary" style={{ width: "100%" }} disabled={busy || !code.trim()}>
              {busy ? "確認中..." : "確認してログイン"}
            </button>
            <button type="button" className="link-btn login-back" onClick={back}>← ユーザー名の入力に戻る</button>
          </>
        ) : (
          <>
            <div className="form-group">
              <label className="form-label">ユーザー名</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />
            </div>
            <div className="form-group">
              <label className="form-label">パスワード</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>
            {error && <p className="form-error">{error}</p>}
            <button className="btn btn-primary" style={{ width: "100%" }} disabled={busy || !username || !password}>
              {busy ? "ログイン中..." : "ログイン"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
