import { FormEvent, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { errorMessage, login } from "../api/client";

export default function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
      const next = params.get("next");
      // 外部サイトへのリダイレクトを防ぐため、同一サイト内のパスのみ許可
      navigate(next && next.startsWith("/") && !next.startsWith("//") ? next : "/devices", { replace: true });
    } catch (err) {
      setError(errorMessage(err, "ログインに失敗しました"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <p className="login-title">⬡ NetConfig</p>
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
      </form>
    </div>
  );
}
