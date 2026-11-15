import { ChangeEvent, useState } from "react";
import { api, errorMessage } from "../api/client";
import { usePlatforms } from "../platforms";
import { downloadCsv } from "./CsvButton";

const MAX_BYTES = 1024 * 1024; // サーバー（nginx）の上限と同じ 1MB

interface ImportRow {
  line: number;
  name: string;
  hostname: string;
  platform: string;
  group: string | null;
  jump_host: string | null;
  credential_profile: string | null;
  status: "ok" | "error" | "skip";
  errors: string[];
  warnings: string[];
}

interface ImportResult {
  dry_run: boolean;
  encoding: "utf-8" | "shift_jis";
  total: number;
  ok: number;
  error: number;
  skip: number;
  created: number;
  registered: boolean;
  ignored_columns: string[];
  rows: ImportRow[];
}

const STATUS_LABEL: Record<ImportRow["status"], [string, string]> = {
  ok: ["登録できます", "badge-success"],
  error: ["エラー", "badge-danger"],
  skip: ["スキップ", "badge-neutral"],
};

/** CSV から機器をまとめて登録する（内容を確認 → 登録する、の 2 段階。ファイルはサーバーで解釈する） */
export default function DeviceImportModal({ onClose, onDone }: { onClose: () => void; onDone: (created: number) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [onDuplicate, setOnDuplicate] = useState<"skip" | "error">("skip");
  const [skipErrors, setSkipErrors] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [done, setDone] = useState<ImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const { platforms } = usePlatforms();

  const pick = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = ""; // 同じファイルを選び直しても選択し直せるように
    if (!f) return;
    setResult(null);
    setSkipErrors(false);
    if (f.size > MAX_BYTES) {
      setFile(null);
      setError("ファイルが大きすぎます（1MB まで）。ファイルを分けてください");
      return;
    }
    setError(f.name.toLowerCase().endsWith(".csv") ? "" : "拡張子が .csv ではありません。CSV ファイルか確認してください");
    setFile(f);
  };

  const send = async (dryRun: boolean) => {
    if (!file) return;
    const fd = new FormData(); // Content-Type はブラウザが boundary 付きで付ける（手で書かない）
    fd.append("file", file);
    fd.append("dry_run", String(dryRun));
    fd.append("skip_errors", String(skipErrors));
    fd.append("on_duplicate", onDuplicate);
    setBusy(true);
    setError("");
    try {
      const r = await api.post<ImportResult>("/devices/import", fd);
      if (dryRun) {
        setResult(r.data);
      } else if (r.data.registered) {
        setDone(r.data);
        onDone(r.data.created);
      } else {
        // 確認のあとで状況が変わった（同じ名前の機器が登録されたなど）。最新の結果を見せる
        setResult(r.data);
        setError("登録できる行がありませんでした。結果を確認してください");
      }
    } catch (e) {
      setError(errorMessage(e));
      if (!dryRun) setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const willCreate = result ? (result.error && !skipErrors ? 0 : result.ok) : 0;

  return (
    // 確認結果を誤って失わないよう、外側のクリックでは閉じない
    <div className="modal-overlay">
      <div className="modal imp-modal" role="dialog" aria-label="CSV から機器を登録">
        <p className="modal-title">CSV から機器を登録</p>
        <div className="imp-warn">
          CSV にはパスワードが<strong>そのまま（平文で）</strong>書かれます。{"取り込みが終わったら、このファイルをパソコン"
            + "（ダウンロードフォルダ・ごみ箱を含む）から削除してください。メールやチャットで共有しないでください。"}
        </div>

        {done ? (
          <>
            <p className="imp-summary">
              {done.created} 台を登録しました
              {(done.skip > 0 || done.error > 0) && `（スキップ ${done.skip} 件・エラー ${done.error} 件は登録していません）`}。
            </p>
            <p className="topo-muted topo-small">コンフィグはまだ収集していません。デバイス管理の「一括収集」などで収集できます。</p>
            <div className="btn-row">
              <button className="btn btn-primary" onClick={onClose}>閉じる</button>
            </div>
          </>
        ) : (
          <>
            <p className="topo-muted topo-small imp-help">
              {"1 行目は列の見出しです（台帳 CSV と同じ見出し＋「ユーザー名」「パスワード」など）。"
                + "機種は ID か表示名、グループ・踏み台・認証情報プロファイルは登録済みの名前で指定します"
                + "（認証情報プロファイルを指定した行は、ユーザー名・パスワードを空にします）。SSH 鍵は CSV では登録できません。"
                + "Excel で編集すると、数字だけ・先頭が 0 のパスワードが変わることがあります（列を「文字列」にしてください）。"}
            </p>
            <div className="imp-pick">
              <button className="btn" onClick={() => downloadCsv("/devices/import/template", {}, "device_import_template.csv")
                .catch((e) => setError(errorMessage(e)))}>ひな形をダウンロード</button>
              <label className="btn">
                ファイルを選ぶ
                <input type="file" accept=".csv,text/csv" style={{ display: "none" }} onChange={pick} aria-label="CSV ファイル" />
              </label>
              <span className="imp-file">{file ? file.name : "ファイルが選ばれていません"}</span>
            </div>
            <fieldset className="imp-options">
              <legend>既に同じ名前の機器がある行</legend>
              <label><input type="radio" name="imp-dup" checked={onDuplicate === "skip"}
                onChange={() => { setOnDuplicate("skip"); setResult(null); }} /> スキップする（登録済みとして飛ばす）</label>
              <label><input type="radio" name="imp-dup" checked={onDuplicate === "error"}
                onChange={() => { setOnDuplicate("error"); setResult(null); }} /> エラーにする</label>
            </fieldset>

            {error && <p className="form-error">{error}</p>}

            {result && (
              <div className="imp-result">
                <p className="imp-summary">
                  {result.total} 行: 登録できる <b className="imp-ok">{result.ok}</b> 件 / エラー{" "}
                  <b className={result.error ? "imp-ng" : ""}>{result.error}</b> 件 / スキップ {result.skip} 件
                  <span className="topo-muted">（{result.encoding === "shift_jis" ? "Shift_JIS" : "UTF-8"} として読み込みました）</span>
                </p>
                {result.ignored_columns.length > 0 && (
                  <p className="topo-muted topo-small">使わない列: {result.ignored_columns.join("、")}</p>
                )}
                <div className="imp-table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr><th>行</th><th>名前</th><th>ホスト / IP</th><th>機種</th><th>グループ</th><th>結果</th></tr>
                    </thead>
                    <tbody>
                      {result.rows.map((r) => (
                        <tr key={r.line} className={`imp-row-${r.status}`}>
                          <td>{r.line}</td>
                          <td>{r.name}</td>
                          <td>{r.hostname}</td>
                          <td>{r.platform}</td>
                          <td>
                            {r.group ?? ""}{r.jump_host ? ` / 踏み台 ${r.jump_host}` : ""}
                            {r.credential_profile ? ` / 認証 ${r.credential_profile}` : ""}
                          </td>
                          <td>
                            <span className={`badge ${STATUS_LABEL[r.status][1]}`}>{STATUS_LABEL[r.status][0]}</span>
                            {r.errors.map((m) => <div key={m} className="imp-msg imp-ng">{m}</div>)}
                            {r.warnings.map((m) => <div key={m} className="imp-msg imp-warn-text">{m}</div>)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {result.rows.some((r) => r.errors.some((m) => m.startsWith("機種:"))) && (
                  <details className="srch-note">
                    <summary>使える機種（ID・表示名）</summary>
                    <ul className="imp-platforms">
                      {platforms.map((p) => <li key={p.id}><code>{p.id}</code> {p.label}</li>)}
                    </ul>
                  </details>
                )}
                {result.error > 0 && (
                  <label className="imp-check">
                    <input type="checkbox" checked={skipErrors} onChange={(e) => setSkipErrors(e.target.checked)} />
                    エラーのない行だけ登録する（チェックしない場合は、エラーを直してファイルを選び直してください）
                  </label>
                )}
              </div>
            )}

            <div className="btn-row">
              <button className="btn" onClick={onClose} disabled={busy}>閉じる</button>
              <button className="btn" onClick={() => send(true)} disabled={!file || busy}>
                {busy && !result ? "確認中..." : "内容を確認"}
              </button>
              {result && (
                <button className="btn btn-primary" onClick={() => send(false)} disabled={busy || willCreate === 0}>
                  {busy ? "登録中..." : `${willCreate} 台を登録する`}
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
