import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { useAuth } from "../auth";
import HelpLink from "../components/HelpLink";

/**
 * システムの状態: worker・スケジューラー・Redis・DB が動いているか、収集の状況、ディスク、証明書の期限、バックアップ、外部 Git への push、コンテナのイメージの新しさ、
 * 外部への接続（プロキシ・追加の CA。管理者は「接続を確かめる」で固定の宛先へ試せる）
 * 「止まっていることに気づけない」をなくすための画面。異常は通知設定（システムの異常）の通知先にも送られる
 *
 * 「項目」メニュー（再確認の横）: 全項目の状態を一覧で確認でき、選ぶと詳細を表示する。＋/− で画面に大きく（カードで）
 * 表示するかを切り替える。表示しない項目はブラウザに覚える（ユーザーごと）。表示しない項目の異常も「要確認」に数える
 */

type Status = "ok" | "warn" | "error" | "unknown";
interface StaleDevice { id: string; name: string; last_success: string | null; }
interface Volume { name: string; path: string; free_gb: number; total_gb: number; free_pct: number; status: Status; }
type Offsite = "none" | "ok" | "failed";
/** backup.sh の 1 回分の結果（app.tools.backup_report が記録する） */
interface BackupResult {
  at: string; status: "ok" | "failed"; file: string; size: number; seconds: number; dir: string;
  copy: Offsite; copy_dir: string; post: Offsite; message: string;
  encrypted?: boolean | null; // null・無し = 古い backup.sh（不明）
}
interface Component {
  key: string; label: string; status: Status; summary: string;
  detail: {
    workers?: string[]; last_heartbeat?: string; active?: number; last_run?: string | null;
    last_success?: string | BackupResult | null; // 収集は日時、バックアップは最後に成功した回
    stale_days?: number; devices?: StaleDevice[]; volumes?: Volume[]; expires_at?: string; days_left?: number;
    last?: BackupResult | null; schedule?: { enabled: boolean; calendar: string | null; since: string } | null;
    url?: string; branch?: string; // 外部 Git（last は GitExportState）
    images?: ImageInfo[]; pull_failed?: string[]; reported_at?: string; // コンテナのイメージ（setup.sh が伝える）
    host?: string; auth?: string; mail_last?: { at: string; ok: boolean } | null; // メール送信
    sources?: { source: string; label: string; last_ok_at: string | null; last_error: string | null }[]; failed?: string[]; // 脆弱性情報の取得
    // 外部への接続（プロキシはホスト:ポートと認証の有無だけ。認証情報は API も返さない）
    proxy?: string | null; proxy_auth?: boolean; proxy_error?: string | null; no_proxy?: string[]; check_url?: string;
    ca?: OutboundCA | null; last_check?: OutboundCheck | null;
  };
}
/** 追加で信頼する CA（OUTBOUND_CA_FILE） */
interface OutboundCA { file: string; count: number; nearest_expiry?: string; days_left?: number; expired?: boolean; error?: string; }
/** 「接続を確かめる」の結果 */
export interface OutboundCheck {
  result: "ok" | "proxy_unreachable" | "proxy_auth" | "cert" | "timeout" | "proxy_refused" | "config" | "error";
  label: string; message: string; via: "proxy" | "direct" | "-"; elapsed_ms: number; target?: string; at?: string;
}
/** コンテナのイメージ（名前・作成日時。stale_days より前なら古い） */
interface ImageInfo { name: string; created: string | null; age_days: number | null; }
/** 外部 Git への push の最後の結果（services/git_export.py） */
interface GitExportState {
  at: string; ok: boolean; message?: string; error?: string; pushed?: string | null; last_success?: string | null; devices?: string[];
}
export interface SystemStatus {
  overall: Status; checked_at: string; components: Component[];
  settings: { watchdog: boolean; alert_after_min: number; stale_days: number; backup_stale_hours: number };
}

const BADGE: Record<Status, [string, string]> = {
  ok: ["badge-success", "正常"], warn: ["badge-warning", "注意"], error: ["badge-danger", "異常"], unknown: ["badge-neutral", "—"],
};
// 何のための項目か（止まると何が起きるか）
const HELP: Record<string, string> = {
  db: "機器・履歴・設定の保存先",
  redis: "収集などの処理の受け渡しに使用",
  worker: "コンフィグ収集・通知・コンプライアンスチェックを実行",
  beat: "スケジュール収集などを定刻に開始",
  schedule: "登録されているスケジュール",
  collect: "有効な機器のコンフィグを収集できているか",
  disk: "コンフィグ履歴・ターミナルの記録の保存先",
  cert: "画面を表示するための証明書",
  backup: "DB・コンフィグ履歴・.env などの定期バックアップ（scripts/backup.sh）",
  git_export: "コンフィグ履歴を GitLab / Gitea などへ push（.env の GIT_EXPORT_URL）",
  images: "PostgreSQL・Redis と、ビルドの土台（Python・Node.js・nginx）のイメージ。setup.sh で取り直す",
  mail: "メール通知の送信（通知設定 → メールサーバー）。最後の送信の結果",
  notes: "メールサーバー・外部 Git の設定のうち、盗み見につながるもの（暗号化なしのパスワード・証明書の未検証・http://）を注意にします。宛先のドメインの制限なしは、正常のまま文だけ出します。送信は止めず、画面に出すだけです（通知はしません）",
  vuln: "脆弱性・サポート終了日の外部からの取得（.env の VULN_ENABLED=true のときだけ）。3 日以上取得できていないと注意",
  outbound: "Webhook の送信・メールの OAuth 2.0 のトークン・脆弱性情報の取り込みで、インターネットへ出るときの経路（.env の OUTBOUND_PROXY・OUTBOUND_CA_FILE）。SMTP・機器への接続はプロキシを通しません",
};

function fmt(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function sizeText(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

const OFFSITE: Record<Offsite, string> = { none: "設定なし", ok: "成功", failed: "失敗" };

function BackupDetail({ d }: { d: Component["detail"] }) {
  const last = d.last;
  const ok = typeof d.last_success === "object" ? d.last_success : null;
  return (
    <ul className="sys-list">
      <li>最後の成功: {ok ? `${fmt(ok.at)}（${sizeText(ok.size)}）` : "—"}</li>
      {ok && <li className="sys-wrap">保存先: {ok.dir}/{ok.file}</li>}
      {last && last.status !== "ok" && <li>最後の失敗: {fmt(last.at)}</li>}
      {last && last.status === "ok" && (
        <>
          <li className="sys-wrap">外部へのコピー: {OFFSITE[last.copy]}{last.copy_dir ? `（${last.copy_dir}）` : ""}</li>
          {last.post !== "none" && <li>後処理のコマンド: {OFFSITE[last.post]}</li>}
          {typeof last.encrypted === "boolean" && (
            <li>暗号化: {last.encrypted ? "する（gpg）" : "しない"}</li>
          )}
        </>
      )}
      {d.schedule && (
        <li>定期実行: {d.schedule.enabled ? `登録済み（${d.schedule.calendar ?? ""}）` : "無効"}</li>
      )}
    </ul>
  );
}

function Detail({ c }: { c: Component }) {
  const d = c.detail;
  if (c.key === "beat" && d.last_heartbeat) return <p className="sys-sub">最後の定期実行: {fmt(d.last_heartbeat)}</p>;
  if (c.key === "schedule") {
    return <p className="sys-sub">最後に実行: {fmt(d.last_run)}　<Link to="/schedules">スケジュールを開く →</Link></p>;
  }
  if (c.key === "collect") {
    return (
      <>
        <p className="sys-sub">最後に成功した収集: {fmt(typeof d.last_success === "string" ? d.last_success : null)}</p>
        {!!d.devices?.length && (
          <ul className="sys-list">
            {d.devices.map((x) => (
              <li key={x.id}>
                <Link to={`/activity?device=${x.id}`}>{x.name}</Link>
                <span className="topo-muted">　{x.last_success ? `最後の成功 ${fmt(x.last_success)}` : "一度も収集できていません"}</span>
              </li>
            ))}
          </ul>
        )}
      </>
    );
  }
  if (c.key === "disk" && d.volumes) {
    return (
      <ul className="sys-list">
        {d.volumes.map((v) => (
          <li key={v.path}>{v.name}: 空き {v.free_gb} GB / {v.total_gb} GB（{v.free_pct}%）</li>
        ))}
      </ul>
    );
  }
  if (c.key === "cert" && d.expires_at) return <p className="sys-sub">期限: {fmt(d.expires_at)}</p>;
  if (c.key === "backup" && (d.last || d.schedule)) return <BackupDetail d={d} />;
  if (c.key === "git_export" && d.url) return <GitExportDetail d={d} />;
  if (c.key === "mail" && d.host) {
    return (
      <ul className="sys-list">
        <li>SMTP サーバー: <span className="mono">{d.host}</span>（{d.auth}）</li>
        {d.mail_last && <li>最後の送信: {fmt(d.mail_last.at)}（{d.mail_last.ok ? "成功" : "失敗"}）</li>}
      </ul>
    );
  }
  if (c.key === "vuln" && d.sources) {
    return (
      <ul className="sys-list">
        {d.sources.map((x) => (
          <li key={x.source} className="sys-wrap">
            {x.label}: {x.last_ok_at ? `最後の成功 ${fmt(x.last_ok_at)}` : "まだ成功していません"}
            {x.last_error ? `　失敗: ${x.last_error}` : ""}
          </li>
        ))}
        <li>{"　"}<Link to="/vulns">脆弱性・サポート期限を開く →</Link></li>
      </ul>
    );
  }
  if (c.key === "outbound") return <OutboundDetail d={d} />;
  if (c.key === "images" && d.images) {
    return (
      <ul className="sys-list">
        {d.images.map((i) => (
          <li key={i.name} className="sys-wrap">
            <span className="mono">{i.name.replace(/^docker\.io\/library\//, "")}</span>
            ：{i.created ? `${fmt(i.created)}（${i.age_days} 日前）` : "作成日時が不明"}
            {i.age_days != null && d.stale_days ? (i.age_days > d.stale_days ? " ⚠ 古い" : "") : ""}
          </li>
        ))}
        {d.reported_at && <li>取り直した日時: {fmt(d.reported_at)}（setup.sh の実行時）</li>}
      </ul>
    );
  }
  return null;
}

/** 項目の中の操作のあとに、システム状態を取り直す合図 */
const RELOAD_EVENT = "ncm:system-reload";

function OutboundDetail({ d }: { d: Component["detail"] }) {
  const [res, setRes] = useState<OutboundCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const shown = res ?? d.last_check ?? null;
  const target = d.check_url ? d.check_url.replace(/^https:\/\//, "").replace(/\/$/, "") : "";
  const run = async () => {
    setBusy(true);
    setNote("");
    try {
      const r = await api.post<OutboundCheck>("/system/outbound-check");
      setRes({ ...r.data, at: r.data.at ?? new Date().toISOString() });
      window.dispatchEvent(new Event(RELOAD_EVENT)); // 印（正常・注意）も取り直す
    } catch (e) {
      setNote(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const ca = d.ca;
  return (
    <>
      <ul className="sys-list">
        <li>プロキシ: {d.proxy ? <><span className="mono">{d.proxy}</span>（認証{d.proxy_auth ? "あり" : "なし"}）</> : "使わない（直接）"}</li>
        {!!d.no_proxy?.length && <li className="sys-wrap">プロキシを通さない宛先: <span className="mono">{d.no_proxy.join(", ")}</span></li>}
        <li className="sys-wrap">
          追加の CA: {!ca ? "なし" : ca.error ? <span className="form-error">{ca.error}</span> : (
            <>{ca.count} 件（<span className="mono">{ca.file}</span>）。いちばん近い期限 {fmt(ca.nearest_expiry)}
              {ca.expired ? " ⚠ 期限切れ" : ca.days_left != null && ca.days_left <= 30 ? ` ⚠ あと ${ca.days_left} 日` : ""}</>
          )}
        </li>
        {shown && (
          <li className="sys-wrap" data-testid="outbound-check-result">
            確認の結果（{fmt(shown.at)}）: <b className={shown.result === "ok" ? "" : "form-error"}>{shown.label}</b>
            {/* 文が「見出し（理由）」の形なら、見出しを繰り返さずに理由だけ */}
            {shown.message && shown.message !== shown.label
              ? (shown.message.startsWith(shown.label) ? shown.message.slice(shown.label.length) : `　${shown.message}`) : ""}
            {shown.via !== "-" ? `（${shown.via === "proxy" ? "プロキシ経由" : "直接"}・${shown.elapsed_ms} ms）` : ""}
          </li>
        )}
      </ul>
      <p className="sys-sub">
        <button className="btn btn-sm" onClick={run} disabled={busy}>{busy ? "確かめています…" : "接続を確かめる"}</button>{" "}
        <span className="topo-muted topo-small">宛先は固定（<span className="mono">{target}</span>）。30 秒に 1 回まで</span>
      </p>
      {note && <p className="sys-sub form-error">{note}</p>}
    </>
  );
}

function GitExportDetail({ d }: { d: Component["detail"] }) {
  const st = d.last as unknown as GitExportState | null | undefined;
  const [note, setNote] = useState("");
  const run = async () => {
    setNote("");
    try {
      await api.post("/system/git-export");
      setNote("push を開始しました。数十秒後に「再確認」で結果を確かめてください");
    } catch (e) {
      setNote(errorMessage(e));
    }
  };
  return (
    <>
      <ul className="sys-list">
        <li className="sys-wrap">送り先: <span className="mono">{d.url}</span>（ブランチ {d.branch}）</li>
        <li>最後の確認: {fmt(st?.at)}　最後に成功: {fmt(st?.last_success)}</li>
        {st?.pushed && <li>push したコミット: <span className="mono">{st.pushed.slice(0, 8)}</span></li>}
      </ul>
      <p className="sys-sub"><button className="btn btn-sm" onClick={run}>今すぐ push</button> {note && <span className="topo-muted">{note}</span>}</p>
    </>
  );
}

// ---------------------------------------------------------------- 表示する項目（ブラウザに保存）

function hiddenKey(username: string | undefined) {
  return `ncm.system.hidden.${username ?? ""}`;
}
function readHidden(username: string | undefined): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(hiddenKey(username)) ?? "[]");
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}
function writeHidden(username: string | undefined, keys: string[]) {
  try {
    localStorage.setItem(hiddenKey(username), JSON.stringify(keys));
  } catch {
    /* 保存できなくても、この画面を開いている間は効く */
  }
}

function ItemMenu({
  components, hidden, onToggle, onShowAll, onClose,
}: {
  components: Component[]; hidden: string[]; onToggle: (key: string) => void; onShowAll: () => void; onClose: () => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const shown = components.length - components.filter((c) => hidden.includes(c.key)).length;
  return (
    <div className="sys-menu" role="dialog" aria-label="項目の状態と表示">
      <div className="sys-menu-head">
        <b>項目</b>
        <span className="topo-muted topo-small">画面に表示: {shown} / {components.length}</span>
        <span style={{ flex: 1 }} />
        {hidden.length > 0 && <button className="btn btn-sm" onClick={onShowAll}>すべて表示</button>}
        <button className="btn btn-sm" onClick={onClose} aria-label="閉じる">×</button>
      </div>
      <p className="topo-muted topo-small sys-menu-help">項目を選ぶと状態を表示します。＋ で画面に大きく表示、− で画面から外します（ここではいつでも確認できます）</p>
      <ul className="sys-menu-list">
        {components.map((c) => {
          const isHidden = hidden.includes(c.key);
          const expanded = open === c.key;
          return (
            <li key={c.key} className={`sys-menu-item${expanded ? " open" : ""}`}>
              <div className="sys-menu-row">
                <button className="sys-menu-name" onClick={() => setOpen(expanded ? null : c.key)} aria-expanded={expanded}>
                  <span className={`sys-dot sys-dot-${c.status}`} aria-hidden="true" />
                  <span className="sys-menu-label">{c.label}</span>
                  <span className={`badge ${BADGE[c.status][0]}`}>{BADGE[c.status][1]}</span>
                </button>
                <button
                  className={`btn btn-sm sys-menu-toggle${isHidden ? "" : " on"}`}
                  onClick={() => onToggle(c.key)}
                  title={isHidden ? "画面に大きく表示する" : "画面から外す"}
                  aria-label={isHidden ? `${c.label} を画面に表示する` : `${c.label} を画面から外す`}
                >
                  {isHidden ? "＋" : "−"}
                </button>
              </div>
              {expanded && (
                <div className="sys-menu-detail">
                  <p className="sys-summary">{c.summary}</p>
                  <Detail c={c} />
                  <p className="sys-help">{HELP[c.key]}</p>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export default function SystemPage() {
  const { me } = useAuth();
  const [hidden, setHidden] = useState<string[]>(() => readHidden(me?.username));
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  useEffect(() => { setHidden(readHidden(me?.username)); }, [me?.username]);
  const updateHidden = (keys: string[]) => { setHidden(keys); writeHidden(me?.username, keys); };
  const toggle = (key: string) => updateHidden(hidden.includes(key) ? hidden.filter((k) => k !== key) : [...hidden, key]);
  // メニューの外を押す・Esc で閉じる
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => { if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [menuOpen]);
  const [data, setData] = useState<SystemStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api.get<SystemStatus>("/system/status")
      .then((r) => { setData(r.data); setError(""); })
      .catch((e) => setError(errorMessage(e)))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    load();
    const t = window.setInterval(load, 30_000);
    window.addEventListener(RELOAD_EVENT, load);
    return () => { window.clearInterval(t); window.removeEventListener(RELOAD_EVENT, load); };
  }, [load]);

  const bad = data?.components.filter((c) => c.status === "error" || c.status === "warn") ?? [];
  const visible = data?.components.filter((c) => !hidden.includes(c.key)) ?? [];
  const hiddenBad = bad.filter((c) => hidden.includes(c.key));
  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">システム状態<HelpLink topic="system" /></span>
        {data && <span className={`badge ${BADGE[data.overall][0]}`}>{data.overall === "ok" ? "すべて正常" : `要確認 ${bad.length} 件`}</span>}
        <span style={{ flex: 1 }} />
        {data && <span className="topo-muted topo-small">確認: {fmt(data.checked_at)}（30秒ごとに更新）</span>}
        <button className="btn" onClick={load} disabled={loading}>再確認</button>
        {data && (
          <div className="sys-menu-wrap" ref={menuRef}>
            <button className="btn" onClick={() => setMenuOpen(!menuOpen)} aria-expanded={menuOpen} aria-haspopup="dialog">
              項目 ▾{hidden.length > 0 && <span className="sys-menu-count">{hidden.length} 件非表示</span>}
            </button>
            {menuOpen && (
              <ItemMenu components={data.components} hidden={hidden} onToggle={toggle}
                onShowAll={() => updateHidden([])} onClose={() => setMenuOpen(false)} />
            )}
          </div>
        )}
      </div>
      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {data && (
          <>
            {hiddenBad.length > 0 && (
              <div className="sys-hidden-alert">
                画面に表示していない項目に要確認があります: {hiddenBad.map((c, i) => (
                  <span key={c.key}>{i > 0 && "、"}
                    <button className="sys-link" onClick={() => toggle(c.key)} title="画面に表示する">{c.label}（{BADGE[c.status][1]}）</button>
                  </span>
                ))}
              </div>
            )}
            {visible.length === 0 && (
              <div className="card topo-muted">画面に表示する項目がありません。「項目」メニューで ＋ を押すと表示します。</div>
            )}
            <div className="sys-grid">
              {visible.map((c) => (
                <div key={c.key} className={`card sys-card sys-${c.status}`}>
                  <div className="sys-head">
                    <b>{c.label}</b>
                    <span className={`badge ${BADGE[c.status][0]}`}>{BADGE[c.status][1]}</span>
                  </div>
                  <p className="sys-summary">{c.summary}</p>
                  <Detail c={c} />
                  <p className="sys-help">{HELP[c.key]}</p>
                </div>
              ))}
            </div>
            <p className="topo-muted topo-small sys-note" style={{ marginTop: 14 }}>
              {data.settings.watchdog
                ? <>異常は <Link to="/notifications">通知設定</Link> で「システムの異常」を選んだ通知先（Discord / Slack / Teams / メール）へ送ります。
                  worker・スケジューラー・Redis の停止は {data.settings.alert_after_min} 分続いたとき、
                  {data.settings.stale_days > 0 ? `${data.settings.stale_days} 日以上収集できていない機器・` : ""}ディスク・証明書は見つけたときに1回通知し、復旧したときにも通知します。
                  バックアップは失敗するたびに通知し{data.settings.backup_stale_hours > 0 ? `、${data.settings.backup_stale_hours} 時間成功していないときも通知し` : ""}ます（記録の無い環境では確認しません）。</>
                : "異常の通知は無効です（.env の SYSTEM_WATCHDOG_ENABLED）。"}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
