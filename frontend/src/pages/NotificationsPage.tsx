import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";

/**
 * 通知（Discord / Slack）: コンフィグの変更・コンプライアンス違反の発生・収集の失敗
 * - 自分の通知: 所属グループの設定を使う / 個別に設定する / 通知しない
 * - ユーザーグループ（管理者）: メンバーとグループの通知先・対象
 */

type Mode = "inherit" | "custom" | "off";
interface Notification {
  mode: Mode;
  discord_webhook: string | null;
  slack_webhook: string | null;
  has_discord: boolean;
  has_slack: boolean;
  all_devices: boolean;
  device_group_ids: string[];
  include_ungrouped: boolean;
  on_change: boolean;
  on_violation: boolean;
  on_failure: boolean;
  last_sent_at: string | null;
  last_error: string | null;
}
interface GroupSummary { id: string; name: string; notification: Notification; }
interface MyNotification extends Notification { groups: GroupSummary[]; }
interface DeviceGroup { id: string; name: string; color: string | null; }
interface Member { id: string; username: string; is_active: boolean; }
interface UserGroup { id: string; name: string; description: string | null; members: Member[]; notification: Notification; }
interface UserItem { id: string; username: string; role_label?: string; is_active: boolean; }
interface PreviewItem { kind: string; webhook: string; via: string[]; }

const KIND_LABEL: Record<string, string> = { discord: "Discord", slack: "Slack" };

function fmt(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { dateStyle: "short", timeStyle: "short" });
}

function targetText(n: Notification, groups: DeviceGroup[]): string {
  if (n.all_devices) return "すべての機器";
  const names = n.device_group_ids.map((id) => groups.find((g) => g.id === id)?.name).filter(Boolean) as string[];
  if (n.include_ungrouped) names.push("未分類");
  return names.length ? names.join("・") : "（なし）";
}

type EventKey = "on_change" | "on_violation" | "on_failure";
const EVENT_OPTIONS: [EventKey, string, string][] = [
  ["on_change", "コンフィグの変更", "収集で設定の変更が見つかったとき"],
  ["on_violation", "コンプライアンス違反の発生", "新しく違反になったとき（同時に多数の機器が違反になったときは1通にまとめます）"],
  ["on_failure", "収集の失敗", "再試行しても収集できなかったとき"],
];

function eventsText(n: Notification): string {
  const t = EVENT_OPTIONS.filter(([k]) => n[k] ?? (k === "on_change")).map(([, label]) => label);
  return t.length ? t.join("・") : "（なし）";
}

function channelText(n: Notification): string {
  const c = [n.has_discord && "Discord", n.has_slack && "Slack"].filter(Boolean);
  return c.length ? c.join("・") : "（未登録）";
}

// ---------------------------------------------------------------- 通知先・対象の入力欄（自分・グループ共通）

interface FormState {
  discord: string; clearDiscord: boolean;
  slack: string; clearSlack: boolean;
  all_devices: boolean; device_group_ids: string[]; include_ungrouped: boolean;
  on_change: boolean; on_violation: boolean; on_failure: boolean;
}

function initForm(n: Notification | null): FormState {
  return {
    discord: "", clearDiscord: false, slack: "", clearSlack: false,
    all_devices: n?.all_devices ?? true, device_group_ids: n?.device_group_ids ?? [], include_ungrouped: n?.include_ungrouped ?? false,
    on_change: n?.on_change ?? true, on_violation: n?.on_violation ?? false, on_failure: n?.on_failure ?? false,
  };
}

function toPayload(mode: Mode, f: FormState) {
  return {
    mode,
    // 空欄は変更なし（null）、削除にチェックがあれば空文字で削除
    discord_webhook: f.clearDiscord ? "" : f.discord.trim() || null,
    slack_webhook: f.clearSlack ? "" : f.slack.trim() || null,
    all_devices: f.all_devices,
    device_group_ids: f.all_devices ? [] : f.device_group_ids,
    include_ungrouped: f.all_devices ? false : f.include_ungrouped,
    on_change: f.on_change, on_violation: f.on_violation, on_failure: f.on_failure,
  };
}

function TargetForm({
  current, form, setForm, deviceGroups, idPrefix,
}: {
  current: Notification | null; form: FormState; setForm: (f: FormState) => void; deviceGroups: DeviceGroup[]; idPrefix: string;
}) {
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm({ ...form, [k]: v });
  const toggleGroup = (id: string, on: boolean) =>
    set("device_group_ids", on ? [...form.device_group_ids, id] : form.device_group_ids.filter((x) => x !== id));
  return (
    <>
      {(["discord", "slack"] as const).map((kind) => {
        const masked = kind === "discord" ? current?.discord_webhook : current?.slack_webhook;
        const clearKey = kind === "discord" ? "clearDiscord" : "clearSlack";
        return (
          <div className="form-group" key={kind}>
            <label className="form-label" htmlFor={`${idPrefix}-${kind}`}>
              {KIND_LABEL[kind]} の Webhook URL{masked ? `（登録済み: ${masked}）` : ""}
            </label>
            <input
              id={`${idPrefix}-${kind}`} value={form[kind]} disabled={form[clearKey]}
              onChange={(e) => set(kind, e.target.value)}
              placeholder={masked ? "変更する場合のみ入力" : kind === "discord" ? "https://discord.com/api/webhooks/…" : "https://hooks.slack.com/services/…"}
            />
            {masked && (
              <label className="form-check" style={{ marginTop: 4 }}>
                <input type="checkbox" checked={form[clearKey]} onChange={(e) => set(clearKey, e.target.checked)} />
                この通知先を削除する
              </label>
            )}
          </div>
        );
      })}
      <div className="form-group">
        <span className="form-label">通知する内容</span>
        {EVENT_OPTIONS.map(([k, label, hint]) => (
          <label key={k} className="form-check">
            <input type="checkbox" checked={form[k]} onChange={(e) => set(k, e.target.checked)} />
            {label}<span className="ntf-muted" style={{ marginLeft: 6 }}>{hint}</span>
          </label>
        ))}
      </div>
      <div className="form-group">
        <span className="form-label">通知する機器</span>
        <label className="form-check">
          <input type="checkbox" checked={form.all_devices} onChange={(e) => set("all_devices", e.target.checked)} />
          すべての機器（グループを問わない）
        </label>
        {!form.all_devices && (
          <div className="ntf-groups">
            {deviceGroups.map((g) => (
              <label key={g.id} className="form-check">
                <input type="checkbox" checked={form.device_group_ids.includes(g.id)} onChange={(e) => toggleGroup(g.id, e.target.checked)} />
                <span className="ntf-dot" style={{ background: g.color ?? "var(--color-muted)" }} />{g.name}
              </label>
            ))}
            <label className="form-check">
              <input type="checkbox" checked={form.include_ungrouped} onChange={(e) => set("include_ungrouped", e.target.checked)} />
              <span className="ntf-dot" />未分類の機器
            </label>
            {deviceGroups.length === 0 && <p className="ntf-muted">機器のグループがまだありません（デバイス管理で作成できます）</p>}
          </div>
        )}
      </div>
    </>
  );
}

function LastResult({ n }: { n: Notification | null }) {
  if (!n?.last_sent_at) return null;
  return (
    <p className="ntf-muted" style={{ marginTop: 4 }}>
      最後の通知: {fmt(n.last_sent_at)}{" "}
      {n.last_error ? <span style={{ color: "var(--color-danger)" }}>失敗（{n.last_error}）</span> : <span style={{ color: "var(--color-success)" }}>成功</span>}
    </p>
  );
}

function TestResult({ r }: { r: Record<string, string> | null }) {
  if (!r) return null;
  return (
    <div className="ntf-test">
      {Object.entries(r).map(([k, v]) => (
        <div key={k}>
          {KIND_LABEL[k]}: {v === "ok" ? <span style={{ color: "var(--color-success)" }}>送信しました</span> : <span style={{ color: "var(--color-danger)" }}>{v}</span>}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------- 自分の通知

function MyTab({ deviceGroups }: { deviceGroups: DeviceGroup[] }) {
  const [data, setData] = useState<MyNotification | null>(null);
  const [mode, setMode] = useState<Mode>("inherit");
  const [form, setForm] = useState<FormState>(initForm(null));
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [test, setTest] = useState<Record<string, string> | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const r = await api.get<MyNotification>("/notifications/me");
    setData(r.data);
    setMode(r.data.mode);
    setForm(initForm(r.data));
  }, []);
  useEffect(() => { load().catch((e) => setError(errorMessage(e))); }, [load]);

  const save = async () => {
    setBusy(true); setError(""); setMsg("");
    try {
      await api.put("/notifications/me", toPayload(mode, form));
      await load();
      setMsg("保存しました");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const sendTest = async () => {
    setTest(null); setError("");
    try {
      setTest((await api.post("/notifications/me/test")).data.results);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  if (!data) return <p className="ntf-muted">{error || "読み込み中..."}</p>;
  const activeGroups = data.groups.filter((g) => g.notification.mode === "custom");
  return (
    <div className="card ntf-card">
      <p className="ntf-lead">機器のコンフィグの変更・コンプライアンス違反の発生・収集の失敗を、Discord / Slack に要約と画面へのリンクで送ります（差分やコンフィグの中身は送りません）。送る内容は通知設定ごとに選べます。</p>
      <div className="ntf-modes" role="radiogroup">
        {([
          ["inherit", "所属グループの設定を使う", "管理者が設定したユーザーグループの通知先・対象で通知します"],
          ["custom", "個別に設定する", "自分の Webhook と、通知する機器のグループを指定します"],
          ["off", "通知しない", ""],
        ] as [Mode, string, string][]).map(([v, label, desc]) => (
          <label key={v} className={`ntf-mode${mode === v ? " active" : ""}`}>
            <input type="radio" name="ntf-mode" checked={mode === v} onChange={() => setMode(v)} />
            <span><b>{label}</b>{desc && <span className="ntf-muted"> — {desc}</span>}</span>
          </label>
        ))}
      </div>

      {mode === "inherit" && (
        <div className="ntf-section">
          {data.groups.length === 0 ? (
            <p className="ntf-muted">所属しているユーザーグループがないため、通知は届きません。個別に設定するか、管理者にグループへの追加を依頼してください。</p>
          ) : (
            <table className="data-table">
              <thead><tr><th>所属グループ</th><th>状態</th><th>通知先</th><th>内容</th><th>対象</th></tr></thead>
              <tbody>
                {data.groups.map((g) => (
                  <tr key={g.id}>
                    <td>{g.name}</td>
                    <td>{g.notification.mode === "custom" ? <span className="badge badge-success">有効</span> : <span className="badge badge-neutral">無効</span>}</td>
                    <td>{channelText(g.notification)}</td>
                    <td>{eventsText(g.notification)}</td>
                    <td>{targetText(g.notification, deviceGroups)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {data.groups.length > 0 && activeGroups.length === 0 && <p className="ntf-muted" style={{ marginTop: 6 }}>有効な通知設定のあるグループがないため、通知は届きません。</p>}
        </div>
      )}

      {mode === "custom" && (
        <div className="ntf-section">
          <TargetForm current={data} form={form} setForm={setForm} deviceGroups={deviceGroups} idPrefix="me" />
          <LastResult n={data} />
        </div>
      )}

      {error && <p className="form-error">{error}</p>}
      {msg && <p className="ntf-ok">{msg}</p>}
      <TestResult r={test} />
      <div className="btn-row">
        {mode === "custom" && (data.has_discord || data.has_slack) && (
          <button className="btn" onClick={sendTest}>テスト通知を送る</button>
        )}
        <button className="btn btn-primary" onClick={save} disabled={busy}>保存</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- ユーザーグループ（管理者）

function GroupModal({
  group, users, deviceGroups, onClose, onSaved,
}: { group: UserGroup | null; users: UserItem[]; deviceGroups: DeviceGroup[]; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [members, setMembers] = useState<string[]>(group?.members.map((m) => m.id) ?? []);
  const [enabled, setEnabled] = useState(group?.notification.mode === "custom");
  const [form, setForm] = useState<FormState>(initForm(group?.notification ?? null));
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true); setError("");
    const body = { name, description: description || null, member_ids: members, notification: toPayload(enabled ? "custom" : "off", form) };
    try {
      if (group) await api.put(`/notifications/groups/${group.id}`, body);
      else await api.post("/notifications/groups", body);
      onSaved();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 620, maxWidth: "95vw" }} onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{group ? "ユーザーグループの編集" : "ユーザーグループの作成"}</p>
        <div className="form-group">
          <label className="form-label" htmlFor="ug-name">名前</label>
          <input id="ug-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="例: ネットワーク運用チーム" autoFocus />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="ug-desc">説明（任意）</label>
          <input id="ug-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div className="form-group">
          <span className="form-label">メンバー（{members.length}人。1人が複数のグループに所属できます）</span>
          <div className="ntf-groups ntf-members">
            {users.map((u) => (
              <label key={u.id} className="form-check">
                <input type="checkbox" checked={members.includes(u.id)}
                  onChange={(e) => setMembers(e.target.checked ? [...members, u.id] : members.filter((x) => x !== u.id))} />
                {u.username}{!u.is_active && <span className="badge badge-neutral">無効</span>}
              </label>
            ))}
          </div>
        </div>
        <div className="ntf-section">
          <label className="form-check" style={{ marginBottom: 10, color: "var(--color-text)" }}>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            このグループの通知を有効にする（「所属グループの設定を使う」メンバーに適用）
          </label>
          {enabled && <TargetForm current={group?.notification ?? null} form={form} setForm={setForm} deviceGroups={deviceGroups} idPrefix="ug" />}
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={save} disabled={busy || !name.trim()}>保存</button>
        </div>
      </div>
    </div>
  );
}

function GroupsTab({ deviceGroups }: { deviceGroups: DeviceGroup[] }) {
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);
  const [editing, setEditing] = useState<UserGroup | null | "new">(null);
  const [error, setError] = useState("");
  const [tests, setTests] = useState<Record<string, Record<string, string>>>({});
  const [previewGroup, setPreviewGroup] = useState("");
  const [previewEvent, setPreviewEvent] = useState("change");
  const [preview, setPreview] = useState<PreviewItem[] | null>(null);

  const load = useCallback(async () => {
    const [g, u] = await Promise.all([api.get<UserGroup[]>("/notifications/groups"), api.get<UserItem[]>("/users/")]);
    setGroups(g.data);
    setUsers(u.data);
  }, []);
  useEffect(() => { load().catch((e) => setError(errorMessage(e))); }, [load]);

  const remove = async (g: UserGroup) => {
    if (!confirm(`ユーザーグループ「${g.name}」を削除しますか？（メンバーのユーザーは削除されません）`)) return;
    try {
      await api.delete(`/notifications/groups/${g.id}`);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const test = async (g: UserGroup) => {
    try {
      const r = await api.post(`/notifications/groups/${g.id}/test`);
      setTests({ ...tests, [g.id]: r.data.results });
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const runPreview = async () => {
    try {
      setPreview((await api.get<PreviewItem[]>("/notifications/preview", { params: { device_group_id: previewGroup || undefined, event: previewEvent } })).data);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <>
      {editing && (
        <GroupModal group={editing === "new" ? null : editing} users={users} deviceGroups={deviceGroups}
          onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} />
      )}
      {error && <p className="form-error">{error}</p>}
      <div className="ntf-toolbar">
        <p className="ntf-muted">「所属グループの設定を使う」ユーザーは、所属する各グループ（通知が有効なもの）の設定で通知されます。同じ Webhook へは1回だけ送ります。</p>
        <button className="btn btn-primary" onClick={() => setEditing("new")}>＋ ユーザーグループを作成</button>
      </div>
      {groups.length === 0 && <div className="card ntf-muted">ユーザーグループはまだありません。</div>}
      <div className="ntf-group-list">
        {groups.map((g) => (
          <div key={g.id} className="card ntf-group">
            <div className="ntf-group-head">
              <b>{g.name}</b>
              {g.notification.mode === "custom" ? <span className="badge badge-success">通知 有効</span> : <span className="badge badge-neutral">通知 無効</span>}
              <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                {(g.notification.has_discord || g.notification.has_slack) && <button className="btn btn-sm" onClick={() => test(g)}>テスト通知</button>}
                <button className="btn btn-sm" onClick={() => setEditing(g)}>編集</button>
                <button className="btn btn-sm btn-danger" onClick={() => remove(g)}>削除</button>
              </span>
            </div>
            {g.description && <p className="ntf-muted">{g.description}</p>}
            <dl className="ntf-kv">
              <dt>メンバー</dt><dd>{g.members.length ? g.members.map((m) => m.username).join("、") : "（なし）"}</dd>
              <dt>通知先</dt><dd>{channelText(g.notification)}</dd>
              <dt>内容</dt><dd>{eventsText(g.notification)}</dd>
              <dt>対象</dt><dd>{targetText(g.notification, deviceGroups)}</dd>
            </dl>
            <LastResult n={g.notification} />
            <TestResult r={tests[g.id] ?? null} />
          </div>
        ))}
      </div>

      <div className="card ntf-card" style={{ marginTop: 16 }}>
        <p className="ntf-lead"><b>通知先の確認</b> — 機器のグループと内容を選ぶと、その機器で起きたときの送信先を表示します（全ユーザーの設定を反映）</p>
        <div style={{ display: "flex", gap: 8 }}>
          <select value={previewGroup} onChange={(e) => { setPreviewGroup(e.target.value); setPreview(null); }} style={{ maxWidth: 320 }}>
            <option value="">未分類の機器</option>
            {deviceGroups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
          <select value={previewEvent} onChange={(e) => { setPreviewEvent(e.target.value); setPreview(null); }} style={{ maxWidth: 240 }} aria-label="通知する内容">
            <option value="change">コンフィグの変更</option>
            <option value="violation">コンプライアンス違反の発生</option>
            <option value="failure">収集の失敗</option>
          </select>
          <button className="btn" onClick={runPreview}>確認</button>
        </div>
        {preview && (
          preview.length === 0 ? <p className="ntf-muted" style={{ marginTop: 8 }}>通知先はありません</p> : (
            <table className="data-table" style={{ marginTop: 8 }}>
              <thead><tr><th>通知先</th><th>Webhook</th><th>理由</th></tr></thead>
              <tbody>
                {preview.map((p) => (
                  <tr key={p.kind + p.webhook}><td>{KIND_LABEL[p.kind]}</td><td className="mono">{p.webhook}</td><td>{p.via.join("、")}</td></tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>
    </>
  );
}

export default function NotificationsPage() {
  const { can } = useAuth();
  const isAdmin = can(PERM.USER_ADMIN);
  const [tab, setTab] = useState<"me" | "groups">("me");
  const [deviceGroups, setDeviceGroups] = useState<DeviceGroup[]>([]);
  useEffect(() => {
    api.get<DeviceGroup[]>("/device-groups/").then((r) => setDeviceGroups(r.data)).catch(() => undefined);
  }, []);

  return (
    <div className="page">
      <div className="page-header">
        <span className="page-title">通知設定</span>
        {isAdmin && (
          <div className="seg-tabs" role="tablist">
            <button role="tab" aria-selected={tab === "me"} className={`seg-tab${tab === "me" ? " active" : ""}`} onClick={() => setTab("me")}>自分の通知</button>
            <button role="tab" aria-selected={tab === "groups"} className={`seg-tab${tab === "groups" ? " active" : ""}`} onClick={() => setTab("groups")}>ユーザーグループ</button>
          </div>
        )}
      </div>
      <div className="page-body">
        {tab === "me" ? <MyTab deviceGroups={deviceGroups} /> : <GroupsTab deviceGroups={deviceGroups} />}
      </div>
    </div>
  );
}
