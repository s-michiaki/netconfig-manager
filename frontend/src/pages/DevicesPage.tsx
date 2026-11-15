import React, { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, errorMessage } from "../api/client";
import { PERM, useAuth } from "../auth";
import { downloadCsv } from "../components/CsvButton";
import DeviceImportModal from "../components/DeviceImportModal";
import { usePlatforms } from "../platforms";
import type { CredentialProfile } from "./CredentialProfilesPage";

interface Device {
  id: string;
  name: string;
  hostname: string;
  platform: string;
  port: number;
  username: string | null; // 接続に使うユーザー名（プロファイルを使う機器はプロファイルのもの）
  description: string | null;
  is_active: boolean;
  // has_* と key_info は接続に実際に使う認証情報（プロファイルを使う機器はプロファイルのもの）
  has_enable_secret: boolean;
  has_password: boolean;
  has_private_key: boolean;
  key_info: string | null;
  jump_host_id: string | null;
  group_id: string | null;
  group_name: string | null;
  jump_host_name: string | null;
  credential_profile_id: string | null;
  credential_profile_name: string | null;
  read_timeout: number | null;
  // 機器台帳（収集のときに自動で読み取る。未取得・対象外の機種は null）
  model: string | null;
  serial_number: string | null;
  os_version: string | null;
  reported_hostname: string | null;
  inventory_at: string | null;
}

// ---- 収集の状態（GET /devices/collect-status）
interface CollectActive { state: "queued" | "running" | "retry"; seconds: number; triggered_by: string | null; }
interface CollectLast { status: "success" | "failed"; at: string; message: string | null; }
interface CollectStatus { active: Record<string, CollectActive>; last: Record<string, CollectLast>; available: boolean; }

const COLLECT_POLL_FAST = 2500; // 収集が動いている間・依頼した直後の更新間隔（ミリ秒）
const COLLECT_POLL_IDLE = 15000; // 何も動いていないとき（スケジュールや他の人が始めた収集に気づくため）
const COLLECT_BOOST = 30000; // 依頼してから worker が取りかかるまでの間も、短い間隔で確認する時間

function fmtCollectAt(iso: string): string {
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  return d.toLocaleString("ja-JP", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}
function fmtElapsed(sec: number): string {
  return sec < 60 ? `${sec} 秒` : `${Math.floor(sec / 60)} 分 ${sec % 60} 秒`;
}

/** カードに出す収集の状態。動いていれば「待ち・収集中・再試行待ち」、そうでなければ最後の結果 */
function CollectState({ active, last }: { active?: CollectActive; last?: CollectLast }) {
  if (active?.state === "running") {
    return (
      <p className="collect-st collect-running" title="コンフィグを収集しています">
        <span className="collect-spin" aria-hidden="true" />収集中… {fmtElapsed(active.seconds)}
      </p>
    );
  }
  if (active?.state === "queued") {
    return <p className="collect-st collect-queued" title="収集を依頼しました。順番を待っています">⏳ 収集待ち</p>;
  }
  if (active?.state === "retry") {
    return (
      <p className="collect-st collect-queued" title="一時的な失敗のため、少し待ってからやり直します">
        ↻ 再試行待ち{last?.status === "failed" && last.message ? `（${last.message.slice(0, 40)}）` : ""}
      </p>
    );
  }
  if (!last) return <p className="collect-st collect-none">未収集</p>;
  if (last.status === "failed") {
    return (
      <p className="collect-st collect-failed" title={last.message ?? "収集に失敗しました"}>
        ✗ 収集失敗 {fmtCollectAt(last.at)}
      </p>
    );
  }
  return <p className="collect-st collect-ok" title="最後の収集は成功しました">✓ 収集 {fmtCollectAt(last.at)}</p>;
}

/** 台帳の項目をカーソルを合わせたときに表示する文章 */
function inventoryTitle(d: Device): string {
  const at = d.inventory_at ? new Date(d.inventory_at.endsWith("Z") ? d.inventory_at : d.inventory_at + "Z").toLocaleString("ja-JP") : "";
  return [
    d.model && `モデル: ${d.model}`, d.os_version && `OS バージョン: ${d.os_version}`,
    d.serial_number && `シリアル番号: ${d.serial_number}`, d.reported_hostname && `機器側のホスト名: ${d.reported_hostname}`,
    at && `取得: ${at}`,
  ].filter(Boolean).join("\n");
}

interface JumpHostOption { id: string; name: string; hostname: string; }

interface DeviceGroup {
  id: string;
  name: string;
  description: string | null;
  color: string | null;
  device_count: number;
}

const EMPTY_FORM = {
  name: "", hostname: "", platform: "cisco_ios", port: 22,
  username: "", password: "", enable_secret: "", description: "", is_active: true,
  clear_enable_secret: false, jump_host_id: "", group_id: "",
  private_key: "", key_passphrase: "", clear_password: false, clear_private_key: false,
  read_timeout: "", // 空欄 = 既定値
  auth_mode: "own" as "own" | "profile", // profile: 認証情報プロファイルを使う / own: この機器だけの認証情報
  credential_profile_id: "",
};

function DeviceModal({
  device, jumpHosts, groups, profiles, defaultGroupId, onClose, onSave,
}: {
  device: Device | null; jumpHosts: JumpHostOption[]; groups: DeviceGroup[]; profiles: CredentialProfile[];
  defaultGroupId?: string; onClose: () => void; onSave: () => void;
}) {
  const isEdit = device !== null;
  const [form, setForm] = useState(() =>
    device
      ? {
          ...EMPTY_FORM,
          name: device.name, hostname: device.hostname, platform: device.platform, port: device.port,
          username: device.username ?? "", description: device.description ?? "", is_active: device.is_active,
          auth_mode: device.credential_profile_id ? "profile" : "own",
          credential_profile_id: device.credential_profile_id ?? "",
          jump_host_id: device.jump_host_id ?? "",
          group_id: device.group_id ?? "",
          read_timeout: device.read_timeout != null ? String(device.read_timeout) : "",
        }
      : { ...EMPTY_FORM, group_id: defaultGroupId ?? "" }
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [reach, setReach] = useState<{ ok: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [defaultTimeout, setDefaultTimeout] = useState<number | null>(null);
  useEffect(() => {
    api.get("/devices/defaults").then((r) => setDefaultTimeout(r.data.read_timeout)).catch(() => {});
  }, []);
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));

  const handleSubmit = async () => {
    setSaving(true);
    setError("");
    const common = {
      name: form.name,
      hostname: form.hostname,
      platform: form.platform,
      port: form.port,
      description: form.description || null,
      is_active: form.is_active,
      jump_host_id: form.jump_host_id || null,
      group_id: form.group_id || null,
      read_timeout: form.read_timeout.trim() ? Number(form.read_timeout) : null,
    };
    // プロファイルを使う機器には、機器側の認証情報を送らない（サーバーでも保存しない）
    const body = useProfile ? { ...common, credential_profile_id: form.credential_profile_id } : {
      ...common,
      credential_profile_id: null,
      username: form.username,
      // 編集時、空欄のパスワードは「変更しない」
      password: form.password || undefined,
      private_key: form.private_key || undefined,
      key_passphrase: form.key_passphrase || undefined,
      enable_secret: form.enable_secret || undefined,
      ...(ownSaved
        ? {
            clear_enable_secret: form.clear_enable_secret,
            clear_password: form.clear_password,
            clear_private_key: form.clear_private_key,
          }
        : {}),
    };
    try {
      if (isEdit) await api.put(`/devices/${device.id}`, body);
      else await api.post("/devices/", body);
      onSave();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  /** 選択した踏み台から、このデバイスのIP:ポートに到達できるか確認する */
  const testReach = async () => {
    setTesting(true);
    setReach(null);
    try {
      const r = await api.post(`/jump-hosts/${form.jump_host_id}/test`, {
        dest_host: form.hostname, dest_port: form.port,
      }, { timeout: 90000 });
      setReach(r.data);
    } catch (e) {
      setReach({ ok: false, message: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  };

  // 秘密鍵ファイルを読み込んでテキスト欄に入れる（ブラウザ内で読むだけで、送信は「保存」時のみ）
  const loadKeyFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 16 * 1024) {
      setError("秘密鍵ファイルが大きすぎます（16KBまで）");
      return;
    }
    file.text().then((t) => set("private_key", t));
    e.target.value = "";
  };

  const { groups: platformGroups, byId: platformById } = usePlatforms();
  const platformInfo = platformById[form.platform];

  // プロファイルが 0 件で、この機器もプロファイルを使っていなければ切り替えは出さない（従来どおりの画面）
  const showAuthMode = profiles.length > 0 || form.auth_mode === "profile";
  const useProfile = form.auth_mode === "profile";
  const selectedProfile = profiles.find((p) => p.id === form.credential_profile_id);
  // この機器が使っているプロファイルを自分が使用できない場合は、接続先を変えられない
  // （接続先を書き換えると、次の接続でプロファイルのパスワードがそこへ送られるため。サーバー側でも断る）
  const currentProfile = isEdit ? profiles.find((p) => p.id === device.credential_profile_id) : undefined;
  const lockTarget = !!currentProfile && !currentProfile.can_use && useProfile
    && form.credential_profile_id === device?.credential_profile_id;
  // 保存済みの「この機器だけの認証情報」があるか（プロファイルを使っていた機器は機器側に何も持っていない）
  const ownSaved = isEdit && !device.credential_profile_id;
  const leavingProfile = isEdit && !!device.credential_profile_id && !useProfile;
  const willHavePassword = (ownSaved && device.has_password && !form.clear_password) || !!form.password;
  const willHaveKey = (ownSaved && device.has_private_key && !form.clear_private_key) || !!form.private_key;
  const timeoutValid = !form.read_timeout.trim() || (/^\d+$/.test(form.read_timeout.trim())
    && Number(form.read_timeout) >= 10 && Number(form.read_timeout) <= 600);
  const authValid = useProfile ? !!form.credential_profile_id : !!form.username && (willHavePassword || willHaveKey);
  const canSave = form.name && form.hostname && authValid && timeoutValid;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">{isEdit ? "デバイス編集" : "デバイス追加"}</p>
        {lockTarget && (
          <p className="form-hint platform-note" style={{ margin: "0 0 12px" }}>
            ⓘ この機器は認証情報プロファイル「{currentProfile.name}」を使っています。あなたはこのプロファイルを使用できないため、
            接続先（IP アドレス・ポート・踏み台）は変更できません。変更するときは、プロファイルの所有者
            {currentProfile.owner_name ? `（${currentProfile.owner_name}）` : ""}に使用の許可を依頼してください。
          </p>
        )}
        <div className="form-group">
          <label className="form-label">ホスト名（識別名）</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="dev-group">グループ</label>
          <select id="dev-group" value={form.group_id} onChange={(e) => set("group_id", e.target.value)}>
            <option value="">（未分類）</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">IPアドレス / FQDN</label>
          <input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} disabled={lockTarget} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
          <div className="form-group">
            <label className="form-label">プラットフォーム</label>
            <select value={form.platform} onChange={(e) => set("platform", e.target.value)}>
              {!platformInfo && <option value={form.platform}>{form.platform}</option>}
              {platformGroups.map(([vendor, list]) => (
                <optgroup key={vendor} label={vendor}>
                  {list.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </optgroup>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">SSHポート</label>
            <input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", +e.target.value)}
              disabled={lockTarget} />
          </div>
        </div>
        {platformInfo?.note && <p className="form-hint platform-note">ⓘ {platformInfo.note}</p>}
        <div className="form-group">
          <label className="form-label">接続経路</label>
          <div style={{ display: "flex", gap: 8 }}>
            <select value={form.jump_host_id} disabled={lockTarget}
              onChange={(e) => { set("jump_host_id", e.target.value); setReach(null); }}>
              <option value="">直接接続</option>
              {jumpHosts.map((j) => <option key={j.id} value={j.id}>踏み台経由: {j.name}（{j.hostname}）</option>)}
            </select>
            {form.jump_host_id && (
              <button className="btn" style={{ whiteSpace: "nowrap" }} onClick={testReach} disabled={testing || !form.hostname}>
                {testing ? "確認中..." : "到達確認"}
              </button>
            )}
          </div>
          {reach && (
            <p style={{ fontSize: 11, marginTop: 6, color: reach.ok ? "var(--color-success)" : "var(--color-danger)" }}>
              {reach.ok ? "✓ " : "✗ "}{reach.message}
            </p>
          )}
        </div>
        {showAuthMode && (
          <div className="form-group">
            <span className="form-label">認証情報</span>
            <div className="seg-tabs" role="tablist" aria-label="認証情報">
              <button type="button" role="tab" aria-selected={useProfile} className={`seg-tab${useProfile ? " active" : ""}`}
                onClick={() => set("auth_mode", "profile")}>プロファイルを使う</button>
              <button type="button" role="tab" aria-selected={!useProfile} className={`seg-tab${!useProfile ? " active" : ""}`}
                onClick={() => set("auth_mode", "own")}>この機器だけの認証情報を入力する</button>
            </div>
          </div>
        )}
        {useProfile ? (
          <div className="form-group">
            <label className="form-label" htmlFor="dev-profile">認証情報プロファイル</label>
            <select id="dev-profile" value={form.credential_profile_id}
              onChange={(e) => set("credential_profile_id", e.target.value)}>
              <option value="">（選んでください）</option>
              {profiles.map((p) => (
                // 使用できないプロファイルは選べない（この機器がいま使っているものは、そのまま残せる）
                <option key={p.id} value={p.id} disabled={!p.can_use && p.id !== device?.credential_profile_id}>
                  {p.name}（{p.username}）{p.can_use ? "" : " — 使用できません"}
                </option>
              ))}
            </select>
            {profiles.some((p) => !p.can_use) && (
              <p className="cp-hint" style={{ marginTop: 6 }}>
                「使用できません」のプロファイルは、所有者か、使用を許可されたユーザーグループのメンバーだけが割り当てられます。
              </p>
            )}
            {selectedProfile && (
              <p className="form-hint platform-note" style={{ margin: "8px 0 0" }}>
                ユーザー名 {selectedProfile.username} ·{" "}
                {[selectedProfile.has_password && "パスワード", selectedProfile.has_private_key && `秘密鍵（${selectedProfile.key_info ?? ""}）`,
                  selectedProfile.has_enable_secret && "Enable"].filter(Boolean).join("・")}
                <br />
                プロファイルの値で接続します（この機器だけの認証情報は保存しません）。
                {ownSaved && " 保存すると、この機器に入っていた認証情報は消えます。"}
              </p>
            )}
          </div>
        ) : (
          <>
            {leavingProfile && (
              <p className="form-hint platform-note">
                ⓘ プロファイルを外すと、この機器のユーザー名と、パスワードまたは SSH 秘密鍵の入力が必要です。
              </p>
            )}
          <div className="form-group">
            <label className="form-label" htmlFor="dev-user">ユーザー名</label>
            <input id="dev-user" value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
          </div>
          <p className="section-label" style={{ marginTop: 6 }}>認証（パスワード・SSH秘密鍵のどちらか、または両方）</p>
          <div className="form-group">
            <label className="form-label">
              パスワード{ownSaved && device.has_password ? "（設定済み。変更時のみ入力）" : ""}
            </label>
            <input type="password" autoComplete="new-password" value={form.password}
              onChange={(e) => set("password", e.target.value)} disabled={form.clear_password} />
            {ownSaved && device.has_password && (
              <label className="form-check" style={{ marginTop: 6 }}>
                <input type="checkbox" checked={form.clear_password} onChange={(e) => set("clear_password", e.target.checked)} />
                パスワードを削除する（鍵認証のみにする）
              </label>
            )}
          </div>
          <div className="form-group">
            <label className="form-label">
              SSH秘密鍵（OpenSSH / PEM 形式）{ownSaved && device.has_private_key ? `— 設定済み: ${device.key_info ?? ""}` : "（任意）"}
            </label>
            <textarea
              className="mono"
              rows={4}
              value={form.private_key}
              onChange={(e) => set("private_key", e.target.value)}
              disabled={form.clear_private_key}
              placeholder={ownSaved && device.has_private_key ? "変更する場合のみ貼り付け" : "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
              spellCheck={false}
              style={{ fontSize: 11, resize: "vertical" }}
            />
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 6 }}>
              <label className="btn" style={{ padding: "2px 10px", fontSize: 11, cursor: "pointer" }}>
                ファイルから読み込む
                <input type="file" onChange={loadKeyFile} style={{ display: "none" }} disabled={form.clear_private_key} />
              </label>
              {ownSaved && device.has_private_key && (
                <label className="form-check">
                  <input type="checkbox" checked={form.clear_private_key}
                    onChange={(e) => set("clear_private_key", e.target.checked)} />
                  秘密鍵を削除する
                </label>
              )}
            </div>
          </div>
          {(form.private_key || (ownSaved && device.has_private_key && !form.clear_private_key)) && (
            <div className="form-group">
              <label className="form-label">鍵のパスフレーズ（鍵が保護されている場合）</label>
              <input type="password" autoComplete="new-password" value={form.key_passphrase}
                onChange={(e) => set("key_passphrase", e.target.value)} />
            </div>
          )}
          {!(willHavePassword || willHaveKey) && (
            <p className="form-error">パスワードとSSH秘密鍵の少なくとも一方が必要です</p>
          )}
          <div className="form-group">
            <label className="form-label">
              Enableシークレット（任意{ownSaved && device.has_enable_secret ? "・設定済み。変更時のみ入力" : ""}）
            </label>
            <input type="password" autoComplete="new-password" value={form.enable_secret}
              onChange={(e) => set("enable_secret", e.target.value)} disabled={form.clear_enable_secret} />
            {ownSaved && device.has_enable_secret && (
              <label className="form-check" style={{ marginTop: 6 }}>
                <input type="checkbox" checked={form.clear_enable_secret}
                  onChange={(e) => set("clear_enable_secret", e.target.checked)} />
                Enableシークレットを削除する
              </label>
            )}
          </div>
          </>
        )}
        <div className="form-group">
          <label className="form-label">応答待ち時間（秒・任意）</label>
          <input type="number" min={10} max={600} value={form.read_timeout}
            placeholder={`空欄で既定値${defaultTimeout ? `（${defaultTimeout}秒）` : ""}`}
            onChange={(e) => set("read_timeout", e.target.value)} />
          <p style={{ fontSize: 11, marginTop: 4, color: timeoutValid ? "var(--color-muted)" : "var(--color-danger)" }}>
            {timeoutValid
              ? "ログイン後のプロンプトやコマンド結果を待つ上限（10〜600秒）。応答の遅い機器でタイムアウトする場合に延ばしてください"
              : "10〜600 の整数で入力してください"}
          </p>
        </div>
        <div className="form-group">
          <label className="form-label">説明（任意）</label>
          <input value={form.description} onChange={(e) => set("description", e.target.value)} />
        </div>
        <label className="form-check" style={{ marginBottom: 14 }}>
          <input type="checkbox" checked={form.is_active} onChange={(e) => set("is_active", e.target.checked)} />
          有効（一括収集・スケジュール収集の対象にする）
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>キャンセル</button>
          <button className="btn btn-primary" onClick={handleSubmit} disabled={saving || !canSave}>
            {isEdit ? "保存" : "追加"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ グループ管理

const GROUP_COLORS = ["#4f8ef7", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#c084fc", "#5eead4", "#7c82a3"];
const UNGROUPED = "__none__"; // 絞り込み・折りたたみでの「未分類」の識別子

function GroupManagerModal({
  groups, onClose, onChanged,
}: { groups: DeviceGroup[]; onClose: () => void; onChanged: () => void }) {
  const [editing, setEditing] = useState<{ id: string | null; name: string; description: string; color: string | null } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setError("");
    const body = { name: editing.name.trim(), description: editing.description.trim() || null, color: editing.color };
    try {
      if (editing.id) await api.put(`/device-groups/${editing.id}`, body);
      else await api.post("/device-groups/", body);
      setEditing(null);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  /** 1つ上・下へ動かす（並び順はすべての画面のグループの表示に使う） */
  const move = async (index: number, delta: number) => {
    const ids = groups.map((g) => g.id);
    const j = index + delta;
    if (j < 0 || j >= ids.length) return;
    [ids[index], ids[j]] = [ids[j], ids[index]];
    setBusy(true);
    setError("");
    try {
      await api.put("/device-groups/order", { ids });
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (g: DeviceGroup) => {
    const msg = g.device_count
      ? `グループ「${g.name}」を削除しますか？\n所属している${g.device_count}台は「未分類」に戻ります（機器は削除されません）。`
      : `グループ「${g.name}」を削除しますか？`;
    if (!window.confirm(msg)) return;
    try {
      await api.delete(`/device-groups/${g.id}`);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal grp-modal" onClick={(e) => e.stopPropagation()}>
        <p className="modal-title">グループの管理</p>
        {groups.length === 0 && !editing && (
          <p className="topo-muted" style={{ marginBottom: 12 }}>グループはまだありません。拠点や用途ごとに作ると、機器をまとめて表示できます。</p>
        )}
        {groups.length > 1 && !editing && (
          <p className="topo-muted topo-small" style={{ marginBottom: 8 }}>▲▼ で並び順を変えられます（デバイス管理・各画面のグループの選択肢などに共通）</p>
        )}
        <ul className="grp-list">
          {groups.map((g, i) => (
            <li key={g.id} className="grp-row">
              <span className="grp-move">
                <button className="btn btn-sm" disabled={busy || i === 0} onClick={() => move(i, -1)}
                  title="上へ" aria-label={`${g.name} を上へ`}>▲</button>
                <button className="btn btn-sm" disabled={busy || i === groups.length - 1} onClick={() => move(i, 1)}
                  title="下へ" aria-label={`${g.name} を下へ`}>▼</button>
              </span>
              <span className="grp-dot" style={{ background: g.color ?? "#7c82a3" }} />
              <div className="grp-row-body">
                <div className="grp-row-name">{g.name}<span className="topo-muted topo-small">　{g.device_count}台</span></div>
                {g.description && <div className="topo-muted topo-small">{g.description}</div>}
              </div>
              <button className="btn" onClick={() => setEditing({ id: g.id, name: g.name, description: g.description ?? "", color: g.color })}>編集</button>
              <button className="btn btn-danger" onClick={() => remove(g)}>削除</button>
            </li>
          ))}
        </ul>
        {editing ? (
          <div className="grp-edit">
            <p className="section-label">{editing.id ? "グループを編集" : "新しいグループ"}</p>
            <div className="form-group">
              <label className="form-label" htmlFor="grp-name">名前</label>
              <input id="grp-name" value={editing.name} maxLength={128} autoFocus placeholder="例: 本社 / 大阪拠点 / DC"
                onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="grp-desc">説明（任意）</label>
              <input id="grp-desc" value={editing.description} maxLength={1000}
                onChange={(e) => setEditing({ ...editing, description: e.target.value })} />
            </div>
            <div className="form-group">
              <span className="form-label">色</span>
              <div className="topo-swatches" role="radiogroup" aria-label="色">
                {GROUP_COLORS.map((c) => (
                  <button key={c} type="button" role="radio" aria-checked={editing.color === c} aria-label={c}
                    className={`topo-swatch${editing.color === c ? " active" : ""}`} style={{ background: c }}
                    onClick={() => setEditing({ ...editing, color: c })} />
                ))}
              </div>
            </div>
            <div className="btn-row" style={{ marginTop: 8 }}>
              <button className="btn" onClick={() => setEditing(null)}>やめる</button>
              <button className="btn btn-primary" onClick={save} disabled={busy || !editing.name.trim()}>保存</button>
            </div>
          </div>
        ) : (
          <button className="btn" onClick={() => setEditing({ id: null, name: "", description: "", color: GROUP_COLORS[groups.length % GROUP_COLORS.length] })}>
            ＋ グループを追加
          </button>
        )}
        {error && <p className="form-error" style={{ marginTop: 10 }}>{error}</p>}
        <div className="btn-row">
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
      </div>
    </div>
  );
}

// ============================================================ 一覧

function readPref<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
function writePref(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* 保存できなくても動作に影響なし */
  }
}

function DeviceCard({
  d, canWrite, canTerminal, selecting, selected, showGroup, groupColor, collectActive, collectLast,
  onToggle, onOpen, onEdit, onDelete,
}: {
  collectActive?: CollectActive; collectLast?: CollectLast;
  d: Device; canWrite: boolean; canTerminal: boolean; selecting: boolean; selected: boolean; showGroup: boolean;
  groupColor: string | null; onToggle: () => void; onOpen: () => void;
  onEdit: (e: React.MouseEvent) => void; onDelete: (e: React.MouseEvent) => void;
}) {
  const { label: platformLabel } = usePlatforms();
  return (
    <div
      className={`device-card${selected ? " selected" : ""}`}
      style={canTerminal || selecting ? undefined : { cursor: "default" }}
      onClick={() => (selecting ? onToggle() : canTerminal && onOpen())}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 6 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {selecting && (
            <input type="checkbox" className="device-check" checked={selected} aria-label={`${d.name} を選択`}
              onClick={(e) => e.stopPropagation()} onChange={onToggle} />
          )}
          <span className={`badge ${d.is_active ? "badge-success" : "badge-neutral"}`}>
            {d.is_active ? "● Active" : "Inactive"}
          </span>
        </div>
        {canWrite && !selecting && (
          <div style={{ display: "flex", gap: 4 }}>
            <button className="btn" style={{ padding: "2px 8px", fontSize: 11 }} onClick={onEdit}>編集</button>
            <button className="btn btn-danger" style={{ padding: "2px 8px", fontSize: 11 }} onClick={onDelete}>削除</button>
          </div>
        )}
      </div>
      <p className="device-card-name">{d.name}</p>
      <p className="device-card-info">{d.hostname}</p>
      <p className="device-card-info" style={{ marginTop: 2 }}>
        {platformLabel(d.platform)} · port {d.port}
      </p>
      {(d.model || d.os_version || d.serial_number) && (
        <p className="device-card-info device-card-inv" style={{ marginTop: 2 }} title={inventoryTitle(d)}>
          {[d.model, d.os_version].filter(Boolean).join(" · ") || d.serial_number}
          {d.serial_number && (d.model || d.os_version) && <span className="device-card-serial"> S/N {d.serial_number}</span>}
        </p>
      )}
      {d.has_private_key && (
        <p className="device-card-info" style={{ marginTop: 2 }}>🔑 鍵認証{d.has_password ? "＋パスワード" : ""}</p>
      )}
      {d.jump_host_name && (
        <p className="device-card-info" style={{ marginTop: 2 }}>↪ 踏み台経由: {d.jump_host_name}</p>
      )}
      {d.credential_profile_name && (
        <p className="device-card-info device-card-profile" style={{ marginTop: 2 }}>🪪 認証: {d.credential_profile_name}</p>
      )}
      {showGroup && (
        <p className="device-card-info device-card-group" style={{ marginTop: 4 }}>
          <span className="grp-dot" style={{ background: groupColor ?? "#4a5178" }} />
          {d.group_name ?? "未分類"}
        </p>
      )}
      <CollectState active={collectActive} last={collectLast} />
      {canTerminal && !selecting && (
        <p style={{ fontSize: 11, color: "var(--color-accent)", marginTop: 8 }}>クリックでターミナルを開く →</p>
      )}
    </div>
  );
}

export default function DevicesPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const canWrite = can(PERM.DEVICE_WRITE);
  const canTerminal = can(PERM.TERMINAL);
  const [devices, setDevices] = useState<Device[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [modal, setModal] = useState<{ device: Device | null; groupId?: string } | null>(null);
  const [managing, setManaging] = useState(false);
  const [importing, setImporting] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [message, setMessage] = useState("");
  const [jumpHosts, setJumpHosts] = useState<JumpHostOption[]>([]);
  const [profiles, setProfiles] = useState<CredentialProfile[]>([]);
  const [error, setError] = useState("");
  // 表示の設定はブラウザに覚えておく
  const [view, setView] = useState<"group" | "list">(() => readPref("devices:view", "group"));
  const [groupFilter, setGroupFilter] = useState<string>(() => readPref("devices:group", ""));
  const [collapsed, setCollapsed] = useState<string[]>(() => readPref("devices:collapsed", []));
  const [query, setQuery] = useState("");
  const [selecting, setSelecting] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [moveTo, setMoveTo] = useState("");

  useEffect(() => writePref("devices:view", view), [view]);
  useEffect(() => writePref("devices:group", groupFilter), [groupFilter]);
  useEffect(() => writePref("devices:collapsed", collapsed), [collapsed]);

  const load = () => {
    api.get<Device[]>("/devices/").then((r) => setDevices(r.data)).catch((e) => setError(errorMessage(e)));
    api.get<DeviceGroup[]>("/device-groups/").then((r) => setGroups(r.data)).catch(() => undefined);
  };
  useEffect(() => {
    load();
    api.get<JumpHostOption[]>("/jump-hosts/").then((r) => setJumpHosts(r.data)).catch(() => undefined);
  }, []);

  // ---- 収集の状態を定期的に読む。動いている間と依頼した直後は短い間隔、それ以外は長い間隔
  const [collectStatus, setCollectStatus] = useState<CollectStatus | null>(null);
  const boostUntil = useRef(0);
  const watched = useRef<Set<string>>(new Set()); // 今回の収集で動いていた機器（終わったときの集計用）
  const pollNow = useRef<() => void>(() => undefined);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      window.clearTimeout(timer);
      let busy = false;
      try {
        const { data } = await api.get<CollectStatus>("/devices/collect-status");
        if (stopped) return;
        setCollectStatus(data);
        const ids = Object.keys(data.active);
        busy = ids.length > 0;
        ids.forEach((id) => watched.current.add(id));
        if (!busy && watched.current.size > 0) {
          // 動いていた収集がすべて終わった: 結果をまとめて知らせ、一覧（機器台帳の項目など）を読み直す
          const done = [...watched.current];
          watched.current = new Set();
          boostUntil.current = 0;
          const failed = done.filter((id) => data.last[id]?.status === "failed").length;
          setMessage(failed
            ? `収集が終わりました（成功 ${done.length - failed} 台・失敗 ${failed} 台）。失敗した機器はカードの「✗ 収集失敗」にカーソルを合わせると理由が出ます。`
            : `収集が終わりました（${done.length} 台すべて成功）。`);
          load();
        }
      } catch {
        /* 一時的に読めなくても、次の回でやり直す */
      }
      if (stopped) return;
      timer = window.setTimeout(tick, busy || Date.now() < boostUntil.current ? COLLECT_POLL_FAST : COLLECT_POLL_IDLE);
    };
    pollNow.current = () => { void tick(); };
    void tick();
    // 別のタブから戻ってきたときはすぐ読み直す
    const onVisible = () => { if (document.visibilityState === "visible") void tick(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  /** 収集を依頼した直後に呼ぶ: しばらく短い間隔で状態を確認する */
  const watchCollect = () => {
    boostUntil.current = Date.now() + COLLECT_BOOST;
    pollNow.current();
  };
  const activeCounts = useMemo(() => {
    const c = { running: 0, waiting: 0 };
    Object.values(collectStatus?.active ?? {}).forEach((a) => { if (a.state === "running") c.running += 1; else c.waiting += 1; });
    return c;
  }, [collectStatus]);
  // 認証情報プロファイルは編集画面を開くときに読み直す（別の画面で追加した直後でも選べるように）
  useEffect(() => {
    if (modal) api.get<CredentialProfile[]>("/credential-profiles/").then((r) => setProfiles(r.data)).catch(() => undefined);
  }, [modal]);

  // 絞り込みで指定していたグループが削除されたら解除する
  useEffect(() => {
    if (groupFilter && groupFilter !== UNGROUPED && groups.length && !groups.some((g) => g.id === groupFilter)) {
      setGroupFilter("");
    }
  }, [groups, groupFilter]);

  const collectAll = async () => {
    setCollecting(true);
    setError("");
    try {
      await api.post("/devices/collect/all");
      setMessage("全機器の収集を依頼しました。進み具合は各機器のカードに表示します。");
      watchCollect();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setTimeout(() => setCollecting(false), 3000);
    }
  };

  const collectGroup = async (groupId: string, name: string) => {
    setError("");
    try {
      await api.post(`/device-groups/${groupId}/collect`);
      setMessage(`グループ「${name}」の機器の収集を依頼しました。進み具合は各機器のカードに表示します。`);
      watchCollect();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const deleteDevice = async (d: Device, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`「${d.name}」を削除しますか？`)) return;
    try {
      await api.delete(`/devices/${d.id}`);
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });

  const moveSelected = async () => {
    if (!selected.size) return;
    setError("");
    try {
      const target = moveTo === UNGROUPED ? null : moveTo;
      await api.post("/device-groups/assign", { device_ids: [...selected], group_id: target });
      const name = target ? groups.find((g) => g.id === target)?.name : "未分類";
      setMessage(`${selected.size}台を「${name}」へ移動しました。`);
      setSelected(new Set());
      setSelecting(false);
      setMoveTo("");
      load();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const colorOf = useMemo(() => new Map(groups.map((g) => [g.id, g.color])), [groups]);
  const q = query.trim().toLowerCase();
  const visible = devices.filter((d) => {
    if (groupFilter === UNGROUPED ? d.group_id : groupFilter && d.group_id !== groupFilter) return false;
    if (!q) return true;
    return `${d.name} ${d.hostname} ${d.description ?? ""} ${d.model ?? ""} ${d.serial_number ?? ""} ${d.os_version ?? ""}`
      .toLowerCase().includes(q);
  });

  // グループ別の表示: グループ（名前順）→ 未分類 の順。絞り込み中は該当するものだけ
  const sections = [
    ...groups.map((g) => ({ key: g.id, name: g.name, description: g.description, color: g.color, group: g })),
    { key: UNGROUPED, name: "未分類", description: null, color: null, group: null },
  ]
    .filter((s) => !groupFilter || groupFilter === s.key)
    .map((s) => ({ ...s, devices: visible.filter((d) => (d.group_id ?? UNGROUPED) === s.key) }))
    // 未分類と、検索で0台になったグループは出さない（空のグループは検索していないときだけ表示）
    .filter((s) => s.devices.length || (s.group && !q));

  const card = (d: Device, showGroup: boolean) => (
    <DeviceCard
      key={d.id} d={d} canWrite={canWrite} canTerminal={canTerminal} selecting={selecting}
      selected={selected.has(d.id)} showGroup={showGroup} groupColor={d.group_id ? colorOf.get(d.group_id) ?? null : null}
      collectActive={collectStatus?.active[d.id]} collectLast={collectStatus?.last[d.id]}
      onToggle={() => toggle(d.id)} onOpen={() => navigate(`/terminal/${d.id}`)}
      onEdit={(e) => { e.stopPropagation(); setModal({ device: d }); }} onDelete={(e) => deleteDevice(d, e)}
    />
  );

  return (
    <div className="page">
      {modal && (
        <DeviceModal device={modal.device} jumpHosts={jumpHosts} groups={groups} profiles={profiles} defaultGroupId={modal.groupId}
          onClose={() => setModal(null)} onSave={load} />
      )}
      {managing && <GroupManagerModal groups={groups} onClose={() => setManaging(false)} onChanged={load} />}
      {importing && (
        <DeviceImportModal onClose={() => setImporting(false)}
          onDone={(n) => { load(); setError(""); setMessage(`CSV から ${n} 台を登録しました。取り込んだ CSV ファイルは削除してください。`); }} />
      )}
      <div className="page-header">
        <span className="page-title">デバイス管理</span>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" title="機器の一覧（モデル・シリアル番号・OS バージョンを含む）を CSV で出力します"
            onClick={() => downloadCsv("/devices/export", {}, "devices.csv").catch((e) => setError(errorMessage(e)))}>
            台帳 CSV
          </button>
          {canWrite && (
            <button className="btn" title="CSV ファイルから複数の機器をまとめて登録します" onClick={() => setImporting(true)}>
              CSV 取り込み
            </button>
          )}
          {canWrite && <button className="btn" onClick={() => setManaging(true)}>グループの管理</button>}
          {canWrite && (
            <button className="btn" onClick={() => setModal({ device: null, groupId: groupFilter && groupFilter !== UNGROUPED ? groupFilter : undefined })}>
              ＋ 追加
            </button>
          )}
          {can(PERM.COLLECT) && (
            <button className="btn btn-primary" onClick={collectAll} disabled={collecting}>
              {collecting ? "投入中..." : "↻ 一括収集"}
            </button>
          )}
        </div>
      </div>

      <div className="page-body">
        {error && <p className="form-error">{error}</p>}
        {message && <p style={{ fontSize: 12, color: "var(--color-success)", marginBottom: 12 }}>{message}</p>}

        <div className="dev-toolbar">
          <div className="seg-tabs" role="tablist" aria-label="表示方法">
            <button role="tab" aria-selected={view === "group"} className={`seg-tab${view === "group" ? " active" : ""}`} onClick={() => setView("group")}>グループ別</button>
            <button role="tab" aria-selected={view === "list"} className={`seg-tab${view === "list" ? " active" : ""}`} onClick={() => setView("list")}>一覧</button>
          </div>
          <select className="dev-filter" value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)} aria-label="グループで絞り込み">
            <option value="">すべてのグループ</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}（{g.device_count}）</option>)}
            <option value={UNGROUPED}>未分類（{devices.filter((d) => !d.group_id).length}）</option>
          </select>
          <input className="dev-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="名前・IP・モデル・S/N" aria-label="名前・IP・モデル・S/N" />
          <span className="topo-muted topo-small">{visible.length} / {devices.length}台</span>
          {(activeCounts.running > 0 || activeCounts.waiting > 0) && (
            <span className="collect-summary" role="status">
              <span className="collect-spin" aria-hidden="true" />
              収集中 {activeCounts.running} 台{activeCounts.waiting > 0 ? `・待ち ${activeCounts.waiting} 台` : ""}
            </span>
          )}
          {collectStatus && !collectStatus.available && (
            <span className="topo-muted topo-small" title="Redis に接続できないため、収集が動いているかを表示できません">収集の進み具合を取得できません</span>
          )}
          {canWrite && groups.length > 0 && (
            <button className={`btn${selecting ? " btn-primary" : ""}`} style={{ marginLeft: "auto" }}
              onClick={() => { setSelecting(!selecting); setSelected(new Set()); }}>
              {selecting ? "選択をやめる" : "選択してグループへ移動"}
            </button>
          )}
        </div>

        {selecting && (
          <div className="dev-selectbar">
            <span>{selected.size}台を選択中</span>
            <button className="link-btn" onClick={() => setSelected(new Set(visible.map((d) => d.id)))}>表示中をすべて選択</button>
            <button className="link-btn" onClick={() => setSelected(new Set())}>解除</button>
            <select value={moveTo} onChange={(e) => setMoveTo(e.target.value)} aria-label="移動先のグループ" style={{ width: "auto" }}>
              <option value="">移動先を選択</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              <option value={UNGROUPED}>未分類に戻す</option>
            </select>
            <button className="btn btn-primary" onClick={moveSelected} disabled={!selected.size || !moveTo}>移動</button>
          </div>
        )}

        {devices.length === 0 ? (
          <p className="topo-muted">デバイスが登録されていません。</p>
        ) : view === "list" ? (
          <div className="device-grid">{visible.map((d) => card(d, true))}</div>
        ) : (
          sections.map((s) => {
            const isCollapsed = collapsed.includes(s.key);
            return (
              <section key={s.key} className="dev-group">
                <div className="dev-group-bar">
                  <button
                    className="dev-group-head" aria-expanded={!isCollapsed}
                    onClick={() => setCollapsed(isCollapsed ? collapsed.filter((k) => k !== s.key) : [...collapsed, s.key])}
                  >
                    <span className="dev-group-caret">{isCollapsed ? "▸" : "▾"}</span>
                    <span className="grp-dot" style={{ background: s.color ?? "#4a5178" }} />
                    <span className="dev-group-name">{s.name}</span>
                    <span className="topo-muted topo-small">{s.devices.length}台</span>
                    {s.description && <span className="topo-muted topo-small dev-group-desc">— {s.description}</span>}
                  </button>
                  {s.group && can(PERM.COLLECT) && s.devices.some((d) => d.is_active) && (
                    <button className="btn btn-sm" onClick={() => collectGroup(s.key, s.name)} title="このグループの有効な機器をまとめて収集">
                      このグループを収集
                    </button>
                  )}
                </div>
                {!isCollapsed && (
                  s.devices.length ? (
                    <div className="device-grid">{s.devices.map((d) => card(d, false))}</div>
                  ) : (
                    <p className="topo-muted topo-small dev-group-empty">
                      このグループには機器がありません。
                      {canWrite && <> 機器の「編集」でグループを選ぶか、「選択してグループへ移動」で追加できます。</>}
                    </p>
                  )
                )}
              </section>
            );
          })
        )}
      </div>
    </div>
  );
}
