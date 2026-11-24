"""通知（Discord / Slack の Webhook、メール）: コンフィグの変更・違反の発生・収集の失敗・機器情報の変化・基準からのずれ

通知する内容は通知設定ごとに選ぶ（on_change / on_violation / on_failure / on_system / on_inventory / on_ping / on_drift）。
on_system（システムの異常）は機器に結び付かないため、対象の機器グループに関係なく送る。

通知先の決め方（機器のコンフィグに変更があったとき）
  有効なユーザーごとに:
    - 個別設定（custom）: 自分の通知先へ。対象の機器グループに含まれるときだけ
    - グループの設定を使う（inherit・設定なし）: 所属する各ユーザーグループの設定（有効なもの）で、
      対象に含まれるものの通知先へ
    - 通知しない（off）: 何もしない
  同じ Webhook URL・同じメールの宛先は1回だけ送る（グループの Webhook はメンバーが何人いても1回）。
  メールは宛先ごとに 1 通（ほかの宛先を見せない）。送信の設定（SMTP・OAuth 2.0）は services/mail.py。
  メンバーがいない・全員が個別設定のグループの Webhook には送らない。

通知内容は要約と画面へのリンクのみ（差分の中身はパスワードのハッシュ等を含みうるため載せない）。
"""
import asyncio
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.device import Device, DeviceGroup
from app.models.notification import NotificationSetting, UserGroup, UserGroupMember
from app.models.user import User
from app.services import inventory, mail
from app.services.activity import record as record_activity

logger = logging.getLogger(__name__)

KINDS = ("discord", "slack")  # Webhook の種類
KIND_LABELS = {"discord": "Discord", "slack": "Slack", "email": "メール"}
# 宛先を公式の Webhook に限る（任意の URL にサーバーからリクエストを送らせないため）
WEBHOOK_RE = {
    "discord": re.compile(
        r"^https://(?:(?:ptb|canary)\.)?(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+$"
    ),
    "slack": re.compile(r"^https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/-]+$"),
}
TIMEOUT_SEC = 10
MAX_RETRY_WAIT_SEC = 10
TRIGGER_LABELS = {"manual": "手動収集", "schedule": "スケジュール収集"}
EVENTS = ("change", "violation", "failure", "system")
EVENT_LABELS = {"change": "変更通知", "violation": "違反の通知", "failure": "収集失敗の通知", "system": "システムの通知",
                "inventory": "機器情報の変化の通知", "ping": "Ping監視の通知", "profile": "認証情報プロファイルの通知",
                "drift": "基準からのずれの通知"}
SENT_MESSAGES = {"change": "変更を通知しました", "violation": "コンプライアンス違反を通知しました",
                 "failure": "収集の失敗を通知しました", "system": "システムの状態を通知しました",
                 "inventory": "機器情報の変化を通知しました",
                 "ping": "Ping監視の応答なし・復旧を通知しました",
                 "profile": "認証情報プロファイルへの操作を所有者に通知しました",
                 "drift": "基準からのずれを通知しました"}
SEVERITY_LABELS = {"high": "高", "medium": "中", "low": "低"}
MAX_LIST = 20  # 1通に載せる機器・ルールの数


def valid_webhook(kind: str, url: str) -> bool:
    return bool(WEBHOOK_RE[kind].match(url))


def mask_webhook(url: str | None) -> str | None:
    """画面表示用（トークン部分を隠す）"""
    if not url:
        return None
    m = re.match(r"^(https://[^/]+/[^/]+/[^/]+/)", url)
    head = m.group(1) if m else url[:24]
    return f"{head}…{url[-4:]}"


def setting_webhooks(s: NotificationSetting) -> dict[str, str]:
    return {k: url for k in KINDS if (url := getattr(s, f"{k}_webhook"))}


def setting_targets(s: NotificationSetting) -> list[tuple[str, str]]:
    """通知先の一覧（種類, Webhook URL かメールアドレス）"""
    return list(setting_webhooks(s).items()) + [("email", a) for a in s.emails]


def has_target(s: NotificationSetting | None) -> bool:
    return bool(s and (s.discord_webhook or s.slack_webhook or s.emails))


# ---------------------------------------------------------------- 通知先の決定


@dataclass
class Destination:
    kind: str
    url: str  # Webhook URL、メールならメールアドレス
    setting_ids: set[str] = field(default_factory=set)  # この宛先を設定している通知設定（送信結果の記録用）
    via: set[str] = field(default_factory=set)  # 誰の設定で送るか（「ユーザー: xx」「グループ: yy」）


async def resolve_destinations(db: AsyncSession, device_group_id: str | None,
                               event: str = "change", any_group: bool = False) -> list[Destination]:
    """指定した機器グループ（None は未分類）の機器で event（change / violation / failure）が起きたときの通知先。

    any_group: 対象の機器グループを見ない（機器に結び付かない event = system 用）
    """
    settings_rows = (await db.execute(select(NotificationSetting))).scalars().all()
    user_settings = {s.owner_id: s for s in settings_rows if s.owner_type == "user"}
    group_settings = {s.owner_id: s for s in settings_rows if s.owner_type == "group"}
    users = (await db.execute(select(User).where(User.is_active.is_(True)))).scalars().all()
    groups = {g.id: g for g in (await db.execute(select(UserGroup))).scalars()}
    memberships: dict[str, list[str]] = {}
    for m in (await db.execute(select(UserGroupMember))).scalars():
        memberships.setdefault(m.user_id, []).append(m.group_id)

    dests: dict[tuple[str, str], Destination] = {}

    def add(s: NotificationSetting, label: str) -> None:
        for kind, url in setting_targets(s):
            key = (kind, url.lower() if kind == "email" else url)
            d = dests.setdefault(key, Destination(kind, url))
            d.setting_ids.add(s.id)
            d.via.add(label)

    for u in users:
        own = user_settings.get(u.id)
        mode = own.mode if own else "inherit"
        if mode == "custom":
            if (any_group or own.matches(device_group_id)) and own.wants(event):
                add(own, f"ユーザー: {u.username}")
        elif mode == "inherit":
            for gid in memberships.get(u.id, []):
                gs = group_settings.get(gid)
                if (gid in groups and gs and gs.mode == "custom" and gs.wants(event)
                        and (any_group or gs.matches(device_group_id))):
                    add(gs, f"グループ: {groups[gid].name}")
    return list(dests.values())


# ---------------------------------------------------------------- メッセージ


@dataclass
class ChangeEvent:
    device_id: str
    device_name: str
    hostname: str
    group_name: str | None
    added: int
    removed: int
    triggered_by: str
    commit_hash: str
    at: datetime  # UTC（naive）


def _local(at: datetime) -> str:
    return at.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(settings.TIMEZONE)).strftime("%Y/%m/%d %H:%M")


def history_url(device_id: str) -> str | None:
    base = settings.PUBLIC_URL.rstrip("/")
    return f"{base}/history?device={device_id}" if base else None


def build_payload(kind: str, ev: ChangeEvent) -> dict:
    title = f"コンフィグ変更: {ev.device_name}"
    facts = [
        ("機器", f"{ev.device_name}（{ev.hostname}）"),
        ("グループ", ev.group_name or "未分類"),
        ("変更", f"+{ev.added} 行 / -{ev.removed} 行"),
        ("収集", f"{TRIGGER_LABELS.get(ev.triggered_by, ev.triggered_by)}・{_local(ev.at)}"),
        ("世代", ev.commit_hash[:8]),
    ]
    url = history_url(ev.device_id)
    if kind == "email":
        return _message(kind, title, facts, url, "差分を画面で確認", 0x4F8EF7)
    if kind == "discord":
        embed = {
            "title": title,
            "color": 0x4F8EF7,
            "fields": [{"name": k, "value": v, "inline": k != "機器"} for k, v in facts],
            "footer": {"text": "NetConfig Manager"},
        }
        if url:
            embed["url"] = url
            embed["description"] = f"[差分を画面で確認]({url})"
        return {"username": "NetConfig Manager", "embeds": [embed]}
    lines = [f"*{title}*"] + [f"{k}: {v}" for k, v in facts]
    if url:
        lines.append(f"<{url}|差分を画面で確認>")
    return {"text": "\n".join(lines)}


def build_test_payload(kind: str, owner_label: str) -> dict:
    text = f"NetConfig Manager からのテスト通知です（{owner_label} の通知設定）"
    if kind == "email":
        return {"title": "テスト通知", "body": text, "facts": [], "url": _page_url("/notifications"),
                "link_text": "通知設定を画面で確認"}
    if kind == "discord":
        return {"username": "NetConfig Manager", "content": text}
    return {"text": text}


# ---------------------------------------------------------------- 送信


def send_webhook(kind: str, url: str, payload: dict) -> str | None:
    """送信する。成功なら None、失敗ならエラーの説明。レート制限（429）は一度だけ待って再送する"""
    if not valid_webhook(kind, url):
        return "Webhook URL の形式が正しくありません"
    body = json.dumps(payload, ensure_ascii=False).encode()
    for attempt in range(2):
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json", "User-Agent": "NetConfig-Manager",
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as r:  # noqa: S310 - URL は WEBHOOK_RE で検証済み
                r.read()
            return None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 0:
                wait = _retry_after(e)
                time.sleep(min(wait, MAX_RETRY_WAIT_SEC))
                continue
            detail = e.read()[:200].decode(errors="replace")
            if e.code in (401, 403, 404):
                return f"Webhook が無効です（HTTP {e.code}。削除・再発行されていないか確認してください）"
            return f"HTTP {e.code} {detail}".strip()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            return f"送信できません（{reason}）"
    return "レート制限のため送信できませんでした"


def _send(kind: str, url: str, payload: dict, cfg: "mail.MailConfig | None") -> str | None:
    """1 か所へ送る（スレッドで実行）。メールは mail.send_notification、ほかは Webhook"""
    if kind == "email":
        return mail.send_notification(cfg or mail.MailConfig(), url, payload)
    return send_webhook(kind, url, payload)


def _retry_after(e: urllib.error.HTTPError) -> float:
    try:
        return float(e.headers.get("Retry-After") or json.loads(e.read() or b"{}").get("retry_after", 1))
    except (ValueError, TypeError):
        return 1.0


async def _deliver(db: AsyncSession, event: str, sends: list[tuple[Destination, dict, Device | None]],
                   ref: str | None) -> dict:
    """送信して結果を記録する（アクティビティログ・通知設定の last_sent_at / last_error）"""
    if not sends:
        return {"sent": 0, "failed": 0}
    cfg = await mail.load_config(db) if any(d.kind == "email" for d, _, _ in sends) else None
    results = await asyncio.gather(*(asyncio.to_thread(_send, d.kind, d.url, payload, cfg) for d, payload, _ in sends))
    await mail.record_last([err for (d, _, _), err in zip(sends, results, strict=True) if d.kind == "email"])
    now = utcnow()
    errors: dict[str, list[str]] = {}
    label = EVENT_LABELS[event]
    for (d, _, device), err in zip(sends, results, strict=True):
        for sid in d.setting_ids:
            errors.setdefault(sid, [])
            if err:
                errors[sid].append(f"{KIND_LABELS[d.kind]}: {err}")
        # 送信先の URL（秘密）・メールアドレスは残さず、種類と誰の設定かだけ記録する
        via = "・".join(sorted(d.via))
        where = {"device_id": device.id, "device_name": device.name} if device else {}
        if err:
            logger.warning("%sの送信に失敗 %s: %s", label, d.kind, err)
            record_activity(db, "notify.failed", f"{KIND_LABELS[d.kind]} への{label}に失敗しました（{via}）: {err}",
                            detail={"kind": d.kind, "via": sorted(d.via), "error": err}, ref=ref, **where)
        else:
            record_activity(db, "notify.sent", f"{KIND_LABELS[d.kind]} へ{SENT_MESSAGES[event]}（{via}）",
                            detail={"kind": d.kind, "via": sorted(d.via)}, ref=ref, **where)
    for sid, errs in errors.items():
        st = await db.get(NotificationSetting, sid)
        if st is not None:
            st.last_sent_at = now
            st.last_error = " / ".join(errs) or None
    await db.commit()
    failed = sum(1 for e in results if e)
    logger.info("%s 送信=%d 失敗=%d", label, len(sends) - failed, failed)
    return {"sent": len(sends) - failed, "failed": failed}


async def notify_change(db: AsyncSession, device_id: str, commit_hash: str, added: int, removed: int,
                        triggered_by: str, ref: str | None = None) -> dict:
    """コンフィグ変更を通知する（worker から呼ぶ）。結果は通知設定の last_sent_at / last_error に残す"""
    device = await db.get(Device, device_id)
    if device is None:
        return {"sent": 0, "failed": 0}
    group = await db.get(DeviceGroup, device.group_id) if device.group_id else None
    dests = await resolve_destinations(db, device.group_id, "change")
    ev = ChangeEvent(device.id, device.name, device.hostname, group.name if group else None,
                     added, removed, triggered_by, commit_hash, utcnow())
    return await _deliver(db, "change", [(d, build_payload(d.kind, ev), device) for d in dests], ref)


def _message(kind: str, title: str, facts: list[tuple[str, str]], url: str | None, link_text: str,
             color: int, body: str | None = None) -> dict:
    """Discord（埋め込み）/ Slack（テキスト）/ メール（件名・本文の材料。組み立ては mail.build_message）の通知"""
    if kind == "email":
        return {"title": title, "facts": facts, "url": url, "link_text": link_text, "body": body}
    if kind == "discord":
        embed: dict = {
            "title": title, "color": color,
            "fields": [{"name": k, "value": v[:1000], "inline": len(v) < 40} for k, v in facts],
            "footer": {"text": "NetConfig Manager"},
        }
        desc = [body] if body else []
        if url:
            embed["url"] = url
            desc.append(f"[{link_text}]({url})")
        if desc:
            embed["description"] = "\n".join(desc)[:4000]
        return {"username": "NetConfig Manager", "embeds": [embed]}
    lines = [f"*{title}*"] + ([body] if body else []) + [f"{k}: {v}" for k, v in facts]
    if url:
        lines.append(f"<{url}|{link_text}>")
    return {"text": "\n".join(lines)}


def _page_url(path: str) -> str | None:
    base = settings.PUBLIC_URL.rstrip("/")
    return f"{base}{path}" if base else None


async def notify_violations(db: AsyncSession, items: list[tuple[str, list[tuple[str, str]]]],
                            ref: str | None = None) -> dict:
    """コンプライアンス違反の発生を通知する。items: [(機器ID, [(ルール名, 重要度), ...])]

    通知先ごとに1通にまとめる（ルールの追加などで多数の機器が一度に違反になっても通知が増えすぎないように）
    """
    devices = {d.id: d for d in (await db.execute(select(Device).where(
        Device.id.in_([i for i, _ in items])))).scalars()}
    groups = {g.id: g.name for g in (await db.execute(select(DeviceGroup))).scalars()}
    per_dest: dict[tuple[str, str], tuple[Destination, list[tuple[Device, list[tuple[str, str]]]]]] = {}
    for device_id, rules in items:
        device = devices.get(device_id)
        if device is None or not rules:
            continue
        for d in await resolve_destinations(db, device.group_id, "violation"):
            entry = per_dest.setdefault((d.kind, d.url), (d, []))
            entry[1].append((device, rules))
    sends = []
    url = _page_url("/compliance")
    for d, entries in per_dest.values():
        if len(entries) == 1:
            device, rules = entries[0]
            facts = [("機器", f"{device.name}（{device.hostname}）"),
                     ("グループ", groups.get(device.group_id, "未分類") if device.group_id else "未分類"),
                     ("違反したルール", "\n".join(f"・{n}（重要度: {SEVERITY_LABELS.get(sv, sv)}）"
                                              for n, sv in rules[:MAX_LIST])
                      + (f"\n…ほか {len(rules) - MAX_LIST} 件" if len(rules) > MAX_LIST else ""))]
            payload = _message(d.kind, f"コンプライアンス違反: {device.name}", facts, url, "違反の一覧を画面で確認",
                               0xF87171)
            sends.append((d, payload, device))
        else:
            body = "\n".join(f"・{dev.name}: {'、'.join(n for n, _ in rules[:5])}{' ほか' if len(rules) > 5 else ''}"
                             for dev, rules in entries[:MAX_LIST])
            if len(entries) > MAX_LIST:
                body += f"\n…ほか {len(entries) - MAX_LIST} 台"
            payload = _message(d.kind, f"コンプライアンス違反: {len(entries)} 台", [], url, "違反の一覧を画面で確認",
                               0xF87171, body)
            sends.append((d, payload, None))
    return await _deliver(db, "violation", sends, ref)


async def notify_failure(db: AsyncSession, device_id: str, error: str, triggered_by: str,
                         ref: str | None = None) -> dict:
    """収集の失敗（リトライしても失敗したとき）を通知する"""
    device = await db.get(Device, device_id)
    if device is None:
        return {"sent": 0, "failed": 0}
    group = await db.get(DeviceGroup, device.group_id) if device.group_id else None
    dests = await resolve_destinations(db, device.group_id, "failure")
    facts = [("機器", f"{device.name}（{device.hostname}）"), ("グループ", group.name if group else "未分類"),
             ("収集", f"{TRIGGER_LABELS.get(triggered_by, triggered_by)}・{_local(utcnow())}"),
             ("エラー", (error or "不明")[:500])]
    url = _page_url(f"/activity?device={device.id}")
    return await _deliver(db, "failure", [
        (d, _message(d.kind, f"収集失敗: {device.name}", facts, url, "アクティビティを画面で確認", 0xFB923C), device)
        for d in dests
    ], ref)


def _error_kind(error: str) -> str:
    """失敗の理由をまとめるための短い見出し（1 行目の先頭 60 文字）"""
    first = (error or "不明").strip().splitlines()[0] if (error or "").strip() else "不明"
    return first[:60] + ("…" if len(first) > 60 else "")


async def notify_failures(db: AsyncSession, items: list[dict]) -> dict:
    """まとめた収集の失敗を通知する。items: [{device_id, error, triggered_by, ref, at}]（services/failure_batch.py）

    通知先ごとに、その通知先が受け取る機器の失敗が 1 台ならこれまでどおりの詳しい通知、
    2 台以上なら 1 通にまとめる（台数・失敗の理由の内訳・機器の一覧）
    """
    latest: dict[str, dict] = {}
    for it in sorted(items, key=lambda x: x.get("at") or 0):
        latest[it["device_id"]] = it  # 同じ機器が何度も失敗したら最後のものだけ
    devices = {d.id: d for d in (await db.execute(select(Device).where(Device.id.in_(list(latest))))).scalars()}
    groups = {g.id: g.name for g in (await db.execute(select(DeviceGroup))).scalars()}
    per_dest: dict[tuple[str, str], tuple[Destination, list[tuple[Device, dict]]]] = {}
    dests_by_group: dict[str | None, list[Destination]] = {}
    for device_id, it in latest.items():
        device = devices.get(device_id)
        if device is None:  # まとめている間に削除された機器
            continue
        if device.group_id not in dests_by_group:
            dests_by_group[device.group_id] = await resolve_destinations(db, device.group_id, "failure")
        for d in dests_by_group[device.group_id]:
            per_dest.setdefault((d.kind, d.url), (d, []))[1].append((device, it))
    refs = {it.get("ref") for it in latest.values() if it.get("ref")}
    ref = refs.pop() if len(refs) == 1 else None  # 1 回の一括収集の失敗だけなら、その実行の記録に結び付ける
    sends = []
    for d, entries in per_dest.values():
        entries.sort(key=lambda e: e[0].name)
        if len(entries) == 1:
            device, it = entries[0]
            facts = [("機器", f"{device.name}（{device.hostname}）"),
                     ("グループ", groups.get(device.group_id, "未分類") if device.group_id else "未分類"),
                     ("収集", f"{TRIGGER_LABELS.get(it['triggered_by'], it['triggered_by'])}・{_local(utcnow())}"),
                     ("エラー", (it.get("error") or "不明")[:500])]
            payload = _message(d.kind, f"収集失敗: {device.name}", facts, _page_url(f"/activity?device={device.id}"),
                               "アクティビティを画面で確認", 0xFB923C)
            sends.append((d, payload, device))
            continue
        kinds: dict[str, int] = {}
        for _, it in entries:
            k = _error_kind(it.get("error", ""))
            kinds[k] = kinds.get(k, 0) + 1
        top = sorted(kinds.items(), key=lambda kv: -kv[1])
        breakdown = "\n".join(f"・{k}（{n} 台）" for k, n in top[:5]) + (f"\n…ほか {len(top) - 5} 種類" if len(top) > 5 else "")
        triggers = sorted({TRIGGER_LABELS.get(it["triggered_by"], it["triggered_by"]) for _, it in entries})
        body = "\n".join(f"・{dev.name}（{dev.hostname}）: {_error_kind(it.get('error', ''))}"
                         for dev, it in entries[:MAX_LIST])
        if len(entries) > MAX_LIST:
            body += f"\n…ほか {len(entries) - MAX_LIST} 台"
        facts = [("収集", f"{'・'.join(triggers)}・{_local(utcnow())}"), ("失敗の理由", breakdown)]
        payload = _message(d.kind, f"収集失敗: {len(entries)} 台", facts, _page_url("/activity?level=error"),
                           "アクティビティを画面で確認", 0xFB923C, body)
        sends.append((d, payload, None))
    return await _deliver(db, "failure", sends, ref)


async def notify_inventory(db: AsyncSession, device_id: str, changes: list[list[str]],
                           ref: str | None = None) -> dict:
    """機器情報の変化（OS バージョンアップ・機器の交換など）を通知する。changes は [項目, 以前, 今回] の並び"""
    device = await db.get(Device, device_id)
    if device is None or not changes:
        return {"sent": 0, "failed": 0}
    group = await db.get(DeviceGroup, device.group_id) if device.group_id else None
    dests = await resolve_destinations(db, device.group_id, "inventory")
    # シリアル番号・モデルが変わるのは機器の交換（または登録先の取り違え）なので、目立つ色にする
    replaced = any(f in ("serial_number", "model") for f, _, _ in changes)
    title = f"{'機器の交換？' if replaced else '機器情報の変化'}: {device.name}"
    facts = [("機器", f"{device.name}（{device.hostname}）"), ("グループ", group.name if group else "未分類")]
    facts += [(inventory.LABELS.get(f, f), f"{a} → {b}") for f, a, b in changes]
    facts.append(("検出", _local(utcnow())))
    body = ("シリアル番号・モデルが変わりました。機器を交換していなければ、登録内容（接続先）を確認してください"
            if replaced else None)
    url = _page_url(f"/activity?device={device.id}")
    return await _deliver(db, "inventory", [
        (d, _message(d.kind, title, facts, url, "アクティビティを画面で確認", 0xFBBF24 if replaced else 0x60A5FA, body),
         device)
        for d in dests
    ], ref)


async def notify_drift(db: AsyncSession, device_id: str, added: int, removed: int, baseline_hash: str,
                       latest_hash: str, ref: str | None = None) -> dict:
    """機器が基準の世代からずれたこと（ずれなし → ずれあり）を通知する。差分の中身は載せない"""
    device = await db.get(Device, device_id)
    if device is None:
        return {"sent": 0, "failed": 0}
    group = await db.get(DeviceGroup, device.group_id) if device.group_id else None
    dests = await resolve_destinations(db, device.group_id, "drift")
    facts = [("機器", f"{device.name}（{device.hostname}）"), ("グループ", group.name if group else "未分類"),
             ("基準からのずれ", f"+{added} 行 / -{removed} 行"),
             ("基準の世代", baseline_hash[:8]), ("最新の世代", latest_hash[:8]), ("検出", _local(utcnow()))]
    url = history_url(device.id)
    return await _deliver(db, "drift", [
        (d, _message(d.kind, f"基準からのずれ: {device.name}", facts, url, "差分を画面で確認", 0xF87171), device)
        for d in dests
    ], ref)


async def notify_ping(db: AsyncSession, down: list[dict], up: list[dict]) -> dict:
    """Ping監視（常時監視）の応答なし・復旧を通知する。通知先ごとに 1 通にまとめる（ネットワーク障害で多数が同時に落ちたとき）

    down / up の要素は services/ping_monitor.py の run_once の戻り値（name・address・group_id・since）
    """
    if not down and not up:
        return {"sent": 0, "failed": 0}
    by_group: dict[str | None, list[Destination]] = {}
    per_dest: dict[tuple[str, str], tuple[Destination, list[dict], list[dict]]] = {}
    for kind_list, item in [(0, x) for x in down] + [(1, x) for x in up]:
        gid = item.get("group_id")
        if gid not in by_group:
            by_group[gid] = await resolve_destinations(db, gid, "ping")
        for d in by_group[gid]:
            entry = per_dest.setdefault((d.kind, d.url), (d, [], []))
            entry[1 + kind_list].append(item)
    sends = []
    for d, ds, us in per_dest.values():
        if ds and not us:
            title = f"Ping監視: 応答なし {ds[0]['name']}" if len(ds) == 1 else f"Ping監視: {len(ds)} 件が応答なし"
            color = 0xEF4444
        elif us and not ds:
            title = f"Ping監視: 復旧 {us[0]['name']}" if len(us) == 1 else f"Ping監視: {len(us)} 件が復旧"
            color = 0x34D399
        else:
            title = f"Ping監視: 応答なし {len(ds)} 件・復旧 {len(us)} 件"
            color = 0xEF4444
        lines = []
        for x in ds[:MAX_LIST]:
            lines.append(f"🔴 {x['name']}（{x['address']}）応答なし（{_local(datetime.fromisoformat(x['since']))} から）"
                         if x.get("since") else f"🔴 {x['name']}（{x['address']}）応答なし")
        if len(ds) > MAX_LIST:
            lines.append(f"…ほか {len(ds) - MAX_LIST} 件が応答なし")
        for x in us[:MAX_LIST]:
            lines.append(f"🟢 {x['name']}（{x['address']}）復旧")
        if len(us) > MAX_LIST:
            lines.append(f"…ほか {len(us) - MAX_LIST} 件が復旧")
        rule = f"{settings.PING_ALERT_AFTER} 回続けて応答が無ければ応答なし（{settings.PING_MONITOR_INTERVAL_SEC} 秒ごと）"
        facts = [("判定", rule)]
        payload = _message(d.kind, title, facts, _page_url("/ping"), "Ping監視を画面で確認", color, "\n".join(lines))
        sends.append((d, payload, None))
    return await _deliver(db, "ping", sends, None)


async def notify_system(db: AsyncSession, title: str, body: str, facts: list[tuple[str, str]] | None = None,
                        ok: bool = False) -> dict:
    """システムの異常・復旧を通知する（services/system.py のウォッチドッグから呼ぶ）"""
    dests = await resolve_destinations(db, None, "system", any_group=True)
    url = _page_url("/system")
    return await _deliver(db, "system", [
        (d, _message(d.kind, title, facts or [], url, "システムの状態を画面で確認", 0x34D399 if ok else 0xEF4444, body), None)
        for d in dests
    ], None)


async def resolve_user_destinations(db: AsyncSession, user_id: str) -> list[Destination]:
    """特定のユーザー本人に届く通知先（個人の設定。グループの設定を引き継いでいる場合は所属グループの設定）。

    本人あての連絡なので、通知する内容の選択（on_*）と対象の機器グループは見ない
    """
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        return []
    dests: dict[tuple[str, str], Destination] = {}

    def add(s: NotificationSetting, label: str) -> None:
        for kind, url in setting_targets(s):
            key = (kind, url.lower() if kind == "email" else url)
            d = dests.setdefault(key, Destination(kind, url))
            d.setting_ids.add(s.id)
            d.via.add(label)

    own = (await db.execute(select(NotificationSetting).where(
        NotificationSetting.owner_type == "user", NotificationSetting.owner_id == user_id))).scalars().first()
    mode = own.mode if own else "inherit"
    if mode == "custom":
        add(own, f"ユーザー: {user.username}")
    elif mode == "inherit":
        group_ids = (await db.execute(
            select(UserGroupMember.group_id).where(UserGroupMember.user_id == user_id))).scalars().all()
        if group_ids:
            groups = {g.id: g.name for g in (await db.execute(
                select(UserGroup).where(UserGroup.id.in_(group_ids)))).scalars()}
            for gs in (await db.execute(select(NotificationSetting).where(
                    NotificationSetting.owner_type == "group", NotificationSetting.owner_id.in_(group_ids)))).scalars():
                if gs.mode == "custom" and gs.owner_id in groups:
                    add(gs, f"グループ: {groups[gs.owner_id]}")
    return list(dests.values())


async def notify_profile_owner(owner_id: str, title: str, body: str, facts: list[tuple[str, str]]) -> dict:
    """認証情報プロファイルの所有者へ、ほかの人の操作（編集・割り当て・引き継ぎなど）を知らせる。

    API の応答を待たせないよう、応答を返したあとに別の DB セッションで送る（失敗しても操作は取り消さない）
    """
    from app.core.database import AsyncSessionLocal  # 循環 import を避けてここで読む

    try:
        async with AsyncSessionLocal() as db:
            dests = await resolve_user_destinations(db, owner_id)
            url = _page_url("/credential-profiles")
            return await _deliver(db, "profile", [
                (d, _message(d.kind, title, facts, url, "認証情報プロファイルを画面で確認", 0xF59E0B, body), None)
                for d in dests
            ], None)
    except Exception:  # noqa: BLE001 - 通知は付加的な処理。失敗しても呼び出し元へ伝えない
        logger.exception("認証情報プロファイルの所有者への通知に失敗しました")
        return {"sent": 0, "failed": 0}


async def wants_any(db: AsyncSession, event: str) -> bool:
    """event を通知する設定が1つでもあるか（無ければ通知のタスクを投入しない）"""
    col = getattr(NotificationSetting, f"on_{event}")
    return (await db.execute(select(NotificationSetting.id).where(
        NotificationSetting.mode == "custom", col.is_(True)).limit(1))).first() is not None


async def send_test(s: NotificationSetting, owner_label: str,
                    cfg: "mail.MailConfig | None" = None) -> dict[str, str | None]:
    """設定されている通知先へテスト通知を送る。{kind: エラー or None}（メールは宛先ごとに "email:<宛先>"）"""
    targets = setting_targets(s)
    results = await asyncio.gather(
        *(asyncio.to_thread(_send, k, url, build_test_payload(k, owner_label), cfg) for k, url in targets)
    )
    await mail.record_last([err for (k, _), err in zip(targets, results, strict=True) if k == "email"])
    return {(f"email:{url}" if k == "email" else k): err for (k, url), err in zip(targets, results, strict=True)}
