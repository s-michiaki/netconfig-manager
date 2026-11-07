"""通知（Discord / Slack の Webhook）: コンフィグの変更・コンプライアンス違反の発生・収集の失敗

通知する内容は通知設定ごとに選ぶ（on_change / on_violation / on_failure）。

通知先の決め方（機器のコンフィグに変更があったとき）
  有効なユーザーごとに:
    - 個別設定（custom）: 自分の通知先へ。対象の機器グループに含まれるときだけ
    - グループの設定を使う（inherit・設定なし）: 所属する各ユーザーグループの設定（有効なもの）で、
      対象に含まれるものの通知先へ
    - 通知しない（off）: 何もしない
  同じ Webhook URL は1回だけ送る（グループの Webhook はメンバーが何人いても1回）。
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
from app.services.activity import record as record_activity

logger = logging.getLogger(__name__)

KINDS = ("discord", "slack")
KIND_LABELS = {"discord": "Discord", "slack": "Slack"}
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
EVENTS = ("change", "violation", "failure")
EVENT_LABELS = {"change": "変更通知", "violation": "違反の通知", "failure": "収集失敗の通知"}
SENT_MESSAGES = {"change": "変更を通知しました", "violation": "コンプライアンス違反を通知しました",
                 "failure": "収集の失敗を通知しました"}
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


# ---------------------------------------------------------------- 通知先の決定


@dataclass
class Destination:
    kind: str
    url: str
    setting_ids: set[str] = field(default_factory=set)  # この宛先を設定している通知設定（送信結果の記録用）
    via: set[str] = field(default_factory=set)  # 誰の設定で送るか（「ユーザー: xx」「グループ: yy」）


async def resolve_destinations(db: AsyncSession, device_group_id: str | None,
                               event: str = "change") -> list[Destination]:
    """指定した機器グループ（None は未分類）の機器で event（change / violation / failure）が起きたときの通知先"""
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
        for kind, url in setting_webhooks(s).items():
            d = dests.setdefault((kind, url), Destination(kind, url))
            d.setting_ids.add(s.id)
            d.via.add(label)

    for u in users:
        own = user_settings.get(u.id)
        mode = own.mode if own else "inherit"
        if mode == "custom":
            if own.matches(device_group_id) and own.wants(event):
                add(own, f"ユーザー: {u.username}")
        elif mode == "inherit":
            for gid in memberships.get(u.id, []):
                gs = group_settings.get(gid)
                if gid in groups and gs and gs.mode == "custom" and gs.matches(device_group_id) and gs.wants(event):
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
    results = await asyncio.gather(
        *(asyncio.to_thread(send_webhook, d.kind, d.url, payload) for d, payload, _ in sends)
    )
    now = utcnow()
    errors: dict[str, list[str]] = {}
    label = EVENT_LABELS[event]
    for (d, _, device), err in zip(sends, results, strict=True):
        for sid in d.setting_ids:
            errors.setdefault(sid, [])
            if err:
                errors[sid].append(f"{KIND_LABELS[d.kind]}: {err}")
        # 送信先の URL（秘密）は残さず、種類と誰の設定かだけ記録する
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
    """Discord（埋め込み）/ Slack（テキスト）の通知を組み立てる"""
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


async def wants_any(db: AsyncSession, event: str) -> bool:
    """event を通知する設定が1つでもあるか（無ければ通知のタスクを投入しない）"""
    col = getattr(NotificationSetting, f"on_{event}")
    return (await db.execute(select(NotificationSetting.id).where(
        NotificationSetting.mode == "custom", col.is_(True)).limit(1))).first() is not None


async def send_test(s: NotificationSetting, owner_label: str) -> dict[str, str | None]:
    """設定されている通知先へテスト通知を送る。{kind: エラー or None}"""
    hooks = setting_webhooks(s)
    results = await asyncio.gather(
        *(asyncio.to_thread(send_webhook, k, url, build_test_payload(k, owner_label)) for k, url in hooks.items())
    )
    return dict(zip(hooks.keys(), results, strict=True))
