"""コンフィグ変更の通知（Discord / Slack の Webhook）

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


async def resolve_destinations(db: AsyncSession, device_group_id: str | None) -> list[Destination]:
    """指定した機器グループ（None は未分類）の機器が変更されたときの通知先"""
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
            if own.matches(device_group_id):
                add(own, f"ユーザー: {u.username}")
        elif mode == "inherit":
            for gid in memberships.get(u.id, []):
                gs = group_settings.get(gid)
                if gid in groups and gs and gs.mode == "custom" and gs.matches(device_group_id):
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


async def notify_change(db: AsyncSession, device_id: str, commit_hash: str, added: int, removed: int,
                        triggered_by: str) -> dict:
    """コンフィグ変更を通知する（worker から呼ぶ）。結果は通知設定の last_sent_at / last_error に残す"""
    device = await db.get(Device, device_id)
    if device is None:
        return {"sent": 0, "failed": 0}
    group = await db.get(DeviceGroup, device.group_id) if device.group_id else None
    dests = await resolve_destinations(db, device.group_id)
    if not dests:
        return {"sent": 0, "failed": 0}
    ev = ChangeEvent(device.id, device.name, device.hostname, group.name if group else None,
                     added, removed, triggered_by, commit_hash, utcnow())
    results = await asyncio.gather(
        *(asyncio.to_thread(send_webhook, d.kind, d.url, build_payload(d.kind, ev)) for d in dests)
    )
    now = utcnow()
    errors: dict[str, list[str]] = {}
    for d, err in zip(dests, results, strict=True):
        for sid in d.setting_ids:
            if err:
                errors.setdefault(sid, []).append(f"{KIND_LABELS[d.kind]}: {err}")
            else:
                errors.setdefault(sid, [])
        if err:
            logger.warning("変更通知の送信に失敗 device=%s %s: %s", device.name, d.kind, err)
    for sid, errs in errors.items():
        s = await db.get(NotificationSetting, sid)
        if s is not None:
            s.last_sent_at = now
            s.last_error = " / ".join(errs) or None
    await db.commit()
    failed = sum(1 for e in results if e)
    logger.info("変更通知 device=%s 送信=%d 失敗=%d", device.name, len(dests) - failed, failed)
    return {"sent": len(dests) - failed, "failed": failed}


async def send_test(s: NotificationSetting, owner_label: str) -> dict[str, str | None]:
    """設定されている通知先へテスト通知を送る。{kind: エラー or None}"""
    hooks = setting_webhooks(s)
    results = await asyncio.gather(
        *(asyncio.to_thread(send_webhook, k, url, build_test_payload(k, owner_label)) for k, url in hooks.items())
    )
    return dict(zip(hooks.keys(), results, strict=True))
