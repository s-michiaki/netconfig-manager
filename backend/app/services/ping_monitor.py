"""Ping監視の常時監視（worker が PING_MONITOR_INTERVAL_SEC ごとに実行する）

- 対象は ping_monitors に登録したもの（登録機器 d:<ID> / 追加IP t:<ID>）。無効の機器は PING しない
- 1 回ごとの結果（応答時間・応答なし）を ping_results に残す（PING_HISTORY_DAYS で削除）
- 状態（連続して応答が無かった回数・応答なしになった時刻）は Redis に持つ。
  PING_ALERT_AFTER 回続けて応答が無ければ「応答なし」、応答が戻れば「復旧」として、アクティビティに残し通知する
  （1 回の取りこぼしで通知しないため。復旧は 1 回の応答で判定する）
- 応答なし・復旧は 1 回の実行ごとにまとめて通知する（ネットワーク障害で多数が同時に落ちても 1 通にする）
"""
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.device import Device
from app.models.ping import PingMonitor, PingResult, PingTarget
from app.services.activity import record
from app.services.ping import ping_many, resolve

logger = logging.getLogger(__name__)

STATE_KEY = "netconfig:ping:state"  # Redis のハッシュ（キー: 対象のキー、値: JSON）


@dataclass
class Item:
    key: str
    name: str
    address: str
    group_id: str | None
    device_id: str | None = None


async def monitored_items(db: AsyncSession, include_inactive: bool = False) -> tuple[list[Item], list[str]]:
    """常時監視の対象。戻り値は (対象, 対象が削除されて残っているキー)"""
    keys = list((await db.execute(select(PingMonitor.key))).scalars())
    dev_ids = [k[2:] for k in keys if k.startswith("d:")]
    tgt_ids = [k[2:] for k in keys if k.startswith("t:")]
    found: dict[str, Item] = {}
    if dev_ids:
        for d in (await db.execute(select(Device).where(Device.id.in_(dev_ids)))).scalars():
            if d.is_active or include_inactive:
                found[f"d:{d.id}"] = Item(f"d:{d.id}", d.name, d.hostname, d.group_id, d.id)
            else:
                found.setdefault(f"d:{d.id}", None)  # 無効の機器: 対象には残すが PING しない
    if tgt_ids:
        for t in (await db.execute(select(PingTarget).where(PingTarget.id.in_(tgt_ids)))).scalars():
            found[f"t:{t.id}"] = Item(f"t:{t.id}", t.name, t.address, t.group_id)
    gone = [k for k in keys if k not in found]
    return [it for it in found.values() if it is not None], gone


def load_state(r) -> dict[str, dict]:
    raw = r.hgetall(STATE_KEY) or {}
    out = {}
    for k, v in raw.items():
        try:
            out[k.decode() if isinstance(k, bytes) else k] = json.loads(v)
        except (ValueError, TypeError):
            continue
    return out


def _iso(dt: datetime) -> str:
    return dt.isoformat()


async def run_once(db: AsyncSession, r, now: datetime | None = None) -> dict:
    """1 回分。戻り値は {"checked", "down": [...], "up": [...]}（down / up は通知に使う）"""
    now = now or utcnow()
    items, gone = await monitored_items(db)
    if gone:
        await db.execute(delete(PingMonitor).where(PingMonitor.key.in_(gone)))
        r.hdel(STATE_KEY, *gone)
    if not items:
        await db.commit()
        return {"checked": 0, "down": [], "up": []}

    ips: dict[str, str] = {}
    for it in items:
        try:
            ips[it.key] = await resolve(it.address)
        except ValueError:
            pass  # 名前解決できない → 応答なし扱い
    # 応答待ちは間隔より短く（次の実行と重ならないように）
    rtts = await ping_many(ips, timeout=min(settings.PING_TIMEOUT, settings.PING_MONITOR_INTERVAL_SEC / 4))
    state = load_state(r)
    down, up, new_state = [], [], {}
    for it in items:
        rtt = rtts.get(it.key)
        db.add(PingResult(key=it.key, at=now, rtt=rtt))
        st = state.get(it.key, {})
        info = {"key": it.key, "name": it.name, "address": it.address, "group_id": it.group_id,
                "device_id": it.device_id}
        if rtt is None:
            fails = st.get("fails", 0) + 1
            first_fail = st.get("first_fail") or _iso(now)
            is_down = st.get("down", False)
            if not is_down and fails >= settings.PING_ALERT_AFTER:
                is_down = True
                down.append({**info, "since": first_fail})
            new_state[it.key] = {"fails": fails, "first_fail": first_fail, "down": is_down,
                                 "since": first_fail if is_down else None, "last_at": _iso(now), "last_rtt": None,
                                 "last_ok": st.get("last_ok")}
        else:
            if st.get("down"):
                up.append({**info, "since": st.get("since")})
            new_state[it.key] = {"fails": 0, "first_fail": None, "down": False, "since": None,
                                 "last_at": _iso(now), "last_rtt": rtt, "last_ok": _iso(now)}
    pipe = r.pipeline()
    for k, v in new_state.items():
        pipe.hset(STATE_KEY, k, json.dumps(v))
    pipe.execute()

    for d in down:
        record(db, "ping.down", f"Ping監視: {d['name']}（{d['address']}）が {settings.PING_ALERT_AFTER} 回続けて応答しません",
               level="error", detail={"key": d["key"], "address": d["address"], "since": d["since"]},
               device_id=d["device_id"], device_name=d["name"] if d["device_id"] else None)
    for u in up:
        span = _span(u.get("since"), now)
        record(db, "ping.up", f"Ping監視: {u['name']}（{u['address']}）の応答が戻りました" + (f"（約 {span}）" if span else ""),
               detail={"key": u["key"], "address": u["address"], "since": u.get("since")},
               device_id=u["device_id"], device_name=u["name"] if u["device_id"] else None)
    await db.commit()
    return {"checked": len(items), "down": down, "up": up}


def _span(since: str | None, now: datetime) -> str:
    """応答なしだった時間の目安（「12 分」「3 時間 5 分」）"""
    if not since:
        return ""
    try:
        sec = int((now - datetime.fromisoformat(since)).total_seconds())
    except ValueError:
        return ""
    if sec < 60:
        return f"{max(sec, 0)} 秒"
    m = sec // 60
    return f"{m // 60} 時間 {m % 60} 分" if m >= 60 else f"{m} 分"


async def availability(db: AsyncSession, keys: list[str], since: datetime) -> dict[str, dict]:
    """期間内の PING の回数と応答なしの回数（対象ごと）"""
    if not keys:
        return {}
    rows = await db.execute(
        select(PingResult.key, func.count(), func.count(PingResult.rtt))
        .where(PingResult.key.in_(keys), PingResult.at >= since).group_by(PingResult.key)
    )
    return {k: {"sent": total, "received": ok} for k, total, ok in rows}


async def history(db: AsyncSession, key: str, since: datetime, until: datetime, buckets: int = 144) -> list[dict]:
    """期間を buckets 個に区切って、区切りごとの回数・応答なし・平均・最大の応答時間を返す"""
    rows = (await db.execute(
        select(PingResult.at, PingResult.rtt).where(PingResult.key == key, PingResult.at >= since, PingResult.at < until)
        .order_by(PingResult.at)
    )).all()
    width = (until - since) / buckets
    out = [{"at": since + width * i, "sent": 0, "lost": 0, "sum": 0.0, "max": None} for i in range(buckets)]
    for at, rtt in rows:
        b = out[min(buckets - 1, int((at - since) / width))]
        b["sent"] += 1
        if rtt is None:
            b["lost"] += 1
        else:
            b["sum"] += rtt
            b["max"] = rtt if b["max"] is None else max(b["max"], rtt)
    return [{"at": b["at"].isoformat(), "sent": b["sent"], "lost": b["lost"],
             "avg": round(b["sum"] / (b["sent"] - b["lost"]), 2) if b["sent"] > b["lost"] else None,
             "max": b["max"]} for b in out]


async def purge(db: AsyncSession, now: datetime | None = None) -> int:
    cutoff = (now or utcnow()) - timedelta(days=settings.PING_HISTORY_DAYS)
    res = await db.execute(delete(PingResult).where(PingResult.at < cutoff))
    return res.rowcount or 0
