"""Ping監視 API（deadman 風）

- 対象は「登録済みの機器（hostname 欄のアドレス）」と「ここで追加した IP / ホスト名」
- 結果は WebSocket で一定間隔ごとに送る。統計（損失率・平均など）は画面側で集計する
- 任意のアドレスへ PING できないよう、クライアントは対象のキーだけを送り、アドレスはサーバー側で DB から引く

WebSocket のやりとり（すべて JSON）
  クライアント -> サーバー
    {"type": "auth", "token": "<JWT>"}                          … 接続直後に1回
    {"type": "start", "keys": ["d:<機器ID>", "t:<追加IPのID>"], "interval": 1}
    {"type": "stop"}
  サーバー -> クライアント
    {"type": "targets", "items": [{"key", "name", "address", "ip", "error"}]}
    {"type": "tick", "seq": 1, "results": {"<key>": 1.23 または null}}   … null は応答なし
    {"type": "error", "message": "..."}

無操作のログアウト（services/idle.py）: 監視が動いている間（start から stop・切断・PING の失敗まで）は、
この接続に使ったログインの最後の操作の時刻を進め続ける（同じログインのほかのタブ・API も切れない）。
接続しただけ・止めている間は進めない。時間を過ぎたら idle.watch_ws が切る（close の reason は "idle_timeout"）

常時監視（/monitors）: 画面を開いていなくても worker が一定間隔で PING し、結果を残して応答なし・復旧を通知する
（services/ping_monitor.py）。ここでは対象の登録・解除と、状態・履歴の表示を扱う
"""
import asyncio
import contextlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Literal

import redis
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, StringConstraints, field_validator
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import authenticate_ws, require
from app.api.terminal import _register, _unregister
from app.core.config import settings
from app.core.database import AsyncSessionLocal, get_db
from app.core.permissions import Perm, has_permission
from app.core.security import decode_access_token
from app.core.timeutil import utcnow
from app.models.device import Device, DeviceGroup
from app.models.ping import PingMonitor, PingResult, PingTarget
from app.models.user import User
from app.services import idle
from app.services import ping_monitor as monitor_svc
from app.services.audit import Audit, get_audit
from app.services.ping import PingUnavailable, Ticker, ping_many, resolve, valid_address

logger = logging.getLogger(__name__)
router = APIRouter()
# WebSocket は接続後の最初のメッセージでトークンを検証するため、ログイン必須の依存を付けない別ルーターにする
ws_router = APIRouter()

AUTH_TIMEOUT_SEC = 10
WS_CLOSE_UNAUTHORIZED = 4401
WS_CLOSE_FORBIDDEN = 4403
INTERVALS = (1, 2, 5, 10)


class TargetIn(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    address: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    group_id: str | None = None

    @field_validator("address")
    @classmethod
    def _addr(cls, v: str) -> str:
        if not valid_address(v):
            raise ValueError("IP アドレスまたはホスト名を入力してください")
        return v


class TargetOut(BaseModel):
    key: str
    kind: Literal["device", "custom"]
    id: str
    name: str
    address: str
    group_id: str | None
    description: str | None = None
    is_active: bool = True  # 機器の有効／無効（追加IPは常に True）
    platform: str | None = None
    created_by: str | None = None
    updated_at: datetime | None = None


class GroupOut(BaseModel):
    id: str
    name: str
    color: str | None


class TargetList(BaseModel):
    groups: list[GroupOut]
    targets: list[TargetOut]
    max_targets: int


def _custom_out(t: PingTarget) -> TargetOut:
    return TargetOut(
        key=f"t:{t.id}", kind="custom", id=t.id, name=t.name, address=t.address, group_id=t.group_id,
        description=t.description, created_by=t.created_by, updated_at=t.updated_at,
    )


async def _check_group(db: AsyncSession, group_id: str | None) -> None:
    if group_id and not await db.get(DeviceGroup, group_id):
        raise HTTPException(status_code=422, detail="指定されたグループが存在しません")


async def _get_or_404(db: AsyncSession, target_id: str) -> PingTarget:
    t = await db.get(PingTarget, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="対象が見つかりません")
    return t


@router.get("/targets", response_model=TargetList, dependencies=[Depends(require(Perm.PING_USE))])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """監視できる対象（登録機器と追加IP）とグループ"""
    groups = (await db.execute(select(DeviceGroup).order_by(DeviceGroup.sort_order, DeviceGroup.name))).scalars().all()
    devices = (await db.execute(select(Device).order_by(Device.name))).scalars().all()
    customs = (await db.execute(select(PingTarget).order_by(PingTarget.name))).scalars().all()
    targets = [
        TargetOut(key=f"d:{d.id}", kind="device", id=d.id, name=d.name, address=d.hostname, group_id=d.group_id,
                  description=d.description, is_active=d.is_active, platform=d.platform)
        for d in devices
    ] + [_custom_out(t) for t in customs]
    return TargetList(
        groups=[GroupOut(id=g.id, name=g.name, color=g.color) for g in groups],
        targets=targets,
        max_targets=settings.PING_MAX_TARGETS,
    )


@router.post("/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.PING_WRITE)),
    audit: Audit = Depends(get_audit),
):
    await _check_group(db, payload.group_id)
    t = PingTarget(id=str(uuid.uuid4()), name=payload.name, address=payload.address,
                   description=payload.description or None, group_id=payload.group_id or None,
                   created_by=user.username)
    db.add(t)
    audit("ping.target_create", target_type="ping_target", target_id=t.id, target_name=t.name,
          detail={"address": t.address})
    await db.commit()
    await db.refresh(t)
    return _custom_out(t)


@router.put("/targets/{target_id}", response_model=TargetOut, dependencies=[Depends(require(Perm.PING_WRITE))])
async def update_target(
    target_id: str, payload: TargetIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)
):
    t = await _get_or_404(db, target_id)
    await _check_group(db, payload.group_id)
    audit("ping.target_update", target_type="ping_target", target_id=t.id, target_name=payload.name,
          detail={"address": payload.address} if payload.address != t.address else None)
    t.name = payload.name
    t.address = payload.address
    t.description = payload.description or None
    t.group_id = payload.group_id or None
    await db.commit()
    await db.refresh(t)
    return _custom_out(t)


@router.delete(
    "/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.PING_WRITE))]
)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    t = await _get_or_404(db, target_id)
    await db.delete(t)
    # 常時監視の登録と結果も消す（状態は次の実行で worker が消す）
    await db.execute(sa_delete(PingMonitor).where(PingMonitor.key == f"t:{t.id}"))
    await db.execute(sa_delete(PingResult).where(PingResult.key == f"t:{t.id}"))
    audit("ping.target_delete", target_type="ping_target", target_id=t.id, target_name=t.name,
          detail={"address": t.address})
    await db.commit()


# ---------------------------------------------------------------- 常時監視


class MonitorOut(BaseModel):
    key: str
    name: str
    address: str
    group_id: str | None
    is_active: bool = True  # 機器が無効なら PING しない
    status: Literal["up", "down", "unknown"]
    since: datetime | None = None  # 応答なしになった時刻（最初に応答が無かった時刻）
    fails: int = 0  # 続けて応答が無かった回数
    last_at: datetime | None = None
    last_rtt: float | None = None
    last_ok: datetime | None = None
    sent_24h: int = 0
    received_24h: int = 0
    created_by: str | None = None


class MonitorList(BaseModel):
    items: list[MonitorOut]
    interval_sec: int
    alert_after: int
    history_days: int
    max_targets: int


class MonitorIn(BaseModel):
    monitored: bool


def _redis_state() -> dict[str, dict]:
    try:
        return monitor_svc.load_state(_redis_client())
    except Exception:  # noqa: BLE001 - Redis が使えなくても一覧は出す（状態は「未確認」）
        logger.warning("Ping監視の状態を Redis から読めません", exc_info=True)
        return {}


def _redis_client() -> redis.Redis:
    return redis.Redis.from_url(settings.REDIS_URL)


def _dt(v: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


@router.get("/monitors", response_model=MonitorList, dependencies=[Depends(require(Perm.PING_USE))])
async def list_monitors(db: AsyncSession = Depends(get_db)):
    """常時監視の対象と、いまの状態・直近 24 時間の応答率"""
    items, _ = await monitor_svc.monitored_items(db, include_inactive=True)
    rows = {m.key: m for m in (await db.execute(select(PingMonitor))).scalars()}
    active = {d.id: d.is_active for d in (await db.execute(
        select(Device).where(Device.id.in_([it.device_id for it in items if it.device_id]))
    )).scalars()}
    state = _redis_state()
    avail = await monitor_svc.availability(db, [it.key for it in items], utcnow() - timedelta(hours=24))
    out = []
    for it in sorted(items, key=lambda x: x.name):
        st = state.get(it.key, {})
        # 応答なしと判定するまで（続けて応答が無いのが PING_ALERT_AFTER 回未満）は「応答あり」のまま。回数は fails で出す
        status = "down" if st.get("down") else "up" if st.get("last_ok") else "unknown"
        a = avail.get(it.key, {})
        m = rows.get(it.key)
        out.append(MonitorOut(
            key=it.key, name=it.name, address=it.address, group_id=it.group_id,
            is_active=active.get(it.device_id, True) if it.device_id else True,
            status=status, since=_dt(st.get("since")), fails=st.get("fails", 0), last_at=_dt(st.get("last_at")),
            last_rtt=st.get("last_rtt"), last_ok=_dt(st.get("last_ok")),
            sent_24h=a.get("sent", 0), received_24h=a.get("received", 0), created_by=m.created_by if m else None,
        ))
    return MonitorList(items=out, interval_sec=settings.PING_MONITOR_INTERVAL_SEC, alert_after=settings.PING_ALERT_AFTER,
                       history_days=settings.PING_HISTORY_DAYS, max_targets=settings.PING_MAX_TARGETS)


@router.put("/monitors/{key}", status_code=status.HTTP_204_NO_CONTENT)
async def set_monitor(
    key: str, payload: MonitorIn, db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.PING_WRITE)), audit: Audit = Depends(get_audit),
):
    """常時監視に加える・外す（外すと結果の履歴も消す）"""
    found = await _lookup([key])
    if not found:
        raise HTTPException(status_code=404, detail="対象が見つかりません")
    current = await db.get(PingMonitor, key)
    if payload.monitored and current is None:
        count = (await db.execute(select(func.count()).select_from(PingMonitor))).scalar_one()
        if count >= settings.PING_MAX_TARGETS:
            raise HTTPException(status_code=422, detail=f"常時監視できるのは {settings.PING_MAX_TARGETS} 件までです")
        db.add(PingMonitor(key=key, created_by=user.username))
        audit("ping.monitor_on", target_type="ping_target", target_id=key, target_name=found[0]["name"],
              detail={"address": found[0]["address"]})
    elif not payload.monitored and current is not None:
        await db.delete(current)
        await db.execute(sa_delete(PingResult).where(PingResult.key == key))
        try:
            _redis_client().hdel(monitor_svc.STATE_KEY, key)
        except Exception:  # noqa: BLE001 - 状態は次の実行で消える
            pass
        audit("ping.monitor_off", target_type="ping_target", target_id=key, target_name=found[0]["name"],
              detail={"address": found[0]["address"]})
    await db.commit()


@router.get("/monitors/{key}/history", dependencies=[Depends(require(Perm.PING_USE))])
async def monitor_history(key: str, hours: int = Query(24, ge=1, le=24 * 365), db: AsyncSession = Depends(get_db)):
    """常時監視の結果を時間で区切って返す（区切りごとの回数・応答なし・平均と最大の応答時間）"""
    if await db.get(PingMonitor, key) is None:
        raise HTTPException(status_code=404, detail="常時監視の対象ではありません")
    hours = min(hours, settings.PING_HISTORY_DAYS * 24)
    until = utcnow()
    since = until - timedelta(hours=hours)
    n = min(144, max(12, hours * 3600 // settings.PING_MONITOR_INTERVAL_SEC))
    buckets = await monitor_svc.history(db, key, since, until, buckets=n)
    sent = sum(b["sent"] for b in buckets)
    lost = sum(b["lost"] for b in buckets)
    return {"key": key, "hours": hours, "since": since.isoformat(), "until": until.isoformat(),
            "sent": sent, "lost": lost, "buckets": buckets}


# ---------------------------------------------------------------- WebSocket


async def _lookup(keys: list[str]) -> list[dict]:
    """キーからアドレスを引く（存在しないキーは無視）"""
    dev_ids = [k[2:] for k in keys if k.startswith("d:")]
    tgt_ids = [k[2:] for k in keys if k.startswith("t:")]
    found: dict[str, dict] = {}
    async with AsyncSessionLocal() as db:
        if dev_ids:
            for d in (await db.execute(select(Device).where(Device.id.in_(dev_ids)))).scalars():
                found[f"d:{d.id}"] = {"key": f"d:{d.id}", "name": d.name, "address": d.hostname}
        if tgt_ids:
            for t in (await db.execute(select(PingTarget).where(PingTarget.id.in_(tgt_ids)))).scalars():
                found[f"t:{t.id}"] = {"key": f"t:{t.id}", "name": t.name, "address": t.address}
    return [found[k] for k in keys if k in found]


async def _resolve_all(items: list[dict]) -> None:
    async def one(it: dict) -> None:
        try:
            it["ip"] = await resolve(it["address"])
            it["error"] = None
        except ValueError as e:
            it["ip"] = None
            it["error"] = str(e)

    await asyncio.gather(*(one(it) for it in items))


@ws_router.websocket("/ws")
async def ping_ws(websocket: WebSocket):
    await websocket.accept()
    ip = websocket.client.host if websocket.client else None
    why = "unauthorized"
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SEC))
        user, why = (await authenticate_ws(str(first.get("token", "")), ip)) if first.get("type") == "auth" \
            else (None, why)
    except (TimeoutError, json.JSONDecodeError, AttributeError, WebSocketDisconnect):
        user = None
    if user is None:
        # 認証の前に相手が切断していると、close は送れない（例外のログを残さない）
        with contextlib.suppress(RuntimeError, WebSocketDisconnect):
            await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason=why)
        return
    if not has_permission(user.role, Perm.PING_USE):
        await websocket.close(code=WS_CLOSE_FORBIDDEN, reason="forbidden")
        return
    # ターミナルと同じく、強制ログアウト・無効化・パスワードの変更・本人のログアウトなどで切れるよう登録する（#29）
    token = str(first.get("token", ""))
    live = _register(user.id, websocket, "ping", token)
    # 無操作の時間を、要求が来なくても確かめる（監視が動いている間は下の run が時刻を進めるので切れない）
    watcher = asyncio.create_task(idle.watch_ws(user, token, ip))
    claims = decode_access_token(token) or {}

    runner: asyncio.Task | None = None

    async def send(msg: dict) -> None:
        await websocket.send_text(json.dumps(msg, ensure_ascii=False))

    async def run(items: list[dict], interval: float) -> None:
        targets = {it["key"]: it["ip"] for it in items if it.get("ip")}
        ticker = Ticker(interval)
        seq = 0
        touched = None  # 最後に無操作の時刻を進めた時刻（loop.time()）
        loop = asyncio.get_running_loop()
        try:
            while True:
                seq += 1
                # 応答待ちが間隔を超えないようにする（間隔ごとに必ず1回結果を返す）
                results = await ping_many(targets, timeout=min(settings.PING_TIMEOUT, interval * 0.9))
                # 監視が動いている間は、無操作でログアウトしない（PING_TOUCH_SEC ごとに時刻を進める）。
                # 実際に PING を送る対象が無い（0 件・すべて名前解決できない）ときは進めない。
                # 時間を過ぎていれば（止めていた間に過ぎた、など）書かずに監視を止め、接続を切る（touch の後始末）
                if targets and (touched is None or loop.time() - touched >= idle.PING_TOUCH_SEC):
                    touched = loop.time()
                    if not await idle.touch(user, token, claims, ip):
                        await idle.close_token_sessions(user.id, token)
                        return
                await send({"type": "tick", "seq": seq, "results": results})
                await ticker.wait()
        except PingUnavailable as e:
            await send({"type": "error", "message": str(e)})
        except (WebSocketDisconnect, RuntimeError):
            pass

    try:
        while True:
            try:
                msg = json.loads(await websocket.receive_text())
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("type") in ("start", "stop") and runner is not None:
                runner.cancel()
                runner = None
            if msg.get("type") != "start":
                continue
            keys = [str(k) for k in msg.get("keys", []) if isinstance(k, str)][: settings.PING_MAX_TARGETS]
            interval = msg.get("interval", 1)
            interval = interval if interval in INTERVALS else 1
            items = await _lookup(list(dict.fromkeys(keys)))
            await _resolve_all(items)
            await send({"type": "targets", "items": items})
            logger.info("Ping監視 開始 user=%s targets=%d interval=%ss", user.username, len(items), interval)
            runner = asyncio.create_task(run(items, float(interval)))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        watcher.cancel()
        _unregister(user.id, live)
        if runner is not None:
            runner.cancel()
