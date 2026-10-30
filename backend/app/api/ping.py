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
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import authenticate_token, require
from app.core.config import settings
from app.core.database import AsyncSessionLocal, get_db
from app.core.permissions import Perm, has_permission
from app.models.device import Device, DeviceGroup
from app.models.ping import PingTarget
from app.models.user import User
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
    groups = (await db.execute(select(DeviceGroup).order_by(DeviceGroup.name))).scalars().all()
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
    audit("ping.target_delete", target_type="ping_target", target_id=t.id, target_name=t.name,
          detail={"address": t.address})
    await db.commit()


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
    try:
        first = json.loads(await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SEC))
        user = await authenticate_token(str(first.get("token", ""))) if first.get("type") == "auth" else None
    except (TimeoutError, json.JSONDecodeError, AttributeError, WebSocketDisconnect):
        user = None
    if user is None:
        await websocket.close(code=WS_CLOSE_UNAUTHORIZED, reason="unauthorized")
        return
    if not has_permission(user.role, Perm.PING_USE):
        await websocket.close(code=WS_CLOSE_FORBIDDEN, reason="forbidden")
        return

    runner: asyncio.Task | None = None

    async def send(msg: dict) -> None:
        await websocket.send_text(json.dumps(msg, ensure_ascii=False))

    async def run(items: list[dict], interval: float) -> None:
        targets = {it["key"]: it["ip"] for it in items if it.get("ip")}
        ticker = Ticker(interval)
        seq = 0
        try:
            while True:
                seq += 1
                # 応答待ちが間隔を超えないようにする（間隔ごとに必ず1回結果を返す）
                results = await ping_many(targets, timeout=min(settings.PING_TIMEOUT, interval * 0.9))
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
        if runner is not None:
            runner.cancel()
