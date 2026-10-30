"""構成図（トポロジー）API

構成図は複数作成できる。1つの構成図の配置・接続線は TopologyData として丸ごと保存する。
- 機器ノード: 登録済みデバイスを参照（device_id）。収集状態を色で表示するため、状態も返す
- 非管理機器ノード（unmanaged）: 登録していない機器（ISPルーター・ハブ・PC など）。名前・補足は自由入力
- 装飾ノード: 雲（cloud）・テキスト（text）・グループ枠（group）
- 保存は楽観ロック（version）。他の人が先に保存していたら 409 を返す
"""
import json
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import CollectLog, ConfigSnapshot, Device, JumpHost
from app.models.topology import EMPTY_TOPOLOGY, TopologyMap
from app.models.user import User

router = APIRouter()

MAX_NODES = 1000
MAX_EDGES = 3000

ElementId = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]
Coord = Annotated[float, Field(ge=-1_000_000, le=1_000_000)]
Size = Annotated[float, Field(ge=10, le=10_000)]
Color = Annotated[str, StringConstraints(pattern=r"^#[0-9a-fA-F]{6}$")]
Label = Annotated[str, StringConstraints(max_length=500)]
Port = Annotated[str, StringConstraints(max_length=64)]
MapName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]


class TopologyNode(BaseModel):
    id: ElementId
    type: Literal["device", "unmanaged", "cloud", "text", "group"]
    x: Coord
    y: Coord
    w: Size | None = None  # 雲・テキスト・グループ枠の大きさ（機器ノードは固定）
    h: Size | None = None
    device_id: str | None = None  # type=device のときのみ
    label: Label | None = None  # 非管理機器の名前・装飾ノードの文字（機器ノードは登録済みの機器名を表示）
    note: Annotated[str, StringConstraints(max_length=200)] | None = None  # 非管理機器の補足（IP・型番など）
    color: Color | None = None
    font_size: Literal["s", "m", "l", "xl"] | None = None  # テキスト用
    # 機器アイコン（未指定なら、機器ノードはプラットフォームから自動: PAN-OS → firewall, JunOS → router,
    # 他 → switch。非管理機器ノードは other）
    icon: Literal[
        "switch", "l3switch", "router", "firewall", "server", "wireless",
        "pc", "printer", "phone", "camera", "storage", "other",
    ] | None = None


class TopologyEdge(BaseModel):
    id: ElementId
    source: ElementId
    target: ElementId
    source_port: Port | None = None
    target_port: Port | None = None
    label: Label | None = None
    color: Color | None = None
    line_style: Literal["solid", "dashed"] | None = None


class Viewport(BaseModel):
    x: Coord = 0
    y: Coord = 0
    zoom: Annotated[float, Field(ge=0.05, le=8)] = 1


class TopologyData(BaseModel):
    nodes: list[TopologyNode] = Field(default_factory=list, max_length=MAX_NODES)
    edges: list[TopologyEdge] = Field(default_factory=list, max_length=MAX_EDGES)
    viewport: Viewport | None = None  # 最後に保存したときの表示位置

    @model_validator(mode="after")
    def _check_refs(self):
        ids = [n.id for n in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("ノードIDが重複しています")
        edge_ids = [e.id for e in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("接続線IDが重複しています")
        devices = [n.device_id for n in self.nodes if n.type == "device"]
        if any(not d for d in devices):
            raise ValueError("機器ノードには device_id が必要です")
        if len(devices) != len(set(devices)):
            raise ValueError("同じ機器を1つの構成図に複数配置することはできません")
        known = set(ids)
        for e in self.edges:
            if e.source not in known or e.target not in known:
                raise ValueError("接続線の端が存在しないノードを指しています")
            if e.source == e.target:
                raise ValueError("同じノード同士は接続できません")
        return self


class DeviceStatus(BaseModel):
    id: str
    name: str
    hostname: str
    platform: str
    is_active: bool
    jump_host_name: str | None = None
    # ok: 前回収集成功（変更なし） / changed: 前回収集で変更あり / failed: 前回収集失敗 / never: 未収集
    status: Literal["ok", "changed", "failed", "never"]
    last_collected_at: datetime | None = None
    last_message: str | None = None


class MapSummary(BaseModel):
    id: str
    name: str
    description: str | None
    version: int
    node_count: int
    device_count: int
    updated_at: datetime | None
    updated_by: str | None


class MapDetail(BaseModel):
    id: str
    name: str
    description: str | None
    version: int
    updated_at: datetime | None
    updated_by: str | None
    data: TopologyData
    devices: dict[str, DeviceStatus]  # device_id → 状態（この構成図に置かれた機器のみ）


class MapCreate(BaseModel):
    name: MapName
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    copy_from: str | None = None  # 既存の構成図を複製して作る場合、その ID


class MapUpdate(BaseModel):
    version: int  # 読み込んだときの version（楽観ロック）
    name: MapName | None = None
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    data: TopologyData | None = None


# ---------------------------------------------------------------- helpers


def _load_data(m: TopologyMap) -> TopologyData:
    try:
        return TopologyData.model_validate(json.loads(m.data or EMPTY_TOPOLOGY))
    except (ValueError, TypeError):
        return TopologyData()


def _prune(data: TopologyData, existing_device_ids: set[str]) -> TopologyData:
    """削除済みの機器のノードと、それにつながる接続線を取り除く"""
    nodes = [n for n in data.nodes if n.type != "device" or n.device_id in existing_device_ids]
    keep = {n.id for n in nodes}
    edges = [e for e in data.edges if e.source in keep and e.target in keep]
    return TopologyData(nodes=nodes, edges=edges, viewport=data.viewport)


async def _existing_devices(db: AsyncSession, ids: set[str]) -> set[str]:
    if not ids:
        return set()
    return set((await db.execute(select(Device.id).where(Device.id.in_(ids)))).scalars().all())


async def device_statuses(db: AsyncSession, ids: set[str]) -> dict[str, DeviceStatus]:
    """機器ごとの最新の収集状態"""
    if not ids:
        return {}
    devices = (await db.execute(select(Device).where(Device.id.in_(ids)))).scalars().all()
    jump_names = dict((await db.execute(select(JumpHost.id, JumpHost.name))).all())

    latest_log_at = (
        select(CollectLog.device_id, func.max(CollectLog.started_at).label("at"))
        .where(CollectLog.device_id.in_(ids))
        .group_by(CollectLog.device_id)
        .subquery()
    )
    logs = (
        await db.execute(
            select(CollectLog).join(
                latest_log_at,
                (CollectLog.device_id == latest_log_at.c.device_id) & (CollectLog.started_at == latest_log_at.c.at),
            )
        )
    ).scalars().all()
    last_log = {log.device_id: log for log in logs}
    last_snapshot = dict(
        (
            await db.execute(
                select(ConfigSnapshot.device_id, func.max(ConfigSnapshot.collected_at))
                .where(ConfigSnapshot.device_id.in_(ids))
                .group_by(ConfigSnapshot.device_id)
            )
        ).all()
    )

    result: dict[str, DeviceStatus] = {}
    for d in devices:
        log = last_log.get(d.id)
        if log is None:
            state = "never"
        elif log.status != "success":
            state = "failed"
        else:
            snap = last_snapshot.get(d.id)
            # 最後の収集で新しい世代が作られていれば「変更あり」
            state = "changed" if snap is not None and snap >= log.started_at else "ok"
        result[d.id] = DeviceStatus(
            id=d.id,
            name=d.name,
            hostname=d.hostname,
            platform=d.platform,
            is_active=d.is_active,
            jump_host_name=jump_names.get(d.jump_host_id) if d.jump_host_id else None,
            status=state,
            last_collected_at=(log.finished_at or log.started_at) if log else None,
            last_message=log.message if log else None,
        )
    return result


async def _detail(db: AsyncSession, m: TopologyMap) -> MapDetail:
    data = _load_data(m)
    ids = {n.device_id for n in data.nodes if n.device_id}
    statuses = await device_statuses(db, ids)
    data = _prune(data, set(statuses))
    return MapDetail(
        id=m.id,
        name=m.name,
        description=m.description,
        version=m.version,
        updated_at=m.updated_at,
        updated_by=m.updated_by,
        data=data,
        devices=statuses,
    )


async def _get_or_404(db: AsyncSession, map_id: str) -> TopologyMap:
    m = await db.get(TopologyMap, map_id)
    if m is None:
        raise HTTPException(status_code=404, detail="構成図が見つかりません")
    return m


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前の構成図が既にあります") from e


# ---------------------------------------------------------------- routes


@router.get("/maps", response_model=list[MapSummary], dependencies=[Depends(require(Perm.TOPOLOGY_READ))])
async def list_maps(db: AsyncSession = Depends(get_db)):
    maps = (await db.execute(select(TopologyMap).order_by(TopologyMap.name))).scalars().all()
    result = []
    for m in maps:
        data = _load_data(m)
        result.append(
            MapSummary(
                id=m.id,
                name=m.name,
                description=m.description,
                version=m.version,
                node_count=len(data.nodes),
                device_count=sum(1 for n in data.nodes if n.type == "device"),
                updated_at=m.updated_at,
                updated_by=m.updated_by,
            )
        )
    return result


@router.post("/maps", response_model=MapDetail, status_code=status.HTTP_201_CREATED)
async def create_map(
    payload: MapCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.TOPOLOGY_WRITE)),
):
    data = EMPTY_TOPOLOGY
    if payload.copy_from:
        data = (await _get_or_404(db, payload.copy_from)).data
    m = TopologyMap(name=payload.name, description=payload.description or None, data=data, updated_by=user.username)
    db.add(m)
    await _commit_or_409(db)
    await db.refresh(m)
    return await _detail(db, m)


@router.get("/maps/{map_id}", response_model=MapDetail, dependencies=[Depends(require(Perm.TOPOLOGY_READ))])
async def get_map(map_id: str, db: AsyncSession = Depends(get_db)):
    return await _detail(db, await _get_or_404(db, map_id))


@router.get(
    "/maps/{map_id}/status",
    response_model=dict[str, DeviceStatus],
    dependencies=[Depends(require(Perm.TOPOLOGY_READ))],
)
async def get_map_status(map_id: str, db: AsyncSession = Depends(get_db)):
    """配置済み機器の収集状態だけを返す（編集中の画面を上書きせずに状態を更新するため）"""
    data = _load_data(await _get_or_404(db, map_id))
    return await device_statuses(db, {n.device_id for n in data.nodes if n.device_id})


@router.post(
    "/device-status",
    response_model=dict[str, DeviceStatus],
    dependencies=[Depends(require(Perm.TOPOLOGY_READ))],
)
async def get_device_status(device_ids: Annotated[list[str], Field(max_length=MAX_NODES)], db: AsyncSession = Depends(get_db)):
    """指定した機器の収集状態（編集中に追加した、まだ保存していない機器の状態表示用）"""
    return await device_statuses(db, set(device_ids))


@router.put("/maps/{map_id}", response_model=MapDetail)
async def update_map(
    map_id: str,
    payload: MapUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.TOPOLOGY_WRITE)),
):
    m = await _get_or_404(db, map_id)
    if payload.version != m.version:
        raise HTTPException(
            status_code=409,
            detail=f"他のユーザー（{m.updated_by or '不明'}）が先にこの構成図を保存しています。"
            "再読み込みしてから編集し直してください",
        )
    fields = payload.model_fields_set
    if "name" in fields and payload.name:
        m.name = payload.name
    if "description" in fields:
        m.description = payload.description or None
    if payload.data is not None:
        data = payload.data
        ids = {n.device_id for n in data.nodes if n.device_id}
        data = _prune(data, await _existing_devices(db, ids))  # 編集中に削除された機器は落とす
        m.data = data.model_dump_json(exclude_none=True)
    m.version += 1
    m.updated_by = user.username
    await _commit_or_409(db)
    await db.refresh(m)
    return await _detail(db, m)


@router.delete(
    "/maps/{map_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require(Perm.TOPOLOGY_WRITE))]
)
async def delete_map(map_id: str, db: AsyncSession = Depends(get_db)):
    await db.delete(await _get_or_404(db, map_id))
    await db.commit()
