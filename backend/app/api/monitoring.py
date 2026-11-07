"""モニタリング（試験導入）の API: SNMP の設定・インタフェースの帯域・FW ルールのヒット数

MONITORING_ENABLED=false（既定）のときはすべて 404 を返す（画面のメニューも出さない）
"""
import math
from datetime import datetime, timedelta
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.device import Device, DeviceGroup
from app.models.monitoring import FwHitStatus, FwRuleHit, IfSample, MonInterface, SnmpSetting
from app.models.user import User
from app.services.audit import Audit, get_audit
from app.services.fw_hits import SUPPORTED as FW_PLATFORMS
from app.services.monitoring import AUTH_PROTOCOLS, PRIV_PROTOCOLS, SnmpError, snmp_get_info, target_of


def require_enabled() -> None:
    if not settings.MONITORING_ENABLED:
        raise HTTPException(status_code=404, detail="モニタリングは無効です（.env の MONITORING_ENABLED=true で有効）")


router = APIRouter(dependencies=[Depends(require_enabled)])

MAX_POINTS = 600  # グラフ1本あたりの点の上限（超える期間はまとめて平均・最大を返す）
NICE_BUCKETS = (600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
UNUSED_DAYS = 30  # この日数より前から一度も使われていないルールを「未使用」とする

Secret = Annotated[str, StringConstraints(max_length=256)]


# ---------------------------------------------------------------- SNMP の設定


class SnmpIn(BaseModel):
    """秘密の値（community・鍵）は None なら変更しない、空文字なら削除する"""

    enabled: bool = True
    version: Literal["2c", "3"] = "2c"
    port: int = Field(default=161, ge=1, le=65535)
    community: Secret | None = None
    v3_user: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] | None = None
    v3_auth_proto: Literal["SHA", "SHA256", "MD5", ""] | None = None
    v3_auth_key: Secret | None = None
    v3_priv_proto: Literal["AES", "AES256", "DES", ""] | None = None
    v3_priv_key: Secret | None = None


class SnmpDevice(BaseModel):
    device_id: str
    name: str
    hostname: str
    platform: str
    group_name: str | None
    via_jump: bool  # 踏み台経由の機器（SNMP は直接届かない）
    configured: bool
    enabled: bool = False
    version: str | None = None
    port: int | None = None
    has_community: bool = False
    v3_user: str | None = None
    v3_auth_proto: str | None = None
    v3_priv_proto: str | None = None
    has_auth_key: bool = False
    has_priv_key: bool = False
    last_polled_at: datetime | None = None
    last_error: str | None = None
    interface_count: int = 0


async def _snmp_rows(db: AsyncSession) -> list[SnmpDevice]:
    devices = (await db.execute(select(Device).order_by(Device.name))).scalars().all()
    settings_map = {s.device_id: s for s in (await db.execute(select(SnmpSetting))).scalars()}
    groups = dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all())
    counts = dict((await db.execute(
        select(MonInterface.device_id, func.count()).group_by(MonInterface.device_id))).all())
    out = []
    for d in devices:
        s = settings_map.get(d.id)
        row = SnmpDevice(device_id=d.id, name=d.name, hostname=d.hostname, platform=d.platform,
                         group_name=groups.get(d.group_id), via_jump=bool(d.jump_host_id), configured=s is not None,
                         interface_count=counts.get(d.id, 0))
        if s is not None:
            row = row.model_copy(update=dict(
                enabled=s.enabled, version=s.version, port=s.port, has_community=bool(s.community),
                v3_user=s.v3_user, v3_auth_proto=s.v3_auth_proto, v3_priv_proto=s.v3_priv_proto,
                has_auth_key=bool(s.v3_auth_key), has_priv_key=bool(s.v3_priv_key),
                last_polled_at=s.last_polled_at, last_error=s.last_error,
            ))
        out.append(row)
    return out


@router.get("/snmp", response_model=list[SnmpDevice], dependencies=[Depends(require(Perm.MONITOR_READ))])
async def list_snmp(db: AsyncSession = Depends(get_db)):
    return await _snmp_rows(db)


@router.put("/snmp/{device_id}", response_model=SnmpDevice, dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def update_snmp(device_id: str, p: SnmpIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    d = await db.get(Device, device_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Device not found")
    s = await db.get(SnmpSetting, device_id)
    if s is None:
        s = SnmpSetting(device_id=device_id)
        db.add(s)
    s.enabled, s.version, s.port = p.enabled, p.version, p.port
    for f in ("community", "v3_auth_key", "v3_priv_key"):
        v = getattr(p, f)
        if v is not None:
            setattr(s, f, v or None)
    if p.v3_user is not None:
        s.v3_user = p.v3_user or None
    if p.v3_auth_proto is not None:
        s.v3_auth_proto = p.v3_auth_proto or None
    if p.v3_priv_proto is not None:
        s.v3_priv_proto = p.v3_priv_proto or None
    # 入力の検証（保存後の値で確認する）
    if s.version == "2c" and not s.community:
        raise HTTPException(status_code=422, detail="SNMP v2c のコミュニティ名を入力してください")
    if s.version == "3":
        if not s.v3_user:
            raise HTTPException(status_code=422, detail="SNMP v3 のユーザー名を入力してください")
        if s.v3_auth_proto and len(s.v3_auth_key or "") < 8:
            raise HTTPException(status_code=422, detail="認証パスワードは8文字以上で入力してください")
        if s.v3_priv_proto and not s.v3_auth_proto:
            raise HTTPException(status_code=422, detail="暗号化（priv）を使う場合は認証（auth）も設定してください")
        if s.v3_priv_proto and len(s.v3_priv_key or "") < 8:
            raise HTTPException(status_code=422, detail="暗号化パスワードは8文字以上で入力してください")
    assert s.v3_auth_proto in (None, *AUTH_PROTOCOLS) and s.v3_priv_proto in (None, *PRIV_PROTOCOLS)
    audit("monitor.snmp_update", target_type="device", target_id=d.id, target_name=d.name,
          detail={"enabled": s.enabled, "version": s.version, "port": s.port,
                  "community": "（変更）" if p.community else None,
                  "v3_auth_key": "（変更）" if p.v3_auth_key else None,
                  "v3_priv_key": "（変更）" if p.v3_priv_key else None})
    await db.commit()
    return next(r for r in await _snmp_rows(db) if r.device_id == device_id)


@router.delete("/snmp/{device_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def delete_snmp(device_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """SNMP の設定と、その機器の帯域の記録を削除する"""
    d = await db.get(Device, device_id)
    s = await db.get(SnmpSetting, device_id)
    if d is None or s is None:
        raise HTTPException(status_code=404, detail="SNMP の設定がありません")
    await delete_device_monitoring(db, device_id, fw=False)
    audit("monitor.snmp_delete", target_type="device", target_id=d.id, target_name=d.name)
    await db.commit()


async def delete_device_monitoring(db: AsyncSession, device_id: str, fw: bool = True) -> None:
    """機器のモニタリングのデータを消す（機器の削除時にも呼ぶ）"""
    ids = select(MonInterface.id).where(MonInterface.device_id == device_id)
    await db.execute(delete(IfSample).where(IfSample.interface_id.in_(ids)))
    await db.execute(delete(MonInterface).where(MonInterface.device_id == device_id))
    await db.execute(delete(SnmpSetting).where(SnmpSetting.device_id == device_id))
    if fw:
        await db.execute(delete(FwRuleHit).where(FwRuleHit.device_id == device_id))
        await db.execute(delete(FwHitStatus).where(FwHitStatus.device_id == device_id))


@router.post("/snmp/{device_id}/test", dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def test_snmp(device_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    """保存済みの設定で sysName / sysDescr を取得してみる"""
    d = await db.get(Device, device_id)
    s = await db.get(SnmpSetting, device_id)
    if d is None or s is None:
        raise HTTPException(status_code=404, detail="SNMP の設定がありません")
    try:
        return await snmp_get_info(target_of(s, d))
    except (SnmpError, OSError) as e:
        raise HTTPException(status_code=422, detail=f"SNMP で応答がありません: {e}") from e


@router.post("/snmp/poll", dependencies=[Depends(require(Perm.COLLECT))])
async def poll_now() -> dict:
    """次の定期取得を待たずに帯域を取得する（2回目からの差分で bps が出る）"""
    from app.worker import poll_snmp  # 循環 import を避ける

    task = poll_snmp.delay()
    return {"task_id": task.id}


# ---------------------------------------------------------------- インタフェース


class InterfaceOut(BaseModel):
    id: str
    device_id: str
    device_name: str
    if_index: int
    name: str
    alias: str | None
    speed_mbps: int | None
    oper_up: bool
    in_bps: float | None
    out_bps: float | None
    in_util: float | None  # 使用率（%）
    out_util: float | None
    last_at: datetime | None


def _util(bps: float | None, speed_mbps: int | None) -> float | None:
    if bps is None or not speed_mbps:
        return None
    return round(bps / (speed_mbps * 1_000_000) * 100, 2)


def _if_out(i: MonInterface, device_name: str) -> InterfaceOut:
    return InterfaceOut(
        id=i.id, device_id=i.device_id, device_name=device_name, if_index=i.if_index, name=i.name, alias=i.alias,
        speed_mbps=i.speed_mbps, oper_up=i.oper_up, in_bps=i.in_bps, out_bps=i.out_bps,
        in_util=_util(i.in_bps, i.speed_mbps), out_util=_util(i.out_bps, i.speed_mbps), last_at=i.last_at,
    )


@router.get("/interfaces", response_model=list[InterfaceOut], dependencies=[Depends(require(Perm.MONITOR_READ))])
async def list_interfaces(device_id: str | None = None, db: AsyncSession = Depends(get_db)):
    q = select(MonInterface, Device.name).join(Device, Device.id == MonInterface.device_id)
    if device_id:
        q = q.where(MonInterface.device_id == device_id)
    rows = (await db.execute(q.order_by(Device.name, MonInterface.if_index))).all()
    return [_if_out(i, name) for i, name in rows]


@router.get("/interfaces/top", response_model=list[InterfaceOut], dependencies=[Depends(require(Perm.MONITOR_READ))])
async def top_interfaces(limit: int = Query(20, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    """直近の使用率が高い順（速度が分かる稼働中のインタフェース）"""
    rows = (await db.execute(
        select(MonInterface, Device.name).join(Device, Device.id == MonInterface.device_id)
        .where(MonInterface.oper_up.is_(True), MonInterface.in_bps.is_not(None))
    )).all()
    items = [_if_out(i, n) for i, n in rows]
    items.sort(key=lambda x: max(x.in_util or 0, x.out_util or 0, 0), reverse=True)
    return items[:limit]


class SamplePoint(BaseModel):
    at: datetime
    in_bps: float
    out_bps: float
    in_max: float | None = None  # まとめたときの最大値
    out_max: float | None = None


class SeriesOut(BaseModel):
    interface: InterfaceOut
    hours: int
    bucket_seconds: int  # 1点あたりの秒数（まとめていなければ取得間隔）
    points: list[SamplePoint]


@router.get("/interfaces/{interface_id}/samples", response_model=SeriesOut,
            dependencies=[Depends(require(Perm.MONITOR_READ))])
async def interface_samples(interface_id: str, hours: int = Query(24, ge=1, le=24 * 400),
                            db: AsyncSession = Depends(get_db)):
    i = await db.get(MonInterface, interface_id)
    if i is None:
        raise HTTPException(status_code=404, detail="インタフェースが見つかりません")
    device = await db.get(Device, i.device_id)
    since = utcnow() - timedelta(hours=hours)
    rows = (await db.execute(
        select(IfSample.at, IfSample.in_bps, IfSample.out_bps)
        .where(IfSample.interface_id == interface_id, IfSample.at >= since).order_by(IfSample.at)
    )).all()
    bucket = settings.MONITOR_INTERVAL_SEC
    if len(rows) <= MAX_POINTS:
        points = [SamplePoint(at=a, in_bps=i_, out_bps=o) for a, i_, o in rows]
    else:
        # 期間を MAX_POINTS 個に区切り、区間ごとの平均と最大を返す
        # 区間の長さは 10分・30分・1時間…のきりのよい値にそろえる（グラフの読み取りやすさのため）
        need = max(bucket, math.ceil(hours * 3600 / MAX_POINTS))
        bucket = next((b for b in NICE_BUCKETS if b >= need), need)
        groups: dict[int, list] = {}
        for a, i_, o in rows:
            groups.setdefault(int((a - since).total_seconds() // bucket), []).append((a, i_, o))
        points = []
        for k in sorted(groups):
            g = groups[k]
            points.append(SamplePoint(
                at=since + timedelta(seconds=k * bucket + bucket / 2),
                in_bps=sum(x[1] for x in g) / len(g), out_bps=sum(x[2] for x in g) / len(g),
                in_max=max(x[1] for x in g), out_max=max(x[2] for x in g),
            ))
    return SeriesOut(interface=_if_out(i, device.name if device else "—"), hours=hours, bucket_seconds=bucket,
                     points=points)


# ---------------------------------------------------------------- FW ルールのヒット数


class FwDevice(BaseModel):
    device_id: str
    name: str
    platform: str
    platform_label: str
    collected_at: datetime | None = None
    success: bool | None = None
    error: str | None = None
    rule_count: int = 0
    unused_count: int = 0  # 未使用のルール（ルール一覧の unused と同じ基準）
    has_raw: bool = False


class FwRuleOut(BaseModel):
    position: int
    rule_id: str | None
    name: str
    hit_count: int | None
    delta: int | None  # 前回の取得からの増加
    delta_hours: float | None  # 前回の取得からの時間
    packets: int | None
    bytes: int | None
    first_hit_at: datetime | None
    last_hit_at: datetime | None
    unused: bool  # 一度も使われていない、または UNUSED_DAYS 日以上使われていない


@router.get("/fw", response_model=list[FwDevice], dependencies=[Depends(require(Perm.MONITOR_READ))])
async def list_fw(db: AsyncSession = Depends(get_db)):
    devices = (await db.execute(select(Device).where(Device.platform.in_(list(FW_PLATFORMS)))
                                .order_by(Device.name))).scalars().all()
    st = {s.device_id: s for s in (await db.execute(select(FwHitStatus))).scalars()}
    # ルール一覧の「未使用」と同じ基準（ヒット 0、または最終ヒットが UNUSED_DAYS 日以上前）で数える
    border = datetime.now(ZoneInfo(settings.TIMEZONE)).replace(tzinfo=None) - timedelta(days=UNUSED_DAYS)
    unused = dict((await db.execute(
        select(FwRuleHit.device_id, func.count())
        .where(or_(FwRuleHit.hit_count == 0, FwRuleHit.last_hit_at < border)).group_by(FwRuleHit.device_id))).all())
    out = []
    for d in devices:
        s = st.get(d.id)
        out.append(FwDevice(
            device_id=d.id, name=d.name, platform=d.platform, platform_label=FW_PLATFORMS[d.platform],
            collected_at=s.collected_at if s else None, success=s.success if s else None, error=s.error if s else None,
            rule_count=s.rule_count if s else 0, unused_count=unused.get(d.id, 0), has_raw=bool(s and s.raw_output),
        ))
    return out


@router.get("/fw/{device_id}/rules", response_model=list[FwRuleOut], dependencies=[Depends(require(Perm.MONITOR_READ))])
async def fw_rules(device_id: str, db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(FwRuleHit).where(FwRuleHit.device_id == device_id)
                             .order_by(FwRuleHit.position))).scalars().all()
    # 機器の時刻（ローカル）で記録された最終ヒットと比べるため、サーバーのタイムゾーンの現在時刻を使う
    now_local = datetime.now(ZoneInfo(settings.TIMEZONE)).replace(tzinfo=None)
    out = []
    for r in rows:
        delta = r.hit_count - r.prev_hit_count if r.hit_count is not None and r.prev_hit_count is not None else None
        if delta is not None and delta < 0:  # ヒット数がリセットされた
            delta = None
        hours = (r.collected_at - r.prev_collected_at).total_seconds() / 3600 if r.prev_collected_at else None
        unused = r.hit_count == 0 or bool(r.last_hit_at and now_local - r.last_hit_at > timedelta(days=UNUSED_DAYS))
        out.append(FwRuleOut(position=r.position, rule_id=r.rule_id, name=r.name, hit_count=r.hit_count, delta=delta,
                             delta_hours=round(hours, 2) if hours is not None else None, packets=r.packets,
                             bytes=r.bytes, first_hit_at=r.first_hit_at, last_hit_at=r.last_hit_at, unused=unused))
    return out


@router.post("/fw/{device_id}/collect")
async def collect_fw(device_id: str, db: AsyncSession = Depends(get_db),
                     user: User = Depends(require(Perm.COLLECT)), audit: Audit = Depends(get_audit)) -> dict:
    d = await db.get(Device, device_id)
    if d is None or d.platform not in FW_PLATFORMS:
        raise HTTPException(status_code=404, detail="ヒット数を取得できる FW ではありません")
    from app.worker import collect_fw_hits_device  # 循環 import を避ける

    task = collect_fw_hits_device.delay(d.id, user.username)
    audit("monitor.fw_collect", target_type="device", target_id=d.id, target_name=d.name, detail={"task_id": task.id})
    await db.commit()
    return {"task_id": task.id}


@router.get("/fw/{device_id}/raw", response_class=PlainTextResponse,
            dependencies=[Depends(require(Perm.DEVICE_WRITE))])
async def fw_raw(device_id: str, db: AsyncSession = Depends(get_db)):
    """直近に取得した生の出力（解析できないときの確認用。管理者のみ）"""
    s = await db.get(FwHitStatus, device_id)
    if s is None or not s.raw_output:
        raise HTTPException(status_code=404, detail="取得した出力がありません")
    return PlainTextResponse(s.raw_output)
