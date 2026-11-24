"""基準の世代（ベースライン）: 機器ごとに「承認済みの状態」の世代を指定し、最新のコンフィグとのずれを見る

指定・解除は config:review（オペレーター以上）、閲覧は config:read。
ずれは保存した値（services/baseline.py が基準の指定時と収集で世代が増えたときに計算）を返す。
基準に指定できるのは、その機器に実在する世代だけ（最初の世代も指定できる）。
"""
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.exc import StaleDataError

from app.api.config_reviews import iso_utc
from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.device import ConfigBaseline, ConfigSnapshot, Device, DeviceGroup
from app.services.audit import Audit, get_audit
from app.services.baseline import apply_drift, compute_drift_stable, drift_total, is_unknown
from app.services.config_service import head_commit_hash, resolve_commit_info

router = APIRouter()

MAX_NOTE_LENGTH = 200
CONFLICT_MESSAGE = "同じ機器の基準が同時に変更されました。画面を開き直してください"

Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=MAX_NOTE_LENGTH)]


# "latest" は、サーバーが実際の最新の世代（HEAD）を解決して指定する（画面が持っている値に頼らない）
LATEST = "latest"


class BaselineBody(BaseModel):
    commit_hash: Annotated[str, StringConstraints(pattern=rf"^(?:{LATEST}|[0-9a-fA-F]{{7,40}})$")]
    note: Note | None = None


def state_of(row: ConfigBaseline | None) -> str:
    """none（基準なし）/ unknown（ずれが未計算）/ drift（ずれあり）/ ok（ずれなし）"""
    if row is None:
        return "none"
    if is_unknown(row):
        return "unknown"
    return "drift" if drift_total(row) > 0 else "ok"


def baseline_dict(row: ConfigBaseline) -> dict:
    """画面に返す基準とずれ"""
    return {
        "commit_hash": row.commit_hash, "hash": row.commit_hash[:8], "note": row.note,
        "set_by": row.set_by, "set_at": iso_utc(row.set_at),
        "drift_added": row.drift_added, "drift_removed": row.drift_removed,
        "latest_hash": row.latest_hash, "latest": row.latest_hash[:8] if row.latest_hash else None,
        "checked_at": iso_utc(row.checked_at),
    }


async def count_baselines(db: AsyncSession) -> dict:
    """ダッシュボード用: 基準を指定した機器の数と、ずれている機器の数"""
    rows = (await db.execute(select(ConfigBaseline))).scalars().all()
    return {"total": len(rows), "drift": sum(1 for r in rows if drift_total(r) > 0),
            "unknown": sum(1 for r in rows if is_unknown(r))}


@router.get("/baselines", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def list_baselines(
    state: Literal["drift", "ok", "unknown", "none", "all"] = "drift",
    group_id: str | None = Query(None, max_length=36),
    db: AsyncSession = Depends(get_db),
):
    """機器ごとの基準とずれ。基準の無い機器も state=none で返す。ずれの大きい順（その次は機器名）"""
    q = select(Device, ConfigBaseline).outerjoin(ConfigBaseline, ConfigBaseline.device_id == Device.id)
    if group_id:
        q = q.where(Device.group_id == group_id)
    rows = (await db.execute(q)).all()
    groups = dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all())
    # 基準の世代を収集した日時（config_snapshots に行があるものだけ）
    snap_at: dict[tuple[str, str], datetime] = {}
    wanted = {(d.id, b.commit_hash) for d, b in rows if b is not None}
    if wanted:
        found = await db.execute(select(ConfigSnapshot.device_id, ConfigSnapshot.commit_hash, ConfigSnapshot.collected_at)
                                 .where(ConfigSnapshot.device_id.in_({d for d, _ in wanted}),
                                        ConfigSnapshot.commit_hash.in_({h for _, h in wanted})))
        for did, h, at in found.all():
            if (did, h) in wanted and ((did, h) not in snap_at or at < snap_at[(did, h)]):
                snap_at[(did, h)] = at
    counts = {"drift": 0, "ok": 0, "unknown": 0, "none": 0}
    items = []
    for dev, base in rows:
        st = state_of(base)
        counts[st] += 1
        if state != "all" and st != state:
            continue
        item = {"device_id": dev.id, "device_name": dev.name, "group_id": dev.group_id,
                "group_name": groups.get(dev.group_id) if dev.group_id else None, "state": st, "baseline": None}
        if base is not None:
            item["baseline"] = {**baseline_dict(base), "collected_at": iso_utc(snap_at.get((dev.id, base.commit_hash)))}
        items.append(item)
    def size(i: dict) -> int:
        b = i["baseline"] or {}
        return (b.get("drift_added") or 0) + (b.get("drift_removed") or 0)

    items.sort(key=lambda i: (-size(i), i["device_name"]))
    return {"total": len(items), "counts": counts, "items": items}


async def _device(db: AsyncSession, device_id: str) -> Device:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/{device_id}/baseline", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def get_baseline(device_id: Annotated[str, Path(max_length=36)], db: AsyncSession = Depends(get_db)):
    """機器の基準とずれ。基準が無ければ null"""
    await _device(db, device_id)
    row = await db.get(ConfigBaseline, device_id)
    return baseline_dict(row) if row else None


@router.put("/{device_id}/baseline", dependencies=[Depends(require(Perm.CONFIG_REVIEW))])
async def set_baseline(
    device_id: Annotated[str, Path(max_length=36)],
    body: BaselineBody,
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """機器の基準の世代を指定する（指定済みなら付け替える）。指定の直後にずれを計算する（通知はしない）"""
    device = await _device(db, device_id)
    wanted = body.commit_hash
    if wanted == LATEST:
        wanted = await run_in_threadpool(head_commit_hash, device_id) or ""
        if not wanted:
            raise HTTPException(status_code=404, detail="この機器にはまだ世代がありません")
    info = await run_in_threadpool(resolve_commit_info, device_id, wanted)
    if not info:
        raise HTTPException(status_code=404, detail="指定した世代が見つかりません")
    full = info[0]
    drift = await run_in_threadpool(compute_drift_stable, device_id, full)
    user = audit.user
    row = await db.get(ConfigBaseline, device_id)
    before = None
    if row is None:
        row = ConfigBaseline(device_id=device_id, commit_hash=full)
        db.add(row)
    else:
        before = {"commit": row.commit_hash, "note": row.note, "set_by": row.set_by}
    row.commit_hash = full
    row.note = body.note or None
    row.set_by, row.set_by_id, row.set_at = user.username, user.id, utcnow()
    if drift is not None:
        apply_drift(row, drift)
    else:  # 計算できなかった（まれ）。未計算にして、次の収集の成功時に計算し直す
        row.drift_added = row.drift_removed = row.latest_hash = row.checked_at = None
    audit("config.baseline_set", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": full, "note": row.note, "before": before,
                  "drift": {"added": drift.added, "removed": drift.removed} if drift else None})
    try:
        await db.commit()
    except (IntegrityError, StaleDataError) as e:  # 同時に指定された
        await db.rollback()
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE) from e
    await db.refresh(row)
    return baseline_dict(row)


@router.delete("/{device_id}/baseline", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require(Perm.CONFIG_REVIEW))])
async def clear_baseline(device_id: Annotated[str, Path(max_length=36)], db: AsyncSession = Depends(get_db),
                         audit: Audit = Depends(get_audit)):
    """基準の世代を解除する"""
    device = await _device(db, device_id)
    row = await db.get(ConfigBaseline, device_id)
    if row is None:
        raise HTTPException(status_code=404, detail="この機器には基準が指定されていません")
    await db.delete(row)
    audit("config.baseline_clear", target_type="device", target_id=device.id, target_name=device.name,
          detail={"before": {"commit": row.commit_hash, "note": row.note, "set_by": row.set_by}})
    try:
        await db.commit()
    except (IntegrityError, StaleDataError) as e:  # 同時に解除された・付け替えられた
        await db.rollback()
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE) from e
