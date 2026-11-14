from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device, DeviceGroup
from app.services import config_search
from app.services.config_service import (
    get_config_content,
    get_config_diff,
    get_config_history,
)

router = APIRouter()

HASH_PATTERN = r"^[0-9a-fA-F]{7,40}$"


async def _ensure_device(db: AsyncSession, device_id: str) -> None:
    if not await db.get(Device, device_id):
        raise HTTPException(status_code=404, detail="Device not found")


@router.get("/{device_id}/history", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def list_history(
    device_id: str,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """デバイスのコンフィグ収集履歴（Gitコミット一覧）を返す"""
    await _ensure_device(db, device_id)
    return await run_in_threadpool(get_config_history, device_id, limit)


@router.get("/{device_id}/diff", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def get_diff(
    device_id: str,
    from_hash: str = Query(..., pattern=HASH_PATTERN),
    to_hash: str = Query(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
):
    """2つのコミット間の差分をUnified Diff形式で返す"""
    await _ensure_device(db, device_id)
    diff = await run_in_threadpool(get_config_diff, device_id, from_hash, to_hash)
    if diff is None:
        raise HTTPException(status_code=404, detail="Commit not found")
    if not diff:
        return {"diff": "", "message": "変更なし"}
    return {"diff": diff}


@router.get(
    "/{device_id}/content/{commit_hash}",
    response_class=PlainTextResponse,
    dependencies=[Depends(require(Perm.CONFIG_READ))],
)
async def get_content(
    device_id: str,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
):
    """指定コミット時点のコンフィグ内容を返す"""
    await _ensure_device(db, device_id)
    content = await run_in_threadpool(get_config_content, device_id, commit_hash)
    if content is None:
        raise HTTPException(status_code=404, detail="Config not found")
    return content


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=200)
    mode: str = Field("contains", pattern="^(contains|regex)$")
    case_sensitive: bool = False
    context: int = Field(0, ge=0, le=3)  # 一致した行の前後に付ける行数
    group_id: str | None = None  # 機器グループで絞る（"none" はグループなし）
    platform: str | None = None


def _target_dict(t: config_search.Target) -> dict:
    return {"id": t.id, "name": t.name, "hostname": t.hostname, "platform": t.platform, "group": t.group}


# 検索語を URL（アクセスログ）に残さないよう POST にしている
@router.post("/search", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def search_configs(body: SearchRequest, db: AsyncSession = Depends(get_db)):
    """全機器（または絞り込んだ機器）の最新コンフィグを横断検索する"""
    if not body.query.strip():
        raise HTTPException(status_code=422, detail="検索する文字列を入力してください")
    try:
        config_search.build_pattern(body.query, body.mode, body.case_sensitive)
    except config_search.SearchPatternError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    q = select(Device).order_by(Device.name)
    if body.group_id == "none":
        q = q.where(Device.group_id.is_(None))
    elif body.group_id:
        q = q.where(Device.group_id == body.group_id)
    if body.platform:
        q = q.where(Device.platform == body.platform)
    devices = (await db.execute(q)).scalars().all()
    groups = {g.id: g.name for g in (await db.execute(select(DeviceGroup))).scalars().all()}
    targets = [config_search.Target(d.id, d.name, d.hostname, d.platform, groups.get(d.group_id)) for d in devices]
    res = await run_in_threadpool(config_search.search, targets, body.query, body.mode, body.case_sensitive, body.context)
    return {
        "searched": len(targets) - len(res.not_collected) - len(res.timed_out),
        "matched": len(res.hits),
        "total_lines": res.total_lines,
        "max_lines_per_device": config_search.MAX_LINES_PER_DEVICE,
        "devices": [{**_target_dict(h.target), "count": h.count, "commit": h.commit, "lines": h.lines} for h in res.hits],
        "unmatched": [_target_dict(t) for t in res.unmatched],
        "not_collected": [_target_dict(t) for t in res.not_collected],
        "timed_out": [_target_dict(t) for t in res.timed_out],
    }
