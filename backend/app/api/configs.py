from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device
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
