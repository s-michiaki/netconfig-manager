from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.config_comments import comment_dict, comments_for
from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import content_disposition
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device, DeviceGroup
from app.services import config_search
from app.services.audit import Audit, get_audit
from app.services.config_service import (
    MAX_COMPARE_LINES,
    compare_texts,
    get_config_content,
    get_config_diff,
    get_config_history,
    get_config_version,
    has_config,
)

router = APIRouter()

HASH_PATTERN = r"^[0-9a-fA-F]{7,40}$"


async def _ensure_device(db: AsyncSession, device_id: str) -> Device:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _load_version(db: AsyncSession, device_id: str, commit_hash: str | None, side: str) -> tuple[Device, dict]:
    """比較する片側（機器と世代）を読み込む。見つからない理由をメッセージで分ける"""
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"比較{side}の機器が見つかりません")
    version = await run_in_threadpool(get_config_version, device_id, commit_hash)
    if version is None:
        if not await run_in_threadpool(has_config, device_id):
            raise HTTPException(status_code=404, detail=f"比較{side}の機器（{device.name}）はまだコンフィグを収集していません")
        raise HTTPException(status_code=404, detail=f"比較{side}の機器（{device.name}）に指定した世代が見つかりません")
    if version["content"].count("\n") > MAX_COMPARE_LINES:
        raise HTTPException(
            status_code=422, detail=f"比較{side}のコンフィグが大きすぎるため比較できません（{MAX_COMPARE_LINES} 行まで）"
        )
    return device, version


def _side(device: Device, version: dict) -> dict:
    return {"device_id": device.id, "name": device.name, "hash": version["hash"], "full_hash": version["full_hash"],
            "date": version["date"]}


# /{device_id}/... より前に定義する（パスの形は違うが、読み違えを避けるため）
@router.get("/compare", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def compare_configs(
    device_a: str = Query(..., max_length=36),
    device_b: str = Query(..., max_length=36),
    hash_a: str | None = Query(None, pattern=HASH_PATTERN),
    hash_b: str | None = Query(None, pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
):
    """2 台の機器（または同じ機器）の世代どうしの差分を返す。世代を省略すると最新を使う"""
    dev_a, ver_a = await _load_version(db, device_a, hash_a, "元")
    dev_b, ver_b = await _load_version(db, device_b, hash_b, "先")
    diff, truncated = await run_in_threadpool(
        compare_texts, ver_a["content"], ver_b["content"],
        f"{dev_a.name} ({ver_a['hash']})", f"{dev_b.name} ({ver_b['hash']})",
    )
    res = {"diff": diff, "a": _side(dev_a, ver_a), "b": _side(dev_b, ver_b), "truncated": truncated}
    if not diff:
        res["message"] = "変更なし"
    return res


@router.get("/{device_id}/history", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def list_history(
    device_id: str,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """デバイスのコンフィグ収集履歴（Gitコミット一覧）を返す。世代へのコメントも含める"""
    await _ensure_device(db, device_id)
    history = await run_in_threadpool(get_config_history, device_id, limit)
    comments = await comments_for(db, device_id, [c["full_hash"] for c in history])
    for c in history:
        found = comments.get(c["full_hash"])
        c["comment"] = comment_dict(found) if found else None
    return history


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


@router.get("/{device_id}/download/{commit_hash}", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def download_config(
    device_id: str,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """指定した世代のコンフィグをテキストファイルとしてダウンロードする（ファイルとして持ち出すので監査ログに残す）"""
    device = await _ensure_device(db, device_id)
    version = await run_in_threadpool(get_config_version, device_id, commit_hash)
    if version is None:
        raise HTTPException(status_code=404, detail="Config not found")
    body = version["content"].encode("utf-8")
    # ファイル名は 機器名_世代の日時_ハッシュ8桁.txt（同じ世代なら何度保存しても同じ名前）
    at = datetime.fromisoformat(version["date"]).astimezone(ZoneInfo(settings.TIMEZONE)).strftime("%Y%m%d-%H%M%S")
    filename = f"{device.name}_{at}_{version['hash']}.txt"
    audit("config.download", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": version["full_hash"], "bytes": len(body)})
    await db.commit()
    return Response(content=body, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": content_disposition(filename)})


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
