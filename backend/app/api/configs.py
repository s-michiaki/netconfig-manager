from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from app.services.config_service import (
    get_config_content,
    get_config_diff,
    get_config_history,
)

router = APIRouter()


@router.get("/{device_name}/history")
async def list_history(device_name: str, limit: int = 50):
    """デバイスのコンフィグ収集履歴（Gitコミット一覧）を返す"""
    history = get_config_history(device_name, limit=limit)
    return history


@router.get("/{device_name}/diff")
async def get_diff(device_name: str, from_hash: str, to_hash: str):
    """2つのコミット間の差分をUnified Diff形式で返す"""
    diff = get_config_diff(device_name, from_hash, to_hash)
    if not diff:
        return {"diff": "", "message": "変更なし"}
    return {"diff": diff}


@router.get("/{device_name}/content/{commit_hash}", response_class=PlainTextResponse)
async def get_content(device_name: str, commit_hash: str):
    """指定コミット時点のコンフィグ内容を返す"""
    content = get_config_content(device_name, commit_hash)
    if not content:
        raise HTTPException(status_code=404, detail="Config not found")
    return content
