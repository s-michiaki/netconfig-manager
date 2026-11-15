"""世代（Git のコミット）へのコメント（作業内容のメモ）

1 世代に 1 件。書けるのはオペレーター以上（config:comment）、閲覧者は読むだけ（世代の一覧に含めて返す）。
他の人が書いたコメントを変更・削除できるのは、書いた本人と管理者だけ。変更・削除は監査ログに残す。
"""
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Perm, has_permission
from app.core.timeutil import utcnow
from app.models.device import ConfigComment, Device
from app.services.audit import Audit, get_audit
from app.services.config_service import resolve_commit

router = APIRouter()

HASH_PATTERN = r"^[0-9a-fA-F]{7,40}$"
MAX_COMMENT_LENGTH = 1000
AUDIT_EXCERPT = 200  # 監査ログに残す本文の長さ（上書き・削除で消える内容を追えるように）


class CommentBody(BaseModel):
    body: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_COMMENT_LENGTH)]


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat() if dt else None


def comment_dict(c: ConfigComment) -> dict:
    return {
        "body": c.body,
        "created_by": c.created_by,
        "created_by_id": c.created_by_id,
        "created_at": _iso(c.created_at),
        "updated_by": c.updated_by,
        "updated_at": _iso(c.updated_at),
    }


async def comments_for(db: AsyncSession, device_id: str, hashes: list[str]) -> dict[str, ConfigComment]:
    """機器の世代（完全なハッシュ）ごとのコメント。1 回の問い合わせで引く"""
    if not hashes:
        return {}
    rows = await db.execute(
        select(ConfigComment).where(ConfigComment.device_id == device_id, ConfigComment.commit_hash.in_(hashes))
    )
    return {c.commit_hash: c for c in rows.scalars()}


async def _target(db: AsyncSession, device_id: str, commit_hash: str) -> tuple[Device, str, ConfigComment | None]:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    full = await run_in_threadpool(resolve_commit, device_id, commit_hash)
    if not full:
        raise HTTPException(status_code=404, detail="指定した世代が見つかりません")
    existing = (await db.execute(
        select(ConfigComment).where(ConfigComment.device_id == device_id, ConfigComment.commit_hash == full)
    )).scalar_one_or_none()
    return device, full, existing


def _ensure_editable(audit: Audit, comment: ConfigComment) -> None:
    user = audit.user
    if comment.created_by_id != user.id and not has_permission(user.role, Perm.USER_ADMIN):
        raise HTTPException(status_code=403, detail="他の人が書いたコメントは、書いた本人か管理者だけが変更・削除できます")


@router.put("/{device_id}/comments/{commit_hash}", dependencies=[Depends(require(Perm.CONFIG_COMMENT))])
async def set_comment(
    device_id: str,
    body: CommentBody,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """世代にコメントを付ける（既にあれば書き換える）"""
    device, full, comment = await _target(db, device_id, commit_hash)
    user = audit.user
    before = None
    if comment is None:
        comment = ConfigComment(device_id=device.id, commit_hash=full, body=body.body, created_by=user.username,
                                created_by_id=user.id, updated_by=user.username)
        db.add(comment)
    else:
        _ensure_editable(audit, comment)
        before = comment.body
        comment.body = body.body
        comment.updated_by = user.username
        comment.updated_at = utcnow()
    audit("config.comment_set", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": full, "created": before is None, "before": (before or "")[:AUDIT_EXCERPT] or None,
                  "after": body.body[:AUDIT_EXCERPT]})
    try:
        await db.commit()
    except IntegrityError as e:  # 同じ世代に同時に書いた
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ世代に別のコメントが書かれました。画面を開き直してください") from e
    await db.refresh(comment)
    return {"commit_hash": full, **comment_dict(comment)}


@router.delete(
    "/{device_id}/comments/{commit_hash}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Perm.CONFIG_COMMENT))],
)
async def delete_comment(
    device_id: str,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """世代のコメントを削除する"""
    device, full, comment = await _target(db, device_id, commit_hash)
    if comment is None:
        raise HTTPException(status_code=404, detail="コメントがありません")
    _ensure_editable(audit, comment)
    await db.delete(comment)
    audit("config.comment_delete", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": full, "before": comment.body[:AUDIT_EXCERPT], "created_by": comment.created_by})
    await db.commit()
