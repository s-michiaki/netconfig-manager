"""変更（世代）の確認: 検出した変更に「確認済み」「想定外」を付け、未確認の変更を一覧にする

状態は世代（Git のコミット）ごとに 1 件。付いていない世代は「未確認」。
付けられるのはオペレーター以上（config:review）、閲覧者は状態を読むだけ（世代の一覧・変更の確認の一覧に含めて返す）。
付け直しは config:review があれば誰でもでき、前の状態は監査ログに残す。
対象は config_snapshots（収集で検出した変更）のうち、各機器の最初の世代（初回の収集）を除いたもの。
"""
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import func, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.exc import StaleDataError

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.device import ConfigComment, ConfigReview, ConfigSnapshot, Device, DeviceGroup
from app.services.audit import Audit, get_audit
from app.services.config_service import first_commit_hash, peek_first_commit, resolve_commit_info

router = APIRouter()

HASH_PATTERN = r"^[0-9a-fA-F]{7,40}$"
MAX_NOTE_LENGTH = 500
MAX_BULK = 200
LIST_LIMIT = 500
AUDIT_EXCERPT = 200
STATUSES = ("confirmed", "unexpected")
CONFLICT_MESSAGE = "同じ世代に別の確認が付けられました（または消されました）。画面を開き直してください"
STATUS_LABELS = {"confirmed": "確認済み", "unexpected": "想定外"}

Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=MAX_NOTE_LENGTH)]


class ReviewBody(BaseModel):
    status: Literal["confirmed", "unexpected"]
    note: Note | None = None


class BulkItem(BaseModel):
    device_id: Annotated[str, StringConstraints(max_length=36)]
    commit_hash: Annotated[str, StringConstraints(pattern=HASH_PATTERN)]


class BulkBody(BaseModel):
    items: list[BulkItem] = Field(min_length=1, max_length=MAX_BULK)
    status: Literal["confirmed", "unexpected"]
    note: Note | None = None


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat() if dt else None


def review_dict(r: ConfigReview | None) -> dict | None:
    """画面に返す確認の状態。付いていなければ None（未確認）"""
    if r is None:
        return None
    return {"status": r.status, "note": r.note, "reviewed_by": r.reviewed_by, "reviewed_at": _iso(r.reviewed_at)}


async def reviews_for(db: AsyncSession, device_id: str, hashes: list[str]) -> dict[str, ConfigReview]:
    """機器の世代（完全なハッシュ）ごとの確認の状態。1 回の問い合わせで引く"""
    if not hashes:
        return {}
    rows = await db.execute(
        select(ConfigReview).where(ConfigReview.device_id == device_id, ConfigReview.commit_hash.in_(hashes))
    )
    return {r.commit_hash: r for r in rows.scalars()}


async def first_commits(device_ids: set[str] | list[str]) -> dict[str, str]:
    """機器ごとの最初の世代（Git の親の無いコミット）のハッシュ。変更の確認の対象外。
    Git を読むのは覚えていない機器だけ（スレッドプールで）"""
    ids = set(device_ids)
    missing = [d for d in ids if peek_first_commit(d) is None]
    if missing:
        await run_in_threadpool(lambda: [first_commit_hash(d) for d in missing])
    return {d: h for d in ids if (h := peek_first_commit(d))}


def _scope(q, since: datetime | None, group_id: str | None):
    """期間・機器グループで絞る（q は ConfigSnapshot と Device を結合済み）"""
    if since is not None:
        q = q.where(ConfigSnapshot.collected_at >= since)
    if group_id:
        q = q.where(Device.group_id == group_id)
    return q


async def load_changes(db: AsyncSession, *, since: datetime | None = None, group_id: str | None = None) -> list[dict]:
    """確認の対象の変更（新しい順）。同じ (機器, 世代) が重複していたら 1 件にまとめ、確認の状態を付ける"""
    q = _scope(select(ConfigSnapshot, Device.name, Device.group_id)
               .join(Device, Device.id == ConfigSnapshot.device_id)
               .order_by(ConfigSnapshot.collected_at.desc(), ConfigSnapshot.id), since, group_id)
    rows = (await db.execute(q)).all()
    if not rows:
        return []
    firsts = await first_commits({s.device_id for s, _, _ in rows})
    # 確認の状態は、対象の世代（期間・グループで絞った snapshot と同じ機器・世代）の分だけ読む
    same = (ConfigSnapshot.device_id == ConfigReview.device_id) & (ConfigSnapshot.commit_hash == ConfigReview.commit_hash)
    rq = _scope(select(ConfigReview).join(ConfigSnapshot, same).join(Device, Device.id == ConfigSnapshot.device_id).distinct(),
                since, group_id)
    reviews = {(r.device_id, r.commit_hash): r for r in (await db.execute(rq)).scalars()}
    groups = dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all())
    seen: set[tuple[str, str]] = set()
    changes = []
    for snap, name, gid in rows:
        key = (snap.device_id, snap.commit_hash)
        if key in seen or firsts.get(snap.device_id) == snap.commit_hash:
            continue
        seen.add(key)
        changes.append({
            "device_id": snap.device_id, "device_name": name, "group_id": gid, "group_name": groups.get(gid) if gid else None,
            "commit_hash": snap.commit_hash, "hash": snap.commit_hash[:8], "collected_at": _iso(snap.collected_at),
            "added": snap.lines_added, "removed": snap.lines_removed, "triggered_by": snap.triggered_by,
            "review": review_dict(reviews.get(key)),
        })
    return changes


def state_of(change: dict) -> str:
    return change["review"]["status"] if change["review"] else "unreviewed"


async def _count_changes(db: AsyncSession, *, since: datetime | None, status: str | None) -> int:
    """確認の対象の変更の数を SQL の集計で数える（一覧と同じ数え方: snapshot のある世代で、最初の世代でないもの）。
    status が None なら未確認（確認の行が無いもの）、それ以外はその状態のもの"""
    dev_q = select(ConfigSnapshot.device_id).distinct()
    if since is not None:
        dev_q = dev_q.where(ConfigSnapshot.collected_at >= since)
    firsts = await first_commits({d for (d,) in (await db.execute(dev_q)).all()})
    q = select(ConfigSnapshot.device_id, ConfigSnapshot.commit_hash)
    on = (ConfigReview.device_id == ConfigSnapshot.device_id) & (ConfigReview.commit_hash == ConfigSnapshot.commit_hash)
    if status is None:
        q = q.outerjoin(ConfigReview, on).where(ConfigReview.id.is_(None))
    else:
        q = q.join(ConfigReview, on).where(ConfigReview.status == status)
    if since is not None:
        q = q.where(ConfigSnapshot.collected_at >= since)
    if firsts:
        q = q.where(tuple_(ConfigSnapshot.device_id, ConfigSnapshot.commit_hash).not_in(list(firsts.items())))
    sub = q.distinct().subquery()
    return (await db.execute(select(func.count()).select_from(sub))).scalar_one()


async def count_unreviewed(db: AsyncSession, days: int) -> int:
    """直近 days 日の未確認の変更の数（ダッシュボード用）"""
    return await _count_changes(db, since=utcnow() - timedelta(days=days), status=None)


async def count_unexpected(db: AsyncSession) -> int:
    """想定外を付けた変更の数（期間なし。一覧の state=unexpected&days=0 と同じ数え方）"""
    return await _count_changes(db, since=None, status="unexpected")


@router.get("/reviews", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def list_reviews(
    state: Literal["unreviewed", "unexpected", "confirmed", "all"] = "unreviewed",
    days: int | None = Query(None, ge=0, le=3650),
    group_id: str | None = Query(None, max_length=36),
    db: AsyncSession = Depends(get_db),
):
    """検出した変更の一覧（新しい順・最大 500 件）。days=0 は期間を問わない。省略すると CHANGE_REVIEW_DAYS 日"""
    if days is None:
        days = settings.CHANGE_REVIEW_DAYS
    since = utcnow() - timedelta(days=days) if days else None
    changes = await load_changes(db, since=since, group_id=group_id or None)
    counts = {"unreviewed": 0, "unexpected": 0, "confirmed": 0}
    for c in changes:
        counts[state_of(c)] += 1
    shown = changes if state == "all" else [c for c in changes if state_of(c) == state]
    page = shown[:LIST_LIMIT]
    if page:
        pairs = {(c["device_id"], c["commit_hash"]) for c in page}
        rows = await db.execute(select(ConfigComment).where(
            ConfigComment.device_id.in_({d for d, _ in pairs}), ConfigComment.commit_hash.in_({h for _, h in pairs})))
        comments = {(c.device_id, c.commit_hash): c.body for c in rows.scalars() if (c.device_id, c.commit_hash) in pairs}
        for c in page:
            c["comment"] = comments.get((c["device_id"], c["commit_hash"]))
    return {"total": len(shown), "limit": LIST_LIMIT, "days": days, "counts": counts, "items": page}


async def _apply(db: AsyncSession, audit: Audit, device: Device, full: str, body: ReviewBody | BulkBody,
                 existing: ConfigReview | None) -> tuple[ConfigReview, dict | None]:
    """確認の状態を付ける（既にあれば付け直す）。付け直しのときは前の状態を返す"""
    user = audit.user
    before = None
    if existing is None:
        existing = ConfigReview(device_id=device.id, commit_hash=full, status=body.status, note=body.note or None,
                                reviewed_by=user.username, reviewed_by_id=user.id)
        db.add(existing)
    else:
        before = {"status": existing.status, "note": (existing.note or "")[:AUDIT_EXCERPT] or None,
                  "reviewed_by": existing.reviewed_by}
        existing.status = body.status
        existing.note = body.note or None
        existing.reviewed_by = user.username
        existing.reviewed_by_id = user.id
        existing.reviewed_at = utcnow()
    return existing, before


async def _existing_map(db: AsyncSession, pairs: list[tuple[str, str]]) -> dict[tuple[str, str], ConfigReview]:
    """(機器, 世代) の組の既存の確認を 1 回の問い合わせで読む"""
    if not pairs:
        return {}
    rows = await db.execute(select(ConfigReview).where(
        ConfigReview.device_id.in_({d for d, _ in pairs}), ConfigReview.commit_hash.in_({h for _, h in pairs})))
    wanted = set(pairs)
    return {(r.device_id, r.commit_hash): r for r in rows.scalars() if (r.device_id, r.commit_hash) in wanted}


async def _existing(db: AsyncSession, device_id: str, full: str) -> ConfigReview | None:
    return (await db.execute(
        select(ConfigReview).where(ConfigReview.device_id == device_id, ConfigReview.commit_hash == full)
    )).scalar_one_or_none()


async def _target(db: AsyncSession, device_id: str, commit_hash: str) -> tuple[Device, str]:
    device = await db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    info = await run_in_threadpool(resolve_commit_info, device_id, commit_hash)
    if not info:
        raise HTTPException(status_code=404, detail="指定した世代が見つかりません")
    full, is_first = info
    if is_first:
        raise HTTPException(status_code=422, detail="最初の世代（初回の収集）は、確認の対象ではありません")
    return device, full


@router.put("/{device_id}/reviews/{commit_hash}", dependencies=[Depends(require(Perm.CONFIG_REVIEW))])
async def set_review(
    device_id: str,
    body: ReviewBody,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """世代に「確認済み」「想定外」を付ける（既にあれば付け直す）"""
    device, full = await _target(db, device_id, commit_hash)
    review, before = await _apply(db, audit, device, full, body, await _existing(db, device_id, full))
    audit("config.review", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": full, "status": body.status, "note": (body.note or "")[:AUDIT_EXCERPT] or None,
                  "before": before})
    try:
        await db.commit()
    except (IntegrityError, StaleDataError) as e:  # 同じ世代に同時に付けた・付け直した
        await db.rollback()
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE) from e
    await db.refresh(review)
    return {"commit_hash": full, **review_dict(review)}  # type: ignore[dict-item]


@router.delete(
    "/{device_id}/reviews/{commit_hash}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Perm.CONFIG_REVIEW))],
)
async def delete_review(
    device_id: str,
    commit_hash: str = Path(..., pattern=HASH_PATTERN),
    db: AsyncSession = Depends(get_db),
    audit: Audit = Depends(get_audit),
):
    """確認の状態を消して、未確認に戻す"""
    device, full = await _target(db, device_id, commit_hash)
    review = await _existing(db, device_id, full)
    if review is None:
        raise HTTPException(status_code=404, detail="この世代は未確認です")
    await db.delete(review)
    audit("config.review_delete", target_type="device", target_id=device.id, target_name=device.name,
          detail={"commit": full, "before": {"status": review.status, "note": (review.note or "")[:AUDIT_EXCERPT] or None,
                                              "reviewed_by": review.reviewed_by}})
    try:
        await db.commit()
    except (IntegrityError, StaleDataError) as e:  # 同時に消された・付け直された
        await db.rollback()
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE) from e


def _resolve_all(items: list[tuple[str, str]]) -> list[tuple[str, bool] | None]:
    return [resolve_commit_info(d, h) for d, h in items]


@router.post("/reviews/bulk", dependencies=[Depends(require(Perm.CONFIG_REVIEW))])
async def bulk_review(body: BulkBody, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """選んだ変更にまとめて同じ状態を付ける。付けられなかったもの（機器・世代が無い、最初の世代）は skipped に返す"""
    devices = {d.id: d for d in (await db.execute(
        select(Device).where(Device.id.in_({i.device_id for i in body.items})))).scalars()}
    known = [i for i in body.items if i.device_id in devices]
    infos = await run_in_threadpool(_resolve_all, [(i.device_id, i.commit_hash) for i in known])
    resolved = {(i.device_id, i.commit_hash): info for i, info in zip(known, infos, strict=True)}
    skipped, applied, seen = [], [], set()
    for i in body.items:
        info = resolved.get((i.device_id, i.commit_hash))
        if i.device_id not in devices:
            skipped.append({"device_id": i.device_id, "commit_hash": i.commit_hash, "reason": "機器が見つかりません"})
        elif info is None:
            skipped.append({"device_id": i.device_id, "commit_hash": i.commit_hash, "reason": "世代が見つかりません"})
        elif info[1]:
            skipped.append({"device_id": i.device_id, "commit_hash": i.commit_hash, "reason": "最初の世代は対象外です"})
        elif (i.device_id, info[0]) not in seen:
            seen.add((i.device_id, info[0]))
            applied.append((devices[i.device_id], info[0]))
    existing = await _existing_map(db, [(d.id, f) for d, f in applied])
    for device, full in applied:
        await _apply(db, audit, device, full, body, existing.get((device.id, full)))
    audit("config.review_bulk", target_type="device", target_name=f"{len(applied)} 件",
          detail={"status": body.status, "note": (body.note or "")[:AUDIT_EXCERPT] or None, "count": len(applied),
                  "skipped": len(skipped),
                  "items": [{"device": d.name, "commit": f[:8]} for d, f in applied[:20]]})
    try:
        await db.commit()
    except (IntegrityError, StaleDataError) as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE) from e
    return {"updated": len(applied), "skipped": skipped}
