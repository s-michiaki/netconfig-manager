"""ダッシュボード: ログイン後の最初の画面に出す要約（機器の収集状況・直近の変更・違反・次のスケジュール）"""
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from croniter import croniter
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.config_baselines import count_baselines
from app.api.config_reviews import count_unexpected, count_unreviewed, first_commits, review_dict
from app.api.deps import get_current_user, require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm, has_permission
from app.core.timeutil import utcnow
from app.models.compliance import ComplianceResult, ComplianceRule
from app.models.device import CollectLog, ConfigComment, ConfigReview, ConfigSnapshot, Device, DeviceGroup, Schedule
from app.models.user import User

router = APIRouter()
LIST_LIMIT = 10
COMMENT_EXCERPT = 60  # 直近の変更に出すコメントの長さ
KIND_LABELS = {"collect": "コンフィグ収集", "compliance": "コンプライアンスチェック"}


@router.get("", dependencies=[Depends(require(Perm.DEVICE_READ))])
async def dashboard(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    now = utcnow()
    devices = (await db.execute(select(Device).order_by(Device.name))).scalars().all()
    names = {d.id: d.name for d in devices}
    active = [d for d in devices if d.is_active]

    # 機器ごとの最新の収集結果
    latest_at = select(CollectLog.device_id, func.max(CollectLog.started_at).label("at")).group_by(
        CollectLog.device_id).subquery()
    logs = (await db.execute(select(CollectLog).join(
        latest_at, (CollectLog.device_id == latest_at.c.device_id) & (CollectLog.started_at == latest_at.c.at)
    ))).scalars().all()
    last_log = {log.device_id: log for log in logs}
    failing = sorted(
        ({"id": d.id, "name": d.name, "hostname": d.hostname, "message": (last_log[d.id].message or "")[:300],
          "at": last_log[d.id].finished_at or last_log[d.id].started_at}
         for d in active if d.id in last_log and last_log[d.id].status != "success"),
        key=lambda x: x["at"], reverse=True)
    never = [{"id": d.id, "name": d.name, "hostname": d.hostname} for d in active if d.id not in last_log]
    last_success = (await db.execute(
        select(func.max(CollectLog.finished_at)).where(CollectLog.status == "success"))).scalar_one()

    # 直近の変更（世代）
    snaps = (await db.execute(
        select(ConfigSnapshot).order_by(ConfigSnapshot.collected_at.desc()).limit(LIST_LIMIT))).scalars().all()

    async def changed_since(delta: timedelta) -> int:
        return (await db.execute(select(func.count()).select_from(ConfigSnapshot)
                                 .where(ConfigSnapshot.collected_at >= now - delta))).scalar_one()

    # コンプライアンス違反（重要度別・違反のある機器数）
    fails = (await db.execute(
        select(ComplianceResult.device_id, ComplianceRule.severity)
        .join(ComplianceRule, ComplianceRule.id == ComplianceResult.rule_id)
        .where(ComplianceResult.status == "fail", ComplianceRule.enabled.is_(True))
    )).all()
    by_severity = {"high": 0, "medium": 0, "low": 0}
    for device_id, sev in fails:
        if device_id in names:
            by_severity[sev] = by_severity.get(sev, 0) + 1
    rules = (await db.execute(
        select(func.count()).select_from(ComplianceRule).where(ComplianceRule.enabled.is_(True)))).scalar_one()

    # 次に実行されるスケジュール
    groups = dict((await db.execute(select(DeviceGroup.id, DeviceGroup.name))).all())
    local_now = datetime.now(ZoneInfo(settings.TIMEZONE))
    upcoming = []
    for s in (await db.execute(select(Schedule).where(Schedule.is_active.is_(True)))).scalars():
        try:
            nxt = croniter(s.cron_expression, local_now).get_next(datetime)
        except (ValueError, KeyError):
            continue
        if s.target == "all":
            target = "全機器"
        elif s.target.startswith("group:"):
            target = f"グループ「{groups.get(s.target.split(':', 1)[1], '（削除済み）')}」"
        else:
            target = names.get(s.target, "（削除済み）")
        upcoming.append({"id": s.id, "name": s.name, "kind": KIND_LABELS.get(s.kind or "collect", s.kind),
                         "target": target, "next_run": nxt.isoformat()})
    upcoming.sort(key=lambda x: x["next_run"])

    # 世代へのコメント（作業内容のメモ）。コンフィグを閲覧できる人にだけ出す。改行は空白にして短くする
    comments: dict[tuple[str, str], str] = {}
    if snaps and has_permission(user.role, Perm.CONFIG_READ):
        rows = await db.execute(select(ConfigComment).where(
            ConfigComment.device_id.in_({s.device_id for s in snaps}),
            ConfigComment.commit_hash.in_({s.commit_hash for s in snaps}),
        ))
        for c in rows.scalars():
            text = " ".join(c.body.split())
            comments[(c.device_id, c.commit_hash)] = text if len(text) <= COMMENT_EXCERPT else text[:COMMENT_EXCERPT] + "…"

    # 変更の確認（未確認の変更の数・想定外の数・直近の変更ごとの状態）。コンフィグを閲覧できる人にだけ出す
    reviews = None
    recent_reviews: dict[tuple[str, str], dict | None] = {}
    firsts: dict[str, str] = {}
    if has_permission(user.role, Perm.CONFIG_READ):
        reviews = {"days": settings.CHANGE_REVIEW_DAYS,
                   "unreviewed": await count_unreviewed(db, settings.CHANGE_REVIEW_DAYS),
                   "unexpected": await count_unexpected(db)}
        if snaps:
            firsts = await first_commits({s.device_id for s in snaps})
            found = await db.execute(select(ConfigReview).where(
                ConfigReview.device_id.in_({s.device_id for s in snaps}),
                ConfigReview.commit_hash.in_({s.commit_hash for s in snaps}),
            ))
            recent_reviews = {(r.device_id, r.commit_hash): review_dict(r) for r in found.scalars()}

    # 基準の世代: 基準を指定した機器の数とずれている機器の数（コンフィグを閲覧できる人にだけ出す）
    baselines = await count_baselines(db) if has_permission(user.role, Perm.CONFIG_READ) else None

    return {
        "devices": {"total": len(devices), "active": len(active), "inactive": len(devices) - len(active),
                    "failing": len(failing), "never": len(never),
                    "ok": len(active) - len(failing) - len(never)},
        "last_success": last_success,
        "failing": failing[:LIST_LIMIT],
        "never": never[:LIST_LIMIT],
        "changes": {"last_24h": await changed_since(timedelta(hours=24)), "last_7d": await changed_since(timedelta(days=7)),
                    "recent": [{"device_id": s.device_id, "device_name": names.get(s.device_id, "（削除済み）"),
                                "at": s.collected_at, "added": s.lines_added, "removed": s.lines_removed,
                                "commit": s.commit_hash[:8], "full_commit": s.commit_hash, "triggered_by": s.triggered_by,
                                "comment": comments.get((s.device_id, s.commit_hash)),
                                # 確認の状態（None は未確認）。最初の世代は確認の対象外なので first を付ける
                                "review": recent_reviews.get((s.device_id, s.commit_hash)),
                                "first": firsts.get(s.device_id) == s.commit_hash} for s in snaps]},
        "reviews": reviews,
        "baselines": baselines,
        "compliance": {"rules": rules, "by_severity": by_severity, "violations": sum(by_severity.values()),
                       "devices": len({d for d, _ in fails if d in names})},
        "schedules": {"active": len(upcoming), "upcoming": upcoming[:5]},
    }
