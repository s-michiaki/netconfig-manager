"""ファームウェアの脆弱性（CVE）とサポート終了日（EOL）の API

VULN_ENABLED=false（既定）のときはすべて 404 を返す（画面のメニューも出さない。外部へも一切つながない）
- 閲覧（VULN_READ）: 全ロール。要約・脆弱性の一覧（CSV 出力を含む）・機器別・判定できない機器・勧告・サポート終了日
- 書き込み（VULN_WRITE）: オペレーター以上。「確認済み」（メモ必須）とその取り消し・サポート終了日の手入力と削除
- 外部からの「いま取得」: 管理者（SYSTEM_READ）。間隔の制限つき
「該当」は、ベンダーの勧告の影響範囲（リリース系列ごとの「この版より前」）と機器の OS バージョンの照合の結果。
機能の設定・構成までは見ない。勧告に載っていない脆弱性はありうる（services/vuln_service.py）
"""
import re
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import MAX_EXPORT_ROWS, csv_response, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.device import Device, DeviceGroup
from app.models.user import User
from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
from app.services import vuln_match as vm
from app.services import vuln_service as svc
from app.services.audit import Audit, get_audit
from app.services.config_service import PLATFORMS


def require_enabled() -> None:
    if not settings.VULN_ENABLED:
        raise HTTPException(status_code=404, detail="脆弱性・サポート期限の管理は無効です（.env の VULN_ENABLED=true で有効）")


router = APIRouter(dependencies=[Depends(require_enabled)])

LIST_MAX = 200
NOTE_MAX = 500
SEVERITIES = ("critical", "high", "medium", "low", "none")
SEVERITY_LABELS = {"critical": "重大", "high": "高", "medium": "中", "low": "低", "none": "不明"}
STATE_LABELS = {"open": "未確認", "ack": "確認済み", "fixed": "解消"}
UNKNOWN_LABELS = {
    "no_version": "OS バージョンを読み取れていません（収集のあとに読み取ります）",
    "unparseable": "OS バージョンの書き方を読み取れません",
    "unsupported": "対象外の機種です",
    "no_vuln_source": "脆弱性の情報源が未対応です（サポート期限だけ確認します）",
}
_BRANCH = re.compile(r"^(?:[0-9A-Za-z][0-9A-Za-z.\-]{0,31}|\*)$")  # "*" はその機種のすべて（バージョンを分解できない機種など）
CANDIDATE_REASON = vm.CANDIDATE_REASONS["panorama"]  # 理由を決められないときの既定（理由は照合をやり直して決める）
_SEV_RANK = case((VulnAdvisory.severity == "critical", 4), (VulnAdvisory.severity == "high", 3),
                 (VulnAdvisory.severity == "medium", 2), (VulnAdvisory.severity == "low", 1), else_=0)

Note = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=NOTE_MAX)]


def iso_utc(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat() if dt else None


def _advisory_out(a: VulnAdvisory) -> dict:
    return {"id": a.id, "source": a.source, "ext_id": a.ext_id, "cve_ids": a.cve_ids or [], "title": a.title,
            "severity": a.severity, "cvss": a.cvss, "published_at": iso_utc(a.published_at),
            "modified_at": iso_utc(a.modified_at), "url": a.url, "kev": a.kev, "rejected": a.rejected,
            "kev_due": a.kev_due.isoformat() if a.kev_due else None}


def _candidate_reason(m: VulnMatch, a: VulnAdvisory, platform: str | None, model: str | None) -> str | None:
    """「候補」の理由（Panorama だけの勧告で機器の種類が分からない／記載のない系列も影響ありとする勧告）"""
    if m.confidence != "candidate":
        return None
    reason = vm.candidate_reason(platform or "", m.os_version, a.affected or [], model) if platform else None
    return reason or CANDIDATE_REASON


def _match_out(m: VulnMatch, a: VulnAdvisory, device_name: str, group_id: str | None, group_name: str | None,
               platform: str | None = None, model: str | None = None) -> dict:
    return {"id": m.id, "device_id": m.device_id, "device_name": device_name, "group_id": group_id,
            "group_name": group_name, "os_version": m.os_version, "confidence": m.confidence, "state": m.state,
            "note": m.note, "acked_by": m.acked_by, "acked_at": iso_utc(m.acked_at), "first_seen": iso_utc(m.first_seen),
            "last_seen": iso_utc(m.last_seen), "advisory": _advisory_out(a),
            "candidate_reason": _candidate_reason(m, a, platform, model)}


# ---------------------------------------------------------------- 要約


def _eol_counts(devices: list[Device], rows: list[EolDate], today: date) -> dict:
    ended = soon = 0
    for d in devices:
        e = svc.device_eol(rows, d, today)
        days = [x["days_left"] for x in (e["os"], e["hardware"]) if x]
        if not days:
            continue
        if min(days) < 0:
            ended += 1
        elif min(days) <= svc.EOL_SOON_DAYS:
            soon += 1
    return {"ended": ended, "soon": soon}


@router.get("/summary", dependencies=[Depends(require(Perm.VULN_READ))])
async def summary(db: AsyncSession = Depends(get_db)):
    now = utcnow()
    today = svc.local_today()
    counts = dict.fromkeys(SEVERITIES, 0)
    kev = candidate = 0
    rows = (await db.execute(
        select(VulnAdvisory.severity, VulnAdvisory.kev, VulnMatch.confidence, func.count())
        .join(VulnMatch, VulnMatch.advisory_id == VulnAdvisory.id).join(Device, Device.id == VulnMatch.device_id)
        .where(VulnMatch.state == "open", VulnMatch.stale.is_(False))
        .group_by(VulnAdvisory.severity, VulnAdvisory.kev, VulnMatch.confidence)
    )).all()
    for sev, is_kev, conf, n in rows:
        if conf == "candidate":
            candidate += n
            continue
        counts[sev] = counts.get(sev, 0) + n
        if is_kev:
            kev += n
    acked = (await db.execute(select(func.count()).select_from(VulnMatch).join(Device, Device.id == VulnMatch.device_id)
                              .where(VulnMatch.state == "ack", VulnMatch.stale.is_(False)))).scalar_one()
    stale = (await db.execute(select(func.count()).select_from(VulnMatch).join(Device, Device.id == VulnMatch.device_id)
                              .where(VulnMatch.stale.is_(True), VulnMatch.state.in_(("open", "ack"))))).scalar_one()
    devices = list((await db.execute(select(Device))).scalars())
    unknown = sum(1 for d in devices if _unknown_reason(d))
    eol_rows = await svc.eol_rows(db)
    saved = {s.source: s for s in (await db.execute(select(VulnSource))).scalars()}
    sources = []
    for name in svc.active_sources():
        s = saved.get(name)
        sources.append({"source": name, "label": svc.SOURCE_LABELS[name], "last_at": iso_utc(s.last_at) if s else None,
                        "last_ok_at": iso_utc(s.last_ok_at) if s else None, "last_error": s.last_error if s else None,
                        "last_count": s.last_count if s else None, "skipped": s.skipped if s else None})
    advisories = list((await db.execute(select(VulnAdvisory).where(VulnAdvisory.source == "paloalto"))).scalars())
    unreadable = svc.unreadable_by_device(devices, advisories)
    return {
        "counts": {**counts, "kev": kev, "candidate": candidate, "acked": acked},
        "eol": _eol_counts(devices, eol_rows, today), "devices": len(devices), "unknown_devices": unknown,
        "range_unreadable": {"devices": len(unreadable), "pairs": sum(len(v) for v in unreadable.values()),
                             "advisories": len({x for v in unreadable.values() for x in v}), "stale": stale},
        "sources": sources, "unknown_sources": svc.unknown_sources(),
        "fetch_hour": settings.VULN_FETCH_HOUR, "checked_at": iso_utc(now),
    }


def _unknown_reason(d: Device) -> str | None:
    """判定できない理由（脆弱性を判定できる機種で、バージョンが読めているなら None）"""
    r = vm.unknown_reason(d.platform, d.os_version)
    if r:
        return r
    return None if d.platform in vm.CONFIRMED_PLATFORMS else "no_vuln_source"


# ---------------------------------------------------------------- 脆弱性の一覧


def _filters(q, device_id, group_id, severity, confidence, state, kev):
    q = q.where(VulnMatch.stale.is_(False))  # 前回は該当・いまの版では判定できないものは「判定できない機器」に出す
    if device_id:
        q = q.where(VulnMatch.device_id == device_id)
    if group_id:
        q = q.where(Device.group_id == group_id)
    if severity:
        q = q.where(VulnAdvisory.severity.in_(severity))
    if confidence:
        q = q.where(VulnMatch.confidence == confidence)
    if state != "all":
        q = q.where(VulnMatch.state == state)
    if kev is not None:
        q = q.where(VulnAdvisory.kev.is_(kev))
    return q


def _base():
    return (select(VulnMatch, VulnAdvisory, Device.name, Device.group_id, DeviceGroup.name, Device.platform, Device.model)
            .join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id).join(Device, Device.id == VulnMatch.device_id)
            .outerjoin(DeviceGroup, DeviceGroup.id == Device.group_id))


def _order(q):
    return q.order_by(VulnAdvisory.kev.desc(), _SEV_RANK.desc(), func.coalesce(VulnAdvisory.cvss, 0).desc(),
                      Device.name, VulnAdvisory.ext_id)


@router.get("/matches", dependencies=[Depends(require(Perm.VULN_READ))])
async def list_matches(
    device_id: str | None = None, group_id: str | None = None,
    severity: Annotated[list[Literal["critical", "high", "medium", "low", "none"]] | None, Query()] = None,
    confidence: Literal["confirmed", "candidate"] | None = None,
    state: Literal["open", "ack", "fixed", "all"] = "open", kev: bool | None = None,
    limit: int = Query(100, ge=1, le=LIST_MAX), offset: int = Query(0, ge=0, le=100_000),
    db: AsyncSession = Depends(get_db),
):
    count_q = _filters(select(func.count()).select_from(VulnMatch)
                       .join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                       .join(Device, Device.id == VulnMatch.device_id), device_id, group_id, severity, confidence, state, kev)
    total = (await db.execute(count_q)).scalar_one()
    rows = (await db.execute(_order(_filters(_base(), device_id, group_id, severity, confidence, state, kev))
                             .limit(limit).offset(offset))).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [_match_out(*r) for r in rows]}


@router.get("/matches/export", dependencies=[Depends(require(Perm.VULN_READ))])
async def export_matches(
    device_id: str | None = None, group_id: str | None = None,
    severity: Annotated[list[Literal["critical", "high", "medium", "low", "none"]] | None, Query()] = None,
    confidence: Literal["confirmed", "candidate"] | None = None,
    state: Literal["open", "ack", "fixed", "all"] = "open", kev: bool | None = None,
    db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit),
):
    rows = (await db.execute(_order(_filters(_base(), device_id, group_id, severity, confidence, state, kev))
                             .limit(MAX_EXPORT_ROWS))).all()
    header = ["機器", "グループ", "OS バージョン", "勧告 ID", "CVE", "題", "重大度", "CVSS", "悪用確認済み", "対応の期限（KEV）",
              "判定", "状態", "確認のメモ", "確認した人", "出典"]
    data = [[name, gname or "", m.os_version, a.ext_id, " ".join(a.cve_ids or []), a.title,
             SEVERITY_LABELS.get(a.severity, a.severity), a.cvss, a.kev, a.kev_due.isoformat() if a.kev_due else "",
             "該当" if m.confidence == "confirmed" else "候補", STATE_LABELS.get(m.state, m.state), m.note or "",
             m.acked_by or "", a.url or ""]
            for m, a, name, _gid, gname, *_ in rows]
    audit("vuln.export", detail={"rows": len(data), "state": state})
    await db.commit()
    return csv_response(header, data, export_name("vulns"))


# ---------------------------------------------------------------- 機器別・判定できない機器


@router.get("/devices", dependencies=[Depends(require(Perm.VULN_READ))])
async def list_devices(db: AsyncSession = Depends(get_db)):
    """脆弱性を判定できた機器ごとの件数（未確認の該当）"""
    devices = (await db.execute(select(Device, DeviceGroup.name).outerjoin(DeviceGroup, DeviceGroup.id == Device.group_id)
                                .order_by(Device.name))).all()
    agg: dict[str, dict] = {}
    for dev_id, sev, is_kev, state, n in (await db.execute(
        select(VulnMatch.device_id, VulnAdvisory.severity, VulnAdvisory.kev, VulnMatch.state, func.count())
        .join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
        .where(VulnMatch.state.in_(("open", "ack")), VulnMatch.stale.is_(False))
        .group_by(VulnMatch.device_id, VulnAdvisory.severity, VulnAdvisory.kev, VulnMatch.state)
    )).all():
        a = agg.setdefault(dev_id, {"open": 0, "acked": 0, "kev": 0, **dict.fromkeys(SEVERITIES, 0)})
        if state == "ack":
            a["acked"] += n
            continue
        a["open"] += n
        a[sev] += n
        if is_kev:
            a["kev"] += n
    out = []
    for d, gname in devices:
        if _unknown_reason(d):
            continue
        out.append({"device_id": d.id, "name": d.name, "group_name": gname, "platform": d.platform, "model": d.model,
                    "os_version": d.os_version,
                    **(agg.get(d.id) or {"open": 0, "acked": 0, "kev": 0, **dict.fromkeys(SEVERITIES, 0)})})
    out.sort(key=lambda x: (-x["kev"], -x["critical"], -x["high"], -x["open"], x["name"]))
    return {"items": out}


@router.get("/unknown", dependencies=[Depends(require(Perm.VULN_READ))])
async def list_unknown(db: AsyncSession = Depends(get_db)):
    """判定できない機器（バージョンが読めない・対象外の機種・脆弱性の情報源が未対応）"""
    rows = (await db.execute(select(Device, DeviceGroup.name).outerjoin(DeviceGroup, DeviceGroup.id == Device.group_id)
                             .order_by(Device.name))).all()
    items = []
    for d, gname in rows:
        reason = _unknown_reason(d)
        if reason:
            items.append({"device_id": d.id, "name": d.name, "group_name": gname, "platform": d.platform,
                          "platform_label": PLATFORMS[d.platform].label if d.platform in PLATFORMS else d.platform,
                          "model": d.model, "os_version": d.os_version, "reason": reason, "reason_label": UNKNOWN_LABELS[reason]})
    # 脆弱性を判定できる機器のうち、範囲を読み取れない勧告がある機器（その勧告は該当・非該当のどちらにもしていない）
    advisories = list((await db.execute(select(VulnAdvisory).where(VulnAdvisory.source == "paloalto"))).scalars())
    by_dev = svc.unreadable_by_device([d for d, _ in rows], advisories)
    # 前回は該当だったが、版が変わり、いまの版では判定できない勧告（state・メモは残してある）
    stale: dict[str, list[dict]] = {}
    for m, ext_id in (await db.execute(
        select(VulnMatch, VulnAdvisory.ext_id).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
        .where(VulnMatch.stale.is_(True), VulnMatch.state.in_(("open", "ack"))).order_by(VulnAdvisory.ext_id)
    )).all():
        stale.setdefault(m.device_id, []).append({
            "advisory": ext_id, "previous_version": m.os_version, "state": m.state, "note": m.note,
            "label": f"前回（版 {m.os_version or '不明'}）は該当。版が変わり、いまの版では判定できません"})
    range_unreadable = [{"device_id": d.id, "name": d.name, "group_name": gname, "os_version": d.os_version,
                         "count": len(by_dev.get(d.id, [])), "advisories": by_dev.get(d.id, [])[:10],
                         "stale": stale.get(d.id, [])[:20], "stale_count": len(stale.get(d.id, []))}
                        for d, gname in rows if d.id in by_dev or d.id in stale]
    return {"items": items, "range_unreadable": range_unreadable}


@router.get("/advisories/{advisory_id}", dependencies=[Depends(require(Perm.VULN_READ))])
async def get_advisory(advisory_id: str, db: AsyncSession = Depends(get_db)):
    a = await db.get(VulnAdvisory, advisory_id)
    if a is None:
        raise HTTPException(status_code=404, detail="勧告が見つかりません")
    keys = ("status", "branch", "ge", "lt", "le", "open", "all", "none", "after_all", "fixes", "platforms", "platforms_bad",
            "unreadable", "broken", "entry", "lt_only", "kind",
            "default", "raw", "src")
    return {**_advisory_out(a), "products": a.products or [],
            "affected": [{k: v for k, v in it.items() if k in keys} for it in a.affected or []]}


# ---------------------------------------------------------------- 確認済み


class AckBody(BaseModel):
    note: Note


async def _get_match(db: AsyncSession, match_id: str) -> VulnMatch:
    m = await db.get(VulnMatch, match_id)
    if m is None:
        raise HTTPException(status_code=404, detail="該当の記録が見つかりません")
    return m


async def _audit_target(db: AsyncSession, m: VulnMatch) -> dict:
    dev = await db.get(Device, m.device_id)
    adv = await db.get(VulnAdvisory, m.advisory_id)
    return {"target_type": "device", "target_id": m.device_id, "target_name": dev.name if dev else None,
            "advisory": adv.ext_id if adv else None}


@router.post("/matches/{match_id}/ack")
async def ack(match_id: str, body: AckBody, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit),
              user: User = Depends(require(Perm.VULN_WRITE))):
    m = await _get_match(db, match_id)
    if m.state == "fixed":
        raise HTTPException(status_code=409, detail="すでに解消している（影響範囲から外れた）ため、確認済みにできません")
    t = await _audit_target(db, m)
    before = m.state
    m.state, m.note, m.acked_by, m.acked_at = "ack", body.note, user.username, utcnow()
    audit("vuln.ack", target_type=t["target_type"], target_id=t["target_id"], target_name=t["target_name"],
          detail={"advisory": t["advisory"], "before": before, "note": body.note[:200]})
    await db.commit()
    return {"id": m.id, "state": m.state, "note": m.note, "acked_by": m.acked_by, "acked_at": iso_utc(m.acked_at)}


@router.post("/matches/{match_id}/unack", dependencies=[Depends(require(Perm.VULN_WRITE))])
async def unack(match_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    m = await _get_match(db, match_id)
    if m.state != "ack":
        raise HTTPException(status_code=409, detail="確認済みではありません")
    t = await _audit_target(db, m)
    m.state, m.note, m.acked_by, m.acked_at = "open", None, None, None
    audit("vuln.unack", target_type=t["target_type"], target_id=t["target_id"], target_name=t["target_name"],
          detail={"advisory": t["advisory"]})
    await db.commit()
    return {"id": m.id, "state": m.state}


# ---------------------------------------------------------------- サポート終了日


class EolIn(BaseModel):
    platform: str = Field(max_length=64)
    kind: Literal["os", "hardware"] = "os"
    branch: Annotated[str, StringConstraints(strip_whitespace=True, max_length=32)] = ""  # kind=os: リリース系列（例 10.2）
    model: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] = ""  # kind=hardware: モデル
    eol_date: date
    eos_date: date | None = None
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=NOTE_MAX)] | None = None


def _eol_out(r: EolDate) -> dict:
    return {"id": r.id, "platform": r.platform, "kind": r.kind, "branch": r.branch, "model": r.model,
            "eol_date": r.eol_date.isoformat(), "eos_date": r.eos_date.isoformat() if r.eos_date else None,
            "source": r.source, "url": r.url, "note": r.note, "updated_by": r.updated_by, "updated_at": iso_utc(r.updated_at)}


@router.get("/eol", dependencies=[Depends(require(Perm.VULN_READ))])
async def list_eol(db: AsyncSession = Depends(get_db)):
    rows = sorted(await svc.eol_rows(db), key=lambda r: (r.platform, r.kind, r.branch, r.model, r.source))
    return {"items": [_eol_out(r) for r in rows],
            "platforms": [{"id": k, "label": v.label} for k, v in sorted(PLATFORMS.items(), key=lambda kv: kv[1].label)]}


@router.put("/eol")
async def put_eol(body: EolIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit),
                  user: User = Depends(require(Perm.VULN_WRITE))):
    """手入力のサポート終了日を登録・更新する（同じ platform・種類・系列またはモデルがあれば更新。自動取得より優先される）"""
    if body.platform not in PLATFORMS:
        raise HTTPException(status_code=422, detail="機種（platform）が正しくありません")
    if body.kind == "os":
        if not _BRANCH.match(body.branch):
            raise HTTPException(status_code=422, detail="リリース系列を入力してください（例: 10.2。その機種のすべては *）")
        body.model = ""
    else:
        if not body.model:
            raise HTTPException(status_code=422, detail="モデルを入力してください")
        body.branch = ""
    r = (await db.execute(select(EolDate).where(
        EolDate.platform == body.platform, EolDate.kind == body.kind, EolDate.branch == body.branch,
        EolDate.model == body.model, EolDate.source == "manual"))).scalar_one_or_none()
    created = r is None
    if r is None:
        r = EolDate(platform=body.platform, kind=body.kind, branch=body.branch, model=body.model, source="manual")
        db.add(r)
    r.eol_date, r.eos_date, r.note, r.updated_by, r.url = body.eol_date, body.eos_date, body.note or None, user.username, None
    audit("vuln.eol_set", target_type="eol", target_id=r.id, target_name=body.branch or body.model,
          detail={"platform": body.platform, "kind": body.kind, "branch": body.branch, "model": body.model,
                  "eol_date": body.eol_date.isoformat(), "created": created})
    await db.commit()
    return _eol_out(r)


@router.delete("/eol/{eol_id}", status_code=204, dependencies=[Depends(require(Perm.VULN_WRITE))])
async def delete_eol(eol_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    r = await db.get(EolDate, eol_id)
    if r is None:
        raise HTTPException(status_code=404, detail="サポート終了日が見つかりません")
    if r.source != "manual":
        raise HTTPException(status_code=409, detail="自動取得のサポート終了日は削除できません（手入力の分だけ削除できます）")
    audit("vuln.eol_delete", target_type="eol", target_id=r.id, target_name=r.branch or r.model,
          detail={"platform": r.platform, "kind": r.kind, "branch": r.branch, "model": r.model})
    await db.delete(r)
    await db.commit()


@router.get("/eol/devices", dependencies=[Depends(require(Perm.VULN_READ))])
async def eol_devices(db: AsyncSession = Depends(get_db)):
    """機器ごとの OS・ハードウェアのサポート終了日と残り日数（短い順。日付の無い機器は後ろ）"""
    today = svc.local_today()
    rows = await svc.eol_rows(db)
    devices = (await db.execute(select(Device, DeviceGroup.name).outerjoin(DeviceGroup, DeviceGroup.id == Device.group_id)
                                .order_by(Device.name))).all()
    items = []
    for d, gname in devices:
        e = svc.device_eol(rows, d, today)
        days = [x["days_left"] for x in (e["os"], e["hardware"]) if x]
        items.append({"device_id": d.id, "name": d.name, "group_name": gname, "platform": d.platform, "model": d.model,
                      "os_version": d.os_version, "branch": e.get("branch"), "os": e["os"], "hardware": e["hardware"],
                      "reason": e["reason"], "days_left": min(days) if days else None})
    items.sort(key=lambda x: (x["days_left"] is None, x["days_left"] if x["days_left"] is not None else 0, x["name"]))
    return {"items": items, "soon_days": svc.EOL_SOON_DAYS}


# ---------------------------------------------------------------- いま取得


@router.post("/fetch", status_code=202)
async def fetch_now(db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit),
                    user: User = Depends(require(Perm.SYSTEM_READ))):
    """外部からの取得を今すぐ行う（管理者だけ。worker で実行し、結果は要約の「情報源」に出る）。連続しては実行できない"""
    from app.services import report  # 利用者ごとの間隔の制限（Redis）を使い回す
    from app.worker import fetch_vulns  # 循環 import を避ける

    wait = await report.take_slot("all", "vuln-fetch", svc.MANUAL_FETCH_INTERVAL_SEC)
    if wait:
        raise HTTPException(status_code=429, detail=f"続けて取得できません。{wait} 秒ほど待ってからやり直してください",
                            headers={"Retry-After": str(wait)})
    task = fetch_vulns.delay(True)
    audit("vuln.fetch", detail={"task_id": task.id, "sources": svc.active_sources()})
    await db.commit()
    return {"queued": True, "task_id": task.id}
