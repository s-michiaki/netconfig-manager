"""コンプライアンスチェック API"""
import json
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.api.devices import Platform
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.compliance import ComplianceResult, ComplianceRule
from app.models.device import Device
from app.models.user import User
from app.services.audit import Audit, get_audit
from app.services.compliance import (
    MAX_PATTERN_LENGTH,
    TEMPLATES,
    RuleSpec,
    applies_to,
    evaluate,
    latest_config,
    load_platforms,
    run_checks,
    validate_spec,
)

router = APIRouter()

Severity = Literal["high", "medium", "low"]
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


class RuleIn(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=1000)] | None = None
    platforms: list[Platform] = Field(default_factory=list, max_length=20)  # 空なら全プラットフォーム
    match_type: Literal["contains", "regex"] = "contains"
    expect: Literal["present", "absent"] = "present"
    pattern: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PATTERN_LENGTH)]
    scope: Literal["config", "section"] = "config"
    section_pattern: Annotated[str, StringConstraints(max_length=500)] | None = None
    severity: Severity = "medium"
    enabled: bool = True

    @model_validator(mode="after")
    def _valid(self):
        if self.scope != "section":
            self.section_pattern = None
        validate_spec(self.spec())
        return self

    def spec(self) -> RuleSpec:
        return RuleSpec(
            match_type=self.match_type, expect=self.expect, pattern=self.pattern, scope=self.scope,
            section_pattern=self.section_pattern, platforms=list(self.platforms),
        )


class RuleOut(BaseModel):
    id: str
    name: str
    description: str | None
    platforms: list[str]
    match_type: str
    expect: str
    pattern: str
    scope: str
    section_pattern: str | None
    severity: str
    enabled: bool
    updated_by: str | None
    updated_at: datetime | None
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0


class RuleTest(BaseModel):
    rule: RuleIn
    device_id: str


class RuleTestResult(BaseModel):
    applicable: bool
    has_config: bool
    status: str | None = None
    details: list[str] = Field(default_factory=list)
    commit_hash: str | None = None


class ResultItem(BaseModel):
    device_id: str
    device_name: str
    platform: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    details: list[str]
    commit_hash: str | None
    checked_at: datetime


class DeviceSummary(BaseModel):
    device_id: str
    name: str
    hostname: str
    platform: str
    checked: bool  # 1件以上の検査結果がある
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    worst_severity: str | None = None  # 違反の中で最も重いもの
    checked_at: datetime | None = None


class Summary(BaseModel):
    rules: int  # 有効なルール数
    devices: list[DeviceSummary]
    fail_by_severity: dict[str, int]


def _rule_out(r: ComplianceRule, counts: dict[str, dict[str, int]] | None = None) -> RuleOut:
    c = (counts or {}).get(r.id, {})
    return RuleOut(
        id=r.id, name=r.name, description=r.description, platforms=load_platforms(r.platforms),
        match_type=r.match_type, expect=r.expect, pattern=r.pattern, scope=r.scope,
        section_pattern=r.section_pattern, severity=r.severity, enabled=r.enabled,
        updated_by=r.updated_by, updated_at=r.updated_at,
        pass_count=c.get("pass", 0), fail_count=c.get("fail", 0), error_count=c.get("error", 0),
    )


def _apply(r: ComplianceRule, payload: RuleIn, username: str) -> None:
    r.name = payload.name
    r.description = payload.description or None
    r.platforms = json.dumps(list(payload.platforms))
    r.match_type = payload.match_type
    r.expect = payload.expect
    r.pattern = payload.pattern
    r.scope = payload.scope
    r.section_pattern = payload.section_pattern
    r.severity = payload.severity
    r.enabled = payload.enabled
    r.updated_by = username


def _rule_detail(payload: RuleIn) -> dict:
    return {k: v for k, v in payload.model_dump().items() if k not in ("name", "description")}


async def _rule_counts(db: AsyncSession) -> dict[str, dict[str, int]]:
    rows = (
        await db.execute(
            select(ComplianceResult.rule_id, ComplianceResult.status, func.count()).group_by(
                ComplianceResult.rule_id, ComplianceResult.status
            )
        )
    ).all()
    out: dict[str, dict[str, int]] = {}
    for rule_id, st, n in rows:
        out.setdefault(rule_id, {})[st] = n
    return out


async def _get_rule(db: AsyncSession, rule_id: str) -> ComplianceRule:
    r = await db.get(ComplianceRule, rule_id)
    if r is None:
        raise HTTPException(status_code=404, detail="ルールが見つかりません")
    return r


async def _commit_or_409(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail="同じ名前のルールが既にあります") from e


# ---------------------------------------------------------------- ルール


@router.get("/templates", dependencies=[Depends(require(Perm.COMPLIANCE_READ))])
async def list_templates() -> list[dict]:
    """よく使うルールのひな形"""
    return TEMPLATES


@router.get("/rules", response_model=list[RuleOut], dependencies=[Depends(require(Perm.COMPLIANCE_READ))])
async def list_rules(db: AsyncSession = Depends(get_db)):
    rules = (await db.execute(select(ComplianceRule).order_by(ComplianceRule.name))).scalars().all()
    counts = await _rule_counts(db)
    return [_rule_out(r, counts) for r in rules]


@router.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.COMPLIANCE_WRITE)),
    audit: Audit = Depends(get_audit),
):
    r = ComplianceRule(id=str(uuid.uuid4()))
    _apply(r, payload, user.username)
    db.add(r)
    audit("compliance.rule_create", target_type="compliance_rule", target_id=r.id, target_name=r.name,
          detail=_rule_detail(payload))
    await _commit_or_409(db)
    # 作成したルールで全機器を検査する
    await run_checks(db, rule_ids=[r.id])
    await db.commit()
    await db.refresh(r)
    return _rule_out(r, await _rule_counts(db))


@router.put("/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: str,
    payload: RuleIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.COMPLIANCE_WRITE)),
    audit: Audit = Depends(get_audit),
):
    r = await _get_rule(db, rule_id)
    _apply(r, payload, user.username)
    audit("compliance.rule_update", target_type="compliance_rule", target_id=r.id, target_name=r.name,
          detail=_rule_detail(payload))
    await _commit_or_409(db)
    await run_checks(db, rule_ids=[r.id])
    await db.commit()
    await db.refresh(r)
    return _rule_out(r, await _rule_counts(db))


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require(Perm.COMPLIANCE_WRITE)),
    audit: Audit = Depends(get_audit),
):
    r = await _get_rule(db, rule_id)
    await db.execute(delete(ComplianceResult).where(ComplianceResult.rule_id == r.id))
    await db.delete(r)
    audit("compliance.rule_delete", target_type="compliance_rule", target_id=r.id, target_name=r.name)
    await db.commit()


@router.post("/rules/test", response_model=RuleTestResult, dependencies=[Depends(require(Perm.COMPLIANCE_READ))])
async def test_rule(payload: RuleTest, db: AsyncSession = Depends(get_db)):
    """保存せずに、指定した機器の現在のコンフィグでルールを試す"""
    d = await db.get(Device, payload.device_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Device not found")
    spec = payload.rule.spec()
    if not applies_to(spec, d.platform):
        return RuleTestResult(applicable=False, has_config=True)
    loaded = await run_in_threadpool(latest_config, d.id)
    if loaded is None:
        return RuleTestResult(applicable=True, has_config=False)
    text, commit = loaded
    ev = await run_in_threadpool(evaluate, spec, text)
    return RuleTestResult(applicable=True, has_config=True, status=ev.status, details=ev.details, commit_hash=commit)


# ---------------------------------------------------------------- 結果


@router.post("/run", dependencies=[Depends(require(Perm.COMPLIANCE_WRITE))])
async def run_all(db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """全機器 × 全ルールを再検査する"""
    result = await run_checks(db)
    audit("compliance.run", detail=result)
    await db.commit()
    return result


@router.get("/results", response_model=list[ResultItem], dependencies=[Depends(require(Perm.COMPLIANCE_READ))])
async def list_results(
    device_id: str | None = None,
    rule_id: str | None = None,
    status_filter: Literal["pass", "fail", "error"] | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(ComplianceResult, Device, ComplianceRule)
        .join(Device, Device.id == ComplianceResult.device_id)
        .join(ComplianceRule, ComplianceRule.id == ComplianceResult.rule_id)
    )
    if device_id:
        q = q.where(ComplianceResult.device_id == device_id)
    if rule_id:
        q = q.where(ComplianceResult.rule_id == rule_id)
    if status_filter:
        q = q.where(ComplianceResult.status == status_filter)
    rows = (await db.execute(q)).all()
    items = [
        ResultItem(
            device_id=d.id, device_name=d.name, platform=d.platform, rule_id=r.id, rule_name=r.name,
            severity=r.severity, status=res.status, details=json.loads(res.detail) if res.detail else [],
            commit_hash=res.commit_hash, checked_at=res.checked_at,
        )
        for res, d, r in rows
    ]
    # 重い違反 → 機器名 → ルール名 の順
    items.sort(key=lambda x: (x.status == "pass", -SEVERITY_ORDER.get(x.severity, 0), x.device_name, x.rule_name))
    return items


@router.get("/summary", response_model=Summary, dependencies=[Depends(require(Perm.COMPLIANCE_READ))])
async def summary(db: AsyncSession = Depends(get_db)):
    enabled = (
        await db.execute(select(func.count()).select_from(ComplianceRule).where(ComplianceRule.enabled.is_(True)))
    ).scalar_one()
    devices = (await db.execute(select(Device).order_by(Device.name))).scalars().all()
    rows = (
        await db.execute(
            select(ComplianceResult.device_id, ComplianceResult.status, ComplianceRule.severity,
                   ComplianceResult.checked_at)
            .join(ComplianceRule, ComplianceRule.id == ComplianceResult.rule_id)
        )
    ).all()
    per: dict[str, DeviceSummary] = {
        d.id: DeviceSummary(device_id=d.id, name=d.name, hostname=d.hostname, platform=d.platform, checked=False)
        for d in devices
    }
    fail_by_severity = {"high": 0, "medium": 0, "low": 0}
    for device_id, st, sev, at in rows:
        s = per.get(device_id)
        if s is None:
            continue
        s.checked = True
        s.checked_at = max(filter(None, [s.checked_at, at]), default=None)
        if st == "pass":
            s.pass_count += 1
        elif st == "fail":
            s.fail_count += 1
            fail_by_severity[sev] = fail_by_severity.get(sev, 0) + 1
            if s.worst_severity is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(s.worst_severity, 0):
                s.worst_severity = sev
        else:
            s.error_count += 1
    return Summary(rules=enabled, devices=list(per.values()), fail_by_severity=fail_by_severity)


async def violation_counts(db: AsyncSession, device_ids: set[str]) -> dict[str, tuple[int, str | None]]:
    """機器ごとの違反数と最も重い重要度（構成図の表示用）"""
    if not device_ids:
        return {}
    rows = (
        await db.execute(
            select(ComplianceResult.device_id, ComplianceRule.severity)
            .join(ComplianceRule, ComplianceRule.id == ComplianceResult.rule_id)
            .where(ComplianceResult.device_id.in_(device_ids), ComplianceResult.status == "fail")
        )
    ).all()
    out: dict[str, tuple[int, str | None]] = {}
    for device_id, sev in rows:
        n, worst = out.get(device_id, (0, None))
        if worst is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(worst, 0):
            worst = sev
        out[device_id] = (n + 1, worst)
    return out
