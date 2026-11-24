"""収集時に無視する行の設定 API（管理者のみ）

毎回変わる行（時刻・カウンタなど）を、機種または機器ごとの正規表現で追加し、変更扱いにしない。
適用は収集のたび（保存前）。過去の世代は変えない。仕組みは services/ignore_rules.py。
「試す」はコンフィグの中身（一致した行）を返すため、一覧・変更と同じく config:ignore（管理者）だけに許す。
監査ログには正規表現・対象だけを残し、一致した行の中身は残さない。
正規表現の検証（コンパイル・空の行への照合）は重くなり得るので、pydantic の validator の中ではなく、
run_in_threadpool で行う（イベントループを止めない）。
保存時も「試す」と同じ割合を計算し、全行の 50% 以上が消える機器があれば、confirm_broad が無い限り 409 にする。
"""
import time
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, StringConstraints, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require
from app.api.devices import Platform
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Perm
from app.models.device import Device
from app.models.ignore_rule import ConfigIgnoreRule
from app.models.user import User
from app.services.audit import Audit, get_audit
from app.services.config_service import PLATFORMS
from app.services.ignore_rules import (
    MAX_PATTERN_LENGTH,
    WARN_RATIO,
    preview_device,
    preview_targets,
    validate_pattern,
)

router = APIRouter(dependencies=[Depends(require(Perm.CONFIG_IGNORE))])

Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)]


class Target(BaseModel):
    scope: Literal["platform", "device"]
    platform: Platform | None = None
    device_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    # 前後の空白は正規表現の一部なので削らない
    pattern: Annotated[str, StringConstraints(min_length=1, max_length=MAX_PATTERN_LENGTH)]

    @model_validator(mode="after")
    def _valid(self):
        if self.scope == "platform":
            if not self.platform:
                raise ValueError("機種を選んでください")
            self.device_id = None
        else:
            if not self.device_id:
                raise ValueError("機器を選んでください")
            self.platform = None
        return self


class RuleIn(Target):
    description: Description | None = None
    enabled: bool = True
    # 全行の 50% 以上が消える機器があっても保存する（画面の確認のダイアログで了承したとき）
    confirm_broad: bool = False


BROAD_CODE = "ignore_rule_broad"  # 409 の detail.code（画面が確認のダイアログを出す目印）


class RuleOut(BaseModel):
    id: str
    scope: str
    platform: str | None
    platform_label: str | None
    device_id: str | None
    device_name: str | None
    pattern: str
    description: str | None
    enabled: bool
    created_by: str | None
    updated_by: str | None
    updated_at: str | None


def _rule_out(r: ConfigIgnoreRule, names: dict[str, str]) -> RuleOut:
    spec = PLATFORMS.get(r.platform or "")
    return RuleOut(
        id=r.id, scope=r.scope, platform=r.platform, platform_label=spec.label if spec else r.platform,
        device_id=r.device_id, device_name=names.get(r.device_id or ""), pattern=r.pattern,
        description=r.description, enabled=r.enabled, created_by=r.created_by, updated_by=r.updated_by,
        updated_at=r.updated_at.isoformat() + "Z" if r.updated_at else None,
    )


async def _names(db: AsyncSession, rules: list[ConfigIgnoreRule]) -> dict[str, str]:
    ids = {r.device_id for r in rules if r.device_id}
    if not ids:
        return {}
    rows = await db.execute(select(Device.id, Device.name).where(Device.id.in_(ids)))
    return dict(rows.all())


async def _check_device(db: AsyncSession, body: Target) -> None:
    if body.scope == "device" and await db.get(Device, body.device_id) is None:
        raise HTTPException(status_code=422, detail="機器が見つかりません")


async def _check_pattern(body: Target) -> None:
    """正規表現の検証（422）。コンパイル・照合はスレッドで行う"""
    try:
        await run_in_threadpool(validate_pattern, body.pattern)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e


async def _run_preview(db: AsyncSession, body: Target) -> list[dict]:
    """対象の機器ごとに、最新の世代へ正規表現を当てた結果（試す・保存時の確認で共通）"""
    devices = await preview_targets(db, body.scope, body.platform, body.device_id)
    end = time.monotonic() + settings.IGNORE_TOTAL_TIMEOUT
    items = []
    for d in devices:
        res = await run_in_threadpool(preview_device, d.id, body.pattern, end)
        items.append({"device_id": d.id, "device_name": d.name, **res})
    return items


def _heavy(items: list[dict]) -> list[dict]:
    """全行の WARN_RATIO 以上に一致する機器（割合の大きい順）"""
    heavy = [i for i in items if i["total_lines"] and i["matched_lines"] / i["total_lines"] >= WARN_RATIO]
    return sorted(heavy, key=lambda i: -i["matched_lines"] / i["total_lines"])


def _pct(i: dict) -> int:
    return int(i["matched_lines"] * 100 / i["total_lines"])


async def _check_broad(db: AsyncSession, body: RuleIn) -> None:
    """保存時の歯止め: 全行の 50% 以上が消える機器があれば、了承（confirm_broad）が無い限り 409"""
    if not body.enabled or body.confirm_broad:
        return  # 無効のルールは収集で使わない（有効にするときに確認する）
    heavy = _heavy(await _run_preview(db, body))
    if not heavy:
        return
    top = heavy[0]
    message = f"{top['device_name']} で全行の {_pct(top)}% が消えます"
    if len(heavy) > 1:
        message += f"（ほか {len(heavy) - 1} 台でも {int(WARN_RATIO * 100)}% 以上）"
    raise HTTPException(status_code=409, detail={
        "code": BROAD_CODE, "message": message,
        "devices": [{"device_id": i["device_id"], "device_name": i["device_name"], "percent": _pct(i),
                     "matched_lines": i["matched_lines"], "total_lines": i["total_lines"]} for i in heavy[:10]],
    })


def _detail(body: RuleIn, names: dict[str, str]) -> dict:
    # 正規表現と対象だけ。一致した行（コンフィグの中身）は残さない
    return {"scope": body.scope, "platform": body.platform, "device_id": body.device_id,
            "device": names.get(body.device_id or ""), "pattern": body.pattern, "enabled": body.enabled}


async def _get(db: AsyncSession, rule_id: str) -> ConfigIgnoreRule:
    r = await db.get(ConfigIgnoreRule, rule_id)
    if r is None:
        raise HTTPException(status_code=404, detail="ルールが見つかりません")
    return r


@router.get("/", response_model=list[RuleOut])
async def list_rules(db: AsyncSession = Depends(get_db)):
    rules = (await db.execute(
        select(ConfigIgnoreRule).order_by(ConfigIgnoreRule.scope, ConfigIgnoreRule.created_at))).scalars().all()
    names = await _names(db, list(rules))
    return [_rule_out(r, names) for r in rules]


@router.post("/", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleIn, db: AsyncSession = Depends(get_db), user: User = Depends(require(Perm.CONFIG_IGNORE)),
    audit: Audit = Depends(get_audit),
):
    await _check_device(db, body)
    await _check_pattern(body)
    await _check_broad(db, body)
    r = ConfigIgnoreRule(id=str(uuid.uuid4()), created_by=user.username, updated_by=user.username)
    _fill(r, body)
    db.add(r)
    names = await _names(db, [r])
    audit("ignore_rule.create", target_type="ignore_rule", target_id=r.id, target_name=body.pattern[:100],
          detail=_detail(body, names))
    await db.commit()
    await db.refresh(r)
    return _rule_out(r, names)


def _fill(r: ConfigIgnoreRule, body: RuleIn) -> None:
    r.scope, r.platform, r.device_id = body.scope, body.platform, body.device_id
    r.pattern, r.description, r.enabled = body.pattern, body.description or None, body.enabled


@router.put("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: str, body: RuleIn, db: AsyncSession = Depends(get_db), user: User = Depends(require(Perm.CONFIG_IGNORE)),
    audit: Audit = Depends(get_audit),
):
    r = await _get(db, rule_id)
    await _check_device(db, body)
    await _check_pattern(body)
    await _check_broad(db, body)
    # 変更前の対象も残す（一致した行の中身は残さない）
    before = {"scope": r.scope, "platform": r.platform, "device_id": r.device_id, "pattern": r.pattern,
              "enabled": r.enabled}
    _fill(r, body)
    r.updated_by = user.username
    names = await _names(db, [r])
    audit("ignore_rule.update", target_type="ignore_rule", target_id=r.id, target_name=body.pattern[:100],
          detail={**_detail(body, names), "before": before})
    await db.commit()
    await db.refresh(r)
    return _rule_out(r, names)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    r = await _get(db, rule_id)
    names = await _names(db, [r])
    audit("ignore_rule.delete", target_type="ignore_rule", target_id=r.id, target_name=r.pattern[:100],
          detail={"scope": r.scope, "platform": r.platform, "device": names.get(r.device_id or ""),
                  "pattern": r.pattern})
    await db.delete(r)
    await db.commit()


@router.post("/preview")
async def preview(body: Target, db: AsyncSession = Depends(get_db)):
    """保存せずに試す: 対象の機器の最新の世代に当て、機器ごとの一致した行数と例を返す"""
    await _check_device(db, body)
    await _check_pattern(body)
    items = await _run_preview(db, body)
    heavy = _heavy(items)
    warning = None
    if heavy:
        warning = (f"{', '.join(i['device_name'] for i in heavy[:3])}"
                   f"{' ほか' if len(heavy) > 3 else ''} で全行の {int(WARN_RATIO * 100)}% 以上に一致します。"
                   "正規表現が広すぎないか確認してください")
    return {"devices": items, "timeout": any(i["timeout"] for i in items), "warning": warning,
            "matched_total": sum(i["matched_lines"] for i in items)}
