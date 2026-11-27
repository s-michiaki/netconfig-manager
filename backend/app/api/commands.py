"""コマンド実行: 複数の機器へ表示コマンド（show / display など）を一括で送り、機器ごとの出力を見る

すべて command:run（オペレーター以上）。出力に設定の中身（show running-config など）が含まれるため、
結果の閲覧も同じ権限にしている（閲覧者には見せない）。
送れるコマンドは services/command_run.py の許可リストで検証する（API と worker の両方）。
監査ログには「誰が・どの機器に・どのコマンドを」だけ残し、出力は残さない。
実際の接続・実行は worker（app/worker.py の run_command_device）。
"""
import csv
import io
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.config_reviews import iso_utc
from app.api.deps import require
from app.core.config import settings
from app.core.csv_export import csv_cell, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.timeutil import utcnow
from app.models.command_run import (
    STATUS_FAILED,
    STATUS_OK,
    STATUS_QUEUED,
    STATUS_SKIPPED,
    CommandResult,
    CommandRun,
)
from app.models.device import Device, DeviceGroup
from app.services import command_run as svc
from app.services.audit import Audit, get_audit
from app.services.config_service import PLATFORMS
from app.worker import enqueue_command_run

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require(Perm.COMMAND_RUN))])

MAX_LIST = 50  # 過去の実行の一覧に出す件数
AUDIT_DEVICE_NAMES = 20  # 監査ログに残す機器名の数

# 1 つの入力が極端に大きいときの歯止め（理由を日本語で返す検査は svc.check_universal が行う）
CommandText = Annotated[str, StringConstraints(max_length=1000)]
DeviceId = Annotated[str, StringConstraints(max_length=36)]


class RunIn(BaseModel):
    device_ids: list[DeviceId] | None = Field(default=None, max_length=1000)
    group_id: Annotated[str, StringConstraints(max_length=36)] | None = None
    commands: list[CommandText] = Field(max_length=50)


def _reject(message: str, status_code: int = 422) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


def _platform_label(platform: str) -> str:
    spec = PLATFORMS.get(platform)
    return spec.label if spec else platform


@router.get("/limits")
async def limits():
    """画面が使う設定と、機種ごとに「先頭に使える語」の例"""
    return {
        "enabled": settings.COMMAND_RUN_ENABLED,
        "max_devices": settings.COMMAND_RUN_MAX_DEVICES,
        "max_commands": svc.MAX_COMMANDS,
        "max_command_length": svc.MAX_COMMAND_LENGTH,
        "max_output": settings.COMMAND_RUN_MAX_OUTPUT,
        "retention_days": settings.COMMAND_RUN_RETENTION_DAYS,
        "heads": {p: r.hint for p in PLATFORMS if (r := svc.rule_for(p)) is not None},
        "unsupported": svc.UNSUPPORTED,
    }


@router.get("/check")
async def check_command(
    command: Annotated[str, Query(max_length=1000)],
    platform: Annotated[str | None, Query(max_length=64)] = None,
):
    """入力中のコマンドの検証。platform を省くと、機種によらない検査（文字・長さ）だけ行う"""
    try:
        cmd = svc.check_universal(command)
        if platform:
            svc.check_platform(platform, cmd)
    except svc.CommandError as e:
        return {"ok": False, "reason": e.reason}
    return {"ok": True, "reason": None}


def _summary_name(names: list[str]) -> str:
    head = "、".join(names[:3])
    return head + (f" ほか {len(names) - 3} 台" if len(names) > 3 else "")


async def _targets(db: AsyncSession, body: RunIn) -> tuple[str, str, list[Device]]:
    """対象の機器（target, 対象の要約, 機器）。対象の指定が正しくなければ 422"""
    if bool(body.device_ids) == bool(body.group_id):
        raise _reject("対象は、機器（device_ids）かグループ（group_id）のどちらか一方で指定してください")
    if body.group_id:
        group = await db.get(DeviceGroup, body.group_id)
        if group is None:
            raise _reject("グループが見つかりません", status.HTTP_404_NOT_FOUND)
        # グループを指定したときは、無効な機器は最初から対象にしない
        devices = list((await db.execute(
            select(Device).where(Device.group_id == group.id, Device.is_active.is_(True)).order_by(Device.name)
        )).scalars().all())
        if not devices:
            raise _reject("このグループには、実行できる（有効な）機器がありません")
        return "group", f"グループ「{group.name}」", devices
    ids = list(dict.fromkeys(body.device_ids or []))
    devices = list((await db.execute(select(Device).where(Device.id.in_(ids)).order_by(Device.name))).scalars().all())
    if len(devices) != len(ids):
        raise _reject("存在しない機器が含まれています。画面を開き直してください")
    return "devices", _summary_name([d.name for d in devices]), devices


async def _check_active_limits(db: AsyncSession, user_id: str) -> None:
    """終わっていない実行（待機中・実行中）が多いときは、新しい実行を断る（機器・worker への負荷の歯止め）"""
    total = (await db.execute(select(func.count()).select_from(CommandRun).where(CommandRun.finished_at.is_(None)))).scalar_one()
    mine = (await db.execute(
        select(func.count()).select_from(CommandRun).where(CommandRun.finished_at.is_(None), CommandRun.created_by_id == user_id)
    )).scalar_one()
    if mine >= settings.COMMAND_RUN_MAX_ACTIVE_PER_USER:
        limit = settings.COMMAND_RUN_MAX_ACTIVE_PER_USER
        raise _reject(f"あなたの実行が {mine} 件動いています（同時に動かせるのは {limit} 件まで）。"
                      "終わってからもう一度実行してください", 429)
    if total >= settings.COMMAND_RUN_MAX_ACTIVE:
        raise _reject(f"全体で {total} 件の実行が動いています（同時に動かせるのは {settings.COMMAND_RUN_MAX_ACTIVE} 件まで）。"
                      "しばらくしてからもう一度実行してください", 429)


@router.post("/runs", status_code=status.HTTP_201_CREATED)
async def create_run(body: RunIn, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """表示コマンドを選んだ機器へ送る実行を作る。送れないコマンドは 422（理由は日本語）。
    機種が混ざるときは機器ごとに検証し、送れない機器は「対象外」として結果に残す"""
    if not settings.COMMAND_RUN_ENABLED:
        raise _reject("コマンド実行は無効に設定されています（COMMAND_RUN_ENABLED）", status.HTTP_403_FORBIDDEN)
    try:
        commands = svc.check_universal_all(list(body.commands))
    except svc.CommandError as e:
        raise _reject(str(e)) from None
    target, target_name, devices = await _targets(db, body)
    if len(devices) > settings.COMMAND_RUN_MAX_DEVICES:
        raise _reject(f"1 回に対象にできる機器は {settings.COMMAND_RUN_MAX_DEVICES} 台までです"
                      f"（{len(devices)} 台選ばれています）")

    await _check_active_limits(db, audit.user.id)
    run = CommandRun(commands=commands, target=target, target_name=target_name[:256], created_by=audit.user.username,
                     created_by_id=audit.user.id, created_at=utcnow(), total=len(devices))
    db.add(run)
    await db.flush()
    results: list[CommandResult] = []
    reasons: dict[str, str] = {}  # 機種の表示名 → 送れない理由（全台が対象外のときの 422 に使う）
    for d in devices:
        status_, error = STATUS_QUEUED, None
        if not d.is_active:
            status_, error = STATUS_SKIPPED, "無効な機器のため、対象外にしました"
        else:
            try:
                svc.validate_for_platform(d.platform, commands)
            except svc.CommandError as e:
                status_, error = STATUS_SKIPPED, f"この機種では送れないコマンドがあるため、対象外にしました（{e}）"
                reasons.setdefault(_platform_label(d.platform), str(e))
        results.append(CommandResult(run_id=run.id, device_id=d.id, device_name=d.name, platform=d.platform,
                                     status=status_, error=error,
                                     finished_at=utcnow() if status_ == STATUS_SKIPPED else None))
    queued = [r for r in results if r.status == STATUS_QUEUED]
    if not queued:
        await db.rollback()
        detail = "；".join(f"{k}: {v}" for k, v in reasons.items()) or "実行できる（有効な）機器がありません"
        raise _reject(f"送れる機器がありません（{detail}）")
    db.add_all(results)
    audit("command.run", target_type="command_run", target_id=run.id, target_name=target_name[:256],
          detail={"commands": commands, "target": target, "devices": len(devices), "skipped": len(devices) - len(queued),
                  "device_names": [d.name for d in devices[:AUDIT_DEVICE_NAMES]]})
    await db.commit()
    try:
        await run_in_threadpool(enqueue_command_run, run.id, [r.id for r in queued])
    except Exception:  # noqa: BLE001 - 投入できなかったら、待たせずに失敗として残す
        logger.exception("コマンド実行を投入できませんでした run=%s", run.id)
        for r in queued:
            row = await db.get(CommandResult, r.id)
            if row is not None and row.status == STATUS_QUEUED:
                row.status, row.finished_at = STATUS_FAILED, utcnow()
                row.error = "実行を投入できませんでした（Redis・worker を確認してください）"
        await svc.mark_finished_if_done(db, run.id)
        await db.commit()
        raise _reject("実行を投入できませんでした。worker・Redis の状態を確認してください",
                      status.HTTP_503_SERVICE_UNAVAILABLE) from None
    return {"id": run.id, "total": run.total, "queued": len(queued), "skipped": len(devices) - len(queued)}


async def _counts(db: AsyncSession, run_ids: list[str]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {rid: dict.fromkeys(("queued", "running", "ok", "failed", "skipped"), 0)
                                      for rid in run_ids}
    if run_ids:
        rows = await db.execute(
            select(CommandResult.run_id, CommandResult.status, func.count())
            .where(CommandResult.run_id.in_(run_ids)).group_by(CommandResult.run_id, CommandResult.status)
        )
        for rid, st, n in rows.all():
            out[rid][st] = n
    return out


def _run_dict(run: CommandRun, counts: dict[str, int]) -> dict:
    return {
        "id": run.id, "commands": list(run.commands), "target": run.target, "target_name": run.target_name,
        "created_by": run.created_by, "created_at": iso_utc(run.created_at), "total": run.total,
        "finished_at": iso_utc(run.finished_at), "finished": run.finished_at is not None, "counts": counts,
    }


@router.get("/runs")
async def list_runs(db: AsyncSession = Depends(get_db)):
    """過去の実行（新しい順に 50 件。ほかのユーザーの実行も見える）。出力は含めない"""
    runs = list((await db.execute(select(CommandRun).order_by(CommandRun.created_at.desc()).limit(MAX_LIST))).scalars().all())
    counts = await _counts(db, [r.id for r in runs])
    return [_run_dict(r, counts[r.id]) for r in runs]


async def _get_run(db: AsyncSession, run_id: str) -> CommandRun:
    run = await db.get(CommandRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="実行が見つかりません（保持期間を過ぎて削除された可能性があります）")
    return run


async def _results(db: AsyncSession, run_id: str) -> list[CommandResult]:
    rows = await db.execute(select(CommandResult).where(CommandResult.run_id == run_id).order_by(CommandResult.device_name))
    return list(rows.scalars().all())


@router.get("/runs/{run_id}")
async def get_run(run_id: str, outputs: bool = True, db: AsyncSession = Depends(get_db),
                  audit: Audit = Depends(get_audit)):
    """実行の状態と、機器ごとの結果。outputs=true なら出力と、コマンドごとの「同じ出力の機器のまとめ（groups）」も返す
    （実行中の進み具合の確認では outputs=false にして、出力を毎回送らない）。

    ほかの人の実行の出力（outputs=true）を開いたら、監査ログ（command.view）に残す（出力は残さない）"""
    run = await _get_run(db, run_id)
    results = await _results(db, run_id)
    if outputs and run.created_by_id != audit.user.id:
        audit("command.view", target_type="command_run", target_id=run.id, target_name=(run.target_name or "")[:256],
              detail={"created_by": run.created_by, "devices": len(results)})
        await db.commit()
    counts = await _counts(db, [run_id])
    body = _run_dict(run, counts[run_id])
    devices, ok_for_groups = [], []
    for r in results:
        items = svc.loads_outputs(r.outputs) if outputs else None
        devices.append({
            "id": r.id, "device_id": r.device_id, "device_name": r.device_name, "platform": r.platform,
            "platform_label": _platform_label(r.platform), "status": r.status, "error": r.error,
            "started_at": iso_utc(r.started_at), "finished_at": iso_utc(r.finished_at),
            "outputs": items,
        })
        if outputs and r.status == STATUS_OK:
            ok_for_groups.append({"result_id": r.id, "device_id": r.device_id, "device_name": r.device_name, "outputs": items})
    body["results"] = devices
    if outputs:
        body["groups"] = svc.group_outputs(list(run.commands), ok_for_groups)
    return body


def _text_export(run: CommandRun, results: list[CommandResult]) -> str:
    lines = [f"# コマンド実行 {iso_utc(run.created_at)}（実行者: {run.created_by}）", f"# 対象: {run.target_name}", ""]
    for r in results:
        lines.append(f"===== {r.device_name}（{_platform_label(r.platform)}） {r.status} =====")
        if r.error:
            lines.append(f"[{r.error}]")
        for it in svc.loads_outputs(r.outputs):
            lines.append(f"--- {it.get('command', '')} ---")
            lines.append((it.get("output") or "").rstrip("\n"))
            if it.get("truncated"):
                kept, total = len(it.get("output") or ""), it.get("chars")
                lines.append(f"[出力が長いため、{kept} 文字で切り捨てています（全体は {total} 文字）]")
        lines.append("")
    return "\n".join(lines)


@router.get("/runs/{run_id}/export")
async def export_run(run_id: str, format: Literal["txt", "csv"] = "txt",
                     db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit)):
    """実行結果のテキスト・CSV 出力（監査ログに記録する）"""
    run = await _get_run(db, run_id)
    results = await _results(db, run_id)
    audit("command.export", target_type="command_run", target_id=run.id, target_name=(run.target_name or "")[:256],
          detail={"format": format, "devices": len(results)})
    await db.commit()
    stamp = export_name("command-run").removesuffix(".csv")
    if format == "txt":
        return Response(content=_text_export(run, results), media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{stamp}.txt"'})
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["機器名", "機種", "状態", "コマンド", "出力", "切り捨て", "エラー"])
    for r in results:
        items = svc.loads_outputs(r.outputs)
        if not items:
            w.writerow([csv_cell(r.device_name), csv_cell(_platform_label(r.platform)), r.status, "", "", "",
                        csv_cell(r.error)])
        for it in items:
            w.writerow([csv_cell(r.device_name), csv_cell(_platform_label(r.platform)), r.status,
                        csv_cell(it.get("command")), csv_cell(it.get("output")), "はい" if it.get("truncated") else "",
                        csv_cell(r.error)])
    return Response(content="﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{stamp}.csv"'})
