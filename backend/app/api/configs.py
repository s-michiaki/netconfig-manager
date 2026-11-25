from collections import Counter
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.config_comments import comment_dict, comments_for
from app.api.config_reviews import review_dict, reviews_for
from app.api.deps import get_current_user, require
from app.core.config import settings
from app.core.csv_export import MAX_EXPORT_ROWS, content_disposition, csv_response, export_name
from app.core.database import get_db
from app.core.permissions import Perm
from app.core.safe_regex import PatternUnavailable
from app.models.device import ConfigBaseline, Device, DeviceGroup
from app.models.user import User
from app.services import config_search
from app.services.audit import Audit, get_audit
from app.services.config_service import (
    MAX_COMPARE_LINES,
    PLATFORMS,
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
    """デバイスのコンフィグ収集履歴（Gitコミット一覧）を返す。世代へのコメント・確認の状態も含める"""
    await _ensure_device(db, device_id)
    history = await run_in_threadpool(get_config_history, device_id, limit)
    hashes = [c["full_hash"] for c in history]
    comments = await comments_for(db, device_id, hashes)
    reviews = await reviews_for(db, device_id, hashes)
    baseline = await db.get(ConfigBaseline, device_id)
    for c in history:
        c["baseline_hash"] = baseline.commit_hash if baseline else None  # 全行に同じ値（画面が「基準」のバッジを付ける）
        found = comments.get(c["full_hash"])
        c["comment"] = comment_dict(found) if found else None
        c["review"] = review_dict(reviews.get(c["full_hash"]))  # 最初の世代（is_first）は確認の対象外
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
    # latest: 最後に収集したコンフィグだけ。history: 過去の世代も含める（since / until で期間を絞れる。日付はサーバーの TIMEZONE）
    scope: str = Field("latest", pattern="^(latest|history)$")
    since: date | None = None
    until: date | None = None


def _period(body: SearchRequest) -> tuple[datetime | None, datetime | None]:
    tz = ZoneInfo(settings.TIMEZONE)
    since = datetime.combine(body.since, time.min, tzinfo=tz) if body.since else None
    until = datetime.combine(body.until + timedelta(days=1), time.min, tzinfo=tz) if body.until else None  # その日の終わりまで
    if since and until and since >= until:
        raise HTTPException(status_code=422, detail="期間の開始日が終了日より後になっています")
    return since, until


# 検索の同時実行数（#16）。検索はスレッドプール（ログインの bcrypt などと共有。既定 40 本）で動き、
# 過去の世代を含めると 1 回で最大 HISTORY_TIMEOUT_SEC 秒かかる。連打や複数のタブでスレッドが埋まらないよう、
# ユーザーごとと全体で上限を設け、超えたら待たせずに 429 を返す。API は 1 プロセスなのでプロセス内で数える
_running: Counter[str] = Counter()


@contextmanager
def _search_slot(user: User):
    total = sum(_running.values())
    if _running[user.id] >= settings.SEARCH_MAX_PER_USER:
        raise HTTPException(status_code=429, detail="前の検索が終わるまでお待ちください")
    if total >= settings.SEARCH_MAX_CONCURRENT:
        raise HTTPException(status_code=429, detail="ほかの検索を実行中です。しばらくしてからもう一度お試しください")
    _running[user.id] += 1  # 確認から加算まで await を挟まないので、同時のリクエストでも数え漏れない
    try:
        yield
    finally:
        _running[user.id] -= 1
        if _running[user.id] <= 0:
            del _running[user.id]


def _run_search(body: SearchRequest, targets: list, context: int, max_lines: int, max_total: int | None):
    if body.scope == "history":
        since, until = _period(body)
        return config_search.search_history(targets, body.query, body.mode, body.case_sensitive, since, until,
                                            max_lines, max_total)
    return config_search.search(targets, body.query, body.mode, body.case_sensitive, context, max_lines, max_total)


async def _threadpool_search(body: SearchRequest, targets: list, context: int, max_lines: int, max_total: int | None):
    try:
        return await run_in_threadpool(_run_search, body, targets, context, max_lines, max_total)
    except PatternUnavailable as e:  # 検証のあとに確かめ直すことになり、それが一時的に失敗した
        raise HTTPException(status_code=503, detail=str(e)) from e


def _local_str(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(ZoneInfo(settings.TIMEZONE)).strftime("%Y/%m/%d %H:%M")


def platform_label(platform: str) -> str:
    spec = PLATFORMS.get(platform)
    return spec.label if spec else platform


def _target_dict(t: config_search.Target) -> dict:
    return {"id": t.id, "name": t.name, "hostname": t.hostname, "platform": t.platform, "group": t.group}


async def _search_targets(db: AsyncSession, body: SearchRequest) -> list[config_search.Target]:
    """検索条件の確認と、対象の機器（機器グループ・機種で絞る。名前順）"""
    if not body.query.strip():
        raise HTTPException(status_code=422, detail="検索する文字列を入力してください")
    try:
        # compile は重くなり得るので、イベントループを止めないようスレッドで行う
        await run_in_threadpool(config_search.build_pattern, body.query, body.mode, body.case_sensitive)
    except config_search.SearchPatternError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except PatternUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    q = select(Device).order_by(Device.name)
    if body.group_id == "none":
        q = q.where(Device.group_id.is_(None))
    elif body.group_id:
        q = q.where(Device.group_id == body.group_id)
    if body.platform:
        q = q.where(Device.platform == body.platform)
    devices = (await db.execute(q)).scalars().all()
    groups = {g.id: g.name for g in (await db.execute(select(DeviceGroup))).scalars().all()}
    return [config_search.Target(d.id, d.name, d.hostname, d.platform, groups.get(d.group_id)) for d in devices]


# 検索語を URL（アクセスログ）に残さないよう POST にしている
@router.post("/search", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def search_configs(body: SearchRequest, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """全機器（または絞り込んだ機器）の最新コンフィグ（scope=history なら過去の世代も）を横断検索する"""
    # 検索語の検証（正規表現の読み込みの重さを子プロセスで測ることがある）も、同時に実行できる数の内側で行う
    with _search_slot(user):
        targets = await _search_targets(db, body)
        if body.scope == "history":
            _period(body)  # 期間の確認（スレッドへ渡す前にエラーを返す）
        res = await _threadpool_search(body, targets, body.context, config_search.MAX_LINES_PER_DEVICE, None)
    return {
        "scope": body.scope,
        "commits_searched": res.commits_searched,
        "partial": [_target_dict(t) for t in res.partial],
        "searched": len(targets) - len(res.not_collected) - len(res.timed_out),
        "matched": len(res.hits),
        "total_lines": res.total_lines,
        "max_lines_per_device": config_search.MAX_LINES_PER_DEVICE,
        "devices": [{**_target_dict(h.target), "count": h.count, "commit": h.commit, "lines": h.lines} for h in res.hits],
        "unmatched": [_target_dict(t) for t in res.unmatched],
        "not_collected": [_target_dict(t) for t in res.not_collected],
        "timed_out": [_target_dict(t) for t in res.timed_out],
    }


@router.post("/search/export", dependencies=[Depends(require(Perm.CONFIG_READ))])
async def export_search(body: SearchRequest, db: AsyncSession = Depends(get_db), audit: Audit = Depends(get_audit),
                        user: User = Depends(get_current_user)):
    """検索結果の CSV（機器・行番号・一致した行）。画面の表示（機器ごとに 50 行）とは別に、一致した行をすべて出す

    - 合計の上限は MAX_EXPORT_ROWS 行、時間の制限は検索と同じ。前後の行は含めない。1 行は検索と同じ長さで切る
    - 調べきれなかった機器の数・上限で打ち切ったかは応答ヘッダーで返す（画面で知らせる）
    - 検索語は URL にも監査ログにも残さない（出力した件数と絞り込み条件だけを残す）
    """
    with _search_slot(user):  # 検索語の検証も同時に実行できる数の内側で行う
        targets = await _search_targets(db, body)
        if body.scope == "history":
            _period(body)
        res = await _threadpool_search(body, targets, 0, MAX_EXPORT_ROWS, MAX_EXPORT_ROWS)
    if body.scope == "history":
        header = ["機器名", "ホスト / IP", "機種", "グループ", "いまもある", "最初に見つかった世代", "その日時",
                  "最後に見つかった世代", "その日時", "一致した行"]
        rows = [
            [h.target.name, h.target.hostname, platform_label(h.target.platform), h.target.group or "",
             "はい" if ln["current"] else "いいえ", ln["first_seen"]["hash"][:7], _local_str(ln["first_seen"]["date"]),
             ln["last_seen"]["hash"][:7], _local_str(ln["last_seen"]["date"]), ln["text"]]
            for h in res.hits for ln in h.lines
        ]
    else:
        header = ["機器名", "ホスト / IP", "機種", "グループ", "世代", "行番号", "一致した行"]
        rows = [
            [h.target.name, h.target.hostname, platform_label(h.target.platform), h.target.group or "",
             (h.commit or "")[:7], ln["line"], ln["text"]]
            for h in res.hits for ln in h.lines
        ]
    truncated = res.total_lines > len(rows)
    audit("config.search_export", detail={
        "rows": len(rows), "devices": len(res.hits), "truncated": truncated, "timed_out": len(res.timed_out),
        "mode": body.mode, "group_id": body.group_id, "platform": body.platform, "scope": body.scope,
        "since": body.since.isoformat() if body.since else None, "until": body.until.isoformat() if body.until else None,
    })
    await db.commit()
    resp = csv_response(header, rows, export_name("config_search"))
    resp.headers["X-Search-Rows"] = str(len(rows))
    resp.headers["X-Search-Total-Lines"] = str(res.total_lines)
    resp.headers["X-Search-Timed-Out"] = str(len(res.timed_out))
    return resp
