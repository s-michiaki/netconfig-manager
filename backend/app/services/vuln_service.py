"""脆弱性・サポート終了日: 取得の実行と保存・機器との照合・画面向けの集計（DB を使う側）

流れ
  run_fetch   : 情報源ごとに取得（services/vuln_fetch.py）→ 保存 → 取得の結果を vuln_sources に記録。1 つの失敗でほかを止めない
  reconcile   : 保存済みの勧告と機器の OS バージョンを照合して、vuln_matches を更新する（外部へはつながない）
                取得のあと全機器に対して、機器の OS バージョンが変わったとき（収集のあと）にその機器だけ行う
  due         : 毎日 VULN_FETCH_HOUR 時以降の最初の判定で取得する（成功した日は取らない。失敗は間をあけて再試行）

判定の移り変わり（vuln_matches.state）
  open  : 該当している（新しく該当したときはここから）
  ack   : 確認済み（対応不要。メモ必須）。バージョンが変わっても ack のまま。影響範囲から外れたら fixed
  fixed : バージョンが上がるなどして影響範囲から外れた。また該当したら open に戻す（確認済みの印は外す）
OS バージョンが読めない機器は照合しない（既存の判定は変えない）
"""
import asyncio
import json
import logging
import time
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import event, or_, select
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.device import Device
from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
from app.services import vuln_fetch as fetch
from app.services import vuln_match as vm

logger = logging.getLogger(__name__)

# 取得する順（kev を先に取っておくと、勧告の保存と同じ回に悪用確認済みの印が付く）
SOURCE_ORDER = ("kev", "paloalto", "fortinet", "eol")
ADVISORY_SOURCES = ("paloalto", "fortinet")  # 勧告の情報源（照合に使う）
SOURCE_LABELS = {"paloalto": "Palo Alto の勧告", "fortinet": "Fortinet の勧告（FortiOS）",
                 "kev": "CISA の悪用確認済み一覧（KEV）", "eol": "サポート終了日（endoflife.date）"}
RETRY_AFTER_MIN = 180  # 失敗した情報源を、次に試すまでの時間（毎時の判定のたびに外へつなぎに行かない）
STALE_DAYS = 3  # この日数より前から取得できていなければ、システム状態で注意
MANUAL_FETCH_INTERVAL_SEC = 300  # 「いま取得」の間隔
MANUAL_IMPORT_INTERVAL_SEC = 60  # Fortinet の過去の勧告の取り込みの間隔
# Fortinet: 1 回の取得で取る勧告の文書（CSAF）の上限と、Fortinet の分の時間の上限（残りは次回）
FORTINET_MAX_DOCS = 60
FORTINET_BUDGET_SEC = 600
FORTINET_IMPORT_MAX = 20  # 過去の勧告の取り込みで、1 回に指定できる ID の数
# 1 回の取得で最悪かかる秒数（kev・paloalto 各 1 回、eol の製品ごと 1 回、Fortinet の時間の上限と、
# 上限の直前に始めた 1 回。1 回は fetch.TOTAL_TIMEOUT で打ち切る）
MAX_FETCH_SECONDS = ((2 + len(fetch.EOL_PRODUCTS)) * (fetch.TOTAL_TIMEOUT + 2)
                     + FORTINET_BUDGET_SEC + fetch.TOTAL_TIMEOUT + 2 * fetch.FORTINET_INTERVAL_SEC)
EOL_SOON_DAYS = 365  # 「終了間近」とみなす日数


def active_sources() -> list[str]:
    wanted = set(settings.vuln_sources)
    return [s for s in SOURCE_ORDER if s in wanted]


def unknown_sources() -> list[str]:
    """VULN_SOURCES に書かれているが、この版では使えない名前（nvd は今後の対応。スペルミスも）"""
    return [s for s in settings.vuln_sources if s not in SOURCE_ORDER]


# ---------------------------------------------------------------- 取得の記録


async def _source_row(db: AsyncSession, name: str) -> VulnSource:
    row = await db.get(VulnSource, name)
    if row is None:
        row = VulnSource(source=name)
        db.add(row)
    return row


def local_now() -> datetime:
    return datetime.now(ZoneInfo(settings.TIMEZONE))


def local_today() -> date:
    """残り日数の数え始めの「今日」（TIMEZONE の日付。UTC の日付は使わない）"""
    return local_now().date()


VULN_WRITE_LOCK_KEY = 7_204_001_126  # pg_advisory_xact_lock の鍵（コンプライアンスの結果とは別）


async def lock_vuln_writes(db: AsyncSession) -> None:
    """照合結果（vuln_matches）の書き換えを直列にする（PostgreSQL のみ。commit / rollback で自動的に外れる）

    取得のあとの全機器の照合と、収集のあとの 1 台の照合が同時に走ると、READ COMMITTED では互いの INSERT が見えず、
    一意制約（uq_vuln_matches_device_advisory）に当たって片方の照合がまるごと捨てられるため。
    ロックを取ってから既存の行を読むので、あとから来た側は先の結果を見て「あれば更新、無ければ作成」になる。
    機器の削除（照合結果を消してから機器を消す）も同じロックを先に取る。SQLite（テスト）は書き込みがもともと直列
    """
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(sql_text("SELECT pg_advisory_xact_lock(:k)"), {"k": VULN_WRITE_LOCK_KEY})


def _local_date(dt: datetime) -> date:
    """DB の UTC の日時 → TIMEZONE の日付"""
    from datetime import UTC

    return dt.replace(tzinfo=UTC).astimezone(ZoneInfo(settings.TIMEZONE)).date()


async def due_sources(db: AsyncSession, now: datetime | None = None, now_local: datetime | None = None) -> list[str]:
    """いま取りに行く情報源。毎日 VULN_FETCH_HOUR 時以降に、その日まだ成功していないもの（失敗は間をあけて再試行）"""
    now = now or utcnow()
    now_local = now_local or local_now()
    if now_local.hour < settings.VULN_FETCH_HOUR:
        return []
    out = []
    for name in active_sources():
        row = await db.get(VulnSource, name)
        if row is not None:
            if row.last_ok_at and _local_date(row.last_ok_at) >= now_local.date():
                continue
            if row.last_at and row.last_error and now - row.last_at < timedelta(minutes=RETRY_AFTER_MIN):
                continue
        out.append(name)
    return out


# ---------------------------------------------------------------- 保存


async def store_paloalto(db: AsyncSession, advisories: list[dict], now: datetime, rejected: list[str] | None = None,
                         broken: list[dict] | None = None, emptied: list[str] | None = None) -> int:
    """勧告を保存する

    - 取り下げ（REJECTED）と分かった保存済みの勧告は rejected にし、その勧告の未確認・確認済みの判定を解消にする（メモは残す）
    - 記録として読めなかった勧告（broken）は、取得の記録の skipped に数える。ID が分かれば、古い範囲のまま判定を続けず、
      「範囲を読み取れない」行だけの勧告として保存する（保存済みなら上書き。どの機器でも「判定できない」になる）
    - 影響なしの行だけに改訂された保存済みの勧告（emptied）は、範囲を空に上書きする（照合で解消になる）
    - 応答から消えただけの勧告は、取得の一時的な欠けと区別できないので何もしない
    """
    existing = {a.ext_id: a for a in (await db.execute(
        select(VulnAdvisory).where(VulnAdvisory.source == "paloalto"))).scalars()}
    published = {d["ext_id"] for d in advisories}
    for ext_id in sorted(set(rejected or []) - published):
        a = existing.get(ext_id)
        if a is None:
            continue
        a.rejected, a.fetched_at = True, now
        await lock_vuln_writes(db)
        for m in (await db.execute(select(VulnMatch).where(VulnMatch.advisory_id == a.id,
                                                           VulnMatch.state.in_(("open", "ack"))))).scalars():
            m.state, m.stale, m.fixed_reason = "fixed", False, "rejected"
    for ext_id in sorted(set(emptied or []) - published):
        if (a := existing.get(ext_id)) is not None:
            a.affected, a.rejected, a.fetched_at = [], False, now
    broken_ids: dict[str, str] = {}
    for b in broken or []:
        if b.get("ext_id") and b["ext_id"] not in published:
            broken_ids.setdefault(b["ext_id"], b.get("reason") or "記録を読み取れません")
    for ext_id, reason in sorted(broken_ids.items()):
        a = existing.get(ext_id)
        if a is None:
            a = existing[ext_id] = VulnAdvisory(source="paloalto", ext_id=ext_id, title=ext_id, severity="none",
                                                cve_ids=[ext_id] if ext_id.startswith("CVE-") else [],
                                                url=fetch.PALOALTO_URL_BASE + ext_id)
            db.add(a)
        a.products = ["paloalto_panos"]
        # broken: 記録そのものを読めない（前回の判定は古い範囲によるもの。照合で stale にする）
        a.affected = [{"unreadable": True, "branch": None, "broken": True,
                       "raw": f"勧告の記録を読み取れません（{reason}）"[:120]}]
        a.rejected, a.fetched_at = False, now
    for d in advisories:
        a = existing.get(d["ext_id"])
        if a is None:
            a = existing[d["ext_id"]] = VulnAdvisory(source="paloalto", ext_id=d["ext_id"])
            db.add(a)
        for k in ("cve_ids", "title", "severity", "cvss", "published_at", "modified_at", "url", "products", "affected"):
            setattr(a, k, d[k])
        a.rejected = False  # 取り下げのあとで再び公開された
        a.fetched_at = now
    row = await _source_row(db, "paloalto")
    # 範囲を読み取れなかった行の数＋記録として読めなかった勧告の数
    row.skipped = sum(d.get("unreadable", 0) for d in advisories) + len(broken or [])
    return len(advisories)


async def store_kev(db: AsyncSession, kev: dict[str, str]) -> int:
    row = await _source_row(db, "kev")
    row.cursor = json.dumps(kev, separators=(",", ":"))
    return len(kev)


async def apply_kev(db: AsyncSession) -> int:
    """取得済みの KEV の一覧で、勧告の kev・kev_due を付け直す（kev を使う設定のときだけ）。変えた件数を返す"""
    if "kev" not in active_sources():
        return 0
    row = await db.get(VulnSource, "kev")
    if row is None or not row.cursor:
        return 0
    try:
        kev = json.loads(row.cursor)
    except ValueError:
        return 0
    changed = 0
    for a in (await db.execute(select(VulnAdvisory))).scalars():
        hits = [c for c in a.cve_ids or [] if c in kev]
        due = min((date.fromisoformat(kev[c]) for c in hits if kev[c]), default=None)
        if a.kev != bool(hits) or a.kev_due != due:
            a.kev, a.kev_due = bool(hits), due
            changed += 1
    return changed


async def store_eol(db: AsyncSession, rows: list[dict], now: datetime) -> int:
    """自動取得のサポート終了日（source=endoflife.date）を保存する。手入力（manual）の行には触れない"""
    existing = {(e.platform, e.branch): e for e in (await db.execute(
        select(EolDate).where(EolDate.kind == "os", EolDate.source == "endoflife.date"))).scalars()}
    for r in rows:
        e = existing.get((r["platform"], r["branch"]))
        if e is None:
            e = existing[(r["platform"], r["branch"])] = EolDate(
                platform=r["platform"], kind="os", branch=r["branch"], model="", source="endoflife.date")
            db.add(e)
        e.eol_date, e.url, e.updated_at = r["eol_date"], r["url"], now
    return len(rows)


# ---------------------------------------------------------------- 取得の実行


async def _fetch_one(db: AsyncSession, name: str, now: datetime) -> int:
    """1 つの情報源を取得して保存する（件数を返す）。失敗は FetchError"""
    if name == "kev":
        return await store_kev(db, fetch.parse_kev(await asyncio.to_thread(fetch.fetch_json, fetch.URL_KEV)))
    if name == "paloalto":
        data = await asyncio.to_thread(fetch.fetch_json, fetch.URL_PALOALTO)
        if isinstance(data, dict) and any(data.get(k) for k in ("next", "nextPage", "next_page", "nextCursor", "hasMore")):
            # 応答に続きを示す項目はない（2026-11 時点）。出てきたら、取りこぼしの可能性があるので記録に残す
            logger.warning("Palo Alto の応答に続きを示す項目があります。1 ページ目だけを読みました")
        rejected: list[str] = []
        broken: list[dict] = []
        emptied: list[str] = []
        advisories = fetch.parse_paloalto(data, rejected, broken, emptied)
        return await store_paloalto(db, advisories, now, rejected, broken, emptied)
    if name == "fortinet":
        return await fetch_fortinet(db, now)
    if name == "eol":
        rows: list[dict] = []
        failed: list[str] = []
        for product in fetch.EOL_PRODUCTS:
            try:
                data = await asyncio.to_thread(fetch.fetch_json, fetch.URL_EOL.format(product=product))
                rows += fetch.parse_eol(product, data)
            except fetch.FetchError as e:
                failed.append(f"{product}: {e}")
        n = await store_eol(db, rows, now)
        if failed:  # 取れた製品は保存する（rollback で消えないよう先に確定）。1 つでも失敗したら、この情報源は失敗として記録する
            await db.commit()
            raise fetch.FetchError("；".join(failed)[:280])
        return n
    raise fetch.FetchError("未対応の情報源です")


async def run_fetch(db: AsyncSession, sources: list[str] | None = None, now: datetime | None = None) -> dict:
    """情報源ごとに取得して保存し、最後に機器と照合する。1 つの失敗でほかを止めない（失敗は vuln_sources に記録）"""
    now = now or utcnow()
    todo = [s for s in (sources if sources is not None else active_sources()) if s in SOURCE_ORDER]
    todo.sort(key=SOURCE_ORDER.index)
    result: dict = {"sources": {}}
    for name in todo:
        try:
            count = await _fetch_one(db, name, now)
            err = None
        except fetch.FetchError as e:
            await db.rollback()
            count, err = None, str(e)[:300]
        except Exception as e:  # noqa: BLE001 - 想定外でも、ほかの情報源を止めない。例外の文言は載せない
            await db.rollback()
            logger.exception("脆弱性情報の取得で想定外のエラー source=%s", name)
            count, err = None, f"想定外のエラーです（{type(e).__name__}）"
        row = await _source_row(db, name)
        row.last_at = now
        if err is None:
            row.last_ok_at, row.last_error, row.last_count = now, None, count
        else:
            row.last_error = err
        await db.commit()
        result["sources"][name] = {"ok": err is None, "count": count, "error": err}
    if any(v["ok"] for v in result["sources"].values()):
        try:
            await apply_kev(db)
            result["matches"] = await reconcile(db, now=now)
            await db.commit()
        except Exception:  # noqa: BLE001 - 取得の記録は保存済み。照合の失敗は次回にやり直せる
            await db.rollback()
            logger.exception("脆弱性の照合に失敗しました")
            result["matches"] = {"error": True}
    return result


# ---------------------------------------------------------------- 照合


async def reconcile(db: AsyncSession, device_ids: list[str] | None = None, now: datetime | None = None) -> dict:
    """保存済みの勧告と、機器の OS バージョン・モデルを照合して vuln_matches を更新する（外部へはつながない。commit は呼び出し側）

    戻り値: {"new": [(device_id, advisory_id) 新しく該当（再び該当を含む）], "fixed": 外れた件数, "devices": 照合した機器の数}
    範囲を読み取れなかった勧告（unreadable）は、該当にも非該当にもしない。その機器×勧告の既存の判定は、
    - 判定を出したときの版（m.os_version）と機器のいまの版が同じなら据え置く（前回の判定はその版についてのもの）
    - 版が違えば「該当」のまま据え置かず、stale（前回は該当・いまの版では判定できない）にする。該当の件数・一覧から外れ、
      「判定できない機器」に出る。state（未確認・確認済み）とメモは消さない。版が戻るか、判定できれば stale を外す
    - 版が読めなくなった機器も同じ（版が違えば stale）。脆弱性の対象外の platform に変わった機器は、版を問わず stale
      （前回の該当は、いまの機種・版についてのものではない）。版の比較は前後の空白を除いてから
    取り下げられた勧告（rejected）は照合に使わない（その勧告の残っている判定は解消になる）
    """
    now = now or utcnow()
    if device_ids is not None and not device_ids:
        return {"new": [], "fixed": 0, "devices": 0}
    await lock_vuln_writes(db)  # 同時の照合を直列にする（既存の行はロックのあとに読む）
    # 照合する機器: 脆弱性の対象の platform の機器と、対象外に変わったが未確認・確認済みの判定が残っている機器
    has_open = select(VulnMatch.device_id).where(VulnMatch.state.in_(("open", "ack")))
    q = select(Device).where(or_(Device.platform.in_(sorted(vm.CONFIRMED_PLATFORMS)), Device.id.in_(has_open)))
    if device_ids is not None:
        q = q.where(Device.id.in_(device_ids))
    devices = (await db.execute(q)).scalars().all()
    advisories = (await db.execute(select(VulnAdvisory).where(
        VulnAdvisory.source.in_(ADVISORY_SOURCES), VulnAdvisory.rejected.is_(False)))).scalars().all()
    existing: dict[tuple[str, str], VulnMatch] = {}
    if devices:
        ids = [d.id for d in devices]
        for i in range(0, len(ids), 500):
            for m in (await db.execute(select(VulnMatch).where(VulnMatch.device_id.in_(ids[i:i + 500])))).scalars():
                existing[(m.device_id, m.advisory_id)] = m
    # 記録そのものを読めなくなった勧告: 版が同じでも、前回の判定は古い範囲によるものなので据え置かない
    broken_ids = {a.id for a in advisories if any(isinstance(x, dict) and x.get("broken") for x in a.affected or [])}
    by_device: dict[str, list[VulnMatch]] = {}
    for m in existing.values():
        by_device.setdefault(m.device_id, []).append(m)
    new: list[tuple[str, str]] = []
    fixed = checked = 0
    stale = 0
    for dev in devices:
        parsed = vm.judgeable(dev.platform, dev.os_version, dev.model)
        if parsed is None:
            # 判定できない機器（版が読めない・対象外の platform・FortiGate 6000 / 7000 系）: 該当・非該当は決めない。
            # 前回の「該当」は、版（または platform・モデル）が変わっていれば stale にして数えない
            # （同じ版なら、その版についての判定なので据え置く）
            for m in by_device.get(dev.id, []):
                if m.state not in ("open", "ack"):
                    continue
                became = dev.platform not in vm.CONFIRMED_PLATFORMS or _changed(m, dev)
                if became and not m.stale:
                    stale += 1
                m.stale = became
            continue
        checked += 1
        hits: dict[str, tuple[str, str | None]] = {}  # 勧告 ID → (confirmed / candidate, 候補の理由の符号)
        keep: set[str] = set()  # 範囲を読み取れず、判定を変えない勧告
        for a in advisories:
            if dev.platform not in (a.products or []) or vm.SOURCE_PLATFORM.get(a.source) != dev.platform:
                continue
            r, code, _plats = vm.judge_source(a.source, parsed, a.affected or [], dev.model)
            if r == "affected":
                hits[a.id] = ("confirmed", None)
            elif r == "candidate":
                hits[a.id] = ("candidate", code)
            elif r == "unreadable":
                keep.add(a.id)
        for adv_id, (conf, reason) in hits.items():
            m = existing.get((dev.id, adv_id))
            if m is None:
                m = VulnMatch(device_id=dev.id, advisory_id=adv_id, confidence=conf, os_version=dev.os_version,
                              model=dev.model, first_seen=now, last_seen=now, state="open", reason=reason)
                db.add(m)
                existing[(dev.id, adv_id)] = m
                new.append((dev.id, adv_id))
                continue
            if m.state == "fixed":
                if m.fixed_reason == "rejected":  # 取り下げ → 再公開: 確認済みの印とメモは残す
                    m.state = "ack" if m.acked_at else "open"
                else:
                    m.state, m.note, m.acked_by, m.acked_at = "open", None, None, None  # また該当した（確認済みの印は外す）
                m.fixed_reason = None
                new.append((dev.id, adv_id))
            m.confidence, m.os_version, m.model, m.last_seen = conf, dev.os_version, dev.model, now  # 最新にする
            m.reason = reason
            m.stale = False
        active = {a.id: vm.SOURCE_PLATFORM.get(a.source) for a in advisories}  # 取り下げていない勧告 → 判定する platform
        for m in by_device.get(dev.id, []):
            if (m.state == "fixed" and m.fixed_reason == "rejected" and m.advisory_id in active
                    and m.advisory_id not in hits and m.advisory_id not in keep):
                m.fixed_reason = None  # 再公開後の照合で非該当: ふつうの解消にする（あとで該当したら未確認で開く）
                continue
            if m.advisory_id in hits or m.state not in ("open", "ack"):
                continue
            if active.get(m.advisory_id) not in (None, dev.platform):
                # 別の機種の勧告での該当（機器の platform が変わった）: いまの機種についての判定ではないので stale
                if not m.stale:
                    stale += 1
                m.stale = True
                continue
            if m.advisory_id in keep:  # いまの版では判定できない
                became = _changed(m, dev) or m.advisory_id in broken_ids
                if became and not m.stale:
                    stale += 1
                m.stale = became
                continue
            m.state, m.stale, m.fixed_reason = "fixed", False, None
            fixed += 1
    notices = await queue_match_notices(db, [d.id for d in devices], now)
    return {"new": new, "fixed": fixed, "devices": checked, "stale": stale, "notices": notices}


def _ver(v: str | None) -> str:
    """stale の比較に使う版・モデル（前後の空白を除く）"""
    return (v or "").strip()


def _changed(m: VulnMatch, dev: Device) -> bool:
    """判定を出したときから、機器の版かモデルが変わったか（変わっていて判定できなければ stale）"""
    return _ver(m.os_version) != _ver(dev.os_version) or _ver(m.model).lower() != _ver(dev.model).lower()


def unreadable_by_device(devices: list[Device], advisories: list[VulnAdvisory]) -> dict[str, list[str]]:
    """機器 → 範囲を読み取れなかった勧告の ID（該当・非該当のどちらにも判定できなかったもの）

    OS バージョンが読める脆弱性の対象機種だけ。外部へはつながない
    """
    out: dict[str, list[str]] = {}
    for d in devices:
        p = vm.judgeable(d.platform, d.os_version, d.model)
        if p is None:
            continue
        ids = [a.ext_id for a in advisories
               if not a.rejected and d.platform in (a.products or []) and vm.SOURCE_PLATFORM.get(a.source) == d.platform
               and vm.judge_source(a.source, p, a.affected or [], d.model)[0] == "unreadable"]
        if ids:
            out[d.id] = sorted(ids)
    return out


# ---------------------------------------------------------------- サポート終了日

EOL_SOURCE_RANK = {"manual": 0, "endoflife.date": 1}
ANY_BRANCH = "*"  # 手入力で「その機種のすべて」を表す系列（バージョンを分解できない機種・系列を問わない設定）


async def eol_rows(db: AsyncSession) -> list[EolDate]:
    return list((await db.execute(select(EolDate))).scalars())


def _eol_platforms(dev: Device, parsed: vm.Parsed | None) -> list[str]:
    """サポート終了日を引く platform の候補。機器の platform を先に、自動取得の表の platform（EOL_PLATFORM）を次に

    cisco_ios と登録されていても中身が IOS XE（17.x）の機器は、cisco_ios でも cisco_xe でも引く
    """
    plats = [dev.platform]
    if parsed is not None:
        if (eol_plat := vm.eol_platform(parsed)) and eol_plat not in plats:
            plats.append(eol_plat)
        if parsed.scheme == "iosxe":
            plats += [x for x in ("cisco_ios", "cisco_xe") if x not in plats]
    return plats


def pick_eol(rows: list[EolDate], platforms: str | list[str], kind: str, branch: str = "", model: str = "",
             any_platform: str | None = None) -> EolDate | None:
    """該当するサポート終了日

    OS の優先順位: 特定の系列の手入力 → 特定の系列の自動取得 → 系列「*」（その機種すべて）の手入力 → 「*」の自動取得
    （同じ段では platforms の並び順）。「*」は any_platform（機器そのものの platform）のものだけを引く
    （cisco_ios と cisco_xe の相互参照で、classic IOS 向けの「*」が IOS XE の機器に当たらないように）。
    any_platform を省くと platforms の先頭。ハードウェア（モデル単位）は別枠で、手入力を優先する
    """
    plats = [platforms] if isinstance(platforms, str) else platforms
    any_plat = any_platform if any_platform is not None else (plats[0] if plats else None)
    best: tuple | None = None
    found: EolDate | None = None
    for r in rows:
        if r.platform not in plats or r.kind != kind:
            continue
        rank = EOL_SOURCE_RANK.get(r.source, 9)
        if kind == "os":
            if branch and r.branch == branch:
                tier = (0, rank)
            elif r.branch == ANY_BRANCH and r.platform == any_plat:
                tier = (1, rank)
            else:
                continue
        elif r.model.lower() == model.lower():
            tier = (0, rank)
        else:
            continue
        key = (*tier, plats.index(r.platform))
        if best is None or key < best:
            best, found = key, r
    return found


def device_eol(rows: list[EolDate], dev: Device, today: date) -> dict:
    """機器 1 台の OS・ハードウェアのサポート終了日（見つからなければ None）

    OS: 手入力は「機器の platform ＋ 分解したリリース系列」で引く（脆弱性を判定できない機種も含む）。自動取得の分は、
    体系に対応する platform（panos・fortios・iosxe）で引く。優先は 特定の系列の手入力 → 特定の系列の自動取得 →
    系列「*」の手入力（機器の platform のものだけ）。バージョンを分解できない機種は、「*」の手入力か、
    モデル単位（hardware。別枠）の手入力で引く
    """
    out: dict = {"os": None, "hardware": None, "reason": vm.unknown_reason(dev.platform, dev.os_version)}
    parsed = vm.parse_version(dev.platform, dev.os_version)
    plats = _eol_platforms(dev, parsed)
    if parsed is not None:
        out["branch"] = parsed.branch
    out["os"] = _eol_dict(pick_eol(rows, plats, "os", branch=parsed.branch if parsed else "", any_platform=dev.platform), today)
    if dev.model:
        out["hardware"] = _eol_dict(pick_eol(rows, plats, "hardware", model=dev.model), today)
    return out


def _eol_dict(r: EolDate | None, today: date) -> dict | None:
    if r is None:
        return None
    return {"id": r.id, "eol_date": r.eol_date.isoformat(), "days_left": (r.eol_date - today).days, "source": r.source,
            "url": r.url, "note": r.note, "branch": r.branch, "model": r.model,
            "eos_date": r.eos_date.isoformat() if r.eos_date else None}


# ---------------------------------------------------------------- Fortinet（FortiOS）の勧告
#
# 毎日の取得: RSS（最新 50 件。条件つき GET）で新しい勧告の ID と文書（CSAF）の URL を見つけ、まだ取っていない ID を
# 「取得待ち」（vuln_sources の fortinet の cursor）に足す。そのうえで、取得待ち（新しい順）→ 確かめ直す時期の来た
# 保存済みの勧告（公開日の新しい順）の順に、1 回 FORTINET_MAX_DOCS 件・FORTINET_BUDGET_SEC 秒まで文書を取る
# （条件つき GET。変更なしは 304。要求の間隔は 2 秒以上）。残りは次回。
# 改訂は RSS に出ない（pubDate は初回の公開日）ので、保存済みの勧告を次の間隔で確かめ直す（ETag が変われば作り直す）:
#   FortiOS の勧告: 公開から 1 年以内は 7 日ごと、それより前は 30 日ごと
#   FortiOS 以外の勧告・要確認の告知（保存はするが照合しない）: 公開から 90 日以内は 14 日ごと（告知は 7 日ごと）、
#   それより前は 60 日ごと（期限なし）。以前は FortiOS の勧告だったものが告知の形になったら、告知にせず「範囲を読み取れない」
# 文書が 404 になった保存済みの勧告は、取得の一時的な欠けと区別できないので変えない（取り下げとは扱わない）

RECHECK_DAYS = {"fortios_recent": 7, "fortios_old": 30, "other_recent": 14, "other_old": 60, "notice_recent": 7}
_PENDING_KEY = "pending"


def _fortinet_state(row: VulnSource) -> dict:
    try:
        st = json.loads(row.cursor or "{}")
    except ValueError:
        st = {}
    pend = st.get(_PENDING_KEY) if isinstance(st, dict) else None
    out: dict[str, dict] = {}
    for k, v in (pend.items() if isinstance(pend, dict) else []):
        if fetch.valid_fortinet_id(k) and isinstance(v, dict) and fetch.fortinet_csaf_url(v.get("url"), k):
            out[k] = {"url": v["url"], "published": v.get("published") if isinstance(v.get("published"), str) else None}
    return {_PENDING_KEY: out}


def _recheck_due(a: VulnAdvisory, now: datetime) -> bool:
    if not a.doc_url:
        return False
    if a.checked_at is None:
        return True
    pub = a.published_at or a.fetched_at or now
    recent = now - pub <= timedelta(days=365)
    if a.products:
        days = RECHECK_DAYS["fortios_recent" if recent else "fortios_old"]
    elif now - pub <= timedelta(days=90):
        # 告知は短い間隔で改訂されている（本物で確認）ので 7 日ごと。FortiOS 以外の製品の勧告は 14 日ごと
        notice = any(isinstance(x, dict) and x.get("notice") for x in a.affected or [])
        days = RECHECK_DAYS["notice_recent" if notice else "other_recent"]
    else:
        days = RECHECK_DAYS["other_old"]  # 改訂で FortiOS が足されることがあるので、期限なしで確かめ直す（条件つき GET）
    return now - a.checked_at >= timedelta(days=days)


def store_fortinet(db: AsyncSession, existing: dict[str, VulnAdvisory], ext_id: str, doc_url: str, got: "fetch.Fetched",
                   now: datetime) -> str:
    """取った文書 1 件を保存する。戻り値: "fortios"（FortiOS の勧告）/ "other"（FortiOS 以外）/
    "notice"（製品の記載が無い告知）/ "broken"（読めない）/ "unchanged"（304）"""
    a = existing.get(ext_id)
    if got.status == 304:
        if a is not None:
            a.checked_at = now
        return "unchanged"
    try:
        adv = fetch.parse_fortinet_csaf(json.loads(got.body.decode("utf-8")), ext_id)
    except (ValueError, RecursionError, fetch.FetchError) as e:
        reason = str(e) if isinstance(e, fetch.FetchError) else "文書を JSON として読めません"
        if a is None:
            a = existing[ext_id] = VulnAdvisory(source="fortinet", ext_id=ext_id, title=ext_id, severity="none", cve_ids=[],
                                                url=fetch.fortinet_page_url(ext_id))
            db.add(a)
        # 記録そのものを読めない: どの FortiOS の機器でも「判定できない」（前回の判定は古い範囲によるもの。照合で stale にする）
        a.products = ["fortinet"]
        a.affected = [{"fmt": "fortios", "v": None, "unreadable": True, "broken": True,
                       "raw": f"勧告の記録を読み取れません（{reason}）"[:120]}]
        a.doc_url, a.etag, a.last_modified, a.checked_at, a.fetched_at, a.rejected = doc_url, None, None, now, now, False
        return "broken"
    if adv.get("notice") and a is not None and "fortinet" in (a.products or []):
        # 以前は FortiOS の勧告として保存していたものが、改訂で告知の形（製品の記載が無い）になった: 告知にすると照合から外れ、
        # 既存の「該当」が「解消」になってしまう。告知にせず「範囲を読み取れない」にする（判定できない。版が同じ機器の
        # 前回の判定は据え置き、版が変わった機器は stale）
        adv = {**adv, "products": ["fortinet"], "notice": False,
               "affected": [{"fmt": "fortios", "v": None, "unreadable": True,
                             "raw": "改訂で製品の記載が無くなりました（以前は FortiOS の勧告）。勧告のページで確かめてください"}]}
    if a is None:
        a = existing[ext_id] = VulnAdvisory(source="fortinet", ext_id=ext_id)
        db.add(a)
    for k in ("cve_ids", "title", "severity", "cvss", "published_at", "modified_at", "url", "products", "affected"):
        setattr(a, k, adv[k])
    a.doc_url, a.etag, a.last_modified = doc_url, got.etag, got.last_modified
    a.checked_at = a.fetched_at = now
    a.rejected = False
    a._unreadable = adv["unreadable"]  # 取得の記録の数え上げ用（保存しない）
    return "fortios" if adv["products"] else "notice" if adv.get("notice") else "other"


async def _get(url: str, *, xml: bool = False, html: bool = False, etag: str | None = None,
               last_modified: str | None = None) -> "fetch.Fetched":
    accept = fetch.ACCEPT_HTML if html else fetch.ACCEPT_XML if xml else "application/json"
    limit = fetch.FORTINET_PAGE_MAX_BYTES if html else fetch.FORTINET_MAX_BYTES
    try:
        return await asyncio.to_thread(fetch.fetch, url, accept=accept, max_bytes=limit, etag=etag, last_modified=last_modified)
    except fetch.FetchError as e:
        if e.code == 500:  # Fortinet の Web アプリケーションファイアウォールは、遮断を HTTP 500 で返す（調査で確認）
            raise fetch.FetchError("HTTP 500（相手の障害か、相手の Web アプリケーションファイアウォールによる遮断の可能性）",
                                   500) from None
        raise


async def fetch_fortinet(db: AsyncSession, now: datetime) -> int:
    """毎日の Fortinet の取得（上の節）。戻り値: 保存済みの FortiOS の勧告の数。RSS の失敗・文書の取得の失敗は FetchError
    （取れた分は保存してから）"""
    row = await _source_row(db, "fortinet")
    state = _fortinet_state(row)
    pending = state[_PENDING_KEY]
    existing = {a.ext_id: a for a in (await db.execute(
        select(VulnAdvisory).where(VulnAdvisory.source == "fortinet"))).scalars()}
    pacer = fetch.Pacer(fetch.FORTINET_INTERVAL_SEC)
    started = time.monotonic()
    pacer.wait()
    rss = await _get(fetch.URL_FORTINET_RSS, xml=True, etag=row.etag, last_modified=row.last_modified)
    skipped = 0
    if rss.status == 200:
        items, skipped = fetch.parse_fortinet_rss(rss.body)
        for it in items:
            a = existing.get(it["ext_id"])
            if a is None:
                pending[it["ext_id"]] = {"url": it["csaf_url"],
                                         "published": it["published"].isoformat() if it["published"] else None}
            elif a.doc_url != it["csaf_url"]:
                a.doc_url, a.etag, a.last_modified, a.checked_at = it["csaf_url"], None, None, None  # 文書の URL が変わった
        row.etag, row.last_modified = rss.etag, rss.last_modified
    queue: list[tuple[str, str]] = [(k, v["url"]) for k, v in sorted(
        pending.items(), key=lambda kv: (kv[1].get("published") or "", kv[0]), reverse=True)]
    # 確かめ直す勧告は、新しい（公開日の新しい）ものを優先する（1 回の件数の上限の中で）
    due = sorted((a for a in existing.values() if a.ext_id not in pending and _recheck_due(a, now)),
                 key=lambda a: (-(a.published_at or a.fetched_at or now).timestamp(), a.checked_at or datetime.min, a.ext_id))
    queue += [(a.ext_id, a.doc_url) for a in due]
    counts = {"fortios": 0, "other": 0, "notice": 0, "broken": 0, "unchanged": 0, "missing": 0, "failed": 0}
    errors: list[str] = []
    done = 0
    for ext_id, url in queue:
        if done >= FORTINET_MAX_DOCS:
            break
        if time.monotonic() - started + fetch.TOTAL_TIMEOUT + fetch.FORTINET_INTERVAL_SEC > FORTINET_BUDGET_SEC:
            break  # Fortinet の分の時間の上限（残りは次回）
        done += 1
        a = existing.get(ext_id)
        pacer.wait()
        try:
            got = await _get(url, etag=a.etag if a is not None and a.doc_url == url else None,
                             last_modified=a.last_modified if a is not None and a.doc_url == url else None)
        except fetch.FetchError as e:
            if e.code == 404:
                counts["missing"] += 1
                pending.pop(ext_id, None)  # 取得待ちの ID は捨てる（RSS にまた出れば足し直す）。保存済みは変えない
                if a is not None:
                    a.checked_at = now
            else:
                counts["failed"] += 1
                errors.append(f"{ext_id}: {e}")
            continue
        kind = store_fortinet(db, existing, ext_id, url, got, now)
        counts[kind] += 1
        pending.pop(ext_id, None)
    row.cursor = json.dumps(state, separators=(",", ":"))
    row.skipped = skipped + counts["broken"] + counts["missing"] + sum(
        getattr(a, "_unreadable", 0) for a in existing.values())
    logger.info("Fortinet の勧告: %s 残り %d 件", counts, max(0, len(queue) - done))
    if errors:
        await db.commit()  # 取れた分は保存する（rollback で消えないよう先に確定）
        raise fetch.FetchError(f"勧告の文書 {len(errors)} 件を取得できませんでした（次回やり直します）: {errors[0]}"[:280])
    return sum(1 for a in existing.values() if a.products)


async def import_fortinet(db: AsyncSession, ids: list[str], now: datetime | None = None) -> list[dict]:
    """管理者が指定した過去の勧告を取り込む（1 件ずつ。要求の間隔は 2 秒以上。commit・照合も行う）

    保存済みで文書の URL が分かっている勧告は、その URL を条件つき GET で確かめる。それ以外は CVRF（ID だけで引ける XML）で
    題名を得て、題名から文書の URL を組み立てる（2021 年以前の勧告には文書が無い。題名が後から変わった勧告は組み立てられない）
    """
    now = now or utcnow()
    existing = {a.ext_id: a for a in (await db.execute(
        select(VulnAdvisory).where(VulnAdvisory.source == "fortinet"))).scalars()}
    pacer = fetch.Pacer(fetch.FORTINET_INTERVAL_SEC)
    out: list[dict] = []
    started = time.monotonic()
    for ext_id in ids[:FORTINET_IMPORT_MAX]:
        res = {"ext_id": ext_id, "ok": False, "result": "failed", "message": ""}
        out.append(res)
        # 時間の上限（毎日の取得と同じ。ロックの期限より短く終える）。1 件に最大 4 回の要求（CVRF・文書・ページ・文書）
        if time.monotonic() - started + 4 * (fetch.TOTAL_TIMEOUT + fetch.FORTINET_INTERVAL_SEC) > FORTINET_BUDGET_SEC:
            res.update(result="not_done", message="時間の上限に達したため、取り込めませんでした。もう一度指定してください")
            continue
        try:
            a = existing.get(ext_id)
            url = a.doc_url if a is not None and a.doc_url else None
            if url is None:
                pacer.wait()
                title = fetch.parse_cvrf_title((await _get(fetch.URL_FORTINET_CVRF.format(ext_id=ext_id), xml=True)).body,
                                               ext_id)
                if title is None:
                    res.update(result="not_found", message="勧告が見つかりません（ID を確かめてください）")
                    continue
                url = fetch.csaf_url_from_title(ext_id, title)
                if url is None:
                    res.update(result="no_csaf", message="勧告の題名から文書（CSAF）の URL を組み立てられません")
                    continue
            pacer.wait()
            try:
                got = await _get(url, etag=a.etag if a is not None and a.doc_url == url else None,
                                 last_modified=a.last_modified if a is not None and a.doc_url == url else None)
            except fetch.FetchError as e:
                if e.code != 404:
                    raise
                # 題名が後から変わった勧告は、題名から作ったファイル名が合わない（本物の FG-IR-24-535）。勧告のページ
                # （クエリなし。robots.txt の許可の範囲）を 1 回だけ取り、ページに書かれた CSAF の URL を検査してから使う
                pacer.wait()
                page = await _get(fetch.FORTINET_PAGE.format(ext_id=ext_id), html=True)
                url = fetch.csaf_url_from_page(page.body, ext_id)
                if url is None:
                    res.update(result="no_csaf", message="機械で読める形式（CSAF）の文書がありません（2021 年以前の勧告の"
                                                         "可能性があります。勧告のページで確かめてください）")
                    continue
                pacer.wait()
                try:
                    got = await _get(url)
                except fetch.FetchError as e2:
                    if e2.code == 404:
                        res.update(result="no_csaf", message="勧告のページに書かれた文書（CSAF）が見つかりません")
                        continue
                    raise
            kind = store_fortinet(db, existing, ext_id, url, got, now)
            msg = {"fortios": "取り込みました（FortiOS の勧告）",
                   "other": "取り込みました（FortiOS 以外の製品の勧告のため、照合には使いません）",
                   "notice": "取り込みました（製品の記載が無い告知。画面の上部の「要確認の告知」に出します）",
                   "broken": "文書を読み取れませんでした（FortiOS の機器では「判定できない」になります）",
                   "unchanged": "取り込み済みで、変更はありません"}[kind]
            res.update(ok=kind != "broken", result=kind, message=msg)
        except fetch.FetchError as e:
            res.update(result="failed", message=f"取得に失敗しました（{e}）"[:200])
    await db.commit()
    try:
        await apply_kev(db)
        await reconcile(db, now=now)
        await db.commit()
    except Exception:  # noqa: BLE001 - 取り込んだ勧告は保存済み。照合は次回にやり直せる
        await db.rollback()
        logger.exception("取り込みのあとの照合に失敗しました")
    return out


IMPORT_STATE = "fortinet_import"  # 取り込みの状態を置く vuln_sources の行（画面に出す）


async def set_import_state(db: AsyncSession, state: dict) -> None:
    row = await _source_row(db, IMPORT_STATE)
    row.cursor = json.dumps(state, ensure_ascii=False, separators=(",", ":"))[:200_000]
    row.last_at = utcnow()


async def get_import_state(db: AsyncSession) -> dict | None:
    row = await db.get(VulnSource, IMPORT_STATE)
    if row is None or not row.cursor:
        return None
    try:
        st = json.loads(row.cursor)
    except ValueError:
        return None
    return st if isinstance(st, dict) else None


async def coverage(db: AsyncSession) -> dict:
    """取得済みの範囲: 情報源ごとの、照合に使う勧告の件数と、最も古い・新しい公開日（取り下げを除く）"""
    out: dict = {}
    for src in ADVISORY_SOURCES:
        rows = (await db.execute(select(VulnAdvisory.published_at, VulnAdvisory.products).where(
            VulnAdvisory.source == src, VulnAdvisory.rejected.is_(False)))).all()
        used = [p for p, prods in rows if prods]
        dates = [p for p in used if p is not None]
        out[src] = {"count": len(used), "documents": len(rows), "oldest": min(dates) if dates else None,
                    "newest": max(dates) if dates else None}
    row = await db.get(VulnSource, "fortinet")
    out["fortinet"]["pending"] = len(_fortinet_state(row)[_PENDING_KEY]) if row is not None else 0
    return out


# ---------------------------------------------------------------- 通知: 新しく該当になった機器と勧告
#
# 通知の条件: 未確認（open）・確認済み（ack）のうち、確定（confirmed）で、重大度が高以上（critical・high）か悪用確認済み（KEV）、
# 前回の該当から版が変わって判定できないもの（stale）を除く。条件に当たった照合結果は、通知したかどうかにかかわらず
# notified_at を入れ、
# 同じ機器 × 勧告は 2 度と通知しない（解消してまた該当・stale から戻った・確認済みを取り消した、でも通知しない）。
# 候補・判定できないは通知しない（候補が確定に変わったとき、重大度・KEV が後から条件に当たったときに初めて通知する）。
# 通知は、照合の呼び出し側の commit が成功したあとに投入する（rollback されたら捨てる。compliance.py の違反の通知と同じ）

_PENDING_VULN = "vuln_pending_notices"  # Session.info のキー
NOTIFY_SEVERITIES = ("critical", "high")
MAX_NOTICE_ITEMS = 500


async def queue_match_notices(db: AsyncSession, device_ids: list[str], now: datetime) -> int:
    """通知の条件に新しく当たった照合結果に印を付け、通知を投入待ちにする（件数を返す）"""
    if not device_ids:
        return 0
    found: list[tuple[VulnMatch, VulnAdvisory]] = []
    for i in range(0, len(device_ids), 500):
        found += (await db.execute(
            select(VulnMatch, VulnAdvisory).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id).where(
                VulnMatch.device_id.in_(device_ids[i:i + 500]), VulnMatch.notified_at.is_(None),
                VulnMatch.state.in_(("open", "ack")), VulnMatch.stale.is_(False), VulnMatch.confidence == "confirmed",
                VulnAdvisory.rejected.is_(False),
                or_(VulnAdvisory.severity.in_(NOTIFY_SEVERITIES), VulnAdvisory.kev.is_(True))))).all()
    by_device: dict[str, list[list]] = {}
    for m, a in found:
        m.notified_at = now
        if m.state == "open":  # 確認済み（対応不要）にしたものは知らせない（印だけ付ける）
            by_device.setdefault(m.device_id, []).append([a.ext_id, a.title[:120], a.severity, a.cvss, bool(a.kev)])
    if not by_device:
        return 0
    from app.services.notify import wants_any  # 循環 import を避ける
    try:
        if not await wants_any(db, "vuln"):
            return 0
        items = [[d, sorted(v, key=lambda x: (-int(x[4]), -(x[3] or 0), x[0]))] for d, v in by_device.items()]
        db.sync_session.info.setdefault(_PENDING_VULN, []).append(items[:MAX_NOTICE_ITEMS])
    except Exception:  # noqa: BLE001 - 通知の準備に失敗しても照合は続ける
        logger.exception("脆弱性の通知を準備できませんでした")
        return 0
    return sum(len(v) for v in by_device.values())


@event.listens_for(Session, "after_commit")
def _flush_vuln_notices(session: Session) -> None:
    """commit が成功したあとに、積んでおいた脆弱性の通知を Celery へ投入する"""
    if session.in_nested_transaction():
        return
    pending = session.info.pop(_PENDING_VULN, None)
    if not pending:
        return
    try:
        from app.worker import send_vuln_notification
        for items in pending:
            send_vuln_notification.delay(items)
    except Exception:  # noqa: BLE001 - 通知の投入に失敗しても、保存済みの照合結果には影響させない
        logger.exception("脆弱性の通知を投入できませんでした")


@event.listens_for(Session, "after_transaction_end")
def _drop_vuln_notices(session: Session, transaction) -> None:
    if transaction.parent is None:
        session.info.pop(_PENDING_VULN, None)


# ---------------------------------------------------------------- 通知: サポート終了日が近い
#
# サポート終了日の 180・90・30 日前と当日（終了後 30 日まで）に、機器ごとではなく「サポート終了日の行（機種・系列、または
# モデル）ごと」にまとめて、1 日 1 回までの 1 通で知らせる。行ごとに、どの段階まで知らせたかを vuln_sources の eol_notice に
# 残し、同じ段階は 2 度知らせない。初めて見た行（有効にした直後・日付を入れた直後）は、いまの段階だけを 1 回知らせる
# （たとえば残り 50 日なら「90 日前」の段階として 1 回。180 日前の分はさかのぼって知らせない）。
# 終了日を変えたら印は付け直す（行と終了日の組で覚える）。終了から 30 日を過ぎた行は、知らせずに印だけ付ける

EOL_NOTICE_TIERS = (180, 90, 30, 0)
EOL_NOTICE_LATE_DAYS = 30
EOL_NOTICE_STATE = "eol_notice"


async def collect_eol_notices(db: AsyncSession, today: date | None = None) -> list[dict]:
    """きょう知らせるサポート終了日の行（印を付ける。commit は呼び出し側）。1 日に 2 度目の呼び出しは [] を返す

    戻り値の要素: {key, platform, kind, branch, model, eol_date, days_left, devices: [機器 ID…]}
    """
    groups, cursor = await plan_eol_notices(db, today)
    await save_eol_notice_state(db, cursor)
    return groups


async def save_eol_notice_state(db: AsyncSession, cursor: str | None) -> None:
    """plan_eol_notices の印を確定する（送信の投入が済んでから呼ぶ。失敗したら呼ばず、次回に送り直す）"""
    if cursor is not None:
        (await _source_row(db, EOL_NOTICE_STATE)).cursor = cursor


async def plan_eol_notices(db: AsyncSession, today: date | None = None) -> tuple[list[dict], str | None]:
    """きょう知らせるサポート終了日の行と、送ったあとに残す印（JSON）。印はまだ保存しない（save_eol_notice_state）"""
    today = today or local_today()
    row = await _source_row(db, EOL_NOTICE_STATE)
    try:
        st = json.loads(row.cursor or "{}")
    except ValueError:
        st = {}
    st = st if isinstance(st, dict) else {}
    if st.get("sent_on") == today.isoformat():
        return [], None
    done: dict[str, list[int]] = st.get("done") if isinstance(st.get("done"), dict) else {}
    rows = await eol_rows(db)
    groups: dict[str, dict] = {}
    for dev in (await db.execute(select(Device).where(Device.is_active.is_(True)))).scalars():
        e = device_eol(rows, dev, today)
        for kind in ("os", "hardware"):
            x = e[kind]
            if not x:
                continue
            key = f"{x['id']}:{x['eol_date']}"
            g = groups.setdefault(key, {"key": key, "platform": dev.platform, "kind": kind, "branch": x["branch"],
                                        "model": x["model"], "eol_date": x["eol_date"], "days_left": x["days_left"],
                                        "devices": []})
            g["devices"].append(dev.id)
    out = []
    for key, g in groups.items():
        d = g["days_left"]
        tiers = [t for t in EOL_NOTICE_TIERS if d <= t]
        if not tiers:
            continue
        tier = min(tiers)
        seen = set(done.get(key, []))
        if tier in seen:
            continue
        done[key] = sorted(seen | set(tiers), reverse=True)
        if d < -EOL_NOTICE_LATE_DAYS:
            continue  # 終了から時間がたった行: 知らせずに印だけ
        out.append({**g, "tier": tier})
    st["done"] = {k: v for k, v in done.items() if k in groups}  # 消えた行・日付を変えた行の印は捨てる
    if out:
        st["sent_on"] = today.isoformat()
    return (sorted(out, key=lambda g: (g["days_left"], g["platform"], g["branch"], g["model"])),
            json.dumps(st, separators=(",", ":")))
