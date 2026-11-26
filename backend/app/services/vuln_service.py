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
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import utcnow
from app.models.device import Device
from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
from app.services import vuln_fetch as fetch
from app.services import vuln_match as vm

logger = logging.getLogger(__name__)

# 取得する順（kev を先に取っておくと、勧告の保存と同じ回に悪用確認済みの印が付く）
SOURCE_ORDER = ("kev", "paloalto", "eol")
SOURCE_LABELS = {"paloalto": "Palo Alto の勧告", "kev": "CISA の悪用確認済み一覧（KEV）",
                 "eol": "サポート終了日（endoflife.date）"}
RETRY_AFTER_MIN = 180  # 失敗した情報源を、次に試すまでの時間（毎時の判定のたびに外へつなぎに行かない）
STALE_DAYS = 3  # この日数より前から取得できていなければ、システム状態で注意
MANUAL_FETCH_INTERVAL_SEC = 300  # 「いま取得」の間隔
# 1 回の取得で最悪かかる秒数（kev・paloalto 各 1 回と、eol の製品ごと 1 回。1 回は fetch.TOTAL_TIMEOUT で打ち切る）
MAX_FETCH_SECONDS = (2 + len(fetch.EOL_PRODUCTS)) * (fetch.TOTAL_TIMEOUT + 2)
EOL_SOON_DAYS = 365  # 「終了間近」とみなす日数


def active_sources() -> list[str]:
    wanted = set(settings.vuln_sources)
    return [s for s in SOURCE_ORDER if s in wanted]


def unknown_sources() -> list[str]:
    """VULN_SOURCES に書かれているが、この版では使えない名前（fortinet・nvd は今後の対応。スペルミスも）"""
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
        VulnAdvisory.source == "paloalto", VulnAdvisory.rejected.is_(False)))).scalars().all()
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
        parsed = vm.parse_version(dev.platform, dev.os_version) if dev.platform in vm.CONFIRMED_PLATFORMS else None
        if parsed is None:
            # 判定できない機器（版が読めない・対象外の platform）: 該当・非該当は決めない。前回の「該当」は、
            # 版（または platform）が変わっていれば stale にして数えない（同じ版なら、その版についての判定なので据え置く）
            for m in by_device.get(dev.id, []):
                if m.state not in ("open", "ack"):
                    continue
                became = dev.platform not in vm.CONFIRMED_PLATFORMS or _changed(m, dev)
                if became and not m.stale:
                    stale += 1
                m.stale = became
            continue
        checked += 1
        hits: dict[str, str] = {}  # 勧告 ID → confirmed / candidate
        keep: set[str] = set()  # 範囲を読み取れず、判定を変えない勧告
        for a in advisories:
            if dev.platform not in (a.products or []):
                continue
            r = vm.judge_parsed(parsed, a.affected or [], dev.model)
            if r == "affected":
                hits[a.id] = "confirmed"
            elif r == "candidate":
                hits[a.id] = "candidate"
            elif r == "unreadable":
                keep.add(a.id)
        for adv_id, conf in hits.items():
            m = existing.get((dev.id, adv_id))
            if m is None:
                m = VulnMatch(device_id=dev.id, advisory_id=adv_id, confidence=conf, os_version=dev.os_version,
                              model=dev.model, first_seen=now, last_seen=now, state="open")
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
            m.stale = False
        active = {a.id for a in advisories}  # 取り下げていない勧告
        for m in by_device.get(dev.id, []):
            if (m.state == "fixed" and m.fixed_reason == "rejected" and m.advisory_id in active
                    and m.advisory_id not in hits and m.advisory_id not in keep):
                m.fixed_reason = None  # 再公開後の照合で非該当: ふつうの解消にする（あとで該当したら未確認で開く）
                continue
            if m.advisory_id in hits or m.state not in ("open", "ack"):
                continue
            if m.advisory_id in keep:  # いまの版では判定できない
                became = _changed(m, dev) or m.advisory_id in broken_ids
                if became and not m.stale:
                    stale += 1
                m.stale = became
                continue
            m.state, m.stale, m.fixed_reason = "fixed", False, None
            fixed += 1
    return {"new": new, "fixed": fixed, "devices": checked, "stale": stale}


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
        if d.platform not in vm.CONFIRMED_PLATFORMS:
            continue
        p = vm.parse_version(d.platform, d.os_version)
        if p is None:
            continue
        ids = [a.ext_id for a in advisories
               if not a.rejected and d.platform in (a.products or [])
               and vm.judge_parsed(p, a.affected or [], d.model) == "unreadable"]
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
