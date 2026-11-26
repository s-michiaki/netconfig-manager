"""コンプライアンスチェック: 収集したコンフィグをルールで検査する

ルールの考え方（1行ずつ判定する）
- 一致方法: contains（文字列を含む）/ regex（正規表現に一致）
- 期待値:   present（一致する行が必要）/ absent（一致する行があってはいけない）
- 範囲:     config（コンフィグ全体）/ section（見出しが section_pattern に一致する各セクションごと）
  セクションは「行頭に空白の無い行」を見出しとし、続く字下げされた行をその中身とする
  （Cisco IOS / NX-OS / Arista / Huawei / Comware の interface ブロックなど）

検査のタイミング
- 収集に成功したとき（その機器だけ）
- ルールを作成・変更したとき、画面から「再検査」したとき（全機器）
結果は機器 × ルールごとに最新の1件だけを保存する

例外（承認済みの逸脱。ComplianceException）
- 機器単位: その機器ではルールの違反を「除外（exempt）」として扱う（違反の件数に数えない）
- 該当箇所単位: 正規表現に一致する箇所を検査から外す
    セクション検査 → 見出しが一致するセクション（未使用のポートなど）
    コンフィグ全体で「あってはいけない」→ 一致する違反行
  外した結果すべて合格になれば「除外」とする
期限切れの例外は使わない（次の検査から反映）

正規表現（ルール・セクションの見出し・例外）の照合
- 利用者が入力したパターンなので、壊滅的なバックトラックを起こすものも入り得る（ReDoS）
- 標準の re は照合中に GIL を手放さず、打ち切る手段も無いため、API・worker 全体が止まる
- そこで regex パッケージで照合し、1回の評価（ルール × 機器）あたりの合計時間を
  COMPLIANCE_REGEX_TIMEOUT 秒に制限する。超えたら評価を「エラー」にして打ち切る
  （concurrent=True で照合中も GIL を手放す。さらに run_checks は照合を専用のスレッドで行い、同時に走る数を
  COMPLIANCE_CHECK_CONCURRENCY に制限するので、再検査の最中もイベントループは止まらない）
- 照合の時間切れでは compile を打ち切れないため、compile の前に別のプロセスで実際に読み込んで重さを測る
  （app.core.safe_regex。重いものは保存させず、DB に入っているものは検査の実行時にそのルールだけ「エラー」として扱う）
"""
import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import git
import regex
from sqlalchemy import delete, event, select
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.safe_regex import PatternTooHeavy, PatternUnavailable, safe_compile
from app.core.timeutil import utcnow
from app.models.compliance import ComplianceException, ComplianceResult, ComplianceRule
from app.models.device import Device
from app.services.activity import SYSTEM_ACTOR
from app.services.activity import record as record_activity
from app.services.compliance_templates import ALL_TEMPLATES, CATEGORIES, TEMPLATES  # noqa: F401  再公開
from app.services.config_service import CONFIG_FILENAME, repo_path

logger = logging.getLogger(__name__)

MAX_DETAILS = 20  # 1件の結果に残す違反箇所の数
MAX_PATTERN_LENGTH = 1000


@dataclass
class RuleSpec:
    match_type: str
    expect: str
    pattern: str
    scope: str = "config"
    section_pattern: str | None = None
    platforms: list[str] = field(default_factory=list)


@dataclass
class Evaluation:
    status: str  # pass / fail / error / exempt（例外で除外）
    details: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)  # 例外で検査から外した箇所


@dataclass
class ExceptionSpec:
    reason: str
    ignore_pattern: str | None = None  # None なら機器単位の除外


class RegexTimeout(Exception):
    """正規表現の照合が制限時間を超えた"""


def compile_pattern(pattern: str) -> regex.Pattern:
    """利用者が入力した正規表現をコンパイルする

    不正なら regex.error、読み込みが重すぎるなら PatternTooHeavy、重さを確かめられなければ PatternUnavailable（一時的。
    呼び出し側で別に扱う。API は 503、検査はその回だけエラー）

    compile の前に重さを確かめる（compile は時間切れで打ち切れないため）。同期処理なので API からはスレッドで呼ぶ
    """
    return safe_compile(pattern, max_length=MAX_PATTERN_LENGTH)


class Deadline:
    """1回の評価で正規表現の照合に使える残り時間"""

    def __init__(self, seconds: float | None = None):
        self.seconds = settings.COMPLIANCE_REGEX_TIMEOUT if seconds is None else seconds
        self.end = time.monotonic() + self.seconds

    def search(self, rx: regex.Pattern, text: str) -> bool:
        left = self.end - time.monotonic()
        if left <= 0:
            raise RegexTimeout()
        try:
            return rx.search(text, timeout=left, concurrent=True) is not None
        except TimeoutError as e:
            raise RegexTimeout() from e


def pattern_allowed(spec: RuleSpec) -> bool:
    """該当箇所単位の例外を使えるルールか（コンフィグ全体で「必要」なルールは外す箇所が無い）"""
    return spec.scope == "section" or spec.expect == "absent"


def validate_ignore_pattern(pattern: str) -> None:
    try:
        compile_pattern(pattern)
    except PatternTooHeavy as e:
        raise ValueError(f"除外する箇所: {e}") from e
    except regex.error as e:
        raise ValueError(f"除外する箇所の正規表現が正しくありません: {e}") from e


def spec_of(rule: ComplianceRule) -> RuleSpec:
    return RuleSpec(
        match_type=rule.match_type,
        expect=rule.expect,
        pattern=rule.pattern,
        scope=rule.scope,
        section_pattern=rule.section_pattern,
        platforms=load_platforms(rule.platforms),
    )


def load_platforms(raw: str | None) -> list[str]:
    try:
        v = json.loads(raw or "[]")
        return [str(x) for x in v] if isinstance(v, list) else []
    except ValueError:
        return []


def applies_to(spec: RuleSpec, platform: str) -> bool:
    return not spec.platforms or platform in spec.platforms


def make_matcher(spec: RuleSpec, deadline: Deadline | None = None) -> Callable[[str], bool]:
    """1行を判定する関数。正規表現が不正なら ValueError、照合が制限時間を超えたら RegexTimeout"""
    if spec.match_type == "regex":
        try:
            rx = compile_pattern(spec.pattern)
        except PatternTooHeavy as e:
            raise ValueError(str(e)) from e
        except regex.error as e:
            raise ValueError(f"正規表現が正しくありません: {e}") from e
        dl = deadline or Deadline()
        return lambda line: dl.search(rx, line)
    return lambda line: spec.pattern in line


def validate_spec(spec: RuleSpec) -> None:
    """保存・試す前の検証（ValueError）。compile するので同期処理。API からは run_in_threadpool で呼ぶ"""
    make_matcher(spec)
    if spec.scope == "section":
        if not spec.section_pattern:
            raise ValueError("セクションごとに検査する場合は、セクションの見出し（正規表現）を指定してください")
        try:
            compile_pattern(spec.section_pattern)
        except PatternTooHeavy as e:
            raise ValueError(f"セクションの見出し: {e}") from e
        except regex.error as e:
            raise ValueError(f"セクションの見出しの正規表現が正しくありません: {e}") from e


def parse_sections(lines: list[str]) -> list[tuple[int, str, list[tuple[int, str]]]]:
    """（見出しの行番号, 見出し, [(行番号, 中身の行)]）の一覧。行番号は1始まり"""
    sections: list[tuple[int, str, list[tuple[int, str]]]] = []
    current = None
    for no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if line[0] in " \t":
            if current is not None:
                current[2].append((no, line))
            continue
        if line.startswith(("!", "#")):  # コメント・区切り行でセクションは終わる
            current = None
            continue
        current = (no, line, [])
        sections.append(current)
    return sections


def _fmt(no: int, line: str) -> str:
    return f"{no}行目: {line.strip()}"


def evaluate(spec: RuleSpec, config_text: str, ignore: list[regex.Pattern] | None = None) -> Evaluation:
    """ignore: 検査から外す箇所（違反行・セクションの見出しに一致する正規表現）"""
    deadline = Deadline()
    try:
        return _evaluate(spec, config_text, ignore or [], deadline)
    except RegexTimeout:
        return Evaluation("error", [
            f"正規表現の照合に {deadline.seconds:g} 秒以上かかったため中止しました。"
            "「(…+)+」のような量指定子の入れ子など、照合に時間のかかるパターンになっていないか見直してください"
        ])


UNAVAILABLE_DETAIL = "正規表現の重さを確かめられませんでした（次の検査でもう一度確かめます）"


def _evaluate(spec: RuleSpec, config_text: str, ignore: list[regex.Pattern], deadline: Deadline) -> Evaluation:
    try:
        match = make_matcher(spec, deadline)
    except PatternUnavailable:
        return Evaluation("error", [UNAVAILABLE_DETAIL])
    except ValueError as e:
        return Evaluation("error", [str(e)])
    lines = config_text.splitlines()

    def ignored(text: str) -> bool:
        return any(deadline.search(rx, text) for rx in ignore)

    skipped: list[str] = []
    if spec.scope != "section":
        hits = [(no, line) for no, line in enumerate(lines, 1) if match(line)]
        if spec.expect == "present":
            return Evaluation("pass") if hits else Evaluation("fail", ["一致する行がありません"])
        if ignore:
            skipped = [_fmt(no, line) for no, line in hits if ignored(line)]
            hits = [(no, line) for no, line in hits if not ignored(line)]
        if not hits:
            return Evaluation("pass", ignored=skipped[:MAX_DETAILS])
        details = [_fmt(no, line) for no, line in hits[:MAX_DETAILS]]
        if len(hits) > MAX_DETAILS:
            details.append(f"ほか {len(hits) - MAX_DETAILS} 行")
        return Evaluation("fail", details, ignored=skipped[:MAX_DETAILS])

    try:
        head_rx = compile_pattern(spec.section_pattern or "")
    except PatternUnavailable:
        return Evaluation("error", [UNAVAILABLE_DETAIL])
    except PatternTooHeavy as e:
        return Evaluation("error", [f"セクションの見出し: {e}"])
    except regex.error as e:
        return Evaluation("error", [f"セクションの見出しの正規表現が正しくありません: {e}"])
    violations: list[str] = []
    count = 0
    for head_no, head, body in parse_sections(lines):
        if not deadline.search(head_rx, head):
            continue
        hits = [(no, line) for no, line in body if match(line)]
        bad = (not hits) if spec.expect == "present" else bool(hits)
        if not bad:
            continue
        if ignore and ignored(head):
            skipped.append(f"{head_no}行目: {head.strip()}")
            continue
        count += 1
        if len(violations) < MAX_DETAILS:
            if spec.expect == "present":
                violations.append(f"{head_no}行目: {head.strip()}（一致する行がありません）")
            else:
                violations.append(f"{head_no}行目: {head.strip()} → {hits[0][1].strip()}")
    if count > MAX_DETAILS:
        violations.append(f"ほか {count - MAX_DETAILS} セクション")
    skipped = skipped[:MAX_DETAILS]
    return Evaluation("fail", violations, ignored=skipped) if violations else Evaluation("pass", ignored=skipped)


def evaluate_with_exceptions(spec: RuleSpec, config_text: str, exceptions: list[ExceptionSpec]) -> Evaluation:
    """例外を適用して評価する。例外のおかげで違反でなくなったものは exempt"""
    ignore = []
    for e in exceptions:
        if e.ignore_pattern:
            try:
                ignore.append(compile_pattern(e.ignore_pattern))
            except PatternUnavailable:
                # 一時的に確かめられない除外を飛ばすと、違反に変わって偽の通知になるため、その回はエラーにする
                return Evaluation("error", [UNAVAILABLE_DETAIL])
            except (regex.error, PatternTooHeavy) as err:
                # 登録時に検証しているので通常は起きない（その除外は使わない＝検査は厳しい側になる）
                logger.warning("読み込めない除外の正規表現を飛ばしました（%s）: %s", err, e.ignore_pattern[:80])
                continue
    ev = evaluate(spec, config_text, ignore if pattern_allowed(spec) else None)
    reasons = "・".join(dict.fromkeys(e.reason for e in exceptions))
    if ev.status == "pass" and ev.ignored:
        return Evaluation("exempt", [f"例外: {reasons}"] + [f"除外: {x}" for x in ev.ignored], ev.ignored)
    if ev.status == "fail" and any(not e.ignore_pattern for e in exceptions):
        return Evaluation("exempt", [f"例外（機器単位）: {reasons}", *ev.details], ev.ignored)
    return ev


def active_exception(e: ComplianceException, now) -> bool:
    return e.expires_at is None or e.expires_at > now


async def recheck_expired_exceptions(db: AsyncSession) -> int:
    """期限が切れた例外の対象（ルール × 機器）を再検査する。定期処理から呼ぶ。再検査した例外の数を返す

    期限切れの例外は検査で使われなくなるが、次の検査まで結果は「除外」のまま残るため、ここで反映する
    """
    now = utcnow()
    expired = (await db.execute(select(ComplianceException).where(
        ComplianceException.expires_at.is_not(None), ComplianceException.expires_at <= now,
        ComplianceException.expiry_handled.is_(False)))).scalars().all()
    if not expired:
        return 0
    rules = {r.id: r for r in (await db.execute(select(ComplianceRule).where(
        ComplianceRule.id.in_({e.rule_id for e in expired})))).scalars()}
    devices = {d.id: d for d in (await db.execute(select(Device).where(
        Device.id.in_({e.device_id for e in expired if e.device_id})))).scalars()}
    for e in expired:
        e.expiry_handled = True
        rule = rules.get(e.rule_id)
        if rule is None:
            continue
        device = devices.get(e.device_id) if e.device_id else None
        record_activity(db, "compliance.exception_expired",
                        f"ルール「{rule.name}」の例外（{device.name if device else '全機器'}・理由: {e.reason}）"
                        "の期限が切れたため再検査しました",
                        device_id=device.id if device else None, device_name=device.name if device else None,
                        detail={"rule": rule.name, "ignore_pattern": e.ignore_pattern}, actor=SYSTEM_ACTOR)
    await db.commit()
    # ルールごとにまとめて再検査（全機器の例外があれば全機器、なければ該当機器だけ）
    targets: dict[str, set[str] | None] = {}
    for e in expired:
        if e.rule_id not in rules:
            continue
        if e.device_id is None or targets.get(e.rule_id, set()) is None:
            targets[e.rule_id] = None
        else:
            targets.setdefault(e.rule_id, set()).add(e.device_id)
    for rule_id, device_ids in targets.items():
        await run_checks(db, device_ids=list(device_ids) if device_ids is not None else None,
                         rule_ids=[rule_id], actor=SYSTEM_ACTOR)
        # ルールごとに commit する（結果の書き換えのロックを持ったまま、次のルールの照合をしないように）
        await db.commit()
    return len(expired)


# ---------------------------------------------------------------- コンフィグの読み込み


def latest_config(device_id: str) -> tuple[str, str | None] | None:
    """最後に保存したコンフィグと、その世代（コミット）。未収集なら None"""
    try:
        path = repo_path(device_id)
    except ValueError:
        return None
    f = path / CONFIG_FILENAME
    if not f.is_file():
        return None
    text = f.read_text(encoding="utf-8", errors="replace")
    commit = None
    try:
        commit = git.Repo(path).head.commit.hexsha
    except (ValueError, git.InvalidGitRepositoryError, git.NoSuchPathError, git.GitCommandError):
        pass
    return text, commit


# ---------------------------------------------------------------- 検査の実行と保存

# 照合専用のスレッド。数が同時に照合できる上限になる（既定のスレッドプールは Git・ターミナルなどと取り合うので使わない）。
# スレッドは使うときに作られる。ループには結び付かないので、worker のようにタスクごとに asyncio.run していても使える
_pool = ThreadPoolExecutor(max_workers=settings.COMPLIANCE_CHECK_CONCURRENCY, thread_name_prefix="compliance-check")

# 結果の書き換え（DELETE + INSERT）を直列にする PostgreSQL のアドバイザリロックのキー（固定値 1 つ）
RESULT_WRITE_LOCK_KEY = 0x636F6D70  # "comp"


def _evaluate_jobs(text: str, jobs: list[tuple[RuleSpec, list[ExceptionSpec]]]) -> list[Evaluation]:
    """1台分のコンフィグを複数のルールで照合する（スレッドで動く。DB・ORM には触れない）"""
    return [evaluate_with_exceptions(s, text, excs) if excs else evaluate(s, text) for s, excs in jobs]


async def _evaluate_in_thread(text: str, jobs: list[tuple[RuleSpec, list[ExceptionSpec]]]) -> list[Evaluation]:
    """照合をイベントループの外（専用のスレッド）で行う。同時に走る数は COMPLIANCE_CHECK_CONCURRENCY まで（超えた分は待つ）"""
    return await asyncio.get_running_loop().run_in_executor(_pool, _evaluate_jobs, text, jobs)


async def lock_result_writes(db: AsyncSession) -> None:
    """結果の書き換えを直列にする（PostgreSQL のみ。トランザクションの終わりで自動的に外れる）

    同じ（機器, ルール）の再検査が同時に走ると、READ COMMITTED では互いの DELETE が見えず、
    2 本目の INSERT が一意制約（uq_compliance_results_device_rule）に当たるため。
    直列にしても、照合した時点より新しい結果を古い結果で上書きすることはありうるが、次の再検査で直るので許容する。
    機器・ルールの削除（結果を消してから機器・ルールの行を消す）も、ほかの書き込みより前にこのロックを取る。
    run_checks は「機器・ルールの行に KEY SHARE → 結果を DELETE / INSERT」の順なので、
    同じロックで直列にしないと、ロックの順序が逆になってデッドロックや外部キー違反になるため。
    ロックは commit / rollback まで外れないので、取ったあとに外部への通信や重い処理をしないこと。
    SQLite（テスト）は書き込みがもともと直列なので何もしない
    """
    if _is_postgres(db):
        await db.execute(sql_text("SELECT pg_advisory_xact_lock(:k)"), {"k": RESULT_WRITE_LOCK_KEY})


def _is_postgres(db: AsyncSession) -> bool:
    return db.get_bind().dialect.name == "postgresql"


async def run_checks(
    db: AsyncSession,
    device_ids: Iterable[str] | None = None,
    rule_ids: Iterable[str] | None = None,
    load_config: Callable[[str], tuple[str, str | None] | None] = latest_config,
    actor: str | None = None,
    ref: str | None = None,
) -> dict:
    """指定した機器（省略時は全機器）× ルール（省略時は全ルール）を検査し、結果を置き換える

    無効なルール・対象外のプラットフォームの結果は削除する。commit は呼び出し側で行う。
    照合を先に全部済ませてから、結果の書き換えを最後に短く行う（途中で例外・キャンセルになっても以前の結果が残る）。
    違反の発生（pass → fail、または初めての fail）と解消（fail → pass）はアクティビティログに記録する。
    違反の通知は commit が成功したあとに投入される（_enqueue_violation_notice。呼び出し側は commit するだけでよい）
    """
    dq = select(Device)
    if device_ids is not None:
        dq = dq.where(Device.id.in_(list(device_ids)))
    devices = (await db.execute(dq)).scalars().all()
    rq = select(ComplianceRule)
    if rule_ids is not None:
        rq = rq.where(ComplianceRule.id.in_(list(rule_ids)))
    rules = (await db.execute(rq)).scalars().all()
    if not devices or not rules:
        return {"devices": len(devices), "rules": len(rules), "checked": 0}

    dev_ids = [d.id for d in devices]
    rule_id_list = [r.id for r in rules]
    specs = {r.id: spec_of(r) for r in rules if r.enabled}
    now = utcnow()
    started_versions = {r.id: r.updated_at for r in rules}  # 照合を始めた時点のルールの版（途中の変更の検知用）
    # 有効な例外: (rule_id, device_id or None) → [ExceptionSpec]
    exceptions: dict[tuple[str, str | None], list[ExceptionSpec]] = {}
    for e in (await db.execute(select(ComplianceException).where(
            ComplianceException.rule_id.in_(rule_id_list)))).scalars():
        if active_exception(e, now):
            exceptions.setdefault((e.rule_id, e.device_id), []).append(ExceptionSpec(e.reason, e.ignore_pattern))
    # 1. コンフィグの読み込みと照合（この間は DB に書かない。以前の結果もそのまま残る）
    new_rows: list[tuple[Device, str, Evaluation, str | None]] = []
    for d in devices:
        targets = [(rid, s) for rid, s in specs.items() if applies_to(s, d.platform)]
        if not targets:
            continue
        loaded = await asyncio.to_thread(load_config, d.id)  # Git の読み込みはスレッドで
        if loaded is None:
            continue  # 未収集の機器は結果を持たない
        text_, commit = loaded
        # 照合（正規表現の compile と全文への照合）は CPU を使うので、専用のスレッドで行う。渡すのは素の値だけ
        jobs = [(s, exceptions.get((rid, None), []) + exceptions.get((rid, d.id), [])) for rid, s in targets]
        evals = await _evaluate_in_thread(text_, jobs)
        new_rows.extend((d, rid, ev, commit) for (rid, _), ev in zip(targets, evals, strict=True))
    # 2. 書き込みは最後にまとめて短く行う（直列化 → 以前の結果を読む → DELETE → INSERT）
    await lock_result_writes(db)
    # 照合の間に消された機器・ルール、変更されたルールの分は書かない（外部キー違反と、古い内容での上書きを避ける）。
    # PostgreSQL では FOR KEY SHARE で行をロックし、このあと commit までの間に消されないようにする。
    # 例外（ComplianceException）の変更は検知しない。その変更を保存した側の再検査が、新しい内容で書き直す
    dev_q = select(Device.id).where(Device.id.in_(dev_ids))
    rule_q = select(ComplianceRule.id, ComplianceRule.updated_at).where(ComplianceRule.id.in_(rule_id_list))
    if _is_postgres(db):
        dev_q, rule_q = dev_q.with_for_update(key_share=True), rule_q.with_for_update(key_share=True)
    live_devs = set((await db.execute(dev_q)).scalars())
    live_rules = {rid for rid, ver in (await db.execute(rule_q)).all() if ver == started_versions.get(rid)}
    dev_ids = [i for i in dev_ids if i in live_devs]
    rule_id_list = [i for i in rule_id_list if i in live_rules]
    new_rows = [x for x in new_rows if x[0].id in live_devs and x[1] in live_rules]
    previous = {
        (r.device_id, r.rule_id): r.status
        for r in (await db.execute(select(ComplianceResult).where(
            ComplianceResult.device_id.in_(dev_ids), ComplianceResult.rule_id.in_(rule_id_list)
        ))).scalars()
    }
    await db.execute(
        delete(ComplianceResult).where(
            ComplianceResult.device_id.in_(dev_ids), ComplianceResult.rule_id.in_(rule_id_list)
        )
    )
    checked = 0
    transitions: list[tuple] = []
    for d, rid, ev, commit in new_rows:
        before = previous.get((d.id, rid))
        if ev.status == "fail" and before != "fail":
            transitions.append(("violation", d, rid, ev.details))
        elif ev.status == "pass" and before == "fail":
            transitions.append(("resolved", d, rid, None))
        elif ev.status == "exempt" and before == "fail":
            transitions.append(("exempted", d, rid, None))
        db.add(ComplianceResult(
            device_id=d.id, rule_id=rid, status=ev.status,
            detail=json.dumps(ev.details, ensure_ascii=False) if ev.details else None,
            commit_hash=commit, checked_at=now,
        ))
        checked += 1
    rule_map = {r.id: r for r in rules if r.id in live_rules}
    _record_transitions(db, transitions, rule_map, actor, ref)
    await _enqueue_violation_notice(db, transitions, rule_map, ref)
    return {"devices": len(devices), "rules": len(rules), "checked": checked,
            "new_violations": sum(1 for t in transitions if t[0] == "violation"),
            "resolved": sum(1 for t in transitions if t[0] == "resolved")}


_PENDING_NOTICES = "compliance_pending_notices"  # Session.info のキー。commit が成功したあとに投入する通知


async def _enqueue_violation_notice(db: AsyncSession, transitions: list[tuple], rules: dict, ref: str | None) -> None:
    """新しく違反になったものの通知を、投入待ちとしてセッションに積む（通知する設定がある場合だけ）。

    ここでは Celery（Redis）へ投入しない。アドバイザリロック（lock_result_writes）を持ったままの通信を避け、
    保存に失敗したのに通知だけが出るのを防ぐため、呼び出し側の commit が成功した直後に
    _flush_pending_notices（Session の after_commit）が投入する。rollback されたら破棄する。
    呼び出し元（API・worker）は何もしなくてよい（commit さえすればよい）
    """
    by_device: dict[str, list[tuple[str, str]]] = {}
    for kind, d, rid, _ in transitions:
        if kind == "violation" and rid in rules:
            by_device.setdefault(d.id, []).append((rules[rid].name, rules[rid].severity))
    if not by_device:
        return
    from app.services.notify import wants_any  # 循環 import を避ける
    try:
        if not await wants_any(db, "violation"):
            return
        db.sync_session.info.setdefault(_PENDING_NOTICES, []).append(([[k, v] for k, v in by_device.items()], ref))
    except Exception:  # noqa: BLE001 - 通知の準備に失敗しても検査は続ける
        logger.exception("違反の通知を準備できませんでした")


@event.listens_for(Session, "after_commit")
def _flush_pending_notices(session: Session) -> None:
    """commit が成功したあとに、積んでおいた違反の通知を Celery へ投入する（run_checks 1 回につき 1 件）"""
    if session.in_nested_transaction():  # SAVEPOINT の解放では投入しない（外側の commit を待つ）
        return
    pending = session.info.pop(_PENDING_NOTICES, None)
    if not pending:
        return
    try:
        from app.worker import send_violation_notification
        for items, ref in pending:
            send_violation_notification.delay(items, ref)
    except Exception:  # noqa: BLE001 - 通知の投入に失敗しても、保存済みの検査結果には影響させない
        logger.exception("違反の通知を投入できませんでした")


@event.listens_for(Session, "after_transaction_end")
def _drop_pending_notices(session: Session, transaction) -> None:
    """一番外側のトランザクションが終わったら、積んでおいた通知を捨てる（commit のあとに呼ばれるので、投入済みなら残っていない）。

    rollback・close のどちらでも消えるので、保存されなかった違反は通知されず、close 後に同じセッションを使い回しても
    古い通知は投入されない。SAVEPOINT の中で積んで SAVEPOINT だけ rollback した場合は破棄されない（この形は使わない）
    """
    if transaction.parent is None:
        session.info.pop(_PENDING_NOTICES, None)


SEVERITY_LABELS = {"high": "高", "medium": "中", "low": "低"}
MAX_TRANSITION_RECORDS = 30  # これを超える変化（ルールの追加で多数の機器が違反になった等）はまとめて1件にする


def _record_transitions(db: AsyncSession, transitions: list[tuple], rules: dict, actor: str | None, ref: str | None):
    if not transitions:
        return
    if len(transitions) > MAX_TRANSITION_RECORDS:
        n_v = sum(1 for t in transitions if t[0] == "violation")
        n_r = len(transitions) - n_v
        kinds = {"violation": "違反", "resolved": "解消", "exempted": "除外"}
        items = [f"{kinds[k]}: {d.name} / {rules[rid].name}" for k, d, rid, _ in transitions]
        record_activity(db, "compliance.summary", f"違反の発生 {n_v} 件・解消・除外 {n_r} 件",
                        level="warning" if n_v else "info", detail={"items": items[:100]}, actor=actor, ref=ref)
        return
    for kind, d, rid, details in transitions:
        rule = rules[rid]
        sev = SEVERITY_LABELS.get(rule.severity, rule.severity)
        if kind == "violation":
            record_activity(db, "compliance.violation", f"ルール「{rule.name}」（重要度 {sev}）に違反しています",
                            device_id=d.id, device_name=d.name,
                            detail={"rule": rule.name, "severity": rule.severity, "matches": (details or [])[:5]},
                            actor=actor, ref=ref)
        elif kind == "exempted":
            record_activity(db, "compliance.exempted", f"ルール「{rule.name}」の違反を例外として除外しました",
                            device_id=d.id, device_name=d.name, detail={"rule": rule.name}, actor=actor, ref=ref)
        else:
            record_activity(db, "compliance.resolved", f"ルール「{rule.name}」の違反が解消しました",
                            device_id=d.id, device_name=d.name, detail={"rule": rule.name}, actor=actor, ref=ref)


# ---------------------------------------------------------------- ルールのテンプレート

# ひな形は機種ごとに app/services/compliance_templates/ に分けて持つ（TEMPLATES は API に出す形。合格・違反の例を含む
# 完全な一覧 ALL_TEMPLATES はテストで使う）
