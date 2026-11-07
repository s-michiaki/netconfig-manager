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
"""
import asyncio
import json
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

import git
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timeutil import utcnow
from app.models.compliance import ComplianceException, ComplianceResult, ComplianceRule
from app.models.device import Device
from app.services.activity import SYSTEM_ACTOR
from app.services.activity import record as record_activity
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


def pattern_allowed(spec: RuleSpec) -> bool:
    """該当箇所単位の例外を使えるルールか（コンフィグ全体で「必要」なルールは外す箇所が無い）"""
    return spec.scope == "section" or spec.expect == "absent"


def validate_ignore_pattern(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as e:
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


def make_matcher(spec: RuleSpec) -> Callable[[str], bool]:
    """1行を判定する関数。正規表現が不正なら ValueError"""
    if spec.match_type == "regex":
        try:
            rx = re.compile(spec.pattern)
        except re.error as e:
            raise ValueError(f"正規表現が正しくありません: {e}") from e
        return lambda line: rx.search(line) is not None
    return lambda line: spec.pattern in line


def validate_spec(spec: RuleSpec) -> None:
    make_matcher(spec)
    if spec.scope == "section":
        if not spec.section_pattern:
            raise ValueError("セクションごとに検査する場合は、セクションの見出し（正規表現）を指定してください")
        try:
            re.compile(spec.section_pattern)
        except re.error as e:
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


def evaluate(spec: RuleSpec, config_text: str, ignore: list[re.Pattern] | None = None) -> Evaluation:
    """ignore: 検査から外す箇所（違反行・セクションの見出しに一致する正規表現）"""
    try:
        match = make_matcher(spec)
    except ValueError as e:
        return Evaluation("error", [str(e)])
    lines = config_text.splitlines()
    ignore = ignore or []

    def ignored(text: str) -> bool:
        return any(rx.search(text) for rx in ignore)

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
        head_rx = re.compile(spec.section_pattern or "")
    except re.error as e:
        return Evaluation("error", [f"セクションの見出しの正規表現が正しくありません: {e}"])
    violations: list[str] = []
    count = 0
    for head_no, head, body in parse_sections(lines):
        if not head_rx.search(head):
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
                ignore.append(re.compile(e.ignore_pattern))
            except re.error:
                continue  # 登録時に検証しているので通常は起きない
    ev = evaluate(spec, config_text, ignore if pattern_allowed(spec) else None)
    reasons = "・".join(dict.fromkeys(e.reason for e in exceptions))
    if ev.status == "pass" and ev.ignored:
        return Evaluation("exempt", [f"例外: {reasons}"] + [f"除外: {x}" for x in ev.ignored], ev.ignored)
    if ev.status == "fail" and any(not e.ignore_pattern for e in exceptions):
        return Evaluation("exempt", [f"例外（機器単位）: {reasons}"] + ev.details, ev.ignored)
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
                        f"ルール「{rule.name}」の例外（{device.name if device else '全機器'}・理由: {e.reason}）の期限が切れたため再検査しました",
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
    違反の発生（pass → fail、または初めての fail）と解消（fail → pass）はアクティビティログに記録する
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
    specs = {r.id: spec_of(r) for r in rules if r.enabled}
    now = utcnow()
    # 有効な例外: (rule_id, device_id or None) → [ExceptionSpec]
    exceptions: dict[tuple[str, str | None], list[ExceptionSpec]] = {}
    for e in (await db.execute(select(ComplianceException).where(
            ComplianceException.rule_id.in_(rule_id_list)))).scalars():
        if active_exception(e, now):
            exceptions.setdefault((e.rule_id, e.device_id), []).append(ExceptionSpec(e.reason, e.ignore_pattern))
    checked = 0
    transitions: list[tuple] = []
    for d in devices:
        targets = [(rid, s) for rid, s in specs.items() if applies_to(s, d.platform)]
        if not targets:
            continue
        loaded = await asyncio.to_thread(load_config, d.id)  # Git の読み込みはスレッドで
        if loaded is None:
            continue  # 未収集の機器は結果を持たない
        text, commit = loaded
        for rid, s in targets:
            excs = exceptions.get((rid, None), []) + exceptions.get((rid, d.id), [])
            ev = evaluate_with_exceptions(s, text, excs) if excs else evaluate(s, text)
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
    rule_map = {r.id: r for r in rules}
    _record_transitions(db, transitions, rule_map, actor, ref)
    await _enqueue_violation_notice(db, transitions, rule_map, ref)
    return {"devices": len(devices), "rules": len(rules), "checked": checked,
            "new_violations": sum(1 for t in transitions if t[0] == "violation"),
            "resolved": sum(1 for t in transitions if t[0] == "resolved")}


async def _enqueue_violation_notice(db: AsyncSession, transitions: list[tuple], rules: dict, ref: str | None) -> None:
    """新しく違反になったものを通知する（通知する設定がある場合だけ、送信は worker のタスクで）"""
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
        from app.worker import send_violation_notification
        send_violation_notification.delay([[k, v] for k, v in by_device.items()], ref)
    except Exception:  # noqa: BLE001 - 通知の投入に失敗しても検査は続ける
        logger.exception("違反の通知を投入できませんでした")


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

_IOS = ["cisco_ios", "cisco_xe"]
_AWPLUS = ["allied_telesis_awplus"]

TEMPLATES: list[dict] = [
    {
        "name": "パスワードの暗号化表示", "severity": "medium", "platforms": _IOS,
        "description": "コンフィグ上のパスワードを暗号化して表示する（service password-encryption）",
        "match_type": "regex", "expect": "present", "pattern": r"^service password-encryption", "scope": "config",
    },
    {
        "name": "enable secret を使う", "severity": "high", "platforms": _IOS,
        "description": "enable password（弱いハッシュ）ではなく enable secret を使う",
        "match_type": "regex", "expect": "absent", "pattern": r"^enable password ", "scope": "config",
    },
    {
        "name": "HTTP サーバーの無効化", "severity": "medium", "platforms": _IOS,
        "description": "Web 管理画面（ip http server）を無効にする",
        "match_type": "regex", "expect": "absent", "pattern": r"^ip http server", "scope": "config",
    },
    {
        "name": "SSH バージョン2", "severity": "high", "platforms": _IOS,
        "description": "SSH はバージョン2のみ許可する",
        "match_type": "regex", "expect": "present", "pattern": r"^ip ssh version 2", "scope": "config",
    },
    {
        "name": "VTY で Telnet を許可しない", "severity": "high", "platforms": _IOS,
        "description": "line vty の transport input に telnet を含めない",
        "match_type": "regex", "expect": "absent", "pattern": r"transport input .*(telnet|all)", "scope": "section",
        "section_pattern": r"^line vty",
    },
    {
        "name": "NTP サーバーの設定", "severity": "low", "platforms": [*_IOS, "cisco_nxos", "arista_eos", *_AWPLUS],
        "description": "時刻同期のため NTP サーバーを設定する",
        "match_type": "regex", "expect": "present", "pattern": r"^ntp server ", "scope": "config",
    },
    {
        "name": "Syslog の転送先", "severity": "low", "platforms": _IOS,
        "description": "ログを Syslog サーバーへ転送する",
        "match_type": "regex", "expect": "present", "pattern": r"^logging (host )?\d", "scope": "config",
    },
    {
        "name": "既定の SNMP コミュニティを使わない", "severity": "high",
        "platforms": [*_IOS, "cisco_nxos", "arista_eos", *_AWPLUS],
        "description": "public / private のコミュニティ名は使わない",
        "match_type": "regex", "expect": "absent", "pattern": r"^snmp-server community (public|private)\b",
        "scope": "config",
    },
    {
        "name": "物理インターフェースに説明を付ける", "severity": "low", "platforms": [*_IOS, "cisco_nxos", "arista_eos"],
        "description": "各物理インターフェースに description を設定する",
        "match_type": "regex", "expect": "present", "pattern": r"^\s+description ", "scope": "section",
        "section_pattern": r"^interface (GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet)",
    },
    {
        "name": "PAN-OS: Telnet 管理を無効化", "severity": "high", "platforms": ["paloalto_panos"],
        "description": "管理インターフェースの Telnet を無効にする",
        "match_type": "contains", "expect": "present", "pattern": "deviceconfig system service disable-telnet yes",
        "scope": "config",
    },
    {
        "name": "FortiGate: 管理アクセスに Telnet / HTTP を許可しない", "severity": "high", "platforms": ["fortinet"],
        "description": "インターフェースの allowaccess に telnet・http（暗号化されない管理アクセス）を含めない",
        "match_type": "regex", "expect": "absent", "pattern": r"^\s*set allowaccess .*\b(telnet|http)\b",
        "scope": "config",
    },
    {
        "name": "FortiGate: 管理者のアイドルタイムアウト", "severity": "low", "platforms": ["fortinet"],
        "description": "管理画面・CLI の無操作時の自動ログアウトを長くしすぎない（30 分以上を違反とする。既定は 5 分）",
        "match_type": "regex", "expect": "absent", "pattern": r"^\s*set admintimeout (\d{3,}|[3-9]\d)$",
        "scope": "config",
    },
    {
        "name": "AW+: Telnet サーバーを無効化", "severity": "high", "platforms": _AWPLUS,
        "description": "Telnet での管理アクセスを無効にする（no service telnet）",
        "match_type": "regex", "expect": "present", "pattern": r"^no service telnet", "scope": "config",
    },
    {
        "name": "AW+: HTTP サーバーを無効化", "severity": "medium", "platforms": _AWPLUS,
        "description": "Web 管理画面（service http）を使わない場合は無効にする",
        "match_type": "regex", "expect": "present", "pattern": r"^no service http\b", "scope": "config",
    },
    {
        "name": "JunOS: root の SSH ログイン禁止", "severity": "high", "platforms": ["juniper_junos"],
        "description": "root ユーザーで SSH ログインできないようにする",
        "match_type": "contains", "expect": "present", "pattern": "set system services ssh root-login deny",
        "scope": "config",
    },
]
