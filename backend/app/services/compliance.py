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
from app.models.compliance import ComplianceResult, ComplianceRule
from app.models.device import Device
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
    status: str  # pass / fail / error
    details: list[str] = field(default_factory=list)


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


def evaluate(spec: RuleSpec, config_text: str) -> Evaluation:
    try:
        match = make_matcher(spec)
    except ValueError as e:
        return Evaluation("error", [str(e)])
    lines = config_text.splitlines()

    if spec.scope != "section":
        hits = [(no, line) for no, line in enumerate(lines, 1) if match(line)]
        if spec.expect == "present":
            return Evaluation("pass") if hits else Evaluation("fail", ["一致する行がありません"])
        if not hits:
            return Evaluation("pass")
        details = [_fmt(no, line) for no, line in hits[:MAX_DETAILS]]
        if len(hits) > MAX_DETAILS:
            details.append(f"ほか {len(hits) - MAX_DETAILS} 行")
        return Evaluation("fail", details)

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
        count += 1
        if len(violations) < MAX_DETAILS:
            if spec.expect == "present":
                violations.append(f"{head_no}行目: {head.strip()}（一致する行がありません）")
            else:
                violations.append(f"{head_no}行目: {head.strip()} → {hits[0][1].strip()}")
    if count > MAX_DETAILS:
        violations.append(f"ほか {count - MAX_DETAILS} セクション")
    return Evaluation("fail", violations) if violations else Evaluation("pass")


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
) -> dict:
    """指定した機器（省略時は全機器）× ルール（省略時は全ルール）を検査し、結果を置き換える

    無効なルール・対象外のプラットフォームの結果は削除する。commit は呼び出し側で行う
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
    await db.execute(
        delete(ComplianceResult).where(
            ComplianceResult.device_id.in_(dev_ids), ComplianceResult.rule_id.in_(rule_id_list)
        )
    )
    specs = {r.id: spec_of(r) for r in rules if r.enabled}
    now = utcnow()
    checked = 0
    for d in devices:
        targets = [(rid, s) for rid, s in specs.items() if applies_to(s, d.platform)]
        if not targets:
            continue
        loaded = await asyncio.to_thread(load_config, d.id)  # Git の読み込みはスレッドで
        if loaded is None:
            continue  # 未収集の機器は結果を持たない
        text, commit = loaded
        for rid, s in targets:
            ev = evaluate(s, text)
            db.add(ComplianceResult(
                device_id=d.id, rule_id=rid, status=ev.status,
                detail=json.dumps(ev.details, ensure_ascii=False) if ev.details else None,
                commit_hash=commit, checked_at=now,
            ))
            checked += 1
    return {"devices": len(devices), "rules": len(rules), "checked": checked}


# ---------------------------------------------------------------- ルールのテンプレート

_IOS = ["cisco_ios", "cisco_xe"]

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
        "name": "NTP サーバーの設定", "severity": "low", "platforms": [*_IOS, "cisco_nxos", "arista_eos"],
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
        "platforms": [*_IOS, "cisco_nxos", "arista_eos"],
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
        "name": "JunOS: root の SSH ログイン禁止", "severity": "high", "platforms": ["juniper_junos"],
        "description": "root ユーザーで SSH ログインできないようにする",
        "match_type": "contains", "expect": "present", "pattern": "set system services ssh root-login deny",
        "scope": "config",
    },
]
