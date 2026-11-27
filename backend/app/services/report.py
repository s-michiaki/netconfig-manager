"""定期レポート（週次・月次）: 期間内の状況をまとめて、通知設定の宛先（Discord / Slack / Teams / メール）へ送る

送り先と範囲
  通知設定（利用者・ユーザーグループ）の report が weekly / monthly / both のもの。対象の機器の絞り込み
  （all_devices / device_group_ids / include_ungrouped）は通知と同じで、その範囲の機器だけで集計する。
  - 利用者の設定: mode が custom のもの（所属グループの設定を使う・通知しない人の設定では送らない）
  - グループの設定: mode が custom で、「所属グループの設定を使う」有効なメンバーが 1 人以上いるもの
  - 管理者向けの項目（2 段階認証・ログインの一時停止・証明書・API トークン）は、管理者または SYSTEM_READ を持つ
    利用者の設定だけに入れる（機器に結び付かないので、グループの設定には入れない）
  設定ごとに 1 通（同じ Webhook を複数の設定が持っていても、設定ごとの範囲で作った別の内容を送る）

送る日（取り戻しの期間）
  settings.TIMEZONE の時刻で判定する。週次は月曜（前の月曜〜日曜の 7 日間）、月次は 1 日（前月）の REPORT_HOUR 時に送る。
  worker の毎時の判定（send_periodic_reports）が呼ぶので、送り損ねた回は取り戻しの期間（CATCHUP_DAYS）のあいだ、まだ送って
  いなければ送る（初日は REPORT_HOUR 時以降、翌日以降は終日）。取り戻しの期間は、期間の終わり（月曜 0 時・1 日 0 時）から
  CATCHUP_DAYS 日と REPORT_HOUR 時間（＝次の期間を送り始める時刻。週次は次の月曜の REPORT_HOUR 時、月次は 28 日の REPORT_HOUR 時）
  までで、新しい期間の分とは重ならない。過ぎても送れなかった回は、アクティビティに 1 回だけ「送れませんでした」と残し、
  report_sends の行を missed にする（毎時くり返さない）。
  設定したあとに終わった期間だけ送る: notification_settings.report_week_since / report_month_since（その種類が「無効 → 有効」
  になった時刻。API が入れる。有効のままの種類は変えない）より前に終わった期間は送らない。since が NULL のまま有効な行
  （API を通らずに作られた行）は、最初の判定で「いま」を入れ、その回は送らない。

二重に送らない
  送る前に (設定, 種類, 期間の最初の日) の行（report_sends）を作る。一意制約があるので、worker の再起動・タスクの重複・
  beat の二重起動・同時に判定した 2 つの worker のうち、行を作れた 1 つだけが送る（PostgreSQL・SQLite とも）。
  すべての宛先で失敗したときだけ failed にして、次の毎時の判定でやり直す（MAX_ATTEMPTS 回まで）。
  送信中のまま止まった行は STALE_MIN 分たったらやり直す（これも MAX_ATTEMPTS 回まで。送信は数十秒で終わるので、動いている
  送信と重ならない。引き継いだときは、途中まで送った宛先に再送しうる）。
  判定のたびに、その期間の行を 1 回の SELECT でまとめて読み、送信済み・送信中の設定は INSERT を試さない
  （PostgreSQL のログに重複エラーを出さない。競合したときの一意制約による保護は残す）。

集計
  期間内の件数（収集の成功・失敗、変更、新しく出た違反・解消した違反、Ping 監視の応答なし、ログインの一時停止）は
  期間の記録（収集の履歴・世代・アクティビティ・監査ログ）から数える。
  いまの件数（現在の違反、基準からのずれ、保存し忘れ、未確認の変更の残り、2 段階認証、証明書、API トークン）は
  現在の状態から数え、「いま」と書く。保持期間（ACTIVITY_LOG_RETENTION_DAYS など）より前の期間は集計できないので、
  その旨を注記する。
  秘密（コンフィグの中身・Webhook・認証情報・利用者のメールアドレス）は入れない。機器名・ルール名・件数だけ。
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import zip_longest
from zoneinfo import ZoneInfo

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.permissions import Perm, permissions_for
from app.core.timeutil import utcnow
from app.models.activity import ActivityLog
from app.models.api_token import ApiToken
from app.models.audit import AuditLog
from app.models.compliance import ComplianceResult, ComplianceRule
from app.models.device import CollectLog, ConfigBaseline, ConfigReview, ConfigSnapshot, Device
from app.models.notification import NotificationSetting, ReportSend, UserGroup, UserGroupMember
from app.models.ping import PingTarget
from app.models.user import User
from app.services import mail, notify, system
from app.services.activity import record as record_activity
from app.services.config_service import first_commit_hash, peek_first_commit

logger = logging.getLogger(__name__)

KINDS = ("week", "month")
# 取り戻しの期間（日）: 期間の終わり（月曜 0 時・1 日 0 時）からこの日数のあいだ、まだ送っていなければ送る
CATCHUP_DAYS = {"week": 7, "month": 27}  # さらに REPORT_HOUR 時間（次の期間を送り始める時刻）まで
KIND_LABELS = {"week": "週次", "month": "月次"}
REPORT_MODES = ("off", "weekly", "monthly", "both")
MAX_ATTEMPTS = 3  # すべての宛先で失敗したときのやり直しの上限（毎時の判定ごとに 1 回）
STALE_MIN = 30  # 送信中のまま止まった行をやり直すまでの時間（分）
TOP_DEVICES = 10
TOP_PING = 5
TOKEN_WARN_DAYS = 30  # 期限が近い API トークン・証明書とみなす日数
NAME_MAX = 60
SEND_NOW_INTERVAL_SEC = 60  # 「いま送る」の最短の間隔（利用者ごと）
PREVIEW_INTERVAL_SEC = 3  # プレビュー（集計）の最短の間隔（利用者ごと。連打で集計が重ならないように）
COLOR = 0x4F8EF7
# 通知手段ごとの長さの上限（Discord の埋め込み全体は 6000 文字・項目は 1024 文字・説明は 4096 文字、Slack は 3000 文字程度、
# Teams のカードは 24KB（notify.TEAMS_MAX_BYTES）。余裕を見る）
DISCORD_TOTAL = 5500
DISCORD_FIELD = 1000
SLACK_MAX = 3000
TOP_STEPS = (10, 5, 3, 2, 1, 0)  # 上位の一覧に載せる件数。長さに収まるまで減らす


# ---------------------------------------------------------------- 期間と送る日


def last_period(kind: str, now_local: datetime) -> tuple[datetime, datetime]:
    """now_local の直前の完結した期間（開始, 終了。終了は含まない）。週次は前の月曜〜日曜、月次は前月。

    now_local は settings.TIMEZONE のタイムゾーン付きの時刻
    """
    d = now_local.date()
    if kind == "week":
        monday = d - timedelta(days=d.weekday())
        start_d, end_d = monday - timedelta(days=7), monday
    elif kind == "month":
        first = d.replace(day=1)
        start_d, end_d = (first - timedelta(days=1)).replace(day=1), first
    else:
        raise ValueError(kind)
    tz = now_local.tzinfo
    return (datetime(start_d.year, start_d.month, start_d.day, tzinfo=tz),
            datetime(end_d.year, end_d.month, end_d.day, tzinfo=tz))


def to_utc(dt: datetime) -> datetime:
    """DB の DateTime（UTC の naive）と比べるための時刻"""
    return dt.astimezone(UTC).replace(tzinfo=None)


def period_label(start: datetime, end: datetime) -> str:
    last = end - timedelta(days=1)
    return f"{start.month}/{start.day}〜{last.month}/{last.day}"


def due_period(kind: str, now_local: datetime) -> tuple[datetime, datetime] | None:
    """今、送ってよい期間（直前の完結した期間）。取り戻しの期間内で、初日（週次は月曜・月次は 1 日）は REPORT_HOUR 時以降。

    送れない時刻（初日の REPORT_HOUR 前・取り戻しの期間を過ぎた）は None
    """
    start, end = last_period(kind, now_local)
    if now_local < end + timedelta(hours=settings.REPORT_HOUR) or window_over(kind, end, now_local):
        return None
    return start, end


def window_over(kind: str, end: datetime, now_local: datetime) -> bool:
    """期間 end（含まない終わり）の取り戻しの期間を過ぎたか（次の期間を送り始める時刻から）"""
    return now_local >= end + timedelta(days=CATCHUP_DAYS[kind], hours=settings.REPORT_HOUR)


def kinds_of(mode: str | None) -> set[str]:
    """report の値が表す種類（week / month）"""
    return {"weekly": {"week"}, "monthly": {"month"}, "both": {"week", "month"}}.get(mode or "off", set())


def local_now() -> datetime:
    return datetime.now(ZoneInfo(settings.TIMEZONE))


# ---------------------------------------------------------------- レポートの中身


@dataclass
class Section:
    key: str
    title: str
    basis: str  # period（期間内の件数）/ now（いまの件数）/ mixed（両方）
    lines: list[str]
    top_title: str = ""
    top: list[str] = field(default_factory=list)  # 上位の一覧（長さに応じて減らして載せる）
    top_total: int = 0  # 上位に絞る前の件数

    def to_dict(self) -> dict:
        return {"key": self.key, "title": self.title, "basis": self.basis, "lines": self.lines,
                "top_title": self.top_title, "top": self.top, "top_total": self.top_total}


@dataclass
class Report:
    kind: str
    label: str  # 例: 11/16〜11/22
    start: datetime  # 期間の開始（TIMEZONE）
    end: datetime  # 期間の終了（含まない）
    devices: int  # 対象の機器の数
    empty: bool  # 期間内に変更・失敗・新しい違反・応答なしが 1 件も無い
    sections: list[Section]
    notes: list[str] = field(default_factory=list)
    at: datetime | None = None  # 集計した時刻（TIMEZONE）。「いまの件数」がいつの時点かを示す

    @property
    def title(self) -> str:
        return f"{KIND_LABELS[self.kind]}レポート {self.label}"

    def head_lines(self) -> list[str]:
        out = [f"期間: {self.start:%Y/%m/%d} 〜 {(self.end - timedelta(days=1)):%Y/%m/%d}（{settings.TIMEZONE}）",
               f"対象の機器: {self.devices} 台"]
        if self.at is not None:
            out.insert(1, f"集計: {self.at:%Y/%m/%d %H:%M} 時点（{settings.TIMEZONE}。「いま」の件数はこの時点）")
        if self.empty:
            out.append("この期間は、変更・収集の失敗・新しい違反・Ping監視の応答なしはありませんでした（変更なし）")
        return out

    def to_dict(self) -> dict:
        return {"kind": self.kind, "title": self.title, "label": self.label, "start": self.start.isoformat(),
                "end": self.end.isoformat(), "devices": self.devices, "empty": self.empty, "head": self.head_lines(),
                "notes": self.notes, "sections": [s.to_dict() for s in self.sections]}


def _name(s: str | None) -> str:
    """機器名・ルール名を 1 行に収める（利用者・機器が決められる文字列。改行・制御文字を除き、長さを切る）"""
    t = " ".join((s or "（名前なし）").split())
    return t[:NAME_MAX] + ("…" if len(t) > NAME_MAX else "")


def _chunks(ids: list[str], n: int = 500):
    for i in range(0, len(ids), n):
        yield ids[i:i + n]


async def _scope_devices(db: AsyncSession, setting: NotificationSetting) -> dict[str, dict]:
    """対象の機器（通知設定の絞り込みに合うもの）。{機器 ID: {name, group_id, active, startup...}}"""
    rows = (await db.execute(select(Device.id, Device.name, Device.group_id, Device.is_active, Device.startup_state,
                                    Device.startup_added, Device.startup_removed))).all()
    return {r.id: {"name": r.name, "group_id": r.group_id, "active": bool(r.is_active), "startup": r.startup_state,
                   "s_add": r.startup_added or 0, "s_rem": r.startup_removed or 0}
            for r in rows if setting.matches(r.group_id)}


def _top(counter: dict[str, int], names: dict[str, str], limit: int) -> list[tuple[str, int]]:
    items = sorted(counter.items(), key=lambda kv: (-kv[1], names.get(kv[0], "")))
    return [(names.get(k, k), n) for k, n in items[:limit]]


async def _collect_section(db, scope, s_utc, e_utc) -> tuple[Section, int]:
    """収集: 期間内の成功・失敗の回数と、失敗が続いている機器

    成功は収集の履歴（collect_logs）の成功。失敗は、再試行しても失敗した最終の失敗（アクティビティの collect.failed の
    error。再試行を待つ途中の失敗は warning なので数えない）
    """
    ok_rows = (await db.execute(
        select(CollectLog.device_id, func.count(), func.max(CollectLog.started_at))
        .where(CollectLog.status == "success", CollectLog.started_at >= s_utc, CollectLog.started_at < e_utc)
        .group_by(CollectLog.device_id))).all()
    ok = sum(n for d, n, _ in ok_rows if d in scope)
    last_ok = {d: t for d, _, t in ok_rows if d in scope}
    fails: dict[str, list[datetime]] = {}
    for d, at in (await db.execute(select(ActivityLog.device_id, ActivityLog.at).where(
            ActivityLog.event == "collect.failed", ActivityLog.level == "error",
            ActivityLog.at >= s_utc, ActivityLog.at < e_utc))).all():
        if d in scope:
            fails.setdefault(d, []).append(at)
    ng = sum(len(v) for v in fails.values())
    streak = {d: sum(1 for t in v if d not in last_ok or t > last_ok[d]) for d, v in fails.items()}
    streak = {d: n for d, n in streak.items() if n >= 2}
    names = {d: v["name"] for d, v in scope.items()}
    top = [f"{_name(n)}: {c} 回続けて失敗" for n, c in _top(streak, names, TOP_DEVICES)]
    lines = [f"収集の成功 {ok} 回・失敗 {ng} 回（再試行の途中の失敗は数えません）"] if (ok or ng) else \
        ["期間内に収集の記録はありません"]
    return Section("collect", "収集", "period", lines, "失敗が続いている機器（期間内の最後の成功のあとに 2 回以上失敗）",
                   top, len(streak)), ng


async def _first_commits(device_ids: set[str]) -> dict[str, str]:
    """機器ごとの最初の世代（初回の収集。変更ではない）。Git を読むのは覚えていない機器だけ（スレッドで）"""
    missing = [d for d in device_ids if peek_first_commit(d) is None]
    if missing:
        await asyncio.to_thread(lambda: [first_commit_hash(d) for d in missing])
    return {d: h for d in device_ids if (h := peek_first_commit(d))}


async def _changes(db, scope, since: datetime, until: datetime) -> list[tuple[str, str, int, int]]:
    """期間内の変更（機器 ID, 世代, 追加行, 削除行）。初回の世代を除き、同じ (機器, 世代) は 1 件"""
    rows = (await db.execute(
        select(ConfigSnapshot.device_id, ConfigSnapshot.commit_hash, ConfigSnapshot.lines_added, ConfigSnapshot.lines_removed)
        .where(ConfigSnapshot.collected_at >= since, ConfigSnapshot.collected_at < until)
        .order_by(ConfigSnapshot.collected_at, ConfigSnapshot.id))).all()
    rows = [r for r in rows if r.device_id in scope]
    firsts = await _first_commits({r.device_id for r in rows})
    seen: set[tuple[str, str]] = set()
    out = []
    for r in rows:
        key = (r.device_id, r.commit_hash)
        if key in seen or firsts.get(r.device_id) == r.commit_hash:
            continue
        seen.add(key)
        out.append((r.device_id, r.commit_hash, r.lines_added or 0, r.lines_removed or 0))
    return out


async def _unreviewed(db, changes: list[tuple[str, str, int, int]]) -> int:
    """変更のうち、いま確認の状態が付いていないものの数"""
    if not changes:
        return 0
    reviewed: set[tuple[str, str]] = set()
    for chunk in _chunks(sorted({c[0] for c in changes})):
        reviewed |= {(d, h) for d, h in (await db.execute(
            select(ConfigReview.device_id, ConfigReview.commit_hash).where(ConfigReview.device_id.in_(chunk)))).all()}
    return sum(1 for c in changes if (c[0], c[1]) not in reviewed)


async def _change_section(db, scope, s_utc, e_utc, now) -> tuple[Section, int]:
    changes = await _changes(db, scope, s_utc, e_utc)
    per: dict[str, int] = {}
    lines_of: dict[str, list[int]] = {}
    for d, _, a, r in changes:
        per[d] = per.get(d, 0) + 1
        t = lines_of.setdefault(d, [0, 0])
        t[0] += a
        t[1] += r
    names = {d: v["name"] for d, v in scope.items()}
    ranked = sorted(per.items(), key=lambda kv: (-kv[1], names[kv[0]]))[:TOP_DEVICES]
    top = [f"{_name(names[d])}: {c} 件（+{lines_of[d][0]} / -{lines_of[d][1]} 行）" for d, c in ranked]
    unrev = await _unreviewed(db, changes)
    if changes:
        lines = [f"変更のあった機器 {len(per)} 台・変更 {len(changes)} 件（うち未確認 {unrev} 件。未確認はいまの状態）"]
    else:
        lines = ["期間内にコンフィグの変更はありませんでした（変更なし）"]
    window = settings.CHANGE_REVIEW_DAYS
    recent = await _changes(db, scope, now - timedelta(days=window), now)
    lines.append(f"未確認の変更の残り（直近 {window} 日・いまの件数）: {await _unreviewed(db, recent)} 件")
    return Section("change", "変更", "mixed", lines, "変更の多い機器", top, len(per)), len(changes)


async def _compliance_section(db, scope, s_utc, e_utc) -> tuple[Section, int]:
    """コンプライアンス: 期間内に新しく出た違反・解消した違反（アクティビティの遷移の記録）と、いまの違反の件数"""
    new_by_dev: dict[str, int] = {}
    resolved = 0
    partial = False
    names = {d: v["name"] for d, v in scope.items()}
    by_name = {v["name"]: d for d, v in scope.items()}
    for ev, dev, detail in (await db.execute(select(ActivityLog.event, ActivityLog.device_id, ActivityLog.detail).where(
            ActivityLog.event.in_(("compliance.violation", "compliance.resolved", "compliance.summary")),
            ActivityLog.at >= s_utc, ActivityLog.at < e_utc))).all():
        if ev == "compliance.summary":
            # 一度に多数が変わったときは機器別の記録が無く、1 件にまとめた一覧（先頭 100 件）だけがある
            try:
                items = json.loads(detail or "{}").get("items", [])
            except ValueError:
                items = []
            partial = partial or len(items) >= 100
            for it in items:
                kind, _, rest = str(it).partition(": ")
                d = by_name.get(rest.rpartition(" / ")[0])
                if d is None:
                    continue
                if kind == "違反":
                    new_by_dev[d] = new_by_dev.get(d, 0) + 1
                elif kind == "解消":
                    resolved += 1
        elif dev in scope:
            if ev == "compliance.violation":
                new_by_dev[dev] = new_by_dev.get(dev, 0) + 1
            else:
                resolved += 1
    new = sum(new_by_dev.values())
    fails = (await db.execute(
        select(ComplianceResult.device_id, ComplianceRule.severity)
        .join(ComplianceRule, ComplianceRule.id == ComplianceResult.rule_id)
        .where(ComplianceResult.status == "fail", ComplianceRule.enabled.is_(True)))).all()
    by_sev = {"high": 0, "medium": 0, "low": 0}
    devs = set()
    for d, sev in fails:
        if d in scope and scope[d]["active"]:
            by_sev[sev] = by_sev.get(sev, 0) + 1
            devs.add(d)
    note = "（一括の検査の一部は数えられていません）" if partial else ""
    lines = [f"新しく出た違反 {new} 件・解消した違反 {resolved} 件{note}",
             f"いまの違反（いまの件数）: 高 {by_sev['high']} 件・中 {by_sev['medium']} 件・低 {by_sev['low']} 件"
             f"（{len(devs)} 台）"]
    top = [f"{_name(n)}: {c} 件" for n, c in _top(new_by_dev, names, TOP_DEVICES)]
    return Section("compliance", "コンプライアンス", "mixed", lines, "新しく違反が出た機器", top, len(new_by_dev)), new + resolved


async def _state_section(db, scope) -> Section:
    """基準の世代からのずれ・保存し忘れ（どちらもいまの件数。履歴は残していない）"""
    drift_rows = (await db.execute(
        select(ConfigBaseline.device_id, ConfigBaseline.drift_added, ConfigBaseline.drift_removed))).all()
    drift = sorted(((scope[d]["name"], (a or 0), (r or 0)) for d, a, r in drift_rows
                    if d in scope and scope[d]["active"] and (a or 0) + (r or 0) > 0), key=lambda x: (-(x[1] + x[2]), x[0]))
    unsaved = sorted(((v["name"], v["s_add"], v["s_rem"]) for v in scope.values()
                      if v["active"] and v["startup"] == "unsaved"), key=lambda x: (-(x[1] + x[2]), x[0]))
    d_lines = [f"基準からのずれ: {_name(n)}（+{a} / -{r} 行）" for n, a, r in drift[:TOP_DEVICES]]
    u_lines = [f"保存し忘れ: {_name(n)}（+{a} / -{r} 行）" for n, a, r in unsaved[:TOP_DEVICES]]
    top = [x for pair in zip_longest(d_lines, u_lines) for x in pair if x][:TOP_DEVICES]
    lines = [f"基準の世代からずれている機器（いまの件数）: {len(drift)} 台",
             f"保存し忘れ（running と startup が不一致。いまの件数）: {len(unsaved)} 台"]
    return Section("state", "基準のずれ・保存し忘れ", "now", lines, "該当する機器", top, len(drift) + len(unsaved))


async def _ping_section(db, scope, setting, s_utc, e_utc) -> tuple[Section, int]:
    """Ping監視: 期間内に「応答なし」になった回数（アクティビティの ping.down。機器と、追加した IP・ホスト名）"""
    targets = {t.id: t for t in (await db.execute(select(PingTarget))).scalars()}
    counts: dict[str, int] = {}
    names: dict[str, str] = {}
    for dev, detail in (await db.execute(select(ActivityLog.device_id, ActivityLog.detail).where(
            ActivityLog.event == "ping.down", ActivityLog.at >= s_utc, ActivityLog.at < e_utc))).all():
        if dev:
            if dev not in scope:
                continue
            key, label = f"d:{dev}", scope[dev]["name"]
        else:
            try:
                k = str(json.loads(detail or "{}").get("key", ""))
            except ValueError:
                continue
            t = targets.get(k[2:]) if k.startswith("t:") else None
            if t is None or not setting.matches(t.group_id):
                continue
            key, label = k, t.name
        counts[key] = counts.get(key, 0) + 1
        names[key] = label
    total = sum(counts.values())
    lines = [f"応答なしになった回数 {total} 回（{len(counts)} 件）" if total else "期間内に応答なしになった対象はありません"]
    top = [f"{_name(n)}: {c} 回" for n, c in _top(counts, names, TOP_PING)]
    return Section("ping", "Ping監視", "period", lines, "応答なしの多い対象", top, len(counts)), total


VULN_EOL_REPORT_DAYS = 180  # 「サポート終了が近い」とみなす日数（通知の最初の段階と同じ）
TOP_EOL = 5


async def _vuln_section(db, scope, s_utc, e_utc) -> Section:
    """脆弱性・サポート期限（VULN_ENABLED のときだけ）: 期間内に新しく該当になった件数、未確認の該当の多い機器（いま）、
    サポート終了が近い機器（いま）。勧告の題・本文・直し方は入れない（件数と機器名だけ）"""
    from app.models.vuln import VulnAdvisory, VulnMatch
    from app.services import vuln_service

    new = (await db.execute(select(VulnMatch.device_id).where(
        VulnMatch.confidence == "confirmed", VulnMatch.first_seen >= s_utc, VulnMatch.first_seen < e_utc))).scalars().all()
    n_new = sum(1 for d in new if d in scope)
    per: dict[str, list[int]] = {}
    for d, sev, kev in (await db.execute(
            select(VulnMatch.device_id, VulnAdvisory.severity, VulnAdvisory.kev)
            .join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
            .where(VulnMatch.state == "open", VulnMatch.stale.is_(False), VulnMatch.confidence == "confirmed"))).all():
        if d in scope:
            t = per.setdefault(d, [0, 0, 0, 0])  # 件数・重大・高・悪用確認済み
            t[0] += 1
            t[1] += sev == "critical"
            t[2] += sev == "high"
            t[3] += bool(kev)
    names = {d: v["name"] for d, v in scope.items()}
    ranked = sorted(per.items(), key=lambda kv: (-kv[1][3], -kv[1][1], -kv[1][2], -kv[1][0], names[kv[0]]))
    top = [f"{_name(names[d])}: {t[0]} 件（重大 {t[1]}・高 {t[2]}・悪用確認済み {t[3]}）" for d, t in ranked[:TOP_DEVICES]]
    eol_rows = await vuln_service.eol_rows(db)
    today = vuln_service.local_today()
    devs = [d for d in (await db.execute(select(Device))).scalars() if d.id in scope and scope[d.id]["active"]]
    soon = []
    for d in devs:
        e = vuln_service.device_eol(eol_rows, d, today)
        days = [(x["days_left"], x["eol_date"]) for x in (e["os"], e["hardware"]) if x]
        if days and min(days)[0] <= VULN_EOL_REPORT_DAYS:
            soon.append((min(days), d.name))
    soon.sort()
    lines = [f"期間内に新しく該当になった件数: {n_new} 件",
             f"未確認の該当（いまの件数）: {sum(t[0] for t in per.values())} 件（{len(per)} 台。"
             f"うち悪用確認済み {sum(t[3] for t in per.values())} 件）",
             f"サポート終了まで {VULN_EOL_REPORT_DAYS} 日以内・終了済みの機器（いまの件数）: {len(soon)} 台"]
    for (days, day), name in soon[:TOP_EOL]:
        when = f"あと {days} 日" if days > 0 else ("きょう終了" if days == 0 else "終了済み")
        lines.append(f"・{_name(name)}: {when}（{day.replace('-', '/')}）")
    if len(soon) > TOP_EOL:
        lines.append(f"…ほか {len(soon) - TOP_EOL} 台")
    return Section("vuln", "脆弱性・サポート期限", "mixed", lines, "未確認の該当が多い機器", top, len(per))


async def _admin_section(db, s_utc, e_utc, now) -> Section:
    """管理者向け: 機器に結び付かない項目（数だけ。利用者名・メールアドレス・トークン名は入れない）"""
    no_mfa = (await db.execute(select(func.count()).select_from(User).where(
        User.is_active.is_(True), User.mfa_enabled.is_(False)))).scalar_one()
    locked = (await db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "auth.login_locked", AuditLog.at >= s_utc, AuditLog.at < e_utc))).scalar_one()
    soon = (await db.execute(select(func.count()).select_from(ApiToken).where(
        ApiToken.revoked_at.is_(None), ApiToken.expires_at > now,
        ApiToken.expires_at <= now + timedelta(days=TOKEN_WARN_DAYS)))).scalar_one()
    cert = await system.check_cert(now)
    days = cert.detail.get("days_left")
    if cert.status == "unknown" or days is None:
        cert_line = f"HTTPS の証明書（いま）: {cert.summary}"
    else:
        cert_line = f"HTTPS の証明書（いま）: 期限まであと {days} 日" + ("（更新してください）" if cert.status != "ok" else "")
    lines = [f"2 段階認証を設定していない利用者（いまの件数）: {no_mfa} 人",
             f"ログインの一時停止（失敗の繰り返し・期間内）: {locked} 回",
             cert_line,
             f"{TOKEN_WARN_DAYS} 日以内に期限が切れる API トークン（いまの件数）: {soon} 件"]
    return Section("admin", "管理者向け", "mixed", lines)


def _retention_notes(start_local: datetime, now: datetime) -> list[str]:
    notes = []
    s = to_utc(start_local)
    for days, what in ((settings.ACTIVITY_LOG_RETENTION_DAYS, "アクティビティ（収集の失敗・違反・Ping監視）"),
                       (settings.AUDIT_LOG_RETENTION_DAYS, "監査ログ（ログインの一時停止）")):
        if days and s < now - timedelta(days=days):
            notes.append(f"{what}の保持期間（{days} 日）より前の期間を含むため、一部しか集計できていません")
    return notes


async def build_report(db: AsyncSession, kind: str, start: datetime, end: datetime, setting: NotificationSetting,
                       include_admin: bool = False, now: datetime | None = None) -> Report:
    """期間 [start, end)（TIMEZONE のタイムゾーン付き）の、setting の範囲の機器のレポートを作る"""
    now = now or utcnow()
    s_utc, e_utc = to_utc(start), to_utc(end)
    scope = await _scope_devices(db, setting)
    collect, n_fail = await _collect_section(db, scope, s_utc, e_utc)
    change, n_change = await _change_section(db, scope, s_utc, e_utc, now)
    comp, n_comp = await _compliance_section(db, scope, s_utc, e_utc)
    state = await _state_section(db, scope)
    ping, n_ping = await _ping_section(db, scope, setting, s_utc, e_utc)
    sections = [collect, change, comp, state, ping]
    if settings.VULN_ENABLED:
        sections.append(await _vuln_section(db, scope, s_utc, e_utc))
    if include_admin:
        sections.append(await _admin_section(db, s_utc, e_utc, now))
    empty = not (n_fail or n_change or n_comp or n_ping)
    return Report(kind, period_label(start, end), start, end, len(scope), empty, sections,
                  _retention_notes(start, now), at=now.replace(tzinfo=UTC).astimezone(ZoneInfo(settings.TIMEZONE)))


# ---------------------------------------------------------------- 通知手段ごとの本文


def _section_lines(sec: Section, n: int) -> list[str]:
    shown = sec.top[:n]
    out = list(sec.lines)
    if shown:
        out.append(f"{sec.top_title}:")
        out += [f"・{x}" for x in shown]
    extra = sec.top_total - len(shown)
    if sec.top_total and extra > 0 and sec.top_title:
        out.append(f"…ほか {extra} 件" if shown else f"（{sec.top_title}: {sec.top_total} 件。一覧は画面で確認してください）")
    return out


def _facts(report: Report, n: int) -> list[tuple[str, str]]:
    return [(f"{s.title}（{ {'period': '期間内', 'now': 'いま', 'mixed': '期間内・いま'}[s.basis] }）",
             "\n".join(_section_lines(s, n))) for s in report.sections]


def _body(report: Report) -> str:
    return "\n".join(report.head_lines() + [f"※ {x}" for x in report.notes])


def _link() -> tuple[str | None, str]:
    return notify._page_url("/activity"), "アクティビティを画面で確認"


def _slack_text(title: str, body: str, facts: list[tuple[str, str]], url: str | None, link_text: str,
                cut: bool = False) -> str:
    """Slack の本文。エスケープした本文のあとにリンクを付ける。cut なら、リンクを含めて SLACK_MAX に収まるよう本文を切る
    （エスケープ（&amp; など）の途中では切らない）"""
    text = notify.slack_escape("\n".join([f"*{title}*", body] + [f"*{k}*\n{v}" for k, v in facts]))
    link = f"\n<{url}|{link_text}>" if url else ""
    if cut and len(text) + len(link) > SLACK_MAX:
        head = text[:SLACK_MAX - len(link) - 1]
        amp = head.rfind("&")
        if amp != -1 and ";" not in head[amp:]:
            head = head[:amp]
        text = head + "…"
    return text + link


def build_payload(kind: str, report: Report) -> dict:
    """通知手段ごとの本文。長さの上限に収まるまで、上位の一覧の件数を減らす（メールは上限なし）"""
    url, link_text = _link()
    title, body = report.title, _body(report)
    if kind == "email":
        return notify._message("email", title, _facts(report, TOP_STEPS[0]), url, link_text, COLOR, body)
    payload: dict = {}
    for n in TOP_STEPS:
        facts = _facts(report, n)
        if kind == "slack":
            payload = {"text": _slack_text(title, body, facts, url, link_text)}
            if len(payload["text"]) <= SLACK_MAX:
                return payload
        elif kind == "discord":
            payload = notify._message("discord", title, facts, url, link_text, COLOR, body)  # リンクの無害化は _message が行う
            e = payload["embeds"][0]
            total = len(title) + len(e.get("description", "")) + sum(len(f["name"]) + len(f["value"]) for f in e["fields"])
            if total <= DISCORD_TOTAL and all(len(notify.break_md(v)) <= DISCORD_FIELD for _, v in facts):
                return payload
        else:  # teams（長さの保険は notify._teams_card の中）
            payload = notify._message("teams", title, facts, url, link_text, COLOR, body)
            if notify._teams_size(payload) <= notify.TEAMS_MAX_BYTES // 2:
                return payload
    if kind == "slack":  # 最小にしても収まらない（注記が長いなど）ときは、リンクを除いた本文を切ってからリンクを付け直す
        payload["text"] = _slack_text(title, body, facts, url, link_text, cut=True)
    return payload


# ---------------------------------------------------------------- 送る設定の選び方・二重送信の防止・送信


@dataclass
class Eligible:
    setting: NotificationSetting
    label: str  # 「ユーザー: xx」「グループ: yy」
    include_admin: bool


async def eligible_settings(db: AsyncSession) -> list[Eligible]:
    """定期レポートを送る設定（宛先があり、mode が custom で、report が off でないもの）"""
    rows = (await db.execute(select(NotificationSetting).where(
        NotificationSetting.mode == "custom", NotificationSetting.report != "off"))).scalars().all()
    rows = [s for s in rows if notify.has_target(s) and s.report_kinds]
    if not rows:
        return []
    users = {u.id: u for u in (await db.execute(select(User).where(User.is_active.is_(True)))).scalars()}
    groups = {g.id: g for g in (await db.execute(select(UserGroup))).scalars()}
    own_mode = {s.owner_id: s.mode for s in (await db.execute(select(NotificationSetting).where(
        NotificationSetting.owner_type == "user"))).scalars()}
    members: dict[str, list[str]] = {}
    for m in (await db.execute(select(UserGroupMember))).scalars():
        members.setdefault(m.group_id, []).append(m.user_id)
    out = []
    for s in rows:
        if s.owner_type == "user":
            u = users.get(s.owner_id)
            if u is not None:
                out.append(Eligible(s, f"ユーザー: {u.username}", Perm.SYSTEM_READ in permissions_for(u.role)))
        else:
            g = groups.get(s.owner_id)
            # 所属グループの設定を使う（inherit・設定なし）有効なメンバーがいるときだけ。通知の宛先の決め方と同じ
            if g is not None and any(uid in users and own_mode.get(uid, "inherit") == "inherit"
                                     for uid in members.get(g.id, [])):
                out.append(Eligible(s, f"グループ: {g.name}", False))
    for el in out:
        # 送信の途中で commit しても、設定の値（宛先・範囲）を読み直さなくて済むよう、セッションから切り離す
        db.expunge(el.setting)
    return out


@dataclass
class RowInfo:
    """読んだ report_sends の行の値（ORM のオブジェクトは rollback で期限切れになるので、素の値に写して使う）"""
    id: str
    status: str
    attempts: int
    claimed_at: datetime


def _stale(row: "ReportSend | RowInfo", now: datetime) -> bool:
    return row.status == "sending" and row.claimed_at < now - timedelta(minutes=STALE_MIN)


def can_retry(row: "ReportSend | RowInfo", now: datetime) -> bool:
    """既にある行を引き継いで送り直してよいか（全宛先で失敗した、または送信中のまま止まった。どちらも上限まで）"""
    return row.attempts < MAX_ATTEMPTS and (row.status == "failed" or _stale(row, now))


async def claim(db: AsyncSession, setting_id: str, kind: str, period_start: str, now: datetime,
                existing: "ReportSend | RowInfo | None" = None) -> bool:
    """この (設定, 種類, 期間) を送る権利を取る。取れたら True（取れなければ、別の worker が送った・送っている）

    existing: 呼び出し側が先に読んだ既存の行（あれば INSERT を試さず、引き継ぎだけを試す）
    """
    if existing is None:
        db.add(ReportSend(setting_id=setting_id, kind=kind, period_start=period_start, status="sending", attempts=1,
                          claimed_at=utcnow()))
        try:
            await db.commit()
            return True
        except IntegrityError:
            await db.rollback()
    # 既にある行は、全宛先で失敗した（上限まで）か、送信中のまま止まった（STALE_MIN 分以上前。これも上限まで）ときだけ引き継ぐ。
    # 条件を付けた UPDATE なので、同時に引き継ごうとしても 1 つだけが rowcount=1 になる
    r = await db.execute(update(ReportSend).where(
        ReportSend.setting_id == setting_id, ReportSend.kind == kind, ReportSend.period_start == period_start,
        ReportSend.attempts < MAX_ATTEMPTS,
        or_(ReportSend.status == "failed",
            and_(ReportSend.status == "sending", ReportSend.claimed_at < now - timedelta(minutes=STALE_MIN))),
    ).values(status="sending", attempts=ReportSend.attempts + 1, claimed_at=utcnow(), finished_at=None))
    await db.commit()
    return r.rowcount == 1


async def mark_missed(db: AsyncSession, el: "Eligible", kind: str, period_start: str, label: str, row: RowInfo | None,
                      now: datetime) -> bool:
    """取り戻しの期間を過ぎても送れなかった回を、アクティビティに 1 回だけ残す（行を missed にして、毎時くり返さない）"""
    if row is None:
        db.add(ReportSend(setting_id=el.setting.id, kind=kind, period_start=period_start, status="missed", attempts=0,
                          claimed_at=now, finished_at=now))
        try:
            await db.flush()
        except IntegrityError:  # 同時に別の worker が行を作った
            await db.rollback()
            return False
    else:
        if row.status not in ("failed", "sending") or (row.status == "sending" and not _stale(row, now)):
            return False
        r = await db.execute(update(ReportSend).where(
            ReportSend.id == row.id, ReportSend.status == row.status,
        ).values(status="missed", finished_at=now))
        if r.rowcount != 1:
            await db.rollback()
            return False
    owner = "グループの設定" if el.setting.owner_type == "group" else "ユーザーの設定"
    msg = f"定期レポートを送れませんでした（{KIND_LABELS[kind]} {label}・{owner}）"
    record_activity(db, "notify.failed", msg, detail={"kind": kind, "period": label, "owner_type": el.setting.owner_type,
                                                      "error": "取り戻しの期間を過ぎました"})
    await db.commit()
    return True


async def finish(db: AsyncSession, setting_id: str, kind: str, period_start: str, ok: bool) -> None:
    await db.execute(update(ReportSend).where(
        ReportSend.setting_id == setting_id, ReportSend.kind == kind, ReportSend.period_start == period_start,
    ).values(status="sent" if ok else "failed", finished_at=utcnow()))
    await db.commit()


async def purge_old(db: AsyncSession, now: datetime | None = None) -> int:
    """古い送信の記録を消す（設定が消えても残るため。1 年以上前）"""
    r = await db.execute(delete(ReportSend).where(ReportSend.claimed_at < (now or utcnow()) - timedelta(days=400)))
    return r.rowcount or 0


async def _send_one(db: AsyncSession, el: Eligible, kind: str, start: datetime, end: datetime, now: datetime) -> bool:
    """1 つの設定へ 1 つの期間のレポートを送る（claim 済み）。1 つでも送れたら True"""
    s = el.setting
    try:
        report = await build_report(db, kind, start, end, s, el.include_admin, now)
        dests = [notify.Destination(k, u, {s.id}, {el.label}) for k, u in notify.setting_targets(s)]
        res = await notify._deliver(db, "report", [(d, build_payload(d.kind, report), None) for d in dests], None)
        return res["sent"] > 0
    except Exception as e:  # noqa: BLE001 - 1 つの設定の失敗でほかの設定のレポートを止めない
        await db.rollback()
        # 例外の文言は載せない（接続文字列などが入りうる）。種類だけ
        logger.exception("定期レポートの作成・送信に失敗しました setting=%s", s.id)
        msg = f"定期レポートの作成に失敗しました（{type(e).__name__}）"
        record_activity(db, "notify.failed", f"{msg}（{el.label}）", detail={"via": [el.label], "error": msg})
        st = await db.get(NotificationSetting, s.id)
        if st is not None:
            st.last_error = msg
        await db.commit()
        return False


async def _init_since(db: AsyncSession, el: Eligible, kind: str, now: datetime) -> bool:
    """since が NULL のまま有効な設定（API を通らずに作られた行）に「いま」を入れる。入れたら True（その回は送らない）"""
    col = f"report_{kind}_since"
    if getattr(el.setting, col) is not None:
        return False
    column = getattr(NotificationSetting, col)
    await db.execute(update(NotificationSetting).where(NotificationSetting.id == el.setting.id, column.is_(None))
                     .values({col: now}))
    await db.commit()
    setattr(el.setting, col, now)  # 切り離した設定の値（この判定の中で使う）
    return True


async def _handle_one(db: AsyncSession, el: Eligible, kind: str, start: datetime, end: datetime, key: str, label: str,
                      row: RowInfo | None, over: bool, started: bool, now: datetime, result: dict) -> None:
    since = getattr(el.setting, f"report_{kind}_since")
    if since is not None and to_utc(end) < since:
        return  # 設定する前に終わった期間は送らない
    if row is not None and row.status in ("sent", "missed"):
        result["skipped"] += 1
        return
    if over:
        result["missed"] += await mark_missed(db, el, kind, key, label, row, now)
        return
    if not started:
        return
    if row is not None and not can_retry(row, now):
        result["skipped"] += 1  # 別の worker が送っている・上限まで失敗した
        return
    if not await claim(db, el.setting.id, kind, key, now, row):
        result["skipped"] += 1
        return
    ok = await _send_one(db, el, kind, start, end, now)
    await finish(db, el.setting.id, kind, key, ok)
    result["sent" if ok else "failed"] += 1


async def send_due_reports(db: AsyncSession, now_local: datetime | None = None) -> dict:
    """送る時刻を迎えた（または取り戻しの期間内の）未送信のレポートを送る。何度呼んでも二重には送らない

    worker の毎時の判定から呼ぶ。期間ごとに、まだ送っていない設定へ送る。設定したあとに終わった期間だけが対象
    （種類ごとの since）。取り戻しの期間を過ぎても送れなかった回は、アクティビティに 1 回だけ残す。
    1 つの設定の処理で例外が出ても、ほかの設定・ほかの種類の判定は続ける
    """
    now_local = now_local or local_now()
    now = to_utc(now_local)
    result = {"sent": 0, "failed": 0, "skipped": 0, "missed": 0, "errors": 0}
    els = await eligible_settings(db)
    for kind in KINDS:
        cand = [el for el in els if kind in el.setting.report_kinds]
        if not cand:
            continue
        ready = []
        for el in cand:
            try:
                if not await _init_since(db, el, kind, now):
                    ready.append(el)
            except Exception as e:  # noqa: BLE001
                await _report_error(db, el, e, result)
        cand = ready
        if not cand:
            continue
        latest = last_period(kind, now_local)
        # 直前の期間と、その 1 つ前（取り戻しの期間を過ぎた回の「送れなかった」の記録だけのため）
        for start, end in (last_period(kind, latest[0]), latest):
            key = start.date().isoformat()
            label = period_label(start, end)
            # ORM のオブジェクトは rollback で期限切れになるので、素の値に写す
            rows = {r.setting_id: RowInfo(r.id, r.status, r.attempts, r.claimed_at)
                    for r in (await db.execute(select(ReportSend).where(
                        ReportSend.kind == kind, ReportSend.period_start == key,
                        ReportSend.setting_id.in_([el.setting.id for el in cand])))).scalars()}
            over = window_over(kind, end, now_local)
            started = now_local >= end + timedelta(hours=settings.REPORT_HOUR)
            for el in cand:
                try:
                    await _handle_one(db, el, kind, start, end, key, label, rows.get(el.setting.id), over, started, now,
                                      result)
                except Exception as e:  # noqa: BLE001 - 1 つの設定の失敗でほかの設定・種類を止めない
                    await _report_error(db, el, e, result)
    return result


async def _report_error(db: AsyncSession, el: Eligible, e: Exception, result: dict) -> None:
    """設定ごとの判定の失敗をログとアクティビティに残す（例外の文言は載せない。種類だけ）"""
    result["errors"] += 1
    logger.exception("定期レポートの判定に失敗しました setting=%s", el.setting.id)
    try:
        await db.rollback()
        record_activity(db, "notify.failed", f"定期レポートの判定に失敗しました（{type(e).__name__}）（{el.label}）",
                        detail={"via": [el.label], "error": f"定期レポートの判定に失敗しました（{type(e).__name__}）"})
        await db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("定期レポートの失敗の記録にも失敗しました")
        await db.rollback()


# ---------------------------------------------------------------- 画面・API 用（プレビュー・いま送る）

_last_send_memory: dict[str, float] = {}  # Redis が使えないときの代わり（プロセス内）


async def take_slot(user_id: str, name: str, interval: int) -> int:
    """利用者ごとの間隔の制限（name ごとに別）。進めてよければ 0、制限中なら待つ秒数。Redis（使えなければメモリ）"""
    import time

    from redis.exceptions import RedisError

    from app.services import login_limit

    key = f"netconfig:report:{name}:{user_id}"
    try:
        r = login_limit.client()
        if await r.set(key, "1", nx=True, ex=interval):
            return 0
        return max(1, await r.ttl(key))
    except (RedisError, OSError):
        now = time.monotonic()
        last = _last_send_memory.get(key)
        if last is not None and now - last < interval:
            return max(1, int(interval - (now - last)))
        _last_send_memory[key] = now
        return 0


async def take_send_slot(user_id: str) -> int:
    """「いま送る」の間隔の制限（SEND_NOW_INTERVAL_SEC）"""
    return await take_slot(user_id, "send-now", SEND_NOW_INTERVAL_SEC)


async def take_preview_slot(user_id: str) -> int:
    """プレビューの間隔の制限（PREVIEW_INTERVAL_SEC）。集計は機器・記録の数に応じて重いので、連打させない"""
    return await take_slot(user_id, "preview", PREVIEW_INTERVAL_SEC)


def default_scope() -> NotificationSetting:
    """通知設定が無い人のプレビューの範囲（すべての機器）"""
    return NotificationSetting(all_devices=True, device_group_ids=None, include_ungrouped=False)


async def preview_report(db: AsyncSession, setting: NotificationSetting | None, user: User, kind: str,
                         now_local: datetime | None = None) -> Report:
    now_local = now_local or local_now()
    start, end = last_period(kind, now_local)
    return await build_report(db, kind, start, end, setting or default_scope(),
                              Perm.SYSTEM_READ in permissions_for(user.role), to_utc(now_local))


async def send_now(db: AsyncSession, setting: NotificationSetting, user: User, kind: str,
                   now_local: datetime | None = None) -> dict[str, str | None]:
    """自分の設定の宛先へ、直前の期間（先週・先月）のレポートを送る。{宛先の種類: エラー or None}（テスト送信と同じ形）"""
    report = await preview_report(db, setting, user, kind, now_local)
    cfg = await mail.load_config(db) if setting.emails else None
    targets = notify.setting_targets(setting)
    results = await asyncio.gather(
        *(asyncio.to_thread(notify._send, k, url, build_payload(k, report), cfg) for k, url in targets))
    await mail.record_last([err for (k, _), err in zip(targets, results, strict=True) if k == "email"])
    return {(f"email:{url}" if k == "email" else k): err for (k, url), err in zip(targets, results, strict=True)}
