"""定期レポート（週次・月次）のテスト

集計（期間の境界・タイムゾーン・機器の範囲）、送る日の判定、二重に送らない仕組み、通知手段ごとの本文と長さ、
秘密が入らないこと、プレビュー・「いま送る」の API と権限、設定の保存。
送信は差し替える（外部へは送らない）。作ったデータ（機器・ルール・利用者・設定・記録）はすべて後片付けする。
集計の期間は過去の固定の週（2026/02/23〜03/01）にして、ほかのテストが「いま」作るデータが混ざらないようにする。
"""
import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, or_, select, update

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.main import app
from app.models import (
    ActivityLog,
    ApiToken,
    AuditLog,
    CollectLog,
    ComplianceResult,
    ComplianceRule,
    ConfigBaseline,
    ConfigReview,
    ConfigSnapshot,
    Device,
    DeviceGroup,
    NotificationSetting,
    PingTarget,
    ReportSend,
    User,
)
from app.services import mail, notify, report, system

JST = ZoneInfo("Asia/Tokyo")
NOW = datetime(2026, 3, 2, 8, 0, tzinfo=JST)  # 月曜 8 時。前の週は 2/23〜3/1
D = "https://discord.com/api/webhooks/{}/tok-{}"
S = "https://hooks.slack.com/services/T000/B{}/xyz{}"
PW = "password-1234"


def uid() -> str:
    return uuid.uuid4().hex[:6]


def nid() -> str:
    """Discord の Webhook URL の数字の ID"""
    return str(uuid.uuid4().int % 10**12)


def run(coro):
    return asyncio.run(coro)


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


def at(day: int, hour: int = 12, month: int = 2) -> datetime:
    """2026/{month}/{day} {hour} 時（JST）を DB の時刻（UTC の naive）で"""
    return report.to_utc(datetime(2026, month, day, hour, tzinfo=JST))


def cfg(**kw) -> NotificationSetting:
    kw.setdefault("all_devices", False)
    kw.setdefault("include_ungrouped", False)
    if "groups" in kw:
        kw["device_group_ids"] = json.dumps(kw.pop("groups"))
    return NotificationSetting(**kw)


# ---------------------------------------------------------------- 期間・送る日の判定


def test_last_period_week_and_month_boundaries():
    s, e = report.last_period("week", NOW)
    assert (s.date().isoformat(), e.date().isoformat()) == ("2026-02-23", "2026-03-02")
    assert report.period_label(s, e) == "2/23〜3/1"
    assert (s.hour, e.hour, s.weekday()) == (0, 0, 0)
    # 週の途中でも「直前の完結した週」（日曜でも前の週のまま）
    assert report.last_period("week", datetime(2026, 3, 8, 23, 59, tzinfo=JST))[0].date().isoformat() == "2026-02-23"
    assert report.last_period("week", datetime(2026, 3, 9, 0, 0, tzinfo=JST))[0].date().isoformat() == "2026-03-02"
    s, e = report.last_period("month", datetime(2026, 3, 1, 8, 0, tzinfo=JST))
    assert (s.date().isoformat(), e.date().isoformat()) == ("2026-02-01", "2026-03-01")
    # 年またぎ・うるう年
    s, e = report.last_period("month", datetime(2026, 1, 1, 8, 0, tzinfo=JST))
    assert (s.date().isoformat(), e.date().isoformat()) == ("2025-12-01", "2026-01-01")
    s, e = report.last_period("month", datetime(2028, 3, 1, 8, 0, tzinfo=JST))
    assert (e - s).days == 29 and s.date().isoformat() == "2028-02-01"
    with pytest.raises(ValueError):
        report.last_period("year", NOW)


def test_period_is_in_the_configured_timezone_not_utc():
    """期間は TIMEZONE の日付で区切る（UTC の日付ではない）。JST の月曜 0 時は UTC では前の日曜 15 時"""
    s, e = report.last_period("week", NOW)
    assert report.to_utc(s) == datetime(2026, 2, 22, 15, 0) and report.to_utc(e) == datetime(2026, 3, 1, 15, 0)
    # 別のタイムゾーン（夏時間をまたぐ週は 7 日より 1 時間短い）
    ny = ZoneInfo("America/New_York")
    s, e = report.last_period("week", datetime(2026, 3, 9, 9, 0, tzinfo=ny))  # 3/8 に夏時間が始まった
    assert (s.date().isoformat(), e.date().isoformat()) == ("2026-03-02", "2026-03-09")
    assert report.to_utc(e) - report.to_utc(s) == timedelta(days=7) - timedelta(hours=1)


@pytest.mark.parametrize("kind,when,expected", [
    ("week", datetime(2026, 3, 2, 8, 0, tzinfo=JST), "2026-02-23"),   # 月曜の REPORT_HOUR
    ("week", datetime(2026, 3, 2, 7, 59, tzinfo=JST), None),  # 月曜でも REPORT_HOUR の前は送らない（前の週の取り戻しは月曜 0 時で終わる）
    ("week", datetime(2026, 3, 2, 23, 0, tzinfo=JST), "2026-02-23"),
    ("week", datetime(2026, 3, 3, 3, 0, tzinfo=JST), "2026-02-23"),   # 火曜は終日（取り戻し）
    ("week", datetime(2026, 3, 8, 23, 59, tzinfo=JST), "2026-02-23"),  # 次の月曜の前日（日曜）まで
    ("week", datetime(2026, 3, 9, 7, 59, tzinfo=JST), None),
    ("week", datetime(2026, 3, 9, 8, 0, tzinfo=JST), "2026-03-02"),   # 次の月曜は新しい週の分だけ
    ("month", datetime(2026, 3, 1, 8, 0, tzinfo=JST), "2026-02-01"),  # 1 日（この日は日曜）
    ("month", datetime(2026, 3, 1, 7, 0, tzinfo=JST), None),
    ("month", datetime(2026, 3, 27, 23, 59, tzinfo=JST), "2026-02-01"),  # 27 日間（27 日まで）
    ("month", datetime(2026, 3, 28, 7, 59, tzinfo=JST), "2026-02-01"),  # 28 日の REPORT_HOUR 時の前は、まだ取り戻せる
    ("month", datetime(2026, 3, 28, 8, 0, tzinfo=JST), None),  # 取り戻しの期間を過ぎた
])
def test_due_period(monkeypatch, kind, when, expected):
    monkeypatch.setattr(settings, "REPORT_HOUR", 8)
    p = report.due_period(kind, when)
    assert (p[0].date().isoformat() if p else None) == expected
    # 1 つ前の期間の取り戻しは、直前の期間を送り始める時刻（初日の REPORT_HOUR 時）に終わる。新しい期間の分とは重ならない
    start, end = report.last_period(kind, when)
    over = report.window_over(kind, report.last_period(kind, start)[1], when)
    if kind == "week":
        assert over == (when >= end + timedelta(hours=8))
    elif when >= end + timedelta(hours=8):  # 月次は月の長さが違うので、新しい期間を送り始めるときには必ず過ぎている
        assert over


def test_due_period_uses_timezone_of_the_given_time(monkeypatch):
    """同じ瞬間でも、TIMEZONE の時刻で判定する（UTC の日曜 23:30 は JST の月曜 8:30）"""
    monkeypatch.setattr(settings, "REPORT_HOUR", 8)
    instant = datetime(2026, 3, 1, 23, 30, tzinfo=UTC)
    assert report.due_period("week", instant.astimezone(JST))[0].date().isoformat() == "2026-02-23"
    assert report.due_period("week", instant)[0].date().isoformat() == "2026-02-16"  # UTC の日曜 23:30（前の週の取り戻し）


def test_report_hour_setting(monkeypatch):
    monkeypatch.setattr(settings, "REPORT_HOUR", 0)
    assert report.due_period("week", datetime(2026, 3, 2, 0, 0, tzinfo=JST))[0].date().isoformat() == "2026-02-23"
    monkeypatch.setattr(settings, "REPORT_HOUR", 23)
    assert report.due_period("week", datetime(2026, 3, 2, 22, 59, tzinfo=JST)) is None
    assert report.due_period("week", datetime(2026, 3, 2, 23, 0, tzinfo=JST))[0].date().isoformat() == "2026-02-23"


# ---------------------------------------------------------------- 集計の準備（データを作って、最後に必ず消す）


class World:
    """集計のテスト用のデータ。機器 A・B（グループ g1）、C（g2）、U（未分類）"""


@pytest.fixture(scope="module")
def client():
    """アプリを起動する（マイグレーションを適用して表を作る）。データの準備より前に必要"""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def world(client):
    w = World()
    tag = uid()
    w.tag = tag
    w.ids = {"g1": str(uuid.uuid4()), "g2": str(uuid.uuid4()), "a": str(uuid.uuid4()), "b": str(uuid.uuid4()),
             "c": str(uuid.uuid4()), "u": str(uuid.uuid4()), "rule": str(uuid.uuid4()), "t_g1": str(uuid.uuid4()),
             "t_g2": str(uuid.uuid4())}
    w.name = {k: f"rpt-{k}-{tag}" for k in ("a", "b", "c", "u")}
    i = w.ids
    snaps = {k: [(str(uuid.uuid4())[:8] * 5)[:40] for _ in range(4)] for k in ("a", "b", "c")}
    w.snaps = snaps

    async def setup():
        async with AsyncSessionLocal() as db:
            db.add_all([DeviceGroup(id=i["g1"], name=f"rpt-g1-{tag}"), DeviceGroup(id=i["g2"], name=f"rpt-g2-{tag}")])
            await db.flush()
            for k, gid, n in (("a", "g1", 1), ("b", "g1", 2), ("c", "g2", 3), ("u", None, 4)):
                db.add(Device(id=i[k], name=w.name[k], hostname=f"198.51.100.{n}", platform="cisco_ios",
                              group_id=i[gid] if gid else None))
            db.add(ComplianceRule(id=i["rule"], name=f"rpt-rule-{tag}", pattern="x", severity="high"))
            await db.flush()
            # 収集の成功（A は期間の始まりちょうど=含む・終わりちょうど=含まない・始まりの直前=含まない）
            week_end = report.to_utc(report.last_period("week", NOW)[1])
            for k, when in (("a", at(23, 0)), ("a", at(24)), ("a", at(25)), ("a", week_end), ("a", at(22, 23)),
                            ("b", at(26)), ("c", at(26)), ("c", at(27)), ("u", at(26))):
                db.add(CollectLog(device_id=i[k], status="success", started_at=when, finished_at=when))
            # 収集の失敗（最終の失敗は error・再試行の途中は warning）。A は最後の成功（25 日）のあとに 3 回
            for k, day, level in (("a", 26, "error"), ("a", 27, "error"), ("a", 28, "error"), ("a", 28, "warning"),
                                  ("b", 27, "error"), ("c", 24, "error"), ("c", 25, "error"), ("u", 27, "error")):
                db.add(ActivityLog(at=at(day), category="collect", event="collect.failed", level=level, device_id=i[k],
                                   device_name=w.name[k], message="収集に失敗しました: timeout"))
            # コンフィグの変更（A: 3 件（うち 1 件は初回の世代）+ 期間外 1 件、B: 1 件、C: 2 件、U: 1 件）
            for k, n, when in (("a", 0, at(23, 1)), ("a", 1, at(24)), ("a", 2, at(25)), ("a", 3, at(20)),
                               ("b", 0, at(26)), ("c", 0, at(26)), ("c", 1, at(27)), ("u", 0, at(26))):
                db.add(ConfigSnapshot(device_id=i[k], commit_hash="f" * 40 if k == "u" else snaps[k][n],
                                      collected_at=when, lines_added=5, lines_removed=2))
            # A の 1 件は確認済み
            db.add(ConfigReview(device_id=i["a"], commit_hash=snaps["a"][2], status="confirmed", reviewed_by="x"))
            # 違反の発生・解消
            for k, ev, day in (("a", "compliance.violation", 24), ("a", "compliance.violation", 25),
                               ("a", "compliance.resolved", 26), ("c", "compliance.violation", 24),
                               ("a", "compliance.violation", 22)):  # 22 日は期間外
                db.add(ActivityLog(at=at(day), category="compliance", event=ev, device_id=i[k], device_name=w.name[k],
                                   message="x", detail=json.dumps({"rule": "r"})))
            # 一括の検査（機器別の記録が無く、一覧だけ）: B の違反 2 件・C の違反 1 件
            db.add(ActivityLog(at=at(25), category="compliance", event="compliance.summary", message="違反の発生 3 件",
                               detail=json.dumps({"items": [f"違反: {w.name['b']} / r1", f"違反: {w.name['b']} / r2",
                                                            f"違反: {w.name['c']} / r1"]})))
            # いまの違反
            for k in ("a", "b", "c", "u"):
                db.add(ComplianceResult(device_id=i[k], rule_id=i["rule"], status="fail"))
            # 基準のずれ・保存し忘れ
            db.add(ConfigBaseline(device_id=i["a"], commit_hash=snaps["a"][0], drift_added=7, drift_removed=1))
            db.add(ConfigBaseline(device_id=i["c"], commit_hash=snaps["c"][0], drift_added=3, drift_removed=0))
            await db.execute(update(Device).where(Device.id == i["b"]).values(
                startup_state="unsaved", startup_added=4, startup_removed=0))
            await db.execute(update(Device).where(Device.id == i["c"]).values(
                startup_state="unsaved", startup_added=9, startup_removed=9))
            # Ping 監視: 機器 A が 2 回・C が 1 回、追加した IP（g1・g2）が 1 回ずつ
            for k, day in (("a", 24), ("a", 25), ("c", 24)):
                db.add(ActivityLog(at=at(day), category="ping", event="ping.down", device_id=i[k], device_name=w.name[k],
                                   message="x", detail=json.dumps({"key": f"d:{i[k]}"})))
            db.add(PingTarget(id=i["t_g1"], name=f"rpt-ip-g1-{tag}", address="203.0.113.1", group_id=i["g1"]))
            db.add(PingTarget(id=i["t_g2"], name=f"rpt-ip-g2-{tag}", address="203.0.113.2", group_id=i["g2"]))
            for t in ("t_g1", "t_g2"):
                db.add(ActivityLog(at=at(26), category="ping", event="ping.down", message="x",
                                   detail=json.dumps({"key": f"t:{i[t]}"})))
            # ログインの一時停止（期間内 2 回・期間外 1 回）
            for day in (24, 26, 21):
                db.add(AuditLog(at=at(day), username=f"rpt-user-{tag}", action="auth.login_locked", success=False))
            await db.commit()

    async def teardown():
        async with AsyncSessionLocal() as db:
            devs = [i[k] for k in ("a", "b", "c", "u")]
            for model in (CollectLog, ConfigSnapshot, ConfigReview, ConfigBaseline, ComplianceResult):
                await db.execute(delete(model).where(model.device_id.in_(devs)))
            await db.execute(delete(ActivityLog).where(or_(
                ActivityLog.device_id.in_(devs), ActivityLog.detail.like(f"%{i['t_g1']}%"), ActivityLog.detail.like(f"%{i['t_g2']}%"),
                ActivityLog.detail.like(f"%{tag}%"))))
            await db.execute(delete(AuditLog).where(AuditLog.username == f"rpt-user-{tag}"))
            await db.execute(delete(PingTarget).where(PingTarget.id.in_([i["t_g1"], i["t_g2"]])))
            await db.execute(delete(ComplianceRule).where(ComplianceRule.id == i["rule"]))
            await db.execute(delete(Device).where(Device.id.in_(devs)))
            await db.execute(delete(DeviceGroup).where(DeviceGroup.id.in_([i["g1"], i["g2"]])))
            await db.commit()

    run(setup())
    try:
        yield w
    finally:
        run(teardown())


@pytest.fixture
def firsts(monkeypatch, world):
    """各機器の「最初の世代」（初回の収集。変更に数えない）。A・B は snaps[0]。C は別の世代（C の世代は全部が変更）"""
    async def fake(device_ids):
        m = {world.ids["a"]: world.snaps["a"][0], world.ids["b"]: world.snaps["b"][0], world.ids["c"]: "0" * 40,
             world.ids["u"]: "f" * 40}
        return {d: m[d] for d in device_ids if d in m}

    monkeypatch.setattr(report, "_first_commits", fake)


def build(setting, admin=False, kind="week", now_local=NOW):
    async def go():
        async with AsyncSessionLocal() as db:
            s, e = report.last_period(kind, now_local)
            return await report.build_report(db, kind, s, e, setting, admin, report.to_utc(now_local))
    return run(go())


def sec(rep, key):
    return next(s for s in rep.sections if s.key == key)


def text_of(rep) -> str:
    return json.dumps(rep.to_dict(), ensure_ascii=False)


# ---------------------------------------------------------------- 集計


def test_aggregate_scope_g1_only_and_boundaries(world, firsts):
    rep = build(cfg(groups=[world.ids["g1"]]))
    assert rep.devices == 2 and rep.label == "2/23〜3/1" and not rep.empty
    # 収集: A は期間内 3 回（始まりちょうどを含み、終わりちょうど・始まりの直前を含まない）+ B 1 回。失敗は A 3 回・B 1 回
    collect = sec(rep, "collect")
    assert collect.lines == ["収集の成功 4 回・失敗 4 回（再試行の途中の失敗は数えません）"]
    # 失敗が続いている機器: A（最後の成功のあとに 3 回）。B は 1 回だけなので載せない
    assert collect.top == [f"{world.name['a']}: 3 回続けて失敗"] and collect.top_total == 1
    # 変更: A は初回の世代・期間外を除いて 2 件、B は初回の世代だけなので 0 件
    change = sec(rep, "change")
    assert change.lines[0].startswith("変更のあった機器 1 台・変更 2 件（うち未確認 1 件")
    assert change.top == [f"{world.name['a']}: 2 件（+10 / -4 行）"]
    # コンプライアンス: A の違反 2 件（期間外の 1 件は除く）+ 一括の B の 2 件、解消 1 件。いまの違反は A・B の 2 件（高）
    comp = sec(rep, "compliance")
    assert comp.lines[0] == "新しく出た違反 4 件・解消した違反 1 件"
    assert comp.lines[1] == "いまの違反（いまの件数）: 高 2 件・中 0 件・低 0 件（2 台）"
    assert comp.top[0].endswith(": 2 件") and {t.rsplit(":", 1)[0] for t in comp.top} == {world.name["a"], world.name["b"]}
    # 基準のずれは A、保存し忘れは B（C はグループ外）
    state = sec(rep, "state")
    assert state.lines == ["基準の世代からずれている機器（いまの件数）: 1 台", "保存し忘れ（running と startup が不一致。いまの件数）: 1 台"]
    assert state.top == [f"基準からのずれ: {world.name['a']}（+7 / -1 行）", f"保存し忘れ: {world.name['b']}（+4 / -0 行）"]
    # Ping: 機器 A が 2 回 + g1 の追加 IP が 1 回（g2 の追加 IP・C は入らない）
    ping = sec(rep, "ping")
    assert ping.lines == ["応答なしになった回数 3 回（2 件）"]
    assert ping.top == [f"{world.name['a']}: 2 回", f"rpt-ip-g1-{world.tag}: 1 回"]
    # 範囲外（C・U・g2 の追加 IP）の名前が一切混じらない。管理者向けの項目もない
    body = text_of(rep)
    for other in (world.name["c"], world.name["u"], f"rpt-ip-g2-{world.tag}"):
        assert other not in body, other
    assert all(s.key != "admin" for s in rep.sections)


def test_aggregate_other_group_and_ungrouped(world, firsts):
    rep = build(cfg(groups=[world.ids["g2"]]))
    assert rep.devices == 1
    body = text_of(rep)
    assert world.name["c"] in body and world.name["a"] not in body and world.name["b"] not in body
    assert sec(rep, "collect").lines == ["収集の成功 2 回・失敗 2 回（再試行の途中の失敗は数えません）"]
    assert sec(rep, "compliance").lines[0] == "新しく出た違反 2 件・解消した違反 0 件"  # 機器別 1 件 + 一括 1 件
    # 未分類だけ
    rep = build(cfg(groups=[], include_ungrouped=True))
    body = text_of(rep)
    for n in ("a", "b", "c"):
        assert world.name[n] not in body
    # すべての機器: 4 台とも入る（ほかのテストの機器が残っていても、この 4 台の分は含まれる）
    rep = build(cfg(all_devices=True))
    assert rep.devices >= 4


def test_aggregate_period_boundary_changes_with_the_week(world, firsts):
    """前の週・次の週では、別の期間の件数になる（境界のちょうどの時刻は新しい期間に入る）"""
    # 3/9 の月曜 → 3/2〜3/8（この期間にデータなし）
    rep = build(cfg(groups=[world.ids["g1"]]), now_local=datetime(2026, 3, 9, 8, 0, tzinfo=JST))
    # 前の週の終わりちょうど（3/2 0:00）の成功 1 回は、この新しい期間に入る
    assert rep.empty and sec(rep, "collect").lines == ["収集の成功 1 回・失敗 0 回（再試行の途中の失敗は数えません）"]
    assert sec(rep, "change").lines[0] == "期間内にコンフィグの変更はありませんでした（変更なし）"
    assert "変更なし" in "\n".join(rep.head_lines())
    # 次の週は、2/16〜2/22: A の期間外の変更（20 日）と、ログインの一時停止（21 日）だけ
    rep = build(cfg(groups=[world.ids["g1"]]), now_local=datetime(2026, 2, 23, 8, 0, tzinfo=JST), admin=True)
    assert sec(rep, "change").lines[0].startswith("変更のあった機器 1 台・変更 1 件")
    assert "ログインの一時停止（失敗の繰り返し・期間内）: 1 回" in "\n".join(sec(rep, "admin").lines)


def test_aggregate_month(world, firsts):
    rep = build(cfg(groups=[world.ids["g1"]]), kind="month", now_local=datetime(2026, 3, 1, 8, 0, tzinfo=JST))
    assert rep.label == "2/1〜2/28" and rep.title == "月次レポート 2/1〜2/28"
    assert sec(rep, "collect").lines[0].startswith("収集の成功 5 回・失敗 4 回")  # 2/22 の成功 1 回が増える


def test_first_commit_excluded_and_unreviewed_remaining(world, firsts):
    rep = build(cfg(groups=[world.ids["g1"]]))
    change = sec(rep, "change")
    # 直近の未確認の残り（CHANGE_REVIEW_DAYS 日・いまの件数）。A の未確認は 2 件（期間外の 1 件も窓に入る。確認済みと初回は除く）
    assert change.lines[1] == f"未確認の変更の残り（直近 {settings.CHANGE_REVIEW_DAYS} 日・いまの件数）: 2 件"


def test_admin_section_only_for_admin_and_has_no_secrets(world, firsts, monkeypatch):
    async def cert(now):
        return system.Component("cert", "HTTPS の証明書", "warn", "あと 20 日", {"days_left": 20})

    monkeypatch.setattr(system, "check_cert", cert)
    tag = uid()

    async def add():
        async with AsyncSessionLocal() as db:
            db.add(User(id=f"rpt-u-{tag}", username=f"rpt-nomfa-{tag}", hashed_password="x", role="viewer"))
            db.add(User(id=f"rpt-v-{tag}", username=f"rpt-mfa-{tag}", hashed_password="x", role="viewer", mfa_enabled=True))
            db.add(ApiToken(id=f"rpt-t-{tag}", user_id=f"rpt-u-{tag}", name=f"secret-name-{tag}", token_hash=tag * 8,
                            prefix="ncm_abcd", scope="read", expires_at=report.to_utc(NOW) + timedelta(days=10)))
            db.add(ApiToken(id=f"rpt-t2-{tag}", user_id=f"rpt-u-{tag}", name="far", token_hash=tag * 8 + "1",
                            prefix="ncm_abcd", scope="read", expires_at=report.to_utc(NOW) + timedelta(days=100)))
            await db.commit()

    async def drop():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(ApiToken).where(ApiToken.user_id == f"rpt-u-{tag}"))
            await db.execute(delete(User).where(User.id.in_([f"rpt-u-{tag}", f"rpt-v-{tag}"])))
            await db.commit()

    run(add())
    try:
        rep = build(cfg(groups=[world.ids["g1"]]), admin=True)
        admin = sec(rep, "admin")
        assert admin.basis == "mixed"
        lines = "\n".join(admin.lines)
        assert "ログインの一時停止（失敗の繰り返し・期間内）: 2 回" in lines
        assert "HTTPS の証明書（いま）: 期限まであと 20 日（更新してください）" in lines
        assert "30 日以内に期限が切れる API トークン（いまの件数）: 1 件" in lines
        assert "2 段階認証を設定していない利用者（いまの件数）:" in lines
        # 利用者名・トークン名は入らない
        body = text_of(rep)
        assert f"rpt-nomfa-{tag}" not in body and f"secret-name-{tag}" not in body and "ncm_abcd" not in body
    finally:
        run(drop())


def test_retention_note(world, firsts, monkeypatch):
    monkeypatch.setattr(settings, "ACTIVITY_LOG_RETENTION_DAYS", 3)
    rep = build(cfg(groups=[world.ids["g1"]]))
    assert any("保持期間（3 日）" in n for n in rep.notes)
    monkeypatch.setattr(settings, "ACTIVITY_LOG_RETENTION_DAYS", 0)  # 0 は無期限
    assert not any("アクティビティ" in n for n in build(cfg(groups=[world.ids["g1"]])).notes)


# ---------------------------------------------------------------- 通知手段ごとの本文・長さ・無害化


def fake_report(n=12, name_len=60, notes=()):
    """上位の一覧がどれも埋まった、大きなレポート"""
    top = [f"{'長' * name_len}{i}: {i} 件（+1 / -1 行）" for i in range(n)]
    secs = [report.Section(k, t, b, [f"{t}の件数 {n} 件", "二行目の説明の文章です" * 3], f"{t}の上位", top[:10], n)
            for k, t, b in (("collect", "収集", "period"), ("change", "変更", "mixed"), ("compliance", "コンプライアンス", "mixed"),
                            ("state", "基準のずれ・保存し忘れ", "now"), ("ping", "Ping監視", "period"),
                            ("admin", "管理者向け", "mixed"))]
    s, e = report.last_period("week", NOW)
    return report.Report("week", report.period_label(s, e), s, e, 300, False, secs, list(notes))


def test_payloads_fit_each_channel_limit():
    rep = fake_report()
    # メールは上限なし（上位 10 件を全部）
    em = report.build_payload("email", rep)
    assert em["title"] == "週次レポート 2/23〜3/1" and len(em["facts"]) == 6
    assert all(len([ln for ln in v.splitlines() if ln.startswith("・")]) == 10 for _, v in em["facts"])
    # Discord: 埋め込み全体 6000 文字・項目 1024 文字・説明 4096 文字に収める（件数を減らして「ほか n 件」）
    dc = report.build_payload("discord", rep)
    e = dc["embeds"][0]
    total = len(e["title"]) + len(e.get("description", "")) + sum(len(f["name"]) + len(f["value"]) for f in e["fields"])
    assert total <= 6000 and len(e["description"]) <= 4096 and all(len(f["value"]) <= 1024 for f in e["fields"])
    assert any("ほか" in f["value"] for f in e["fields"])
    # Slack: 3000 文字以内
    sl = report.build_payload("slack", rep)
    assert len(sl["text"]) <= report.SLACK_MAX and "ほか" in sl["text"]
    # Teams: Adaptive Card で 24KB 以内
    tm = report.build_payload("teams", rep)
    assert tm["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert notify._teams_size(tm) <= notify.TEAMS_MAX_BYTES
    blocks = tm["attachments"][0]["content"]["body"]
    assert blocks[0]["text"] == "週次レポート 2/23〜3/1" and any(b["type"] == "FactSet" for b in blocks)


def test_payload_small_report_shows_everything():
    rep = fake_report(n=2, name_len=3)
    for kind in ("discord", "slack", "teams", "email"):
        text = json.dumps(report.build_payload(kind, rep), ensure_ascii=False)
        assert "ほか" not in text and "長長長0" in text, kind


def test_payload_empty_report_says_no_change():
    s, e = report.last_period("week", NOW)
    rep = report.Report("week", "2/23〜3/1", s, e, 5, True, [report.Section("change", "変更", "mixed", ["期間内にコンフィグの変更はありませんでした（変更なし）"])])
    for kind in ("discord", "slack", "teams", "email"):
        text = json.dumps(report.build_payload(kind, rep), ensure_ascii=False)
        assert "変更なし" in text and "2026/02/23" in text, kind
        assert len(text) < 1500  # 短い


def test_payload_names_cannot_inject_links_or_mentions():
    s, e = report.last_period("week", NOW)
    evil = "x](https://evil.example/)<!channel>@everyone"
    sec_ = report.Section("collect", "収集", "period", ["a"], "失敗が続いている機器", [f"{evil}: 3 回続けて失敗"], 1)
    rep = report.Report("week", "2/23〜3/1", s, e, 1, False, [sec_])
    tm = json.dumps(report.build_payload("teams", rep), ensure_ascii=False)
    assert "](" not in tm  # Markdown のリンクにならない
    dc = json.dumps(report.build_payload("discord", rep), ensure_ascii=False)
    assert "](https://evil" not in dc.replace("​", "") or "]​(" in dc
    sl = report.build_payload("slack", rep)["text"]
    assert "<!channel>" not in sl and "&lt;!channel&gt;" in sl
    # メール（テキストと HTML）: HTML はエスケープされる
    msg = mail.build_message(mail.MailConfig(enabled=True, from_address="ncm@example.test", subject_prefix="[NetConfig]"),
                             "ops@example.test", **{k: v for k, v in report.build_payload("email", rep).items()
                                                    if k in ("title", "facts", "body", "url", "link_text")})
    assert msg["Subject"] == "[NetConfig] 週次レポート 2/23〜3/1"
    html_part = msg.get_body(("html",)).get_content()
    assert "<!channel>" not in html_part and "&lt;!channel&gt;" in html_part


def test_names_are_one_line_and_cut():
    assert report._name("a\nb\tc") == "a b c"
    assert len(report._name("x" * 500)) == report.NAME_MAX + 1


def test_mail_subject_for_week_and_month():
    cfg_ = mail.MailConfig(enabled=True, from_address="ncm@example.test", subject_prefix="[NetConfig]")
    s, e = report.last_period("week", datetime(2026, 11, 23, 8, 0, tzinfo=JST))
    rep = report.Report("week", report.period_label(s, e), s, e, 1, True, [])
    p = report.build_payload("email", rep)
    assert mail.build_message(cfg_, "ops@example.test", p["title"], p["facts"], p["body"], p["url"], p["link_text"])["Subject"] \
        == "[NetConfig] 週次レポート 11/16〜11/22"
    s, e = report.last_period("month", datetime(2026, 12, 1, 8, 0, tzinfo=JST))
    assert report.Report("month", report.period_label(s, e), s, e, 1, True, []).title == "月次レポート 11/1〜11/30"


# ---------------------------------------------------------------- 設定・送信・二重送信の防止


@pytest.fixture(scope="module")
def ctx(world, client):
    c = client
    if True:
        admin = login(c, "admin", "initial-pass-123")
        made = []

        def user(role):
            name = f"rpt-{role}-{uid()}"
            u = c.post("/api/users/", json={"username": name, "password": PW, "role": role, "confirm_password": "initial-pass-123"}, headers=admin).json()
            made.append(u["id"])
            return {"id": u["id"], "name": name, "h": login(c, name, PW)}

        env = {"c": c, "admin": admin, "viewer": user("viewer"), "operator": user("operator"), "admin2": user("admin"),
               "user": user}
        try:
            yield env
        finally:
            async def cleanup():
                async with AsyncSessionLocal() as db:
                    owners = set(made)
                    await db.execute(delete(ReportSend).where(ReportSend.setting_id.in_(
                        select(NotificationSetting.id).where(NotificationSetting.owner_id.in_(owners)))))
                    await db.execute(delete(NotificationSetting).where(NotificationSetting.owner_id.in_(owners)))
                    await db.execute(delete(AuditLog).where(or_(AuditLog.target_id.in_(owners), AuditLog.username.like("rpt-%"))))
                    await db.commit()
            run(cleanup())
            for uid_ in made:
                c.delete(f"/api/users/{uid_}", headers=admin)


@pytest.fixture
def sent(monkeypatch):
    """送信を差し替える（外部へは送らない）。Webhook は send_webhook、メールは notify._send 経由で記録"""
    calls: list[tuple[str, str, dict]] = []
    fail: dict[str, str] = {}

    def fake(kind, url, payload):
        calls.append((kind, url, payload))
        return fail.get(kind)

    monkeypatch.setattr(notify, "send_webhook", fake)
    calls_fail = fail
    return calls, calls_fail


def set_since(owner_id, value, week=True, month=True):
    """種類ごとの since を直接入れる（None で NULL）"""
    async def go():
        async with AsyncSessionLocal() as db:
            vals = {}
            if week:
                vals["report_week_since"] = value
            if month:
                vals["report_month_since"] = value
            await db.execute(update(NotificationSetting).where(NotificationSetting.owner_id == owner_id).values(**vals))
            await db.commit()
    run(go())


def put_me(env, u, keep_since=False, **body):
    """自分の通知設定を保存する。since は API が「いま」にするので、過去の期間を送るテストのために消す（keep_since で残す）"""
    body.setdefault("mode", "custom")
    r = env["c"].put("/api/notifications/me", json=body, headers=u["h"])
    assert r.status_code == 200, r.text
    if not keep_since:
        # 2/23 の週が始まった直後に設定した、ということにする（API は「いま」にする。それより前に終わった期間は送らない）
        set_since(u["id"], report.to_utc(datetime(2026, 2, 23, 0, 0, 1, tzinfo=JST)))
    return r.json()


def my_setting(owner_id):
    async def go():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(NotificationSetting).where(NotificationSetting.owner_id == owner_id))).scalar_one_or_none()
    return run(go())


def sends_of(setting_id):
    async def go():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(ReportSend).where(ReportSend.setting_id == setting_id)
                                     .order_by(ReportSend.period_start, ReportSend.kind))).scalars().all()
    return run(go())


def due(now_local=NOW):
    async def go():
        async with AsyncSessionLocal() as db:
            return await report.send_due_reports(db, now_local)
    return run(go())


def test_settings_save_and_validation(ctx):
    c, u = ctx["c"], ctx["operator"]
    assert c.get("/api/notifications/me", headers=u["h"]).json()["report"] == "off"
    out = put_me(ctx, u, discord_webhook=D.format(nid(), uid()), report="weekly")
    assert out["report"] == "weekly"
    assert c.get("/api/notifications/me", headers=u["h"]).json()["report"] == "weekly"
    for v in ("monthly", "both", "off"):
        assert put_me(ctx, u, report=v)["report"] == v
    assert c.put("/api/notifications/me", json={"mode": "custom", "report": "daily"}, headers=u["h"]).status_code == 422
    # レポートだけを選んだ（ほかの通知の内容はすべて外す）設定も保存できる。何も選ばなければ 422
    only = dict(on_change=False, on_violation=False, on_failure=False, on_system=False, on_inventory=False, on_ping=False,
                on_drift=False, on_unsaved=False)
    assert put_me(ctx, u, report="weekly", **only)["report"] == "weekly"
    r = c.put("/api/notifications/me", json={"mode": "custom", "report": "off", **only}, headers=u["h"])
    assert r.status_code == 422
    # グループの設定にも持てる
    g = c.post("/api/notifications/groups", json={"name": f"rpt-grp-{uid()}", "notification": {
        "mode": "custom", "slack_webhook": S.format(uid(), uid()), "report": "monthly"}}, headers=ctx["admin"])
    try:
        assert g.status_code == 201 and g.json()["notification"]["report"] == "monthly"
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                await db.execute(delete(NotificationSetting).where(NotificationSetting.owner_id == g.json()["id"]))
                await db.commit()
        run(drop())
        c.delete(f"/api/notifications/groups/{g.json()['id']}", headers=ctx["admin"])


def test_send_due_reports_sends_once_per_period(ctx, world, firsts, sent):
    calls, _ = sent
    u = ctx["user"]("operator")
    hook_d, hook_s = D.format(nid(), uid()), S.format(uid(), uid())
    put_me(ctx, u, discord_webhook=hook_d, slack_webhook=hook_s, all_devices=False, device_group_ids=[world.ids["g1"]],
           report="weekly")
    sid = my_setting(u["id"]).id
    # 月曜の 7 時（REPORT_HOUR の前）は送らない
    due(datetime(2026, 3, 2, 7, 0, tzinfo=JST))
    assert not [c for c in calls if c[1] in (hook_d, hook_s)]
    # 月曜の 8 時: Discord と Slack に 1 通ずつ（この設定の範囲 = g1 だけ）
    res = due()
    assert res["sent"] >= 1
    mine = [(k, p) for k, url, p in calls if url in (hook_d, hook_s)]
    assert sorted(k for k, _ in mine) == ["discord", "slack"]
    for _, p in mine:
        t = json.dumps(p, ensure_ascii=False)
        assert world.name["a"] in t and world.name["c"] not in t and world.name["u"] not in t
        assert "週次レポート 2/23〜3/1" in t
    rows = sends_of(sid)
    assert [(r.kind, r.period_start, r.status, r.attempts) for r in rows] == [("week", "2026-02-23", "sent", 1)]
    # 同じ日に何度判定しても（再起動・再実行・beat の二重起動）、同じ期間は二重に送らない
    before = len(calls)
    for hour in (8, 9, 12, 23):
        due(datetime(2026, 3, 2, hour, 0, tzinfo=JST))
    due(datetime(2026, 3, 3, 8, 0, tzinfo=JST))  # 火曜（取り戻しの期間）でも、送信済みなら送らない
    assert not [c for c in calls[before:] if c[1] in (hook_d, hook_s)]
    assert len(sends_of(sid)) == 1
    # 翌週は別の期間として送る
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))
    assert [r.period_start for r in sends_of(sid)] == ["2026-02-23", "2026-03-02"]
    assert len([c for c in calls if c[1] == hook_d]) == 2
    # last_sent_at が記録され、アクティビティに送信が残る（URL は残さない）
    st = my_setting(u["id"])
    assert st.last_sent_at is not None and st.last_error is None

    async def acts():
        async with AsyncSessionLocal() as db:
            return [a.message + (a.detail or "") for a in (await db.execute(select(ActivityLog).where(
                ActivityLog.event == "notify.sent", ActivityLog.message.like("%定期レポート%")))).scalars()]
    msgs = acts_text = "\n".join(run(acts()))
    assert "定期レポートを送信しました" in msgs and hook_d not in acts_text and hook_s not in acts_text
    _cleanup_activity()


def _cleanup_activity():
    async def go():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(ActivityLog).where(ActivityLog.event.in_(("notify.sent", "notify.failed")),
                                                       ActivityLog.message.like("%定期レポート%")))
            await db.commit()
    run(go())


def test_month_and_both(ctx, world, firsts, sent):
    calls, _ = sent
    u = ctx["user"]("viewer")
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="monthly")
    sid = my_setting(u["id"]).id
    # 月次は 1 日（日曜でも）の REPORT_HOUR から。それより前は送らない
    due(datetime(2026, 3, 1, 7, 0, tzinfo=JST))
    assert not [c for c in calls if c[1] == hook]
    due(datetime(2026, 3, 1, 8, 0, tzinfo=JST))
    assert [(r.kind, r.period_start) for r in sends_of(sid)] == [("month", "2026-02-01")]
    assert "月次レポート 2/1〜2/28" in json.dumps(next(p for _, url, p in calls if url == hook), ensure_ascii=False)
    # both: 1 日が月曜なら、週次と月次を別々に送る（2026/06/01 は月曜）
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="both")
    n = len([c for c in calls if c[1] == hook])
    due(datetime(2026, 6, 1, 8, 0, tzinfo=JST))
    titles = [json.dumps(p, ensure_ascii=False) for _, url, p in calls if url == hook][n:]
    assert len(titles) == 2 and any("週次レポート 5/25〜5/31" in t for t in titles) and any("月次レポート 5/1〜5/31" in t for t in titles)
    _cleanup_activity()


def test_only_custom_users_with_targets_get_reports(ctx, world, firsts, sent):
    calls, _ = sent
    c = ctx["c"]
    cases = {}
    for mode in ("inherit", "off"):
        u = ctx["user"]("viewer")
        hook = D.format(nid(), uid())
        put_me(ctx, u, mode=mode, discord_webhook=hook, report="weekly")
        cases[mode] = (u, hook)
    # custom でも report が off なら送らない
    u = ctx["user"]("viewer")
    hook_off = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook_off, report="off")
    # 無効にした利用者の設定は送らない
    u2 = ctx["user"]("viewer")
    hook_dis = D.format(nid(), uid())
    put_me(ctx, u2, discord_webhook=hook_dis, report="weekly")
    assert c.patch(f"/api/users/{u2['id']}", json={"is_active": False}, headers=ctx["admin"]).status_code == 200
    due()
    sent_urls = {url for _, url, _ in calls}
    assert not ({h for _, h in cases.values()} | {hook_off, hook_dis}) & sent_urls
    _cleanup_activity()


def test_group_report_needs_inheriting_members(ctx, world, firsts, sent):
    calls, _ = sent
    c, admin = ctx["c"], ctx["admin"]
    m1, m2 = ctx["user"]("viewer"), ctx["user"]("viewer")
    hook1, hook2 = S.format(uid(), uid()), S.format(uid(), uid())
    body = {"mode": "custom", "all_devices": False, "device_group_ids": [world.ids["g2"]], "report": "weekly"}
    g1 = c.post("/api/notifications/groups", json={"name": f"rpt-g-{uid()}", "member_ids": [m1["id"]],
                                                    "notification": {**body, "slack_webhook": hook1}}, headers=admin).json()
    g2 = c.post("/api/notifications/groups", json={"name": f"rpt-g-{uid()}", "member_ids": [m2["id"]],
                                                    "notification": {**body, "slack_webhook": hook2}}, headers=admin).json()
    for g in (g1, g2):
        set_since(g["id"], report.to_utc(datetime(2026, 2, 23, 0, 0, 1, tzinfo=JST)))
    try:
        # m2 は個別設定（custom）なのでグループの設定は使わない → g2 のレポートは送らない
        put_me(ctx, m2, discord_webhook=D.format(nid(), uid()), report="off")
        due()
        urls = {url for _, url, _ in calls}
        assert hook1 in urls and hook2 not in urls
        text = json.dumps(next(p for _, url, p in calls if url == hook1), ensure_ascii=False)
        # グループの設定の範囲（g2 = 機器 C だけ）。管理者向けの項目は入らない
        assert world.name["c"] in text and world.name["a"] not in text and "管理者向け" not in text
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                ids = [g1["id"], g2["id"]]
                await db.execute(delete(ReportSend).where(ReportSend.setting_id.in_(
                    select(NotificationSetting.id).where(NotificationSetting.owner_id.in_(ids)))))
                await db.execute(delete(NotificationSetting).where(NotificationSetting.owner_id.in_(ids)))
                await db.commit()
        run(drop())
        for g in (g1, g2):
            c.delete(f"/api/notifications/groups/{g['id']}", headers=admin)
        _cleanup_activity()


def test_admin_items_only_in_admin_user_settings(ctx, world, firsts, sent, monkeypatch):
    calls, _ = sent

    async def cert(now):
        return system.Component("cert", "HTTPS の証明書", "ok", "あと 200 日", {"days_left": 200})

    monkeypatch.setattr(system, "check_cert", cert)
    adm, op = ctx["user"]("admin"), ctx["user"]("operator")
    h_adm, h_op = D.format(nid(), uid()), D.format(nid(), uid())
    put_me(ctx, adm, discord_webhook=h_adm, all_devices=False, device_group_ids=[world.ids["g1"]], report="weekly")
    put_me(ctx, op, discord_webhook=h_op, all_devices=False, device_group_ids=[world.ids["g1"]], report="weekly")
    due()
    got = {url: json.dumps(p, ensure_ascii=False) for _, url, p in calls}
    assert "管理者向け" in got[h_adm] and "HTTPS の証明書（いま）: 期限まであと 200 日" in got[h_adm]
    assert "管理者向け" not in got[h_op] and "証明書" not in got[h_op]
    put_me(ctx, op, report="off")
    put_me(ctx, adm, report="off")
    _cleanup_activity()


def test_one_failing_destination_does_not_block_others_and_error_has_no_url(ctx, world, firsts, sent):
    calls, fail = sent
    u = ctx["user"]("operator")
    hook_d, hook_s = D.format(nid(), "SECRETTOKEN"), S.format(uid(), "SECRETSLACK")
    put_me(ctx, u, discord_webhook=hook_d, slack_webhook=hook_s, all_devices=False, device_group_ids=[world.ids["g1"]],
           report="weekly")
    sid = my_setting(u["id"]).id
    fail["discord"] = "Webhook が無効です（HTTP 404。削除・再発行されていないか確認してください）"
    due()
    assert {k for k, url, _ in calls if url in (hook_d, hook_s)} == {"discord", "slack"}  # Slack には送れた
    st = my_setting(u["id"])
    assert st.last_error and "Discord" in st.last_error and "SECRETTOKEN" not in st.last_error
    assert [(r.status) for r in sends_of(sid)] == ["sent"]  # 1 つでも送れたので、やり直さない

    async def acts():
        async with AsyncSessionLocal() as db:
            return "\n".join(a.message + (a.detail or "") for a in (await db.execute(select(ActivityLog).where(
                ActivityLog.event == "notify.failed", ActivityLog.message.like("%定期レポート%")))).scalars())
    text = run(acts())
    assert "Discord への定期レポートに失敗しました" in text and "SECRETTOKEN" not in text and "SECRETSLACK" not in text
    _cleanup_activity()


def test_all_destinations_failing_is_retried_up_to_the_limit(ctx, world, firsts, sent):
    calls, fail = sent
    u = ctx["user"]("viewer")
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="weekly")
    sid = my_setting(u["id"]).id
    fail["discord"] = "HTTP 500"
    for hour in (8, 9, 10, 11, 12):  # 毎時の判定
        due(datetime(2026, 3, 2, hour, 0, tzinfo=JST))
    rows = sends_of(sid)
    assert [(r.status, r.attempts) for r in rows] == [("failed", report.MAX_ATTEMPTS)]
    assert len([c for c in calls if c[1] == hook]) == report.MAX_ATTEMPTS  # 上限で止める
    # 直った後でも、上限に達した期間はやり直さない。次の週は送れる
    fail.clear()
    due(datetime(2026, 3, 2, 13, 0, tzinfo=JST))
    assert len([c for c in calls if c[1] == hook]) == report.MAX_ATTEMPTS
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))
    assert [r.status for r in sends_of(sid)] == ["missed", "sent"]  # 取り戻しの期間を過ぎた週は「送れなかった」として残る
    _cleanup_activity()


def test_failed_then_success_marks_sent(ctx, world, firsts, sent):
    calls, fail = sent
    u = ctx["user"]("viewer")
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="weekly")
    sid = my_setting(u["id"]).id
    fail["discord"] = "HTTP 500"
    due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    fail.clear()
    due(datetime(2026, 3, 2, 9, 0, tzinfo=JST))
    due(datetime(2026, 3, 2, 10, 0, tzinfo=JST))
    assert [(r.status, r.attempts) for r in sends_of(sid)] == [("sent", 2)]
    assert len([c for c in calls if c[1] == hook]) == 2
    _cleanup_activity()


def test_concurrent_claims_only_one_wins(ctx):
    """同時に 2 つの worker が同じ期間を判定しても、送る権利を取れるのは 1 つ（一意制約）"""
    sid = f"rpt-claim-{uid()}"

    async def go():
        async def one():
            async with AsyncSessionLocal() as db:
                return await report.claim(db, sid, "week", "2026-02-23", utcnow_())
        return await asyncio.gather(*(one() for _ in range(4)))

    try:
        results = run(go())
        assert sorted(results) == [False, False, False, True]
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                await db.execute(delete(ReportSend).where(ReportSend.setting_id == sid))
                await db.commit()
        run(drop())


def utcnow_():
    from app.core.timeutil import utcnow
    return utcnow()


def test_stale_sending_is_taken_over_but_fresh_is_not():
    sid = f"rpt-stale-{uid()}"
    now = utcnow_()

    async def go():
        async with AsyncSessionLocal() as db:
            assert await report.claim(db, sid, "week", "2026-02-23", now) is True
            # 送信中（始めたばかり）は引き継がない
            assert await report.claim(db, sid, "week", "2026-02-23", now + timedelta(minutes=5)) is False
            # 止まったままの送信（STALE_MIN 分以上）は引き継ぐ。送信済みは引き継がない
            assert await report.claim(db, sid, "week", "2026-02-23", now + timedelta(minutes=report.STALE_MIN + 1)) is True
            await report.finish(db, sid, "week", "2026-02-23", True)
            assert await report.claim(db, sid, "week", "2026-02-23", now + timedelta(days=1)) is False
            # 種類・期間が違えば別
            assert await report.claim(db, sid, "month", "2026-02-23", now) is True
            assert await report.claim(db, sid, "week", "2026-03-02", now) is True
    try:
        run(go())
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                await db.execute(delete(ReportSend).where(ReportSend.setting_id == sid))
                await db.commit()
        run(drop())


def test_purge_old_sends():
    sid = f"rpt-purge-{uid()}"

    async def go():
        async with AsyncSessionLocal() as db:
            old = utcnow_() - timedelta(days=401)
            db.add(ReportSend(setting_id=sid, kind="week", period_start="2025-01-06", status="sent", claimed_at=old))
            db.add(ReportSend(setting_id=sid, kind="week", period_start="2026-02-23", status="sent", claimed_at=utcnow_()))
            await db.commit()
            assert await report.purge_old(db) >= 1
            left = (await db.execute(select(ReportSend).where(ReportSend.setting_id == sid))).scalars().all()
            assert [r.period_start for r in left] == ["2026-02-23"]
            await db.execute(delete(ReportSend).where(ReportSend.setting_id == sid))
            await db.commit()
    run(go())


def test_secrets_never_in_payloads(ctx, world, firsts, sent):
    """レポートに Webhook の URL・トークン・宛先のメールアドレス・コンフィグの中身を入れない"""
    calls, _ = sent
    u = ctx["user"]("operator")
    hook_d, hook_s = D.format(nid(), "TOPSECRETDISCORD"), S.format(uid(), "TOPSECRETSLACK")
    put_me(ctx, u, discord_webhook=hook_d, slack_webhook=hook_s, all_devices=True, report="weekly")
    due()
    mine = [json.dumps(p, ensure_ascii=False) for _, url, p in calls if url in (hook_d, hook_s)]
    assert len(mine) == 2
    for t in mine:
        assert "TOPSECRET" not in t and "discord.com/api/webhooks" not in t and "hooks.slack.com" not in t
        assert u["name"] not in t  # 利用者名も入れない
    _cleanup_activity()


def test_email_report_goes_through_mail_with_subject(ctx, world, firsts, monkeypatch):
    """メール: 宛先ごとに 1 通・件名は「週次レポート 期間」・本文は集計"""
    sent_mail = []

    def fake_send(kind, url, payload, cfg):
        sent_mail.append((kind, url, payload))

    async def fake_cfg(db):
        return mail.MailConfig(enabled=True, from_address="ncm@example.test", subject_prefix="[NetConfig]")

    async def noop(errors):
        return None

    monkeypatch.setattr(notify, "_send", fake_send)
    monkeypatch.setattr(mail, "load_config", fake_cfg)
    monkeypatch.setattr(mail, "record_last", noop)
    u = ctx["user"]("viewer")
    # メールの宛先は API ではメールサーバーの設定が要るので、DB に直接入れる
    async def add():
        async with AsyncSessionLocal() as db:
            db.add(NotificationSetting(owner_type="user", owner_id=u["id"], mode="custom", email_to="a@example.test,b@example.test",
                                       all_devices=False, device_group_ids=json.dumps([world.ids["g1"]]), report="weekly",
                                       report_week_since=report.to_utc(datetime(2026, 2, 23, 0, 0, 1, tzinfo=JST))))
            await db.commit()
    run(add())
    due()
    mine = [(k, url, p) for k, url, p in sent_mail if url in ("a@example.test", "b@example.test")]
    assert sorted(url for _, url, _ in mine) == ["a@example.test", "b@example.test"]
    p = mine[0][2]
    msg = mail.build_message(mail.MailConfig(enabled=True, from_address="ncm@example.test", subject_prefix="[NetConfig]"),
                             "a@example.test", p["title"], p["facts"], p["body"], p["url"], p["link_text"])
    assert msg["Subject"] == "[NetConfig] 週次レポート 2/23〜3/1"
    assert world.name["a"] in msg.get_body(("plain",)).get_content() and world.name["c"] not in msg.get_body(("plain",)).get_content()
    _cleanup_activity()


# ---------------------------------------------------------------- API（プレビュー・いま送る）


def test_preview_api_scope_permission_and_shape(ctx, world, firsts, monkeypatch):
    async def free(user_id):
        return 0

    monkeypatch.setattr(report, "take_preview_slot", free)  # 間隔の制限は別のテストで確かめる
    c = ctx["c"]
    v = ctx["viewer"]
    put_me(ctx, v, discord_webhook=D.format(nid(), uid()), all_devices=False, device_group_ids=[world.ids["g1"]])
    assert c.get("/api/notifications/report-preview").status_code == 401
    r = c.get("/api/notifications/report-preview", params={"period": "week"}, headers=v["h"])
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["kind"] == "week" and d["title"].startswith("週次レポート ") and d["devices"] == 2
    assert [s["key"] for s in d["sections"]] == ["collect", "change", "compliance", "state", "ping"]  # 閲覧者には管理者向けなし
    assert "対象の機器: 2 台" in d["head"] and d["head"][1].startswith("集計: ")
    # 月次・不正な期間
    assert c.get("/api/notifications/report-preview", params={"period": "month"}, headers=v["h"]).json()["kind"] == "month"
    assert c.get("/api/notifications/report-preview", params={"period": "year"}, headers=v["h"]).status_code == 422
    # 範囲外の機器の名前が入らない（設定の範囲 = g1）
    body = r.text
    assert world.name["c"] not in body and world.name["u"] not in body and "discord.com" not in body
    # 管理者には管理者向けの項目が付く
    a = ctx["admin2"]
    rr = c.get("/api/notifications/report-preview", headers=a["h"]).json()
    assert rr["sections"][-1]["key"] == "admin"
    # 通知設定が無い利用者は、すべての機器の範囲
    nu = ctx["user"]("viewer")
    assert c.get("/api/notifications/report-preview", headers=nu["h"]).json()["devices"] >= 4


def test_send_now_api(ctx, world, firsts, sent):
    calls, fail = sent
    c = ctx["c"]
    u = ctx["user"]("operator")
    # 通知先が無いと 400（テスト送信と同じ）
    assert c.post("/api/notifications/me/report", headers=u["h"]).status_code == 400
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="off")
    assert c.post("/api/notifications/me/report").status_code == 401
    r = c.post("/api/notifications/me/report", params={"period": "week"}, headers=u["h"])
    assert r.status_code == 200 and r.json() == {"results": {"discord": "ok"}}
    mine = [p for k, url, p in calls if url == hook]
    assert len(mine) == 1 and "週次レポート" in json.dumps(mine[0], ensure_ascii=False)
    assert world.name["c"] not in json.dumps(mine[0], ensure_ascii=False)
    # 連打は 429（利用者ごとに間隔を空ける。ほかの人は送れる）
    r2 = c.post("/api/notifications/me/report", headers=u["h"])
    assert r2.status_code == 429 and int(r2.headers["Retry-After"]) >= 1 and "待って" in r2.json()["detail"]
    assert len([1 for k, url, p in calls if url == hook]) == 1
    # 監査ログに残る（URL は残さない）
    logs = c.get("/api/audit/logs", params={"action": "notify.report_send", "limit": 50}, headers=ctx["admin"]).json()["items"]
    assert any(x["target_id"] == u["id"] for x in logs) and hook not in json.dumps(logs)
    # 送信が失敗すると、結果にエラーを返す（URL は含まない）
    other = ctx["user"]("viewer")
    hook2 = D.format(nid(), "SECRETTOKEN2")
    put_me(ctx, other, discord_webhook=hook2)
    fail["discord"] = "Webhook が無効です（HTTP 404）"
    r3 = c.post("/api/notifications/me/report", params={"period": "month"}, headers=other["h"])
    assert r3.status_code == 200 and r3.json()["results"] == {"discord": "Webhook が無効です（HTTP 404）"}
    assert "SECRETTOKEN2" not in r3.text


def test_send_now_slot_falls_back_to_memory_without_redis(monkeypatch):
    from redis.exceptions import RedisError

    from app.services import login_limit

    class Broken:
        async def set(self, *a, **k):
            raise RedisError("down")

    monkeypatch.setattr(login_limit, "_client", Broken())
    report._last_send_memory.pop("rpt-mem-user", None)
    assert run(report.take_send_slot("rpt-mem-user")) == 0
    assert run(report.take_send_slot("rpt-mem-user")) > 0
    assert run(report.take_preview_slot("rpt-mem-user")) == 0  # プレビューは別の枠
    assert run(report.take_preview_slot("rpt-mem-user")) > 0
    report._last_send_memory.clear()


# ---------------------------------------------------------------- worker（毎時の判定のタスク）


def test_beat_schedule_runs_hourly():
    from app import worker

    entry = worker.celery_app.conf.beat_schedule["send-periodic-reports"]
    assert entry["task"] == "app.worker.send_periodic_reports" and entry["schedule"] == 3600.0
    assert worker.send_periodic_reports.name == entry["task"]


def test_worker_task_sends_once_even_when_run_twice(ctx, world, firsts, sent, monkeypatch):
    """タスクを重ねて実行しても（beat の二重起動・再起動）、同じ期間は 1 回だけ"""
    from app import worker

    calls, _ = sent
    monkeypatch.setattr(report, "local_now", lambda: NOW)
    u = ctx["user"]("operator")
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], report="weekly")
    first = worker.send_periodic_reports.apply().get()
    second = worker.send_periodic_reports.apply().get()
    assert first["sent"] >= 1 and second["sent"] == 0 and second["skipped"] >= 1
    assert len([1 for _, url, _ in calls if url == hook]) == 1
    # 火曜（取り戻しの期間）でも、送信済みなら送らない
    monkeypatch.setattr(report, "local_now", lambda: datetime(2026, 3, 3, 8, 0, tzinfo=JST))
    third = worker.send_periodic_reports.apply().get()
    assert third["sent"] == 0 and len([1 for _, url, _ in calls if url == hook]) == 1
    _cleanup_activity()


def test_worker_task_survives_errors(monkeypatch):
    from app import worker

    async def boom(db, now_local=None):
        raise RuntimeError("secret-connection-string")

    monkeypatch.setattr(report, "send_due_reports", boom)
    assert worker.send_periodic_reports.apply().get() == {"error": True}


def test_purge_task_removes_old_report_sends():
    from app import worker

    sid = f"rpt-purge2-{uid()}"

    async def add():
        async with AsyncSessionLocal() as db:
            db.add(ReportSend(setting_id=sid, kind="week", period_start="2024-01-01", status="sent",
                              claimed_at=utcnow_() - timedelta(days=500)))
            await db.commit()
    run(add())
    assert worker.purge_audit_logs.apply().get()["report_sends"] >= 1
    assert sends_of(sid) == []


# ---------------------------------------------------------------- 取り戻し・設定した直後・送れなかった記録・低指摘の対応


def hook_user(ctx, world, role="operator", **kw):
    u = ctx["user"](role)
    hook = D.format(nid(), uid())
    put_me(ctx, u, discord_webhook=hook, all_devices=False, device_group_ids=[world.ids["g1"]], **kw)
    return u, hook, my_setting(u["id"]).id


def n_calls(calls, hook):
    return len([1 for _, url, _ in calls if url == hook])


def test_catch_up_on_tuesday_and_sunday_then_only_new_week_on_monday(ctx, world, firsts, sent):
    """火曜・日曜に起きたら先週分を送る。次の月曜には先週分ではなく新しい週の分だけ"""
    calls, _ = sent
    # 火曜に初めて判定が走った（月曜は worker が止まっていた）
    _u, hook, sid = hook_user(ctx, world, report="weekly")
    due(datetime(2026, 3, 3, 3, 0, tzinfo=JST))  # 火曜の 3 時（REPORT_HOUR 前でも、取り戻しの期間は終日）
    assert n_calls(calls, hook) == 1 and "週次レポート 2/23〜3/1" in json.dumps(calls[-1][2], ensure_ascii=False)
    due(datetime(2026, 3, 4, 12, 0, tzinfo=JST))
    assert n_calls(calls, hook) == 1  # 二重には送らない
    # 日曜（次の月曜の前日の最後）まで取り戻せる
    _u2, hook2, _sid2 = hook_user(ctx, world, report="weekly")
    due(datetime(2026, 3, 8, 23, 30, tzinfo=JST))
    assert n_calls(calls, hook2) == 1 and "2/23〜3/1" in json.dumps(calls[-1][2], ensure_ascii=False)
    # 次の月曜の 0:00〜7:59 は、まだ先週分を取り戻せる（新しい週の分は 8 時から）
    _u4, hook4, _sid4 = hook_user(ctx, world, report="weekly")
    due(datetime(2026, 3, 9, 7, 59, tzinfo=JST))
    assert n_calls(calls, hook4) == 1 and "2/23〜3/1" in json.dumps(calls[-1][2], ensure_ascii=False)
    # 次の月曜 8 時: 新しい週（3/2〜3/8）の分だけ。先週分（2/23〜3/1）は送り直さない
    n = n_calls(calls, hook)
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))
    assert n_calls(calls, hook) == n + 1 and "3/2〜3/8" in json.dumps(calls[-1][2], ensure_ascii=False)
    assert [r.period_start for r in sends_of(sid)] == ["2026-02-23", "2026-03-02"]
    # 月曜の 8 時前は、新しい週（3/9〜3/15）の分は送らない（まだ取り戻せる前の週 3/2〜3/8 だけ）
    _u3, hook3, _sid3 = hook_user(ctx, world, report="weekly")
    due(datetime(2026, 3, 16, 7, 59, tzinfo=JST))
    assert n_calls(calls, hook3) == 1 and "3/2〜3/8" in json.dumps(calls[-1][2], ensure_ascii=False)
    _cleanup_activity()


def test_month_catch_up_window_ends_at_report_hour_of_day_28(ctx, world, firsts, sent):
    calls, _ = sent
    _u, hook, _sid = hook_user(ctx, world, report="monthly")
    due(datetime(2026, 3, 27, 23, 0, tzinfo=JST))
    assert n_calls(calls, hook) == 1 and "月次レポート 2/1〜2/28" in json.dumps(calls[-1][2], ensure_ascii=False)
    _u2, hook2, _sid2 = hook_user(ctx, world, report="monthly")
    due(datetime(2026, 3, 28, 7, 59, tzinfo=JST))  # 28 日の REPORT_HOUR 時の前は、まだ取り戻せる
    assert n_calls(calls, hook2) == 1
    _u3, hook3, sid3 = hook_user(ctx, world, report="monthly")
    due(datetime(2026, 3, 28, 8, 0, tzinfo=JST))  # 取り戻しの期間を過ぎた（次の期間を送り始める時刻）
    assert n_calls(calls, hook3) == 0
    assert [r.status for r in sends_of(sid3)] == ["missed"]
    _cleanup_activity()


def test_report_since_skips_periods_that_ended_before_setting(ctx, world, firsts, sent):
    """設定した直後は過去の分を送らない。設定したあとに終わった期間だけ送る"""
    calls, _ = sent
    u, hook, sid = hook_user(ctx, world, report="weekly")
    set_since(u["id"], report.to_utc(datetime(2026, 3, 3, 10, 0, tzinfo=JST)))  # 火曜の昼に毎週を選んだ
    due(datetime(2026, 3, 3, 12, 0, tzinfo=JST))
    due(datetime(2026, 3, 7, 12, 0, tzinfo=JST))
    assert n_calls(calls, hook) == 0 and sends_of(sid) == []  # 先週分（月曜 0 時に終わった）は送らず、「送れなかった」も残さない
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))  # 設定したあとに終わった週（3/2〜3/8）は送る
    assert n_calls(calls, hook) == 1 and "3/2〜3/8" in json.dumps(calls[-1][2], ensure_ascii=False)
    due(datetime(2026, 3, 23, 7, 59, tzinfo=JST))  # 3/9〜3/15 はまだ取り戻せる期間（ここで送られる）
    assert [r.status for r in sends_of(sid)] == ["sent", "sent"]
    _u5, _hook5, sid5 = hook_user(ctx, world, report="weekly")
    set_since(_u5["id"], report.to_utc(datetime(2026, 3, 3, 10, 0, tzinfo=JST)))
    due(datetime(2026, 3, 23, 8, 0, tzinfo=JST))  # 3/9〜3/15 は一度も送れないまま取り戻しの期間を過ぎた。設定後に終わったので「送れなかった」
    assert [(r.period_start, r.status) for r in sends_of(sid5)][:1] == [("2026-03-09", "missed")]
    # 終わりちょうどが設定の時刻のときは送る（前に終わった分だけを送らない）
    u2, hook2, _sid2 = hook_user(ctx, world, report="weekly")
    set_since(u2["id"], report.to_utc(datetime(2026, 3, 2, 0, 0, tzinfo=JST)))
    due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    assert n_calls(calls, hook2) == 1
    _cleanup_activity()


def since_of(owner_id):
    s = my_setting(owner_id)
    return s.report_week_since, s.report_month_since


def test_api_sets_since_per_kind_only_when_that_kind_is_turned_on(ctx):
    c, u = ctx["c"], ctx["user"]("viewer")
    hook = D.format(nid(), uid())

    def save(**kw):
        r = c.put("/api/notifications/me", json={"mode": "custom", "discord_webhook": hook, **kw}, headers=u["h"])
        assert r.status_code == 200, r.text
        return since_of(u["id"])

    assert save(report="off") == (None, None)
    w1, m1 = save(report="weekly")
    assert w1 is not None and (utcnow_() - w1).total_seconds() < 30 and m1 is None  # off から変えた週次だけ
    old = w1 - timedelta(days=3)
    set_since(u["id"], old, month=False)
    assert save(report="weekly") == (old, None)  # 同じ内容の保存では変わらない（last_sent_at の更新でも変えない）
    w2, m2 = save(report="both")  # 週次は有効のまま（変えない）。月次が増えた
    assert w2 == old and m2 is not None and m2 > old
    set_since(u["id"], old - timedelta(days=1), week=False)
    w3, m3 = save(report="weekly")  # 月次が無効になった → NULL。週次は変えない
    assert w3 == old and m3 is None
    w4, m4 = save(report="both")  # 月次が入れ直される
    assert w4 == old and m4 is not None and m4 > old
    assert save(report="monthly") == (None, m4)  # 週次が無効 → NULL。月次は変えない
    assert save(report="off") == (None, None)
    w5, m5 = save(report="monthly")
    assert w5 is None and m5 is not None


def test_api_resets_since_when_mode_returns_to_custom(ctx):
    """通知を止めていた（inherit / off）あとに個別設定へ戻したとき、止めていた期間の分は送らない"""
    c, u = ctx["c"], ctx["user"]("viewer")
    hook = D.format(nid(), uid())
    body = {"discord_webhook": hook, "report": "both"}
    assert c.put("/api/notifications/me", json={"mode": "custom", **body}, headers=u["h"]).status_code == 200
    old = utcnow_() - timedelta(days=20)
    set_since(u["id"], old)
    for mode in ("off", "inherit"):
        assert c.put("/api/notifications/me", json={"mode": mode, **body}, headers=u["h"]).status_code == 200
        assert since_of(u["id"]) == (None, None)  # 個別設定でない間は送らないので、since も持たない
        set_since(u["id"], None)
        assert c.put("/api/notifications/me", json={"mode": "custom", **body}, headers=u["h"]).status_code == 200
        w, m = since_of(u["id"])
        assert w is not None and m is not None and (utcnow_() - w).total_seconds() < 30 and (utcnow_() - m).total_seconds() < 30
        set_since(u["id"], old)
    # 個別設定のままの保存では変えない
    assert c.put("/api/notifications/me", json={"mode": "custom", **body}, headers=u["h"]).status_code == 200
    assert since_of(u["id"]) == (old, old)


def test_widening_does_not_stop_the_enabled_weekly_but_month_starts_after_setting(ctx, world, firsts, sent):
    """月曜 7:00 に weekly → both にしても、8:00 の判定で先週分の週次は送る。月次は設定後に終わった期間から"""
    calls, _ = sent
    u, hook, sid = hook_user(ctx, world, report="weekly")  # since は 2/23 0:00:01（put_me が入れる）
    r = ctx["c"].put("/api/notifications/me", json={
        "mode": "custom", "discord_webhook": hook, "all_devices": False, "device_group_ids": [world.ids["g1"]],
        "report": "both"}, headers=u["h"])
    assert r.status_code == 200
    w, m = since_of(u["id"])
    assert w == report.to_utc(datetime(2026, 2, 23, 0, 0, 1, tzinfo=JST)) and m is not None  # 週次は変わらず、月次は「いま」
    set_since(u["id"], report.to_utc(datetime(2026, 3, 2, 7, 0, tzinfo=JST)), week=False)  # 月次は月曜 7:00 に足した
    due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    kinds = {r.kind: r.status for r in sends_of(sid)}
    assert kinds == {"week": "sent"}  # 先週分の週次は送る。2 月分の月次（3/1 0:00 に終わった）は送らない
    assert n_calls(calls, hook) == 1 and "週次レポート 2/23〜3/1" in json.dumps(calls[-1][2], ensure_ascii=False)
    due(datetime(2026, 4, 1, 8, 0, tzinfo=JST))  # 月次は設定後に終わった 3 月分から
    assert {(r.kind, r.period_start) for r in sends_of(sid)} >= {("month", "2026-03-01")}
    _cleanup_activity()


def test_failed_weekly_is_retried_after_widening(ctx, world, firsts, sent):
    _calls, fail = sent
    u, hook, sid = hook_user(ctx, world, report="weekly")
    fail["discord"] = "HTTP 500"
    due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    assert [(r.kind, r.status, r.attempts) for r in sends_of(sid)] == [("week", "failed", 1)]
    r = ctx["c"].put("/api/notifications/me", json={
        "mode": "custom", "discord_webhook": hook, "all_devices": False, "device_group_ids": [world.ids["g1"]],
        "report": "both"}, headers=u["h"])
    assert r.status_code == 200
    fail.clear()
    due(datetime(2026, 3, 2, 9, 0, tzinfo=JST))  # 種類を増やしたあとも、失敗していた週次をやり直す
    assert [(r.kind, r.status, r.attempts) for r in sends_of(sid)] == [("week", "sent", 2)]
    _cleanup_activity()


def test_null_since_is_initialized_without_sending_or_missing(ctx, world, firsts, sent):
    """since が NULL のまま有効な行（API を通らずに作られた）は、最初の判定で「いま」を入れて、その回は送らない"""
    calls, _ = sent
    u, hook, sid = hook_user(ctx, world, report="weekly")
    set_since(u["id"], None)
    due(datetime(2026, 3, 3, 12, 0, tzinfo=JST))
    assert n_calls(calls, hook) == 0 and sends_of(sid) == []
    w, m = since_of(u["id"])
    assert w is not None and m is None  # 有効な週次だけ入る
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))  # since は判定の時刻（3/3）。それより前に終わった 2/23 の週は送らない・記録も残さない
    assert n_calls(calls, hook) == 1 and "3/2〜3/8" in json.dumps(calls[-1][2], ensure_ascii=False)
    assert [r.period_start for r in sends_of(sid)] == ["2026-03-02"]
    _cleanup_activity()


def test_error_in_one_setting_does_not_stop_others_and_rollback_is_safe(ctx, world, firsts, sent, monkeypatch):
    """同時に判定した別の worker が先に行を作った（claim が一意制約違反）あとも、次の設定（failed の行あり）をやり直す"""
    calls, _ = sent
    _u1, hook1, sid1 = hook_user(ctx, world, report="weekly")
    _u2, hook2, sid2 = hook_user(ctx, world, report="weekly")
    now = report.to_utc(datetime(2026, 3, 2, 8, 0, tzinfo=JST))

    async def seed():
        async with AsyncSessionLocal() as db:
            db.add(ReportSend(setting_id=sid2, kind="week", period_start="2026-02-23", status="failed", attempts=1,
                              claimed_at=now - timedelta(hours=1)))
            await db.commit()
    run(seed())
    orig = report.claim

    async def racing(db, setting_id, kind, period_start, now_, existing=None):
        if setting_id == sid1 and existing is None:
            async with AsyncSessionLocal() as other:  # 別の worker が claim の直前に行を作った
                other.add(ReportSend(setting_id=sid1, kind=kind, period_start=period_start, status="sending", attempts=1,
                                     claimed_at=utcnow_()))
                await other.commit()
        return await orig(db, setting_id, kind, period_start, now_, existing)

    monkeypatch.setattr(report, "claim", racing)
    # 設定の順序に依らないよう、sid1 が先に処理されるかは問わず、どちらの順でも sid2 がやり直されること
    res = due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    assert res["errors"] == 0
    assert n_calls(calls, hook1) == 0  # 別の worker が送っている
    assert n_calls(calls, hook2) == 1
    assert [(r.status, r.attempts) for r in sends_of(sid2)] == [("sent", 2)]
    _cleanup_activity()


def test_exception_in_one_setting_is_logged_and_others_continue(ctx, world, firsts, sent, monkeypatch):
    calls, _ = sent
    _u1, hook1, sid1 = hook_user(ctx, world, report="weekly")
    _u2, hook2, _sid2 = hook_user(ctx, world, report="both")
    orig = report.claim

    async def boom(db, setting_id, kind, period_start, now_, existing=None):
        if setting_id == sid1:
            raise RuntimeError("postgresql://user:SECRETPW@db/x")
        return await orig(db, setting_id, kind, period_start, now_, existing)

    monkeypatch.setattr(report, "claim", boom)
    res = due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    assert res["errors"] == 1 and n_calls(calls, hook1) == 0
    assert n_calls(calls, hook2) == 2  # ほかの設定は送る（週次と月次の両方）
    due(datetime(2026, 3, 2, 9, 0, tzinfo=JST))

    async def logs():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(ActivityLog).where(
                ActivityLog.message.like("定期レポートの判定に失敗しました%")))).scalars().all()
    ls = run(logs())
    assert ls and "SECRETPW" not in json.dumps([(x.message, x.detail) for x in ls], ensure_ascii=False)
    _cleanup_activity()


def test_report_head_has_the_aggregation_time(ctx, world, firsts):
    s, e = report.last_period("week", NOW)
    at = datetime(2026, 3, 9, 8, 0, tzinfo=JST)
    rep = report.Report("week", "2/23〜3/1", s, e, 1, True, [], at=at)
    assert any(x.startswith("集計: 2026/03/09 08:00 時点（") for x in rep.head_lines())
    assert any(x.startswith("集計: ") for x in rep.to_dict()["head"])
    assert not any(x.startswith("集計: ") for x in report.Report("week", "x", s, e, 1, True, []).head_lines())


def test_group_setting_gets_report_since_too(ctx):
    c, admin = ctx["c"], ctx["admin"]
    g = c.post("/api/notifications/groups", json={"name": f"rpt-since-{uid()}", "notification": {
        "mode": "custom", "slack_webhook": S.format(uid(), uid()), "report": "weekly"}}, headers=admin).json()
    try:
        assert my_setting(g["id"]).report_week_since is not None
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                await db.execute(delete(NotificationSetting).where(NotificationSetting.owner_id == g["id"]))
                await db.commit()
        run(drop())
        c.delete(f"/api/notifications/groups/{g['id']}", headers=admin)


def test_missed_is_recorded_once_after_three_failures(ctx, world, firsts, sent):
    """3 回失敗したまま取り戻しの期間を過ぎたら、「送れませんでした」を 1 回だけ残す（毎時くり返さない）"""
    calls, fail = sent
    _u, hook, sid = hook_user(ctx, world, report="weekly")
    fail["discord"] = "HTTP 500"
    for hour in (8, 9, 10, 11):
        due(datetime(2026, 3, 2, hour, 0, tzinfo=JST))
    assert [(r.status, r.attempts) for r in sends_of(sid)] == [("failed", report.MAX_ATTEMPTS)]

    def missed_logs():
        async def go():
            async with AsyncSessionLocal() as db:
                return (await db.execute(select(ActivityLog).where(
                    ActivityLog.message.like("定期レポートを送れませんでした%")))).scalars().all()
        return run(go())

    before = len(missed_logs())
    due(datetime(2026, 3, 8, 23, 0, tzinfo=JST))  # まだ取り戻しの期間内
    assert len(missed_logs()) == before
    due(datetime(2026, 3, 9, 7, 59, tzinfo=JST))  # 次の期間を送り始める時刻の前は、まだ取り戻しの期間内（失敗の上限に達している）
    assert len(missed_logs()) == before
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))  # 期間を過ぎた
    logs = missed_logs()
    assert len(logs) > before
    mine = [lg for lg in logs if "週次 2/23〜3/1・ユーザーの設定" in lg.message]
    assert mine and "ユーザー" in mine[0].message
    assert ("2026-02-23", "missed") in [(r.period_start, r.status) for r in sends_of(sid)]
    for hour in (8, 9, 10):  # 毎時に判定しても、増えない
        due(datetime(2026, 3, 9, hour, 0, tzinfo=JST))
    fail.clear()
    due(datetime(2026, 3, 12, 8, 0, tzinfo=JST))
    assert len(missed_logs()) == len(logs)  # 新しい週はまだ取り戻しの期間内なので、増えない
    assert n_calls(calls, hook) >= report.MAX_ATTEMPTS
    text = json.dumps([(lg.message, lg.detail) for lg in missed_logs()], ensure_ascii=False)
    assert hook not in text
    _cleanup_activity()


def test_missed_not_recorded_twice_for_same_setting_and_period(ctx, world, firsts, sent):
    _u, _hook, sid = hook_user(ctx, world, report="weekly")
    due(datetime(2026, 3, 9, 8, 0, tzinfo=JST))  # 2/23 の週は一度も送れないまま取り戻しの期間を過ぎた（worker が止まっていた）
    assert ("2026-02-23", "missed") in [(r.period_start, r.status) for r in sends_of(sid)]
    n = len(sends_of(sid))
    due(datetime(2026, 3, 9, 8, 30, tzinfo=JST))
    assert len(sends_of(sid)) == n
    _cleanup_activity()


def test_claim_does_not_take_over_beyond_the_attempt_limit():
    """送信中のまま止まった行の引き継ぎにも、やり直しの上限がある"""
    sid = f"rpt-cap-{uid()}"
    now = utcnow_()

    async def go():
        async with AsyncSessionLocal() as db:
            db.add(ReportSend(setting_id=sid, kind="week", period_start="2026-02-23", status="sending",
                              attempts=report.MAX_ATTEMPTS, claimed_at=now - timedelta(hours=3)))
            db.add(ReportSend(setting_id=sid, kind="week", period_start="2026-02-16", status="sending",
                              attempts=report.MAX_ATTEMPTS - 1, claimed_at=now - timedelta(hours=3)))
            await db.commit()
            assert await report.claim(db, sid, "week", "2026-02-23", now) is False
            assert await report.claim(db, sid, "week", "2026-02-16", now) is True
    try:
        run(go())
    finally:
        async def drop():
            async with AsyncSessionLocal() as db:
                await db.execute(delete(ReportSend).where(ReportSend.setting_id == sid))
                await db.commit()
        run(drop())


def test_sent_or_sending_rows_are_not_inserted_again(ctx, world, firsts, sent, monkeypatch):
    """claim の前にまとめて読み、送信済み・送信中の設定は INSERT を試さない（重複エラーのログを出さない）"""
    calls, _ = sent
    _u, hook, sid = hook_user(ctx, world, report="weekly")
    seen = []
    orig = report.claim

    async def spy(db, setting_id, kind, period_start, now, existing=None):
        seen.append((setting_id, period_start, existing is not None))
        return await orig(db, setting_id, kind, period_start, now, existing)

    monkeypatch.setattr(report, "claim", spy)
    due(datetime(2026, 3, 2, 8, 0, tzinfo=JST))
    assert [x for x in seen if x[0] == sid] == [(sid, "2026-02-23", False)]  # 初回は INSERT で取る
    due(datetime(2026, 3, 2, 9, 0, tzinfo=JST))
    due(datetime(2026, 3, 3, 9, 0, tzinfo=JST))
    assert [x for x in seen if x[0] == sid] == [(sid, "2026-02-23", False)]  # 送信済みは claim も呼ばない
    # 送信中（新しい行）も触らない
    async def mark():
        async with AsyncSessionLocal() as db:
            await db.execute(update(ReportSend).where(ReportSend.setting_id == sid).values(
                status="sending", claimed_at=utcnow_(), attempts=1))
            await db.commit()
    run(mark())
    due(datetime(2026, 3, 3, 10, 0, tzinfo=JST))
    assert [x for x in seen if x[0] == sid] == [(sid, "2026-02-23", False)]
    # 全宛先で失敗した行は、読んだ行を渡して引き継ぐ（INSERT は試さない）
    async def fail_row():
        async with AsyncSessionLocal() as db:
            await db.execute(update(ReportSend).where(ReportSend.setting_id == sid).values(status="failed"))
            await db.commit()
    run(fail_row())
    due(datetime(2026, 3, 3, 11, 0, tzinfo=JST))
    assert [x for x in seen if x[0] == sid][-1] == (sid, "2026-02-23", True)
    assert [r.status for r in sends_of(sid)] == ["sent"] and n_calls(calls, hook) == 2
    _cleanup_activity()


def test_slack_truncation_keeps_link_and_never_cuts_an_entity(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_URL", "https://ncm.example.test")
    s, e = report.last_period("week", NOW)
    for pad in range(0, 8):  # 切る位置をずらして、エスケープ（&amp; &lt; &gt;）の途中で切れないことを確かめる
        note = "x" * pad + "<&>" * 2000
        rep = report.Report("week", "2/23〜3/1", s, e, 1, False, [], [note])
        text = report.build_payload("slack", rep)["text"]
        assert len(text) <= report.SLACK_MAX
        assert text.endswith("\n<https://ncm.example.test/activity|アクティビティを画面で確認>")  # リンクは付け直されて残る
        body = text.rsplit("\n<https://", 1)[0]
        assert body.endswith("…")
        tail = body[:-1][-6:]
        assert not (("&" in tail) and (";" not in tail[tail.rindex("&"):])), tail  # 途中で切れた &amp; が無い
    # 収まるときは切らない
    small = report.Report("week", "2/23〜3/1", s, e, 1, True, [])
    t = report.build_payload("slack", small)["text"]
    assert "…" not in t and t.endswith("アクティビティを画面で確認>")


def test_preview_api_has_a_short_interval_per_user(ctx, world, firsts, sent):
    c = ctx["c"]
    u = ctx["user"]("viewer")
    other = ctx["user"]("viewer")
    r1 = c.get("/api/notifications/report-preview", headers=u["h"])
    assert r1.status_code == 200
    r2 = c.get("/api/notifications/report-preview", headers=u["h"])
    assert r2.status_code == 429 and int(r2.headers["Retry-After"]) >= 1 and "待って" in r2.json()["detail"]
    assert c.get("/api/notifications/report-preview", headers=other["h"]).status_code == 200  # 別の人は影響しない
    # 「いま送る」とは別の枠（プレビューの直後でも送れる）
    put_me(ctx, u, discord_webhook=D.format(nid(), uid()), report="off")
    assert c.post("/api/notifications/me/report", headers=u["h"]).status_code == 200


def test_model_and_migration_agree_on_report_sends(ctx):
    """モデルとマイグレーションの食い違いが無い（NOT NULL・既定値）"""
    from sqlalchemy import inspect

    async def go():
        async with AsyncSessionLocal() as db:
            def cols(sync_db):
                return {c["name"]: c for c in inspect(sync_db.connection()).get_columns("report_sends")}
            return await db.run_sync(cols)
    cols = run(go())
    assert cols["claimed_at"]["nullable"] is False
    assert "sending" in str(cols["status"]["default"]) and "1" in str(cols["attempts"]["default"])
    assert ReportSend.__table__.c.claimed_at.nullable is False
    assert ReportSend.__table__.c.status.server_default is not None and ReportSend.__table__.c.attempts.server_default is not None


def test_discord_field_length_is_judged_after_breaking_links(monkeypatch):
    """`](` が多い値は、ゼロ幅スペースを足した分だけ長くなる。無害化のあとの長さで判定し、項目の上限で黙って切れない"""
    big = "](" * 480  # 960 文字。無害化のあとは 1440 文字
    steps = []

    def facts(rep, n):
        steps.append(n)
        return [("項目", big if n > 0 else "短い")]
    monkeypatch.setattr(report, "_facts", facts)
    dc = report.build_payload("discord", fake_report())
    assert steps[0] == report.TOP_STEPS[0] and steps[-1] == 0  # 上位の件数を減らして収めた
    assert dc["embeds"][0]["fields"][0]["value"] == "短い"
