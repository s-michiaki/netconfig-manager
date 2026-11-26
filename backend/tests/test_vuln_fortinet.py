"""脆弱性（J-2）: Fortinet の勧告の取得・保存・照合、過去の勧告の取り込み、通知、ダッシュボード・定期レポートのテスト

外部へは実際につながない（vuln_fetch._open を差し替え。tests/fixtures/vuln/fortinet_* は作り物の ID で、形だけ本物に合わせた見本）。
作ったデータはテストの終わりに消す（テスト用の DB はファイル間で共有）。数えるのは自分の作った機器・勧告だけ
"""
import asyncio
import json
import urllib.error
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from test_vulns import FakeResp, Net

from app import worker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.timeutil import utcnow
from app.main import app
from app.models.audit import AuditLog
from app.models.device import Device, DeviceGroup
from app.models.notification import NotificationSetting
from app.models.user import User
from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
from app.services import notify, report, vuln_service
from app.services import vuln_fetch as vf

FIX = Path(__file__).parent / "fixtures" / "vuln"
PW = "password-1234"
CS = "https://filestore.fortinet.com/fortiguard/psirt/csaf_{}_{}.json"
URL101 = CS.format("out-of-bound-write-in-example-daemon", "fg-ir-99-101")
URL102 = CS.format("improper-certificate-validation-in-example-vpn", "fg-ir-99-102")
URL103 = CS.format("example-proxy-issue", "fg-ir-99-103")
URL104 = CS.format("example-library-notice", "fg-ir-99-104")
ETAG_RSS = '"rss-etag-1"'


def fb(name: str) -> bytes:
    return (FIX / name).read_bytes()


def run(coro):
    return asyncio.run(coro)


def resp(body: bytes, etag: str | None = None):
    def f(req):
        return FakeResp(body, req.full_url, {"ETag": etag} if etag else {})
    return f


def not_modified_if(etag: str, body: bytes):
    """If-None-Match が etag なら 304、違えば 200（本文と ETag）"""
    def f(req):
        if req.get_header("If-none-match") == etag:
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {"ETag": etag}, None)
        return FakeResp(body, req.full_url, {"ETag": etag})
    return f


def fortinet_routes() -> dict:
    return {vf.URL_FORTINET_RSS: not_modified_if(ETAG_RSS, fb("fortinet_rss.xml")),
            URL101: not_modified_if('"c101"', fb("fortinet_csaf_101.json")),
            URL102: not_modified_if('"c102"', fb("fortinet_csaf_102.json")),
            URL103: not_modified_if('"c103"', fb("fortinet_csaf_103.json")),
            URL104: not_modified_if('"c104"', fb("fortinet_csaf_104.json")),
            vf.URL_KEV: json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-1102", "dueDate": "2099-12-01"}]}).encode()}


@pytest.fixture(autouse=True)
def net(monkeypatch):
    n = Net()
    monkeypatch.setattr(vf, "_open", n)
    return n


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """要求の間隔のための待ち（実際には待たない。待った秒数を記録する）"""
    got: list[float] = []
    monkeypatch.setattr(vf, "_sleep", got.append)
    return got


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "VULN_ENABLED", True)
    monkeypatch.setattr(settings, "VULN_SOURCES", "fortinet,kev")


@pytest.fixture
def queued(monkeypatch):
    """照合の commit のあとに投入される通知（Celery へは投入しない）"""
    got: list = []
    monkeypatch.setattr(worker.send_vuln_notification, "delay", lambda items: got.append(items))
    return got


async def _cleanup():
    async with AsyncSessionLocal() as db:
        await db.execute(delete(VulnMatch))
        await db.execute(delete(VulnAdvisory))
        await db.execute(delete(EolDate))
        await db.execute(delete(VulnSource))
        await db.execute(delete(Device).where(Device.name.like("vfn-%")))
        await db.execute(delete(DeviceGroup).where(DeviceGroup.name.like("vfn-%")))
        await db.execute(delete(AuditLog).where(AuditLog.action.like("vuln.%")))
        ids = list((await db.execute(select(User.id).where(User.username.like("vfn-%")))).scalars())
        if ids:
            await db.execute(delete(NotificationSetting).where(NotificationSetting.owner_id.in_(ids)))
            await db.execute(delete(User).where(User.id.in_(ids)))
        await db.commit()


@pytest.fixture(scope="module", autouse=True)
def _schema():
    from app.core import migrate

    migrate.run_migrations()


@pytest.fixture(autouse=True)
def clean(_schema):
    run(_cleanup())
    yield
    run(_cleanup())


async def _mk(name: str, version: str | None, model: str | None = "FortiGate-60F", platform: str = "fortinet",
              group_id: str | None = None) -> str:
    async with AsyncSessionLocal() as db:
        d = Device(name=f"vfn-{name}", hostname="192.0.2.10", platform=platform, username="admin", password="x",
                   os_version=version, model=model, group_id=group_id)
        db.add(d)
        await db.commit()
        return d.id


def mk(name, version, model="FortiGate-60F", **kw):
    return run(_mk(name, version, model, **kw))


async def _fetch(sources=("kev", "fortinet"), now=None):
    async with AsyncSessionLocal() as db:
        return await vuln_service.run_fetch(db, list(sources), now=now)


async def _matches(device_id: str) -> dict[str, VulnMatch]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(VulnMatch, VulnAdvisory.ext_id).join(VulnAdvisory, VulnAdvisory.id == VulnMatch.advisory_id)
                                 .where(VulnMatch.device_id == device_id))).all()
        return {ext: m for m, ext in rows}


async def _advisories() -> dict[str, VulnAdvisory]:
    async with AsyncSessionLocal() as db:
        return {a.ext_id: a for a in (await db.execute(select(VulnAdvisory).where(VulnAdvisory.source == "fortinet"))).scalars()}


async def _source(name: str) -> VulnSource | None:
    async with AsyncSessionLocal() as db:
        return await db.get(VulnSource, name)


# ================================================================ RSS・XML の解析


def test_parse_rss_fixture_and_skips_items_outside_allowlist():
    items, skipped = vf.parse_fortinet_rss(fb("fortinet_rss.xml"))
    assert [i["ext_id"] for i in items] == ["FG-IR-99-104", "FG-IR-99-101", "FG-IR-99-102", "FG-IR-99-103"]
    assert items[1]["csaf_url"] == URL101 and items[1]["published"] == datetime(2099, 11, 10, 7, 0)
    assert skipped == 5  # 許可リスト外のホスト・パスの形・ID の不一致・CSAF の URL なし・ID の形
    assert all(vf.fortinet_csaf_url(i["csaf_url"], i["ext_id"]) for i in items)


@pytest.mark.parametrize("url,ok", [
    (URL101, True),
    ("http://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-99-101.json", False),
    ("https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-99-101.json?x=1", False),
    ("https://filestore.fortinet.com:8443/fortiguard/psirt/csaf_x_fg-ir-99-101.json", False),
    ("https://www.fortiguard.com/fortiguard/psirt/csaf_x_fg-ir-99-101.json", False),
    ("https://filestore.fortinet.com/fortiguard/psirt/csaf_../x_fg-ir-99-101.json", False),
    ("https://filestore.fortinet.com/fortiguard/psirt/csaf_X_fg-ir-99-101.json", False),
    ("https://user@filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-99-101.json", False),
    ("https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-99-102.json", False),
])
def test_csaf_url_shape(url, ok):
    assert bool(vf.fortinet_csaf_url(url, "FG-IR-99-101")) is ok


@pytest.mark.parametrize("body,needle", [
    (b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "x">]><rss><channel/></rss>', "DTD"),
    (b'<!DOCTYPE rss SYSTEM "http://example.test/x.dtd"><rss/>', "DTD"),
    (b"<rss><!ENTITY a 'x'><channel/></rss>", "DTD"),
    (b"<rss><!doctype x><channel/></rss>", "DTD"),
    ('<?xml version="1.0" encoding="UTF-16"?><rss/>'.encode("utf-16"), "UTF-8"),
    (b'<?xml version="1.0" encoding="ISO-8859-1"?><rss/>', "UTF-8"),
    (b"\xff\xfe<rss/>", "UTF-8"),
    (b"<rss><channel>", "XML"),
    (b"not xml", "XML"),
    (b"", "XML"),
    (b"<a>" * 40 + b"</a>" * 40, "深すぎる"),
    (b"<rss>" + b"<i/>" * (vf.MAX_XML_ELEMENTS + 1) + b"</rss>", "多すぎ"),
    (b"<rss>" + b"x" * (vf.MAX_XML_BYTES + 1) + b"</rss>", "大きすぎ"),
])
def test_xml_rejects_dtd_and_broken_and_huge(body, needle):
    with pytest.raises(vf.FetchError) as e:
        vf.parse_xml(body)
    assert needle in str(e.value)


def test_xml_text_limit_and_rss_shape(monkeypatch):
    monkeypatch.setattr(vf, "MAX_XML_TEXT", 100)
    with pytest.raises(vf.FetchError, match="文字が多すぎ"):
        vf.parse_xml(b"<rss>" + b"x" * 200 + b"</rss>")
    with pytest.raises(vf.FetchError, match="形が想定と違います"):
        vf.parse_fortinet_rss(b"<feed><entry/></feed>")
    with pytest.raises(vf.FetchError, match="1 件も"):
        vf.parse_fortinet_rss(b"<rss><channel><title>x</title></channel></rss>")


def test_cvrf_title_and_missing_id():
    assert vf.parse_cvrf_title(fb("fortinet_cvrf_101.xml"), "FG-IR-99-101") == "Out-of-bound write in example daemon"
    assert vf.parse_cvrf_title(fb("fortinet_cvrf_none.xml"), "FG-IR-99-999") is None
    with pytest.raises(vf.FetchError, match="違います"):
        vf.parse_cvrf_title(fb("fortinet_cvrf_101.xml"), "FG-IR-99-102")
    assert vf.csaf_url_from_title("FG-IR-99-101", "Out-of-bound write in example daemon") == URL101
    assert vf.csaf_url_from_title("FG-IR-99-101", "[FortiOS] Heap  overflow (SSL-VPN)") == CS.format("fortios-heap-overflow-ssl-vpn",
                                                                                                   "fg-ir-99-101")
    assert vf.csaf_url_from_title("FG-IR-99-101", "!!!") is None and vf.csaf_url_from_title("bad", "x") is None


# ================================================================ 取得の枠組み: 条件つき GET・304・間隔


def test_conditional_get_sends_validators_and_handles_304(net):
    net.routes[URL101] = not_modified_if('"v1"', b"{}")
    got = vf.fetch(URL101)
    assert got.status == 200 and got.etag == '"v1"' and net.calls[-1].get_header("If-none-match") is None
    got = vf.fetch(URL101, etag='"v1"', last_modified="Tue, 10 Nov 2099 00:00:00 GMT")
    assert got.status == 304 and got.body == b"" and got.etag == '"v1"'
    req = net.calls[-1]
    assert req.get_header("If-none-match") == '"v1"' and req.get_header("If-modified-since") == "Tue, 10 Nov 2099 00:00:00 GMT"
    # 形の違う条件は送らない（ヘッダーへの改行の混入を防ぐ）。条件を送っていない 304 は失敗
    net.routes[URL101] = lambda req: (_ for _ in ()).throw(urllib.error.HTTPError(req.full_url, 304, "x", {}, None))
    with pytest.raises(vf.FetchError, match="304"):
        vf.fetch(URL101, etag='"a"\r\nX-Evil: 1', last_modified="yesterday")
    assert net.calls[-1].get_header("If-none-match") is None and net.calls[-1].get_header("If-modified-since") is None
    # 応答の ETag も形を確かめたものだけを覚える
    net.routes[URL101] = lambda req: FakeResp(b"{}", req.full_url, {"ETag": "no-quotes", "Last-Modified": "garbage"})
    got = vf.fetch(URL101)
    assert got.etag is None and got.last_modified is None


def test_fetch_size_limit_per_call(net):
    net.routes[URL101] = b"x" * 2000
    with pytest.raises(vf.FetchError, match="大きすぎ"):
        vf.fetch(URL101, max_bytes=1000)


def test_pacer_waits_between_requests(sleeps):
    p = vf.Pacer(2.0)
    p.wait()
    p.wait()
    p.wait()
    assert len(sleeps) == 2 and all(1.9 < s <= 2.0 for s in sleeps)


# ================================================================ 取得・保存・照合


def _device_set():
    return {"fg1": mk("fg1", "7.4.2 build2000"), "fg2": mk("fg2", "7.0.5", "FortiGate-100F"),
            "fg3": mk("fg3", "7.4.1", "FortiGate-7121F"), "fg4": mk("fg4", "v7.2.14,build1700,251001 (GA.M)"),
            "fg5": mk("fg5", "7.4.2", None), "pa": mk("pa", "10.2.3", "PA-440", platform="paloalto_panos")}


def test_fetch_stores_matches_and_sends_no_device_info(net, enabled, sleeps, queued):
    net.routes.update(fortinet_routes())
    devs = _device_set()
    res = run(_fetch())
    # 101・102（103 は FortiProxy だけ、104 は製品の記載が無い告知。どちらも照合に使わない）
    assert res["sources"]["fortinet"]["ok"] and res["sources"]["fortinet"]["count"] == 2
    advs = run(_advisories())
    assert set(advs) == {"FG-IR-99-101", "FG-IR-99-102", "FG-IR-99-103", "FG-IR-99-104"}
    assert advs["FG-IR-99-103"].products == [] and advs["FG-IR-99-101"].products == ["fortinet"]
    assert advs["FG-IR-99-104"].products == [] and advs["FG-IR-99-104"].affected[0]["notice"] is True
    a = advs["FG-IR-99-101"]
    assert (a.severity, a.cvss, a.cve_ids, a.url) == ("critical", 9.6, ["CVE-2099-1101"], "https://www.fortiguard.com/psirt/FG-IR-99-101")
    assert a.doc_url == URL101 and a.etag == '"c101"' and a.checked_at is not None
    assert advs["FG-IR-99-102"].kev and advs["FG-IR-99-102"].kev_due == date(2099, 12, 1)  # KEV と合流
    m1 = run(_matches(devs["fg1"]))
    assert {k: (m.confidence, m.state) for k, m in m1.items()} == {"FG-IR-99-101": ("confirmed", "open"),
                                                                   "FG-IR-99-102": ("confirmed", "open")}
    m2 = run(_matches(devs["fg2"]))  # 7.0 はどちらの勧告にも載っていない: 候補（非該当にしない）
    assert {k: (m.confidence, m.reason) for k, m in m2.items()} == {"FG-IR-99-101": ("candidate", "not_listed"),
                                                                    "FG-IR-99-102": ("candidate", "not_listed")}
    assert run(_matches(devs["fg3"])) == {}  # 6000 / 7000 系は判定しない
    assert run(_matches(devs["fg4"])) == {}  # 101 は修正版以上・102 は未公開の修正版以上（判定できない）
    m5 = run(_matches(devs["fg5"]))  # モデルが分からない: 該当は候補
    assert {k: (m.confidence, m.reason) for k, m in m5.items()} == {"FG-IR-99-101": ("candidate", "model_unknown"),
                                                                    "FG-IR-99-102": ("candidate", "model_unknown")}
    assert run(_matches(devs["pa"])) == {}  # Fortinet の勧告は PAN-OS の機器に当てない
    # 機器の情報（名前・IP・版・モデル）は URL・ヘッダーに入らない
    for req in net.calls:
        text = req.full_url + json.dumps(dict(req.header_items()))
        for leak in ("vfn-", "192.0.2.10", "7.4.2", "7.0.5", "FortiGate-60F", "build2000"):
            assert leak not in text, (leak, req.full_url)
        assert req.get_header("User-agent").startswith("netconfig-manager")
    rss = next(r for r in net.calls if r.full_url == vf.URL_FORTINET_RSS)
    assert "xml" in rss.get_header("Accept")
    assert len(sleeps) == len([r for r in net.calls if "fortinet" in r.full_url]) - 1  # Fortinet への要求のあいだは毎回あける
    src = run(_source("fortinet"))
    assert src.etag == ETAG_RSS and src.skipped == 5  # RSS の使わない項目 5 件（告知は読めない文書に数えない）


def test_unknown_lists_6k7k_and_unreadable_and_api(net, enabled, queued):
    net.routes.update(fortinet_routes())
    devs = _device_set()
    run(_fetch())
    with TestClient(app) as c:
        h = {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]}
        un = c.get("/api/vulns/unknown", headers=h).json()
        mine = {x["device_id"]: x for x in un["items"] if x["name"].startswith("vfn-")}
        assert mine[devs["fg3"]]["reason"] == "fortios_6k7k" and "6000" in mine[devs["fg3"]]["reason_label"]
        ru = {x["device_id"]: x for x in un["range_unreadable"] if x["name"].startswith("vfn-")}
        # 製品の記載が無い告知（104）は、機器ごとの「判定できない」に数えない（M5）
        assert devs["fg1"] not in ru
        assert set(ru[devs["fg4"]]["advisories"]) == {"FG-IR-99-102"}
        s = c.get("/api/vulns/summary", headers=h).json()
        assert s["notices"]["count"] == 1 and s["notices"]["items"][0]["ext_id"] == "FG-IR-99-104"
        assert s["notices"]["items"][0]["url"] == "https://www.fortiguard.com/psirt/FG-IR-99-104"
        assert all("FG-IR-99-104" not in json.dumps(x) for x in un["range_unreadable"])
        cov = {x["source"]: x for x in s["coverage"]}
        assert cov["fortinet"]["count"] == 2 and cov["fortinet"]["documents"] == 4
        assert cov["fortinet"]["oldest"].startswith("2099-01-10") and cov["fortinet"]["pending"] == 0
        assert s["counts"]["candidate_not_listed"] >= 2
        rows = c.get("/api/vulns/matches", params={"confidence": "candidate", "reason": "not_listed"}, headers=h).json()["items"]
        assert {r["device_name"] for r in rows if r["device_name"].startswith("vfn-")} == {"vfn-fg2"}
        assert all(r["candidate_code"] == "not_listed" and "載っていません" in r["candidate_reason"] for r in rows)
        hidden = c.get("/api/vulns/matches", params={"hide_reason": "not_listed"}, headers=h).json()["items"]
        assert not [r for r in hidden if r["device_name"] == "vfn-fg2"]
        assert {r["device_name"] for r in hidden if r["device_name"].startswith("vfn-")} == {"vfn-fg1", "vfn-fg5"}
        assert c.get("/api/vulns/matches", params={"reason": "bogus"}, headers=h).status_code == 422
        adv_id = rows[0]["advisory"]["id"]
        detail = c.get(f"/api/vulns/advisories/{adv_id}", headers=h).json()
        assert detail["source"] == "fortinet" and any(r.get("fix") for r in detail["affected"])


def test_second_run_uses_304_and_rechecks_only_when_due(net, enabled, queued):
    net.routes.update(fortinet_routes())
    dev = mk("fg1", "7.4.2")
    t0 = utcnow()
    run(_fetch(now=t0))
    n0 = len(net.calls)
    run(_fetch(now=t0 + timedelta(hours=1)))
    later = net.calls[n0:]
    assert [r.full_url for r in later if "fortinet" in r.full_url] == [vf.URL_FORTINET_RSS]  # RSS は 304・文書は確かめる時期でない
    assert later[-1].get_header("If-none-match") == ETAG_RSS
    # 8 日後: FortiOS の勧告（101・102）と告知（104。公開から 90 日以内は 7 日ごと）を条件つきで確かめ直す（304）。
    # FortiOS 以外の製品の勧告（103）は 14 日ごと
    n1 = len(net.calls)
    run(_fetch(now=t0 + timedelta(days=8)))
    urls = [r.full_url for r in net.calls[n1:] if r.full_url != vf.URL_KEV]
    assert set(urls) == {vf.URL_FORTINET_RSS, URL101, URL102, URL104}
    assert all(r.get_header("If-none-match") for r in net.calls[n1:] if r.full_url in (URL101, URL102))
    # 改訂: 101 の範囲が変わった（7.4 の修正版が 7.4.2 に）→ 作り直して照合（該当 → 解消）
    doc = json.loads(fb("fortinet_csaf_101.json"))
    st = doc["vulnerabilities"][0]["product_status"]
    st["known_affected"][0] = "FortiOS >=7.4.0|<=7.4.1"
    st["known_not_affected"][0] = "FortiOS-7.4.2"
    doc["document"]["tracking"]["current_release_date"] = "2099-02-01T00:00:00"
    net.routes[URL101] = not_modified_if('"c101-rev2"', json.dumps(doc).encode())
    assert run(_matches(dev))["FG-IR-99-101"].state == "open"
    run(_fetch(now=t0 + timedelta(days=16)))
    a = run(_advisories())["FG-IR-99-101"]
    assert a.etag == '"c101-rev2"' and a.modified_at == datetime(2099, 2, 1)
    assert run(_matches(dev))["FG-IR-99-101"].state == "fixed"


def test_cap_and_leftover_pending(net, enabled, monkeypatch, queued):
    monkeypatch.setattr(vuln_service, "FORTINET_MAX_DOCS", 2)
    net.routes.update(fortinet_routes())
    run(_fetch(["fortinet"]))
    assert len([r for r in net.calls if "/psirt/csaf_" in r.full_url]) == 2
    st = json.loads(run(_source("fortinet")).cursor)
    assert len(st["pending"]) == 2  # 残りは次回
    assert set(run(_advisories())) == {"FG-IR-99-104", "FG-IR-99-102"}  # 新しい順（RSS の公開日。同じ日は ID の大きい順）
    n = len(net.calls)
    run(_fetch(["fortinet"], now=utcnow() + timedelta(hours=1)))
    assert {r.full_url for r in net.calls[n:] if "/psirt/csaf_" in r.full_url} == {URL101, URL103}
    assert json.loads(run(_source("fortinet")).cursor)["pending"] == {}


def test_time_budget_stops_and_keeps_rest(net, enabled, monkeypatch, queued):
    monkeypatch.setattr(vuln_service, "FORTINET_BUDGET_SEC", vf.TOTAL_TIMEOUT + vf.FORTINET_INTERVAL_SEC - 1)
    net.routes.update(fortinet_routes())
    res = run(_fetch(["fortinet"]))
    assert res["sources"]["fortinet"]["ok"]
    assert not [r for r in net.calls if "/psirt/csaf_" in r.full_url]  # 文書は 1 件も取らずに次回へ
    assert len(json.loads(run(_source("fortinet")).cursor)["pending"]) == 4


def test_lock_timeout_covers_fortinet_budget():
    assert worker.VULN_FETCH_LOCK_TIMEOUT > vuln_service.MAX_FETCH_SECONDS
    assert vuln_service.MAX_FETCH_SECONDS >= vuln_service.FORTINET_BUDGET_SEC + vf.TOTAL_TIMEOUT


def test_document_failures_are_recorded_and_retried(net, enabled, queued):
    net.routes.update(fortinet_routes())
    net.routes[URL102] = urllib.error.HTTPError(URL102, 500, "x", {}, None)
    net.routes[URL103] = urllib.error.HTTPError(URL103, 404, "x", {}, None)
    res = run(_fetch(["fortinet"]))
    f = res["sources"]["fortinet"]
    assert not f["ok"] and "FG-IR-99-102" in f["error"] and "遮断" in f["error"] and "filestore" not in f["error"]
    advs = run(_advisories())
    assert set(advs) == {"FG-IR-99-101", "FG-IR-99-104"}  # 取れた分は保存した
    pend = json.loads(run(_source("fortinet")).cursor)["pending"]
    assert set(pend) == {"FG-IR-99-102"}  # 失敗はやり直す。404 は捨てる（RSS にまた出れば足す）
    assert run(_source("fortinet")).last_error and run(_source("fortinet")).last_ok_at is None


def test_rss_failure_and_broken_document(net, enabled, queued):
    net.routes[vf.URL_FORTINET_RSS] = b'<!DOCTYPE x [<!ENTITY a "b">]><rss/>'
    res = run(_fetch(["fortinet"]))
    assert not res["sources"]["fortinet"]["ok"] and "DTD" in res["sources"]["fortinet"]["error"]
    net.routes.update(fortinet_routes())
    net.routes[URL101] = resp(b"{not json")
    dev = mk("fg1", "7.4.2")
    run(_fetch(["fortinet"], now=utcnow() + timedelta(hours=4)))
    a = run(_advisories())["FG-IR-99-101"]
    assert a.products == ["fortinet"] and a.affected[0]["broken"] and a.etag is None
    assert "FG-IR-99-101" not in run(_matches(dev))  # 読めない文書は該当にしない（判定できない）


def test_stale_when_document_breaks_after_match(net, enabled, queued):
    net.routes.update(fortinet_routes())
    dev = mk("fg1", "7.4.2")
    t0 = utcnow()
    run(_fetch(["fortinet"], now=t0))
    assert run(_matches(dev))["FG-IR-99-101"].state == "open"
    net.routes[URL101] = resp(b'{"document": {"tracking": {"id": "FG-IR-99-777"}}}', '"broken"')
    run(_fetch(["fortinet"], now=t0 + timedelta(days=8)))
    m = run(_matches(dev))["FG-IR-99-101"]
    assert m.state == "open" and m.stale  # 前回の該当は古い範囲によるもの: 一覧から外して「判定できない機器」に


def test_fortinet_not_in_sources_is_not_fetched(net, monkeypatch, queued):
    monkeypatch.setattr(settings, "VULN_ENABLED", True)
    monkeypatch.setattr(settings, "VULN_SOURCES", "kev")
    net.routes.update(fortinet_routes())
    run(_fetch(vuln_service.active_sources()))
    assert vf.URL_FORTINET_RSS not in net.urls
    assert "fortinet" in default_sources()


def default_sources() -> list[str]:
    """既定の一覧（.env が無いとき）"""
    from app.core.config import Settings
    return [x.strip() for x in Settings.model_fields["VULN_SOURCES"].default.split(",")]


def test_default_sources_exclude_nvd():
    assert default_sources() == ["paloalto", "fortinet", "kev", "eol"]


# ================================================================ 過去の勧告の取り込み


def test_import_by_id(net, enabled, queued):
    net.routes.update(fortinet_routes())
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-99-101")] = fb("fortinet_cvrf_101.xml")
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-99-999")] = fb("fortinet_cvrf_none.xml")
    cv_old = fb("fortinet_cvrf_101.xml").replace(b"FG-IR-99-101", b"FG-IR-18-384").replace(b"Out-of-bound", b"Old")
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-18-384")] = cv_old
    net.routes[CS.format("old-write-in-example-daemon", "fg-ir-18-384")] = urllib.error.HTTPError("u", 404, "x", {}, None)
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-99-500")] = urllib.error.HTTPError("u", 500, "x", {}, None)
    net.routes[vf.FORTINET_PAGE.format(ext_id="FG-IR-18-384")] = b"<html>no csaf link</html>"
    # 題名が後から変わった勧告（本物の FG-IR-24-535 の形）: 題名から作った URL は 404、勧告のページの csaf_url で取れる（M3）
    cv_renamed = fb("fortinet_cvrf_101.xml").replace(b"FG-IR-99-101", b"FG-IR-99-535").replace(b"Out-of-bound write in example daemon",
                                                                                                b"Example bypass and more")
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-99-535")] = cv_renamed
    net.routes[CS.format("example-bypass-and-more", "fg-ir-99-535")] = urllib.error.HTTPError("u", 404, "x", {}, None)
    real535 = CS.format("example-bypass", "fg-ir-99-535")
    net.routes[vf.FORTINET_PAGE.format(ext_id="FG-IR-99-535")] = (
        b'<html><a href="/psirt/csaf/FG-IR-99-535?csaf_url=' + real535.encode() + b'">CSAF</a></html>')
    net.routes[real535] = fb("fortinet_csaf_101.json").replace(b"FG-IR-99-101", b"FG-IR-99-535")
    dev = mk("fg1", "7.4.2")

    async def go(ids):
        async with AsyncSessionLocal() as db:
            return await vuln_service.import_fortinet(db, ids)
    out = {r["ext_id"]: r for r in run(go(["FG-IR-99-101", "FG-IR-99-999", "FG-IR-18-384", "FG-IR-99-500", "FG-IR-99-535"]))}
    assert out["FG-IR-99-535"]["result"] == "fortios"
    assert run(_advisories())["FG-IR-99-535"].doc_url == real535
    page_req = next(r for r in net.calls if r.full_url == vf.FORTINET_PAGE.format(ext_id="FG-IR-99-535"))
    assert page_req.get_header("Accept") == "text/html" and "?" not in page_req.full_url
    assert out["FG-IR-99-101"]["result"] == "fortios" and out["FG-IR-99-101"]["ok"]
    assert out["FG-IR-99-999"]["result"] == "not_found" and "見つかりません" in out["FG-IR-99-999"]["message"]
    assert out["FG-IR-18-384"]["result"] == "no_csaf" and "2021 年以前" in out["FG-IR-18-384"]["message"]
    assert [r.full_url for r in net.calls].count(vf.FORTINET_PAGE.format(ext_id="FG-IR-18-384")) == 1  # ページは 1 回だけ
    assert out["FG-IR-99-500"]["result"] == "failed" and "HTTP 500" in out["FG-IR-99-500"]["message"]
    assert run(_matches(dev))["FG-IR-99-101"].confidence == "confirmed"  # 取り込みのあとに照合する
    # 取り込み済みの勧告は、覚えている文書の URL を条件つきで確かめる（CVRF は引かない）
    n = len(net.calls)
    again = run(go(["FG-IR-99-101"]))
    assert again[0]["result"] == "unchanged" and [r.full_url for r in net.calls[n:]] == [URL101]


def test_import_api_permissions_validation_and_task(net, enabled, monkeypatch):
    sent = []
    monkeypatch.setattr(worker.import_fortinet_advisories, "delay",
                        lambda ids, actor: (sent.append((ids, actor)), type("T", (), {"id": "task-1"})())[1])
    monkeypatch.setattr(report, "take_slot", lambda *a: _zero())
    with TestClient(app) as c:
        admin = {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]}
        uname = f"vfn-op-{uuid.uuid4().hex[:6]}"
        c.post("/api/users/", json={"username": uname, "password": PW, "role": "operator"}, headers=admin)
        op = {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": uname, "password": PW}).json()["access_token"]}
        assert c.post("/api/vulns/fortinet/import", json={"ids": "FG-IR-24-015"}, headers=op).status_code == 403
        assert c.get("/api/vulns/fortinet/import", headers=op).status_code == 403
        for bad in ("", "FG-IR-24-15", "FG-IR-24-015x", "CVE-2024-0001", "FG-IR-24-015; rm -rf /", "fg/ir/24/015"):
            r = c.post("/api/vulns/fortinet/import", json={"ids": bad}, headers=admin)
            assert r.status_code == 422, (bad, r.text)
        many = ",".join(f"FG-IR-24-{i:03d}" for i in range(vuln_service.FORTINET_IMPORT_MAX + 1))
        assert c.post("/api/vulns/fortinet/import", json={"ids": many}, headers=admin).status_code == 422
        r = c.post("/api/vulns/fortinet/import", json={"ids": "fg-ir-24-015\nFG-IR-22-398, FG-IR-24-015、FG-IR-23-097"}, headers=admin)
        assert r.status_code == 202, r.text
        assert sent == [(["FG-IR-24-015", "FG-IR-22-398", "FG-IR-23-097"], "admin")]
        st = c.get("/api/vulns/fortinet/import", headers=admin).json()
        assert st["state"]["status"] == "queued" and st["max"] == vuln_service.FORTINET_IMPORT_MAX
        monkeypatch.setattr(settings, "VULN_SOURCES", "kev")
        assert c.post("/api/vulns/fortinet/import", json={"ids": "FG-IR-24-015"}, headers=admin).status_code == 409
        monkeypatch.setattr(settings, "VULN_ENABLED", False)
        assert c.get("/api/vulns/fortinet/import", headers=admin).status_code == 404


async def _zero():
    return 0


def test_import_task_records_results_and_respects_lock(net, enabled, monkeypatch, queued):
    net.routes.update(fortinet_routes())
    net.routes[vf.URL_FORTINET_CVRF.format(ext_id="FG-IR-99-101")] = fb("fortinet_cvrf_101.xml")
    r = fakeredis.FakeRedis()
    monkeypatch.setattr(worker, "_redis", lambda: r)
    assert worker.import_fortinet_advisories.apply(args=(["FG-IR-99-101"], "admin")).get() == {"results": 1}
    st = run(_state())
    assert st["status"] == "done" and st["results"][0]["result"] == "fortios" and st["by"] == "admin"
    lock = r.lock("netconfig:vuln-fetch", timeout=60)
    lock.acquire()
    assert worker.import_fortinet_advisories.apply(args=(["FG-IR-99-101"], "admin")).get() == {"busy": True}
    assert run(_state())["status"] == "busy"


async def _state():
    async with AsyncSessionLocal() as db:
        return await vuln_service.get_import_state(db)


# ================================================================ 通知: 新しく該当


async def _setting(user_name: str, *, group_ids: list[str] | None = None, on_vuln: bool = True) -> str:
    async with AsyncSessionLocal() as db:
        u = User(username=user_name, hashed_password="x", role="viewer", is_active=True)
        db.add(u)
        await db.flush()
        s = NotificationSetting(owner_type="user", owner_id=u.id, mode="custom", on_change=False, on_system=False,
                                on_inventory=False, on_ping=False, on_vuln=on_vuln,
                                discord_webhook="https://discord.com/api/webhooks/1/vfn-tok",
                                slack_webhook="https://hooks.slack.com/services/T0/B0/vfn",
                                all_devices=group_ids is None, device_group_ids=json.dumps(group_ids or []))
        db.add(s)
        await db.commit()
        return s.id


async def _group(name: str) -> str:
    async with AsyncSessionLocal() as db:
        g = DeviceGroup(name=f"vfn-{name}")
        db.add(g)
        await db.commit()
        return g.id


@pytest.fixture
def webhooks(monkeypatch):
    calls: list = []
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: calls.append((kind, url, payload)))
    return calls


def _send_queued(queued) -> None:
    async def go():
        async with AsyncSessionLocal() as db:
            for items in queued:
                await notify.notify_vulns(db, items)
    run(go())


def test_new_matches_are_notified_once_and_batched(net, enabled, queued, webhooks):
    run(_setting(f"vfn-n-{uuid.uuid4().hex[:6]}"))
    net.routes.update(fortinet_routes())
    d1 = mk("fg1", "7.4.2")
    d2 = mk("fg1b", "7.4.1")
    mk("fg2", "7.0.5")  # 候補だけ: 通知しない
    t0 = utcnow()
    run(_fetch(now=t0))
    assert len(queued) == 1  # 1 回の取得・照合ぶんで 1 件
    items = {d: [a[0] for a in advs] for d, advs in queued[0]}
    assert items == {d1: ["FG-IR-99-102", "FG-IR-99-101"], d2: ["FG-IR-99-102", "FG-IR-99-101"]}  # 悪用確認済みが先
    _send_queued(queued)
    assert {k for k, _, _ in webhooks} == {"discord", "slack"}  # 通知先ごとに 1 通（2 台をまとめる）
    disc = next(p for k, _, p in webhooks if k == "discord")
    assert "2 台" in disc["embeds"][0]["title"] and "FG-IR-99-101" in disc["embeds"][0]["description"]
    assert disc["allowed_mentions"] == {"parse": []}
    # 同じ該当は繰り返し通知しない（次の照合・次の取得）
    queued.clear()
    run(_fetch(now=t0 + timedelta(days=1)))
    assert queued == []
    # 解消してまた該当しても、stale から戻っても通知しない
    async def set_ver(d, v):
        async with AsyncSessionLocal() as db:
            (await db.get(Device, d)).os_version = v
            await db.commit()
            await vuln_service.reconcile(db, device_ids=[d])
            await db.commit()
    run(set_ver(d1, "7.4.9"))
    assert run(_matches(d1))["FG-IR-99-101"].state == "fixed"
    run(set_ver(d1, "7.4.2"))
    assert run(_matches(d1))["FG-IR-99-101"].state == "open"
    assert queued == []


def test_candidates_medium_ack_and_scope_are_not_notified(net, enabled, queued, webhooks):
    g_in, g_out = run(_group("in")), run(_group("out"))
    run(_setting(f"vfn-s-{uuid.uuid4().hex[:6]}", group_ids=[g_in]))
    routes = fortinet_routes()
    routes[vf.URL_KEV] = json.dumps({"vulnerabilities": [{"cveID": "CVE-2000-0001"}]}).encode()  # 102 は KEV でない（中）
    net.routes.update(routes)
    d_in = mk("in", "7.4.2", group_id=g_in)
    mk("out", "7.4.2", group_id=g_out)
    mk("nomodel", "7.4.2", None, group_id=g_in)  # 候補（モデル不明）
    run(_fetch())
    assert len(queued) == 1
    assert {d: [a[0] for a in advs] for d, advs in queued[0]}.get(d_in) == ["FG-IR-99-101"]  # 中（102）は通知しない
    assert all(advs for _, advs in queued[0])
    _send_queued(queued)
    disc = [p for k, _, p in webhooks if k == "discord"]
    assert len(disc) == 1 and "vfn-in" in disc[0]["embeds"][0]["title"]  # 範囲外のグループの機器は届かない
    text = json.dumps(disc, ensure_ascii=False)
    assert "vfn-out" not in text and "vfn-nomodel" not in text


def test_no_notice_marks_when_nobody_wants_and_migration_backfill(net, enabled, queued):
    net.routes.update(fortinet_routes())
    d = mk("fg1", "7.4.2")
    run(_fetch())
    assert queued == []  # 通知する設定が無い
    assert all(m.notified_at is not None for m in run(_matches(d)).values())  # 印は付ける（あとで有効にしても過去の分は届かない）


def test_notification_text_is_sanitized(net, enabled, queued, webhooks):
    run(_setting(f"vfn-z-{uuid.uuid4().hex[:6]}"))
    doc = json.loads(fb("fortinet_csaf_101.json"))
    doc["document"]["title"] = "[click](https://evil.example.test) <!channel> @everyone"
    net.routes.update(fortinet_routes())
    net.routes[URL101] = resp(json.dumps(doc).encode())
    mk("[x](https://evil.example.test)<@U123>", "7.4.2")
    run(_fetch())
    _send_queued(queued)
    disc = next(p for k, _, p in webhooks if k == "discord")
    slack = next(p for k, _, p in webhooks if k == "slack")
    dtext = json.dumps(disc["embeds"], ensure_ascii=False)
    assert "](https://evil" not in dtext and disc["allowed_mentions"] == {"parse": []}
    assert "<!channel>" not in slack["text"] and "<@U123>" not in slack["text"] and "&lt;!channel&gt;" in slack["text"]


# ================================================================ 通知: サポート終了日


async def _eol(platform: str, branch: str, eol_date: date, model: str = "", kind: str = "os") -> str:
    async with AsyncSessionLocal() as db:
        e = EolDate(platform=platform, kind=kind, branch=branch, model=model, eol_date=eol_date, source="manual")
        db.add(e)
        await db.commit()
        return e.id


async def _collect(today: date) -> list[dict]:
    async with AsyncSessionLocal() as db:
        out = await vuln_service.collect_eol_notices(db, today)
        await db.commit()
        return out


def test_eol_notice_tiers_once_per_day_and_grouped(enabled):
    today = date(2099, 1, 1)
    mk("e1", "7.0.5")
    mk("e2", "7.0.12")
    mk("e3", "7.4.1")
    run(_eol("fortinet", "7.0", today + timedelta(days=90)))
    run(_eol("fortinet", "7.4", today + timedelta(days=50)))
    first = run(_collect(today))
    by = {g["branch"]: g for g in first}
    assert set(by) == {"7.0", "7.4"}
    assert by["7.0"]["tier"] == 90 and len(by["7.0"]["devices"]) == 2  # 機器ごとではなく系列ごとに 1 件
    assert by["7.4"]["tier"] == 90 and by["7.4"]["days_left"] == 50  # 初めて見た行は、いまの段階だけ（180 日前はさかのぼらない）
    assert run(_collect(today)) == []  # 1 日 1 回まで
    assert run(_collect(today + timedelta(days=1))) == []  # 同じ段階は 2 度知らせない
    at20 = run(_collect(today + timedelta(days=30)))  # 7.4 は残り 20 日（30 日前の段階）。7.0 は残り 60 日（90 日前は済み）
    assert [(g["branch"], g["tier"]) for g in at20] == [("7.4", 30)]
    at30 = run(_collect(today + timedelta(days=60)))  # 7.0 は残り 30 日・7.4 は終了から 10 日（当日の段階。終了後 30 日まで）
    assert [(g["branch"], g["tier"], g["days_left"]) for g in at30] == [("7.4", 0, -10), ("7.0", 30, 30)]
    at0 = run(_collect(today + timedelta(days=90)))
    assert [(g["branch"], g["tier"], g["days_left"]) for g in at0] == [("7.0", 0, 0)]
    assert run(_collect(today + timedelta(days=91))) == []


def test_eol_notice_skips_long_ended_and_rearms_on_date_change(enabled):
    today = date(2099, 1, 1)
    mk("e1", "7.0.5")
    eid = run(_eol("fortinet", "7.0", today - timedelta(days=100)))
    assert run(_collect(today)) == []  # 終了から時間がたった行は知らせない（印だけ）

    async def move():
        async with AsyncSessionLocal() as db:
            (await db.get(EolDate, eid)).eol_date = today + timedelta(days=170)
            await db.commit()
    run(move())
    out = run(_collect(today + timedelta(days=1)))
    assert [(g["tier"], g["days_left"]) for g in out] == [(180, 169)]  # 日付を変えたら印を付け直す


def test_eol_notice_message_counts_devices_in_scope(enabled, webhooks):
    g_in = run(_group("eol-in"))
    run(_setting(f"vfn-e-{uuid.uuid4().hex[:6]}", group_ids=[g_in]))
    mk("e1", "7.0.5", group_id=g_in)
    mk("e2", "7.0.6", group_id=g_in)
    mk("e3", "7.0.7")
    run(_eol("fortinet", "7.0", date(2099, 4, 1)))
    groups = run(_collect(date(2099, 1, 1)))

    async def go():
        async with AsyncSessionLocal() as db:
            return await notify.notify_eol(db, groups)
    assert run(go())["sent"] == 2
    disc = next(p for k, _, p in webhooks if k == "discord")["embeds"][0]
    assert "FortiOS" in disc["title"] or "Forti" in disc["title"]
    assert "あと 90 日（2099/04/01）・2 台" in disc["description"]  # 範囲外の機器は数えない


def test_worker_runs_eol_notice_after_fetch_hour(enabled, monkeypatch, webhooks):
    from zoneinfo import ZoneInfo
    run(_setting(f"vfn-w-{uuid.uuid4().hex[:6]}"))
    mk("e1", "7.0.5")
    today = vuln_service.local_today()
    run(_eol("fortinet", "7.0", today + timedelta(days=30)))
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime(2099, 1, 1, 3, 0, tzinfo=ZoneInfo(settings.TIMEZONE)))
    assert run(worker._eol_notices())["sent"] == 0  # 4 時前は何もしない
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime.now(ZoneInfo(settings.TIMEZONE)).replace(hour=12))
    assert run(worker._eol_notices())["sent"] == 2
    assert run(worker._eol_notices())["sent"] == 0  # きょうは送った


# ================================================================ ダッシュボード・定期レポート


def _admin(c):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]}


def test_dashboard_tile_only_when_enabled(net, enabled, queued, monkeypatch):
    net.routes.update(fortinet_routes())
    mk("fg1", "7.4.2")
    mk("fg2", "7.0.5")
    with TestClient(app) as c:
        h = _admin(c)
        base = c.get("/api/dashboard", headers=h).json()["vuln"]
        run(_eol("fortinet", "7.0", vuln_service.local_today() + timedelta(days=60)))
        run(_fetch())
        v = c.get("/api/dashboard", headers=h).json()["vuln"]
        assert v["open"] - base["open"] == 2 and v["kev"] - base["kev"] == 1  # fg1 の 101・102（102 が KEV）。候補は数えない
        assert v["eol_soon"] - base["eol_soon"] == 1 and v["eol_days"] == 90
        monkeypatch.setattr(settings, "VULN_ENABLED", False)
        assert c.get("/api/dashboard", headers=h).json()["vuln"] is None


def test_report_section_only_when_enabled(net, enabled, queued, monkeypatch):
    from zoneinfo import ZoneInfo
    net.routes.update(fortinet_routes())
    mk("fg1", "7.4.2")
    run(_eol("fortinet", "7.4", vuln_service.local_today() + timedelta(days=100)))
    run(_fetch())
    tz = ZoneInfo(settings.TIMEZONE)
    now = datetime.now(tz)
    start, end = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0), now + timedelta(days=1)
    s = NotificationSetting(owner_type="user", owner_id="x", mode="custom", all_devices=True)

    async def build():
        async with AsyncSessionLocal() as db:
            return await report.build_report(db, "week", start, end, s)
    r = run(build())
    sec = next(x for x in r.sections if x.key == "vuln")
    text = "\n".join(sec.lines + sec.top)
    assert "新しく該当になった件数" in text and "vfn-fg1: 2 件（重大 1・高 0・悪用確認済み 1）" in sec.top
    assert "vfn-fg1: あと 100 日" in text
    assert "Out-of-bound" not in text and "Upgrade" not in text  # 勧告の題・直し方は入れない
    monkeypatch.setattr(settings, "VULN_ENABLED", False)
    assert not [x for x in run(build()).sections if x.key == "vuln"]


def test_recheck_schedule_includes_old_non_fortios():
    """M4: FortiOS 以外・告知の勧告も、公開から 90 日を過ぎたら 60 日ごとに期限なしで確かめ直す"""
    now = datetime(2026, 11, 27)

    def adv(products, pub_days, checked_days):
        return VulnAdvisory(source="fortinet", ext_id="FG-IR-99-001", products=products, doc_url=URL101,
                            published_at=now - timedelta(days=pub_days), checked_at=now - timedelta(days=checked_days))
    assert vuln_service._recheck_due(adv([], 400, 61), now)
    assert not vuln_service._recheck_due(adv([], 400, 59), now)
    assert vuln_service._recheck_due(adv([], 30, 15), now) and not vuln_service._recheck_due(adv([], 30, 13), now)
    assert vuln_service._recheck_due(adv(["fortinet"], 30, 8), now) and vuln_service._recheck_due(adv(["fortinet"], 900, 31), now)


def test_recheck_prefers_newer_advisories(net, enabled, monkeypatch, queued):
    """確かめ直しは、1 回の件数の上限の中で新しい勧告を優先する"""
    net.routes.update(fortinet_routes())
    t0 = utcnow()
    run(_fetch(["fortinet"], now=t0))

    async def age():
        async with AsyncSessionLocal() as db:
            for a in (await db.execute(select(VulnAdvisory))).scalars():
                a.published_at = {"FG-IR-99-101": datetime(2020, 1, 1), "FG-IR-99-102": datetime(2025, 1, 1),
                                  "FG-IR-99-103": datetime(2024, 1, 1), "FG-IR-99-104": datetime(2026, 1, 1)}[a.ext_id]
                a.checked_at = t0 - timedelta(days=400)
            await db.commit()
    run(age())
    monkeypatch.setattr(vuln_service, "FORTINET_MAX_DOCS", 1)
    n = len(net.calls)
    run(_fetch(["fortinet"], now=t0 + timedelta(hours=1)))
    docs = [r.full_url for r in net.calls[n:] if "/psirt/csaf_" in r.full_url]
    assert docs == [URL104]  # 公開日の新しい順（104 が 2026 年で最も新しい）


def test_eol_notice_state_is_saved_only_after_sending(enabled, monkeypatch, webhooks):
    """L6: すべての宛先で送れなかったら印を残さず、次の毎時の判定で送り直す。届いたら印を確定する（二重に送らない）"""
    from zoneinfo import ZoneInfo
    run(_setting(f"vfn-l6-{uuid.uuid4().hex[:6]}"))
    mk("e1", "7.0.5")
    today = vuln_service.local_today()
    run(_eol("fortinet", "7.0", today + timedelta(days=30)))
    monkeypatch.setattr(vuln_service, "local_now", lambda: datetime.now(ZoneInfo(settings.TIMEZONE)).replace(hour=12))
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: "送信できません（作り物の失敗）")
    r = run(worker._eol_notices())
    assert r["sent"] == 0 and r["failed"] == 2
    monkeypatch.setattr(notify, "send_webhook", lambda kind, url, payload: webhooks.append((kind, url, payload)))
    assert run(worker._eol_notices())["sent"] == 2  # 送り直す
    assert run(worker._eol_notices())["sent"] == 0  # 届いたので、きょうはもう送らない


def test_newer_branch_reason_and_list_filters_and_provisional(net, enabled, queued):
    """勧告より新しい系列は newer_branch（候補）。一覧の reason・hide_reason は複数を受け付ける。final でない文書は暫定の印"""
    routes = fortinet_routes()
    doc = json.loads(fb("fortinet_csaf_102.json"))
    doc["document"]["tracking"]["status"] = "interim"
    routes[URL102] = resp(json.dumps(doc).encode())
    net.routes.update(routes)
    d = mk("new", "7.6.1")
    run(_fetch())
    m = run(_matches(d))
    assert (m["FG-IR-99-101"].confidence, m["FG-IR-99-101"].reason) == ("candidate", "newer_branch")  # 101 の系列は 7.4 まで
    assert m["FG-IR-99-102"].confidence == "confirmed"
    with TestClient(app) as c:
        h = _admin(c)
        mine = lambda params: [r for r in c.get("/api/vulns/matches", params=params, headers=h).json()["items"]  # noqa: E731
                               if r["device_name"] == "vfn-new"]
        rows = mine({"reason": ["not_listed", "newer_branch"]})
        assert [r["advisory"]["ext_id"] for r in rows] == ["FG-IR-99-101"]
        assert "勧告より新しい系列" in rows[0]["candidate_reason"] and rows[0]["candidate_code"] == "newer_branch"
        assert [r["advisory"]["ext_id"] for r in mine({"hide_reason": ["not_listed", "newer_branch"]})] == ["FG-IR-99-102"]
        prov = mine({"confidence": "confirmed"})[0]["advisory"]
        assert prov["provisional"] is True
        assert c.get("/api/vulns/summary", headers=h).json()["counts"]["candidate_not_listed"] >= 1


def test_fortios_advisory_revised_into_notice_shape_keeps_match(net, enabled, queued):
    """N3: 以前は FortiOS の勧告だったものが、改訂で告知の形（vulnerabilities が無い）になっても、告知にせず「範囲を読み取れない」
    にする。版が同じ機器の「該当」は据え置き（解消にしない）、版が変わった機器は stale"""
    net.routes.update(fortinet_routes())
    same, moved = mk("same", "7.4.2"), mk("moved", "7.4.1")
    t0 = utcnow()
    run(_fetch(["fortinet"], now=t0))
    assert run(_matches(same))["FG-IR-99-101"].state == "open"
    doc = json.loads(fb("fortinet_csaf_101.json"))
    del doc["vulnerabilities"]
    doc["product_tree"] = {"branches": []}
    net.routes[URL101] = resp(json.dumps(doc).encode(), '"c101-notice"')

    async def bump():
        async with AsyncSessionLocal() as db:
            (await db.get(Device, moved)).os_version = "7.4.0"
            await db.commit()
    run(bump())
    run(_fetch(["fortinet"], now=t0 + timedelta(days=8)))
    a = run(_advisories())["FG-IR-99-101"]
    assert a.products == ["fortinet"] and a.affected[0]["unreadable"] and not a.affected[0].get("notice")
    m_same, m_moved = run(_matches(same))["FG-IR-99-101"], run(_matches(moved))["FG-IR-99-101"]
    assert (m_same.state, m_same.stale) == ("open", False)
    assert (m_moved.state, m_moved.stale) == ("open", True)
    with TestClient(app) as c:
        s = c.get("/api/vulns/summary", headers=_admin(c)).json()
        assert all(n["ext_id"] != "FG-IR-99-101" for n in s["notices"]["items"])


def test_notice_recheck_is_weekly_for_recent_ones():
    """L-b: 告知は公開から 90 日以内は 7 日ごと、その後は 60 日ごと"""
    now = datetime(2026, 11, 27)
    notice = [{"fmt": "fortios", "v": None, "notice": True}]

    def adv(pub_days, checked_days, affected):
        return VulnAdvisory(source="fortinet", ext_id="FG-IR-99-001", products=[], doc_url=URL101, affected=affected,
                            published_at=now - timedelta(days=pub_days), checked_at=now - timedelta(days=checked_days))
    assert vuln_service._recheck_due(adv(30, 7, notice), now) and not vuln_service._recheck_due(adv(30, 6, notice), now)
    assert not vuln_service._recheck_due(adv(30, 7, []), now)  # FortiOS 以外の製品の勧告は 14 日ごと
    assert vuln_service._recheck_due(adv(200, 60, notice), now) and not vuln_service._recheck_due(adv(200, 30, notice), now)


def test_note_candidate_reason_through_api(net, enabled, queued):
    """N2: 注記つきの影響ありの行に入る機器は「候補」（note）で、理由に注記の文が出る"""
    doc = json.loads(fb("fortinet_csaf_101.json"))
    doc["vulnerabilities"][0]["product_status"]["known_affected"].append("FortiOS 7.0 all versions (except <b>7.0.5</b>)")
    routes = fortinet_routes()
    routes[URL101] = resp(json.dumps(doc).encode())
    net.routes.update(routes)
    d = mk("noted", "7.0.5")
    run(_fetch())
    m = run(_matches(d))["FG-IR-99-101"]
    assert (m.confidence, m.reason) == ("candidate", "note")
    with TestClient(app) as c:
        rows = [r for r in c.get("/api/vulns/matches", params={"reason": "note"}, headers=_admin(c)).json()["items"]
                if r["device_name"] == "vfn-noted"]
        assert rows and rows[0]["candidate_reason"] == "勧告に注記があります（except <b>7.0.5</b>）。勧告のページで確かめてください"
