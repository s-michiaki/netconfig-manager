"""画面テスト用の初期データ（backend のディレクトリで、start-backend.sh が設定した環境変数で実行する）

起動時の DB マイグレーションも TestClient で済ませてから、API と config_service で投入する
ユーザー: admin / op1（オペレーター）/ view1（閲覧者）/ mfa1（閲覧者。2 段階認証の確認用）  パスワードは password-1234（admin は ADMIN_PASSWORD）
"""
import os
import sys

sys.path.insert(0, os.getcwd())

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services import config_service as cs  # noqa: E402

CONFIG_OK = "hostname {name}\nservice password-encryption\ninterface GigabitEthernet0/1\n description uplink\n"
CONFIG_NG = "hostname {name}\nip http server\ninterface GigabitEthernet0/1\n description uplink\ninterface GigabitEthernet0/2\n"


def main() -> None:
    with TestClient(app) as c:
        def call(method: str, path: str, h=None, **kw):
            r = c.request(method, "/api" + path, headers=h, **kw)
            assert r.status_code < 300, (path, r.status_code, r.text)
            return r.json() if r.content else None

        tok = call("POST", "/auth/token", data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]})
        h = {"Authorization": f"Bearer {tok['access_token']}"}
        for name, role in [("op1", "operator"), ("view1", "viewer"), ("mfa1", "viewer")]:
            call("POST", "/users/", h, json={"username": name, "password": "password-1234", "role": role})
        hq = call("POST", "/device-groups/", h, json={"name": "本社", "color": "#4f8ef7"})
        dc = call("POST", "/device-groups/", h, json={"name": "データセンター", "color": "#c084fc"})
        devs = {}
        first_gen = {}
        for name, host, group, ng in [("Core-SW01", "10.0.1.1", hq, False), ("SW-2F", "10.0.1.12", hq, True),
                                      ("SW-3F", "10.0.1.13", hq, False), ("DC-SW01", "10.0.2.1", dc, True)]:
            d = call("POST", "/devices/", h, json={"name": name, "hostname": host, "platform": "cisco_ios",
                                                   "username": "admin", "password": "pw", "group_id": group["id"]})
            devs[name] = d
            first_gen[name] = cs.save_config(d["id"], (CONFIG_NG if ng else CONFIG_OK).format(name=name), "manual")
        # 脆弱性・サポート期限（vulns.spec.ts）用の Palo Alto の機器 2 台。OS バージョンは台帳の自動取得のかわりに下で入れる
        for name, host in [("FW-Edge01", "10.0.3.1"), ("FW-Edge02", "10.0.3.2")]:
            devs[name] = call("POST", "/devices/", h, json={"name": name, "hostname": host, "platform": "paloalto_panos",
                                                            "username": "admin", "password": "pw", "group_id": dc["id"]})
        # 世代の比較用に Core-SW01 だけ 2 世代にする（検索・コンプライアンスの結果が変わらない行を足す）
        second = cs.save_config(devs["Core-SW01"]["id"], CONFIG_OK.format(name="Core-SW01") + "logging host 10.0.9.9\n", "schedule")
        # 変更の確認（reviews.spec.ts）用に SW-3F を 2 世代にする（検索・コンプライアンスの結果が変わらない行を足す）
        sw3f_second = cs.save_config(devs["SW-3F"]["id"], CONFIG_OK.format(name="SW-3F") + "snmp-server location rack-12\n", "schedule")
        # ルールを作ると収集済みのコンフィグを検査する（SW-2F・DC-SW01 が違反）
        call("POST", "/compliance/rules", h, json={
            "name": "HTTP サーバーの無効化", "severity": "medium", "match_type": "regex", "expect": "absent",
            "pattern": "^ip http server", "platforms": ["cisco_ios"]})
        m = call("POST", "/topology/maps", h, json={"name": "本社ネットワーク"})
        detail = call("GET", f"/topology/maps/{m['id']}", h)
        nodes = [{"id": f"n{i}", "type": "device", "x": 200 * i, "y": 0 if i == 0 else 160, "device_id": d["id"]}
                 for i, d in enumerate(devs.values())]
        call("PUT", f"/topology/maps/{m['id']}", h, json={
            "version": detail["version"],
            "data": {"nodes": nodes, "edges": [{"id": f"e{i}", "source": "n0", "target": f"n{i}"} for i in (1, 2)]},
        })
        # 脆弱性（Fortinet）の見本の機器 3 台（未分類。構成図には載せない）。OS バージョン・モデルは下の vulns で入れる
        for name, host in [("FG-Branch01", "10.0.4.1"), ("FG-Branch02", "10.0.4.2"), ("FG-DC7121", "10.0.4.3")]:
            devs[name] = call("POST", "/devices/", h, json={"name": name, "hostname": host, "platform": "fortinet",
                                                            "username": "admin", "password": "pw"})
    # 機器台帳（実際は収集のときに読み取る）。Core-SW01 だけ取得済みにしておく
    import asyncio

    from datetime import timedelta

    from sqlalchemy import update

    from app.core.database import AsyncSessionLocal
    from app.core.timeutil import utcnow
    from app.models.device import ConfigSnapshot, Device

    async def inventory() -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(update(Device).where(Device.name == "Core-SW01").values(
                model="C9300-24T", serial_number="FCW2245L0AB", os_version="17.06.05", reported_hostname="Core-SW01",
                inventory_at=utcnow()))
            # 保存し忘れの検出（実際は収集のとき worker が startup-config と比べて記録する）。SW-2F だけ未保存
            await db.execute(update(Device).where(Device.name == "SW-2F").values(
                startup_state="unsaved", startup_added=2, startup_removed=1, startup_checked_at=utcnow(),
                startup_diff="--- startup-config\n+++ running-config\n@@ -3,2 +3,3 @@\n interface Gi0/1\n- description old-uplink\n"
                             "+ description uplink-to-core\n+ shutdown"))
            await db.execute(update(Device).where(Device.name == "Core-SW01").values(
                startup_state="synced", startup_added=0, startup_removed=0, startup_checked_at=utcnow()))
            # ダッシュボードの「直近の変更」に出す世代（実際は収集のときに worker が記録する）
            db.add(ConfigSnapshot(device_id=devs["Core-SW01"]["id"], commit_hash=second.commit_hash, collected_at=utcnow(),
                                  lines_added=second.added, lines_removed=second.removed, triggered_by="schedule"))
            # SW-3F: 最初の世代（初回の収集。変更の確認の対象外）と、その後の変更（未確認）
            db.add(ConfigSnapshot(device_id=devs["SW-3F"]["id"], commit_hash=first_gen["SW-3F"].commit_hash,
                                  collected_at=utcnow() - timedelta(days=2), lines_added=4, lines_removed=0, triggered_by="manual"))
            db.add(ConfigSnapshot(device_id=devs["SW-3F"]["id"], commit_hash=sw3f_second.commit_hash,
                                  collected_at=utcnow() - timedelta(hours=2), lines_added=sw3f_second.added,
                                  lines_removed=sw3f_second.removed, triggered_by="schedule"))
            # ターミナルの記録（実際は SSH ターミナルの切断時に保存する）。色・打ち直しを含む出力を 1 件
            import uuid
            from app.models.audit import TerminalSession
            from app.services.audit import TerminalRecorder

            sid, started = str(uuid.uuid4()), utcnow() - timedelta(minutes=30)
            rec = TerminalRecorder(sid, started, 100, 30, "admin@Core-SW01")
            rec.output("Core-SW01#show clcok\b \b\b \b\b \bock\r\n12:00:00.000 JST Mon Nov 16 2026\r\n")
            rec.output("Core-SW01#\x1b[1mshow ip interface brief\x1b[0m\r\nVlan10   10.0.1.1   YES manual up   up\r\n")
            rec.output(" --More-- \r         \rVlan20   10.0.2.1   YES manual up   up\r\nCore-SW01#exit\r\n")
            rec.close()
            rec.write_text()
            db.add(TerminalSession(id=sid, username="admin", device_id=devs["Core-SW01"]["id"], device_name="Core-SW01",
                                   device_host="10.0.1.1", ip="127.0.0.1", started_at=started,
                                   ended_at=started + timedelta(minutes=2), end_reason="利用者が切断",
                                   log_file=rec.rel_path, bytes_out=rec.bytes, truncated=False, cols=100, rows=30))
            # Ping監視の常時監視（実際は worker が PING して残す）。Core-SW01 の 24 時間分、途中に応答なし
            from app.models.ping import PingMonitor, PingResult

            key = f"d:{devs['Core-SW01']['id']}"
            db.add(PingMonitor(key=key, created_by="admin"))
            now = utcnow()
            for i in range(24 * 60, 0, -5):
                rtt = None if 300 <= i < 330 else round(1.2 + (i % 37) / 20, 2)
                db.add(PingResult(key=key, at=now - timedelta(minutes=i), rtt=rtt))
            await db.commit()
    asyncio.run(inventory())
    asyncio.run(vulns(devs))
    print("seeded")


async def vulns(devs: dict) -> None:
    """脆弱性・サポート期限の見本のデータ（作り物。実際は worker が外部から取得して保存する）。照合は本物の処理で行う"""
    from datetime import date, timedelta

    from sqlalchemy import select, update

    from app.core.database import AsyncSessionLocal
    from app.core.timeutil import utcnow
    from app.models.device import Device
    from app.models.vuln import EolDate, VulnAdvisory, VulnMatch, VulnSource
    from app.services import vuln_service

    now = utcnow()
    async with AsyncSessionLocal() as db:
        for name, model, version in [("FW-Edge01", "PA-440", "10.2.5-h1"), ("FW-Edge02", "PA-440", "10.2.9"),
                                     ("FG-Branch01", "FortiGate-60F", "7.4.2 build2571"),
                                     ("FG-Branch02", "FortiGate-100F", "7.0.15 build0632"),
                                     ("FG-DC7121", "FortiGate-7121F", "7.4.1 build2463")]:
            await db.execute(update(Device).where(Device.name == name).values(model=model, os_version=version, inventory_at=now))

        def adv(ext_id, title, severity, cvss, affected, kev=False):
            db.add(VulnAdvisory(
                source="paloalto", ext_id=ext_id, cve_ids=[ext_id] if ext_id.startswith("CVE-") else [], title=title,
                severity=severity, cvss=cvss, published_at=now - timedelta(days=20), modified_at=now - timedelta(days=3),
                url=f"https://security.paloaltonetworks.com/{ext_id}", products=["paloalto_panos"], affected=affected,
                kev=kev, kev_due=date(2099, 2, 1) if kev else None, fetched_at=now))
        adv("CVE-2099-0001", "（見本）管理画面の認証の回避", "critical", 9.3,
            [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.5-h2"}], kev=True)
        adv("CVE-2099-0002", "（見本）VPN 機能のサービス拒否", "high", 7.5, [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.9"}])
        adv("PAN-SA-2099-0001", "（見本）すべてのバージョンに影響する情報漏えい", "medium", 5.3, [{"all": True}])
        # 影響範囲を読み取れなかった勧告（該当・非該当のどちらにもしない。画面の注記と「判定できない機器」に出る）
        adv("CVE-2099-0004", "（見本）影響範囲の書き方を読み取れない勧告", "high", 7.0, [{"unreadable": True, "branch": "10.2", "raw": "10.2.0"}])
        # 「候補」の見本（FW-Edge01 は 10.2.5-h1・PA-440）。特定の機種だけに影響する勧告（10.2.6 より前の FW-Edge01 だけが当たる）と、
        # 記載のない系列も影響ありとする勧告（10.2 は表に載っていないので両方の機器が当たる）
        adv("CVE-2099-0005", "（見本）特定の機種だけに影響するコマンド実行", "medium", 5.0,
            [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.6", "platforms": ["PA-3200 Series"]}])
        adv("CVE-2099-0006", "（見本）記載のない系列も影響ありとする勧告", "low", 3.1,
            [{"branch": "10.1", "ge": "10.1.0", "lt": "10.1.9"}, {"kind": "default", "default": "affected"}])
        # あとで取り下げる勧告（最初は該当にして、下で rejected にして照合し直すと解消になる。実際の流れと同じ）
        adv("CVE-2099-0007", "（見本）取り下げられた勧告", "high", 8.0, [{"branch": "10.2", "ge": "10.2.0", "lt": "10.2.99"}])
        # Fortinet（FortiOS）の勧告の見本（作り物の ID。行の形は本物の CSAF を取得のときと同じ解析にかけたもの）
        from app.services import vuln_fetch

        def fos(ext_id, title, score, affected, not_affected, status="final", sev="HIGH", vulns=True):
            doc = {"document": {"title": title, "tracking": {"id": ext_id, "status": status,
                                                             "initial_release_date": (now - timedelta(days=17)).isoformat(),
                                                             "current_release_date": (now - timedelta(days=16)).isoformat()}},
                   "vulnerabilities": [{"cve": f"CVE-2099-{ext_id[-3:]}1", "title": f"FortiOS - {sev} - {ext_id}",
                                        "scores": [{"products": ["FortiOS"], "cvss_v3": {"baseScore": score}}],
                                        "product_status": {"known_affected": affected, "known_not_affected": not_affected}}]}
            if not vulns:
                del doc["vulnerabilities"]
            a = vuln_fetch.parse_fortinet_csaf(doc, ext_id)
            db.add(VulnAdvisory(fetched_at=now, checked_at=now, **{k: a[k] for k in (
                "source", "ext_id", "cve_ids", "title", "severity", "cvss", "published_at", "modified_at", "url", "products",
                "affected")}))
        fos("FG-IR-99-101", "（見本）SSL-VPN のヒープの範囲外への書き込み", 9.6,
            ["FortiOS >=7.4.0|<=7.4.2", "FortiOS >=7.2.0|<=7.2.6"], ["FortiOS-7.4.3", "FortiOS-7.2.7"], sev="CRITICAL")
        # 102 は確定版でない文書（暫定の勧告）の見本
        fos("FG-IR-99-102", "（見本）証明書の検証の不備（修正版が未公開の系列あり）", 7.7,
            ["FortiOS >=7.6.0|<=7.6.4", "FortiOS >=7.4.0|<=7.4.9", "FortiOS >=7.2.0|<=7.2.13"],
            ["FortiOS/ 8.0 all versions", "FortiOS-7.6.5", "FortiOS-7.4.10", "FortiOS-upcoming  7.2.14"], status="interim")
        # 製品の記載が無い告知（要確認の告知。機器ごとの件数には数えない）
        fos("FG-IR-99-103", "（見本）外部のライブラリの脆弱性についての告知", 8.1, [], [], vulns=False)
        for name, ok_days in (("kev", 0), ("paloalto", 0), ("fortinet", 0), ("eol", 0)):
            db.add(VulnSource(source=name, last_at=now, last_ok_at=now - timedelta(days=ok_days),
                              last_count={"kev": 1800, "paloalto": 3, "fortinet": 2, "eol": 6}[name]))
        today = now.date()
        # サポート終了日（自動取得の見本）: PAN-OS 10.2 は終了済み、Core-SW01 の IOS XE 17.6 は約 200 日後
        db.add(EolDate(platform="paloalto_panos", kind="os", branch="10.2", model="", eol_date=today - timedelta(days=400),
                       source="endoflife.date", url="https://endoflife.date/panos", updated_at=now))
        db.add(EolDate(platform="cisco_xe", kind="os", branch="17.6", model="", eol_date=today + timedelta(days=200),
                       source="endoflife.date", url="https://endoflife.date/cisco-ios-xe", updated_at=now))
        # FortiOS 7.0 は約 60 日後に終了（ダッシュボードの「サポート終了まで 90 日以内」に入る）
        db.add(EolDate(platform="fortinet", kind="os", branch="7.0", model="", eol_date=today + timedelta(days=60),
                       source="endoflife.date", url="https://endoflife.date/fortios", updated_at=now))
        await db.flush()
        await vuln_service.reconcile(db)
        # 取り下げ: CVE-2099-0007 を rejected にして照合し直す（該当の判定は解消になり、未確認の一覧には出ない）
        await db.execute(update(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-0007").values(rejected=True))
        await vuln_service.reconcile(db)
        # stale の見本: 前回（古い版）は該当だったが、機器の版が変わり、いまの版では範囲を読み取れない勧告（CVE-2099-0004）。
        # FW-Edge01 は未確認、FW-Edge02 は確認済み（メモ付き）。古い版で作ってから照合し直すと、本物の処理が stale にする
        adv04 = (await db.execute(select(VulnAdvisory).where(VulnAdvisory.ext_id == "CVE-2099-0004"))).scalar_one()
        for name, old, state, note in [("FW-Edge01", "10.2.4", "open", None), ("FW-Edge02", "10.2.8", "ack", "次回の保守で版を確かめる")]:
            dev = (await db.execute(select(Device).where(Device.name == name))).scalar_one()
            db.add(VulnMatch(device_id=dev.id, advisory_id=adv04.id, confidence="confirmed", os_version=old, first_seen=now,
                             last_seen=now, state=state, note=note, acked_by="admin" if note else None,
                             acked_at=now if note else None))
        await db.flush()
        await vuln_service.reconcile(db)
        await db.commit()


if __name__ == "__main__":
    main()
