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
        for name, host, group, ng in [("Core-SW01", "10.0.1.1", hq, False), ("SW-2F", "10.0.1.12", hq, True),
                                      ("SW-3F", "10.0.1.13", hq, False), ("DC-SW01", "10.0.2.1", dc, True)]:
            d = call("POST", "/devices/", h, json={"name": name, "hostname": host, "platform": "cisco_ios",
                                                   "username": "admin", "password": "pw", "group_id": group["id"]})
            devs[name] = d
            cs.save_config(d["id"], (CONFIG_NG if ng else CONFIG_OK).format(name=name), "manual")
        # 世代の比較用に Core-SW01 だけ 2 世代にする（検索・コンプライアンスの結果が変わらない行を足す）
        second = cs.save_config(devs["Core-SW01"]["id"], CONFIG_OK.format(name="Core-SW01") + "logging host 10.0.9.9\n", "schedule")
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
    # 機器台帳（実際は収集のときに読み取る）。Core-SW01 だけ取得済みにしておく
    import asyncio

    from sqlalchemy import update

    from app.core.database import AsyncSessionLocal
    from app.core.timeutil import utcnow
    from app.models.device import ConfigSnapshot, Device

    async def inventory() -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(update(Device).where(Device.name == "Core-SW01").values(
                model="C9300-24T", serial_number="FCW2245L0AB", os_version="17.06.05", reported_hostname="Core-SW01",
                inventory_at=utcnow()))
            # ダッシュボードの「直近の変更」に出す世代（実際は収集のときに worker が記録する）
            db.add(ConfigSnapshot(device_id=devs["Core-SW01"]["id"], commit_hash=second.commit_hash, collected_at=utcnow(),
                                  lines_added=second.added, lines_removed=second.removed, triggered_by="schedule"))
            # ターミナルの記録（実際は SSH ターミナルの切断時に保存する）。色・打ち直しを含む出力を 1 件
            import uuid
            from datetime import timedelta

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
    print("seeded")


if __name__ == "__main__":
    main()
