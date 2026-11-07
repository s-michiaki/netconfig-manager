"""画面テスト用の初期データ（backend のディレクトリで、start-backend.sh が設定した環境変数で実行する）

起動時の DB マイグレーションも TestClient で済ませてから、API と config_service で投入する
ユーザー: admin / op1（オペレーター）/ view1（閲覧者）  パスワードは password-1234（admin は ADMIN_PASSWORD）
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
        for name, role in [("op1", "operator"), ("view1", "viewer")]:
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
    print("seeded")


if __name__ == "__main__":
    main()
