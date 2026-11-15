"""コンフィグの比較（別の機器・離れた世代）とダウンロードのテスト"""
import json
import os
from unittest import mock
from urllib.parse import quote

import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app.core.csv_export import content_disposition, safe_filename
from app.main import app
from app.services import config_service as cs


@pytest.fixture(scope="module")
def client():
    with (
        mock.patch("app.api.devices.collect_device_config"),
        mock.patch("app.api.devices.collect_all_devices"),
        TestClient(app) as c,
    ):
        yield c


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def env(client):
    admin = _login(client, "admin", "initial-pass-123")
    for name, role in [("cfgcmp-op", "operator"), ("cfgcmp-view", "viewer")]:
        r = client.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        assert r.status_code == 201, r.text

    def dev(name, host):
        r = client.post("/api/devices/", json=dict(name=name, hostname=host, platform="cisco_ios", username="u", password="p"),
                        headers=admin)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    a, b, empty = dev("cfgcmp-core1", "10.7.0.1"), dev("cfgcmp-core2", "10.7.0.2"), dev("cfgcmp-empty", "10.7.0.3")
    a1 = cs.save_config(a, "hostname cfgcmp-core1\nvlan 10\n", "manual").commit_hash
    a2 = cs.save_config(a, "hostname cfgcmp-core1\nvlan 10\nvlan 20\n", "manual").commit_hash
    a3 = cs.save_config(a, "hostname cfgcmp-core1\nvlan 10\nvlan 20\nvlan 30\n", "manual").commit_hash
    b1 = cs.save_config(b, "hostname cfgcmp-core2\nvlan 10\nvlan 20\n", "manual").commit_hash
    yield {
        "admin": admin,
        "operator": _login(client, "cfgcmp-op", "password-1234"),
        "viewer": _login(client, "cfgcmp-view", "password-1234"),
        "a": a, "b": b, "empty": empty, "a1": a1, "a2": a2, "a3": a3, "b1": b1,
    }
    # 他のテスト（ダッシュボードの「未収集」の一覧など）に影響しないよう、作った機器を消す
    for did in (a, b, empty):
        assert client.delete(f"/api/devices/{did}", headers=admin).status_code == 204


def _compare(client, h, **params):
    return client.get("/api/configs/compare", params=params, headers=h)


def test_compare_latest_of_two_devices(client, env):
    r = _compare(client, env["viewer"], device_a=env["a"], device_b=env["b"])
    assert r.status_code == 200, r.text
    d = r.json()
    lines = d["diff"].split("\n")
    assert lines[0] == f"--- cfgcmp-core1 ({env['a3'][:8]})" and lines[1] == f"+++ cfgcmp-core2 ({env['b1'][:8]})"
    assert lines[2].startswith("@@")
    assert "-hostname cfgcmp-core1" in lines and "+hostname cfgcmp-core2" in lines and "-vlan 30" in lines
    assert " vlan 10" in lines  # 共通の行は前後の行として出る
    assert d["a"]["name"] == "cfgcmp-core1" and d["a"]["full_hash"] == env["a3"]
    assert d["b"]["name"] == "cfgcmp-core2" and d["b"]["hash"] == env["b1"][:8] and d["b"]["date"].endswith("+00:00")
    assert d["truncated"] is False and "message" not in d


def test_compare_generations(client, env):
    # 同じ機器の離れた世代（短縮ハッシュでもよい）
    r = _compare(client, env["admin"], device_a=env["a"], hash_a=env["a1"][:8], device_b=env["a"], hash_b=env["a3"])
    assert r.status_code == 200
    assert "+vlan 20" in r.json()["diff"] and "+vlan 30" in r.json()["diff"]
    # 別の機器の過去の世代と、この機器の最新
    r = _compare(client, env["admin"], device_a=env["a"], hash_a=env["a2"], device_b=env["b"])
    assert r.json()["diff"].count("\n+") == 2 and "+hostname cfgcmp-core2" in r.json()["diff"]
    # 同じ内容は「変更なし」
    r = _compare(client, env["admin"], device_a=env["a"], device_b=env["a"])
    assert r.json()["diff"] == "" and r.json()["message"] == "変更なし"


def test_compare_errors(client, env):
    h = env["admin"]
    r = _compare(client, h, device_a=env["a"], device_b=env["empty"])
    assert r.status_code == 404 and "まだコンフィグを収集していません" in r.json()["detail"]
    r = _compare(client, h, device_a="00000000-0000-0000-0000-000000000000", device_b=env["a"])
    assert r.status_code == 404 and "比較元の機器が見つかりません" in r.json()["detail"]
    # 他の機器の世代は、その機器のリポジトリには無い
    r = _compare(client, h, device_a=env["a"], hash_a=env["b1"], device_b=env["b"])
    assert r.status_code == 404 and "指定した世代が見つかりません" in r.json()["detail"]
    r = _compare(client, h, device_a=env["a"], device_b=env["b"], hash_b="0" * 40)
    assert r.status_code == 404
    # git のオプションとして解釈される文字列は受け付けない
    r = _compare(client, h, device_a=env["a"], hash_a=f"--output={TMP}/pwn2", device_b=env["b"])
    assert r.status_code == 422 and not os.path.exists(f"{TMP}/pwn2")
    assert client.get("/api/configs/compare", params={"device_a": env["a"], "device_b": env["b"]}).status_code == 401


def test_compare_limits(client, env):
    big = "".join(f"line {i}\n" for i in range(cs.MAX_DIFF_LINES + 10))
    diff, truncated = cs.compare_texts("", big, "a", "b")
    assert truncated and len(diff.split("\n")) == cs.MAX_DIFF_LINES
    # 見出しに改行・タブが入っても行が崩れない
    diff, _ = cs.compare_texts("x\n", "y\n", "名前\nに改行\tタブ", "b")
    assert diff.split("\n")[0] == "--- 名前 に改行 タブ"
    with mock.patch("app.api.configs.MAX_COMPARE_LINES", 2):
        r = _compare(client, env["admin"], device_a=env["a"], device_b=env["b"])
    assert r.status_code == 422 and "大きすぎる" in r.json()["detail"]


def test_download_and_audit(client, env):
    for role in ("viewer", "operator", "admin"):
        r = client.get(f"/api/configs/{env['a']}/download/{env['a1'][:8]}", headers=env[role])
        assert r.status_code == 200, (role, r.text)
    assert r.text == "hostname cfgcmp-core1\nvlan 10\n"
    assert r.headers["content-type"] == "text/plain; charset=utf-8"
    cd = r.headers["content-disposition"]
    assert cd.startswith('attachment; filename="cfgcmp-core1_') and cd.endswith(f'_{env["a1"][:8]}.txt"')
    assert client.get(f"/api/configs/{env['a']}/download/{'0' * 40}", headers=env["admin"]).status_code == 404
    assert client.get(f"/api/configs/{env['empty']}/download/{env['a1']}", headers=env["admin"]).status_code == 404
    assert client.get(f"/api/configs/{env['a']}/download/{env['a1']}").status_code == 401
    # ダウンロードは監査ログに残る（画面での表示は残さない）
    logs = client.get("/api/audit/logs", params={"action": "config.download"}, headers=env["admin"]).json()
    assert logs["total"] == 3
    item = logs["items"][0]
    assert item["target_name"] == "cfgcmp-core1" and json.loads(item["detail"]) == {"commit": env["a1"], "bytes": len(r.content)}
    client.get(f"/api/configs/{env['a']}/content/{env['a1']}", headers=env["admin"])
    assert client.get("/api/audit/logs", params={"action": "config."}, headers=env["admin"]).json()["total"] == 3
    assert client.get("/api/audit/actions", headers=env["admin"]).json()["config.download"] == "コンフィグのダウンロード"


@pytest.mark.parametrize("name", ["東京-コアSW", 'sw"1\r\nX-Injected: 1', "../../etc/passwd", "😀"])
def test_download_unusual_device_names(client, env, name):
    h = env["admin"]
    r = client.post("/api/devices/", json=dict(name=name, hostname="10.7.1.1", platform="cisco_ios", username="u", password="p"),
                    headers=h)
    if r.status_code == 422:  # 機器名として受け付けない名前は、ファイル名の単体テストで確かめる
        pytest.skip("機器名として登録できない")
    did = r.json()["id"]
    c = cs.save_config(did, "hostname x\n", "manual")
    r = client.get(f"/api/configs/{did}/download/{c.commit_hash}", headers=h)
    assert r.status_code == 200, r.text
    cd = r.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd and "/" not in cd.split("filename*=")[0]
    assert client.delete(f"/api/devices/{did}", headers=h).status_code == 204


def test_safe_filename():
    assert safe_filename("Core/SW:01*?") == "Core_SW_01__"
    assert safe_filename("..") == "file" and safe_filename("") == "file" and safe_filename("  ") == "file"
    assert safe_filename("CON") == "_CON" and safe_filename("nul.txt") == "_nul.txt" and safe_filename("CONSOLE") == "CONSOLE"
    assert safe_filename("a\r\nb\tc\x00") == "a__b_c_"
    assert len(safe_filename("東" * 128)) == 100
    assert safe_filename("ｶﾞ") == "ｶﾞ" and safe_filename("が") == "が"


def test_content_disposition():
    assert content_disposition("sw1_20261115-093000_a1b2c3d4.txt") == 'attachment; filename="sw1_20261115-093000_a1b2c3d4.txt"'
    cd = content_disposition("東京-コアSW_20261115-093000_a1b2c3d4.txt")
    assert cd == ('attachment; filename="__-__SW_20261115-093000_a1b2c3d4.txt"; '
                  f"filename*=UTF-8''{quote('東京-コアSW_20261115-093000_a1b2c3d4.txt', safe='')}")
    cd = content_disposition("東京.txt")
    assert cd.startswith('attachment; filename="download.txt"; filename*=UTF-8\'\'%E6%9D%B1%E4%BA%AC.txt')
    cd = content_disposition('a"b\r\nSet-Cookie: x.txt')
    assert cd.encode("latin-1") and cd.count('"') == 2 and "\n" not in cd and "\r" not in cd
