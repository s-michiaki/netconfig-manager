"""機器の CSV 一括登録のテスト"""
import json
import sqlite3
import uuid

import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app.main import app
from app.services import device_import as di
from app.services.config_service import PLATFORMS

HEADER = "名前,ホスト / IP,ポート,グループ,機種,踏み台,有効,ユーザー名,パスワード,Enable パスワード,応答待ち時間（秒）,説明"


def login(c, u, p):
    return {"Authorization": f"Bearer {c.post('/api/auth/token', data={'username': u, 'password': p}).json()['access_token']}"}


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        for name, role in (("imp-op", "operator"), ("imp-viewer", "viewer")):
            c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role}, headers=admin)
        yield {"c": c, "admin": admin, "op": login(c, "imp-op", "password-1234"),
               "viewer": login(c, "imp-viewer", "password-1234")}


def post(c, h, data: bytes | str, **form):
    if isinstance(data, str):
        data = data.encode("utf-8")
    fields = {k: str(v).lower() if isinstance(v, bool) else v for k, v in form.items()}
    return c.post("/api/devices/import", files={"file": ("d.csv", data, "text/csv")}, data=fields, headers=h)


def tag():
    return uuid.uuid4().hex[:6]


def devices(c, h, prefix):
    return {d["name"]: d for d in c.get("/api/devices/", headers=h).json() if d["name"].startswith(prefix)}


def audit_items(c, h, action, q):
    return c.get("/api/audit/logs", params={"action": action, "q": q}, headers=h).json()["items"]


def test_platform_labels_unique_and_distinct_from_ids():
    # 機種は ID と表示名のどちらでも指定できる。どちらで書いても 1 つに決まることを固定する
    labels = {di._norm(s.label): pid for pid, s in PLATFORMS.items()}
    assert len(labels) == len(PLATFORMS)
    # 表示名が別の機種の ID と重ならない（VyOS のように自分の ID と同じなのはよい）
    assert all(labels.get(di._norm(pid), pid) == pid for pid in PLATFORMS)
    for pid, spec in PLATFORMS.items():
        assert di.resolve_platform(pid) == pid
        assert di.resolve_platform(spec.label) == pid
    assert di.resolve_platform("cisco ios") == "cisco_ios"
    assert di.resolve_platform("ＣＩＳＣＯ　ＩＯＳ") == "cisco_ios"  # 全角・大文字
    assert di.resolve_platform("nope") is None


def test_decode():
    text = "名前,ホスト\r\n"
    assert di.decode(text.encode("utf-8")) == (text, "utf-8")
    assert di.decode(("﻿" + text).encode("utf-8")) == (text, "utf-8")
    assert di.decode(text.encode("cp932")) == (text, "shift_jis")
    for bad in (text.encode("utf-16"), b"a,b\x00\r\n"):
        with pytest.raises(di.ImportFormatError):
            di.decode(bad)


def test_parse_header_and_limits():
    p = di.parse(f"{HEADER},モデル,シリアル番号\r\n\r\n# メモ\r\nsw,10.0.0.1,,,cisco_ios,,,u,p,,,\"複数\n行\"\r\nsw2,h,,,x,,,u,p\r\n")
    assert p.ignored_columns == ["モデル", "シリアル番号"]
    assert [line for line, _ in p.rows] == [4, 6]  # 空行・コメント・引用符内の改行があっても物理行
    # 英語の見出し・順不同・全角のゆれも受ける
    p = di.parse("USERNAME,platform,Hostname,name,パスワード\nu,cisco_ios,h,n,p\n")
    assert set(p.columns) == {"username", "platform", "hostname", "name", "password"}
    for text, msg in [("", "空"), ("名前,ホスト / IP,機種\nx,y,z\n", "ユーザー名、パスワード"),
                      (HEADER + ",名前\n", "2 つ"), (HEADER + "\n# c\n\n", "取り込む行がありません"),
                      (HEADER + "\n" + "a,h,,,cisco_ios,,,u,p\n" * 501, "500 行")]:
        with pytest.raises(di.ImportFormatError, match=msg):
            di.parse(text)


def test_import_end_to_end(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    grp = c.post("/api/device-groups/", json={"name": f"本社-{t}"}, headers=admin).json()
    jh = c.post("/api/jump-hosts/", json={"name": f"踏み台-{t}", "hostname": "10.9.0.1", "username": "j",
                                          "password": "jp"}, headers=admin)
    assert jh.status_code == 201, jh.text
    pw = f"S3cret-{t}!"
    csv_text = (
        "﻿" + HEADER + "\r\n"
        f"imp-{t}-a,10.7.0.1,,{grp['name']},Cisco IOS,,はい,admin,{pw},En-{t},60,'-説明\r\n"
        # 機種は ID・全角のホスト・グループ名の全角半角のゆれ・踏み台
        f"imp-{t}-b,１０．７．０．２,2222,{grp['name'].replace('-', '－')},yamaha,踏み台-{t},いいえ,admin, {pw} ,,,\r\n"
    )
    # 確認だけ（既定）: DB は変わらず、監査も残らない。結果にパスワードは出ない
    r = post(c, admin, csv_text)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True and body["registered"] is False and body["created"] == 0
    assert (body["total"], body["ok"], body["error"], body["skip"]) == (2, 2, 0, 0), body
    assert body["encoding"] == "utf-8"
    assert body["rows"][0]["platform"] == "Cisco IOS" and body["rows"][1]["platform"] == PLATFORMS["yamaha"].label
    assert pw not in r.text and f"En-{t}" not in r.text
    assert devices(c, admin, f"imp-{t}") == {}
    assert audit_items(c, admin, "device.import", f"imp-{t}") == []

    # 本登録
    r = post(c, admin, csv_text, dry_run=False)
    assert r.status_code == 200 and r.json()["created"] == 2 and r.json()["registered"] is True, r.text
    assert pw not in r.text
    got = devices(c, admin, f"imp-{t}")
    a, b = got[f"imp-{t}-a"], got[f"imp-{t}-b"]
    assert (a["port"], a["group_id"], a["is_active"], a["read_timeout"], a["description"]) == (
        22, grp["id"], True, 60, "-説明")  # 台帳 CSV の ' は外す
    assert a["has_password"] and a["has_enable_secret"] and not a["has_private_key"]
    assert (b["hostname"], b["port"], b["group_id"], b["jump_host_id"], b["is_active"]) == (
        "10.7.0.2", 2222, grp["id"], jh.json()["id"], False)
    raw = sqlite3.connect(f"{TMP}/t.db").execute(
        "select password, enable_secret from devices where id=?", (a["id"],)).fetchone()
    assert raw[0].startswith("enc:") and raw[1].startswith("enc:")

    # 監査: 機器ごとの device.create（via=csv）と、全体の device.import。パスワードは入らない
    creates = audit_items(c, admin, "device.create", f"imp-{t}")
    assert len(creates) == 2
    d = json.loads(creates[0]["detail"])
    assert d["via"] == "csv" and d["auth"] == ["password"]
    logs = c.get("/api/audit/logs", params={"action": "device.import"}, headers=admin).json()["items"]
    summary = next(json.loads(x["detail"]) for x in logs if f"imp-{t}-a" in x["detail"])
    assert summary["created"] == 2 and summary["encoding"] == "utf-8"
    assert pw not in json.dumps(creates + logs, ensure_ascii=False)

    # 同じファイルをもう一度: 既定は同じ名前をスキップ（何度実行しても同じ結果）
    r = post(c, admin, csv_text, dry_run=False).json()
    assert (r["skip"], r["created"], r["registered"]) == (2, 0, False)
    assert "既にあります" in r["rows"][0]["warnings"][0]
    r = post(c, admin, csv_text, on_duplicate="error").json()
    assert r["error"] == 2 and r["rows"][0]["errors"][0].startswith("名前: 同じ名前の機器")


def test_row_errors_and_skip_errors(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    lines = [
        f"imp-{t}-ok,10.7.1.1,,,cisco_ios,,,u,pw,,,",
        f"imp-{t}-host,a b;rm,,,cisco_ios,,,u,pw,,,",
        f"imp-{t}-port,10.7.1.3,70000,,cisco_ios,,,u,pw,,,",
        f"imp-{t}-port2,10.7.1.4,abc,,cisco_ios,,,u,pw,,,",
        "x" * 129 + ",10.7.1.5,,,cisco_ios,,,u,pw,,,",
        f"imp-{t}-nopw,10.7.1.6,,,cisco_ios,,,u,,,,",
        f"imp-{t}-act,10.7.1.7,,,cisco_ios,,たぶん,u,pw,,,",
        f"imp-{t}-grp,10.7.1.8,,無いグループ-{t},cisco_ios,無い踏み台-{t},,u,pw,,,",
        f"imp-{t}-to,10.7.1.9,,,cisco_ios,,,u,pw,,5,",
        f"imp-{t}-plat,10.7.1.10,,,なにか,,,u,pw,,,",
        f"imp-{t}-ok,10.7.1.11,,,cisco_ios,,,u,pw,,,",  # ファイル内で名前が重複
        f"IMP-{t}-OK,10.7.1.1,,,cisco_ios,,,u,pw,,,",  # 大文字小文字だけ違う・IP が重複 → 警告のみ
        f"imp-{t}-nouser,10.7.1.12,,,cisco_ios,,,,pw,,,",
    ]
    text = HEADER + "\n" + "\n".join(lines) + "\n"
    r = post(c, admin, text).json()
    rows = {row["line"]: row for row in r["rows"]}
    errs = {line: " / ".join(row["errors"]) for line, row in rows.items()}
    assert rows[2]["status"] == "ok"
    assert "ホスト / IP: 使えない文字" in errs[3]
    assert "ポート: 65535 以下" in errs[4]
    assert "ポート: 数字で" in errs[5]
    assert "名前: 128 文字以内" in errs[6]
    assert "パスワード: 空です（SSH 鍵は CSV では登録できません" in errs[7]
    assert "有効: 「はい」か「いいえ」" in errs[8]
    assert "グループ: グループ「無いグループ" in errs[9] and "踏み台: 踏み台「無い踏み台" in errs[9]
    assert "応答待ち時間（秒）: 10 以上" in errs[10]
    assert "機種: 「なにか」は対応する機種にありません" in errs[11]
    assert "名前: 2 行目と名前が同じです" in errs[12]
    assert rows[13]["status"] == "ok" and len(rows[13]["warnings"]) == 2
    assert "ユーザー名: 空です" in errs[14]
    assert (r["ok"], r["error"]) == (2, 11)
    assert "pw" not in json.dumps([row["errors"] for row in r["rows"]])

    # エラーがあれば（既定では）1 台も登録しない
    r = post(c, admin, text, dry_run=False).json()
    assert r["registered"] is False and r["created"] == 0
    assert devices(c, admin, f"imp-{t}") == {}
    # エラーのない行だけ登録する
    r = post(c, admin, text, dry_run=False, skip_errors=True).json()
    assert r["created"] == 2
    assert set(devices(c, admin, f"imp-{t}")) | set(devices(c, admin, f"IMP-{t}")) == {f"imp-{t}-ok", f"IMP-{t}-OK"}


def test_encodings_and_format_errors(ctx):
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    text = HEADER + f"\r\n東京-{t},10.7.2.1,,,Cisco IOS,,はい,u,pw,,,本社\r\n"
    r = post(c, admin, text.encode("cp932")).json()
    assert r["encoding"] == "shift_jis" and r["rows"][0]["name"] == f"東京-{t}" and r["ok"] == 1
    r = post(c, admin, text.encode("utf-8")).json()
    assert r["encoding"] == "utf-8" and r["ok"] == 1
    for data, msg in [(text.encode("utf-16"), "文字コード"), (b"", "空"),
                      (b"a" * (di.MAX_IMPORT_BYTES + 1), "1MB"), ("名前,機種\nx,y\n", "必須の列")]:
        r = post(c, admin, data)
        assert r.status_code == 422 and msg in r.json()["detail"], r.text
    assert post(c, admin, text, on_duplicate="overwrite").status_code == 422


def test_ledger_csv_needs_credentials(ctx):
    # 台帳 CSV はそのまま取り込めない（認証情報を書き出さないため）。台帳だけの列は無視する
    c, admin = ctx["c"], ctx["admin"]
    t = tag()
    c.post("/api/devices/", json=dict(name=f"imp-led-{t}", hostname="10.7.3.1", platform="cisco_ios",
                                      username="u", password="p"), headers=admin)
    ledger = c.get("/api/devices/export", headers=admin).content
    r = post(c, admin, ledger)
    assert r.status_code == 422 and "ユーザー名、パスワード" in r.json()["detail"]
    # 台帳 CSV に「ユーザー名」「パスワード」の列を足せば取り込める（既存の機器は同じ名前でスキップ）
    lines = ledger.decode("utf-8-sig").splitlines()
    added = [lines[0] + ",ユーザー名,パスワード"] + [ln + ",admin,pw" for ln in lines[1:]]
    r = post(c, admin, "\n".join(added) + "\n").json()
    assert "モデル" in r["ignored_columns"] and "シリアル番号" in r["ignored_columns"]
    assert r["error"] == 0 and r["skip"] == r["total"]


def test_template_and_permissions(ctx):
    c, admin, op, viewer = ctx["c"], ctx["admin"], ctx["op"], ctx["viewer"]
    r = c.get("/api/devices/import/template", headers=admin)
    assert r.status_code == 200 and r.content.startswith("﻿".encode())
    header = r.content.decode("utf-8-sig").splitlines()[0].split(",")
    ledger = c.get("/api/devices/export", headers=admin).content.decode("utf-8-sig").splitlines()[0].split(",")
    common = {"名前", "ホスト / IP", "ポート", "グループ", "機種", "踏み台", "有効", "説明"}
    assert common <= set(header) and common <= set(ledger)
    assert {"ユーザー名", "パスワード"} <= set(header)
    # ひな形をそのまま取り込んでも、パスワードが空なので登録されない
    res = post(c, admin, r.content, dry_run=False).json()
    assert res["created"] == 0 and res["error"] == res["total"] == 2
    for h in (op, viewer):
        assert c.get("/api/devices/import/template", headers=h).status_code == 403
        assert post(c, h, HEADER + "\n").status_code == 403
    assert c.get("/api/devices/import/template").status_code == 401
    assert c.post("/api/devices/import", files={"file": ("d.csv", b"x")}).status_code == 401
