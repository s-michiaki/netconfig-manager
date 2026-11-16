"""ターミナルの画面出力を読めるテキストに直す"""
import json

import pytest

from app.services import terminal_text as tt


@pytest.mark.parametrize("raw, expected", [
    # ふつうの出力（CRLF）
    ("R1#show clock\r\n12:00:00 JST\r\nR1#", "R1#show clock\n12:00:00 JST\nR1#\n"),
    # Backspace での打ち直し（機器は「\b \b」で 1 文字消す）
    ("R1#shwo\b \b\b \bow version\r\n", "R1#show version\n"),
    # --More-- を消して続きを表示（行頭へ戻って空白で上書き → 行頭へ）
    ("line1\r\n --More-- \r         \rline2\r\n", "line1\nline2\n"),
    # --More-- を Backspace の列で消す機種
    ("line1\r\n --More-- \b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\bline2\r\n", "line1\nline2\n"),
    # 行の消去（ESC[K / ESC[2K）と色
    ("\x1b[1;32mR1#\x1b[0m show x\r\x1b[Kok\r\n", "ok\n"),
    ("abcdef\r\x1b[2Kxy\r\n", "xy\n"),
    ("abcdef\x1b[3D\x1b[KXY\r\n", "abcXY\n"),
    # カーソルを左へ動かして上書き、文字の削除と挿入
    ("show ip route\x1b[5Dbrief\r\n", "show ip brief\n"),
    ("abcdef\x1b[4D\x1b[2P\r\n", "abef\n"),
    ("abef\x1b[2D\x1b[2@cd\r\n", "abcdef\n"),
    # ウィンドウタイトル（OSC）とキーパッドの切り替えは捨てる
    ("\x1b]0;admin@fw: ~\x07admin@fw> \x1b=\x1b>show\r\n", "admin@fw> show\n"),
    # 日本語、タブ
    ("説明: 本社\tコア\r\n", "説明: 本社  コア\n"),
    # 画面全体の書き換え（位置指定・画面消去）は改行として扱う。行末の空白と最後の空行は落とす
    ("top\x1b[2J\x1b[Hnext   \r\n\r\n\r\n", "top\nnext\n"),
    # BEL などの制御文字は捨てる
    ("a\x07b\x00c\r\n", "abc\n"),
])
def test_render(raw, expected):
    assert tt.render([raw]) == expected


def test_render_split_sequences_and_limits():
    # 制御シーケンスが出力の区切りで分かれていても解釈する
    assert tt.render(["R1#\x1b", "[1;3", "1mred\x1b[0", "m\r\n"]) == "R1#red\n"
    assert tt.render(["x\x1b]0;ti", "tle\x07y\r\n"]) == "xy\n"
    # 1 文字ずつ届いても同じ結果
    raw = "R1#shwo\b \b\b \bow\r\n\x1b[32mOK\x1b[0m\r\n"
    assert tt.render(list(raw)) == tt.render([raw]) == "R1#show\nOK\n"
    # 壊れた出力で 1 行が際限なく伸びない
    assert len(tt.render(["x" * (tt.MAX_LINE + 500)])) == tt.MAX_LINE + 1
    assert tt.render([]) == "" and tt.render(["\r\n\r\n"]) == ""


def test_cast_to_text():
    cast = "\n".join([
        json.dumps({"version": 2, "width": 120, "height": 40}),
        json.dumps([0.1, "o", "R1#sh"]),
        json.dumps([0.2, "r", "100x30"]),  # 画面サイズの変更は出力ではない
        json.dumps([0.3, "o", "ow ver\r\nIOS 15.2\r\n"]),
        "broken line",
        json.dumps([0.4, "o", "R1#"]),
    ])
    assert tt.cast_to_text(cast) == "R1#show ver\nIOS 15.2\nR1#\n"


# ---- セッション終了時の保存と、監査ログからの閲覧・ダウンロード・検索
import asyncio  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from datetime import timedelta  # noqa: E402
from pathlib import Path  # noqa: E402

import fake_sshd  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal  # noqa: E402
from app.core.timeutil import utcnow  # noqa: E402
from app.main import app  # noqa: E402
from app.models.audit import TerminalSession  # noqa: E402
from app.services.audit import TerminalRecorder, purge_old, text_path_for  # noqa: E402


def login(c, u="admin", p="initial-pass-123"):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


def run_session(c, admin, device_id, commands):
    token = admin["Authorization"].split()[1]
    with c.websocket_connect(f"/api/terminal/ws/{device_id}") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token, "cols": 100, "rows": 30}))
        assert "R1#" in ws.receive_text()
        for cmd, until in commands:
            ws.send_text(json.dumps({"type": "input", "data": cmd + "\r"}))
            buf, deadline = "", time.time() + 10
            while until not in buf and time.time() < deadline:
                buf += ws.receive_text()
        time.sleep(0.3)


def test_text_is_saved_viewed_downloaded_and_searched():
    port, _, _ = fake_sshd.start()
    with TestClient(app) as c:
        admin = login(c)
        tag = uuid.uuid4().hex[:6]
        name = f"txt-{tag}"
        d = c.post("/api/devices/", json=dict(name=name, hostname="127.0.0.1", port=port, platform="cisco_ios",
                                              username="admin", password="pw"), headers=admin).json()
        c.post("/api/users/", json={"username": f"txt-op-{tag}", "password": "password-1234", "role": "operator"}, headers=admin)
        op = login(c, f"txt-op-{tag}", "password-1234")
        try:
            run_session(c, admin, d["id"], [("show running-config", "description")])
            for _ in range(50):
                s = c.get("/api/audit/terminal-sessions", params={"device": name}, headers=admin).json()
                if s["items"] and s["items"][0]["ended_at"]:
                    break
                time.sleep(0.1)
            item = s["items"][0]
            assert item["has_recording"] and item["has_text"]
            url = f"/api/audit/terminal-sessions/{item['id']}/text"

            # 読める形のテキスト: 制御文字が無く、打ったコマンド（機器のエコー）と結果が上から読める
            r = c.get(url, headers=admin)
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
            text = r.text
            assert "\x1b" not in text and "\r" not in text
            assert "R1#show running-config" in text and "hostname R1" in text and "日本語の説明" in text
            assert "content-disposition" not in r.headers
            # ファイルは暗号化して保存している（そのままでは読めない）
            f = next(Path(settings.TERMINAL_LOG_PATH).rglob(f"{item['id']}.txt.enc"))
            raw = f.read_text(encoding="utf-8")
            assert "hostname" not in raw and raw.startswith("gAAAA")
            # ダウンロード: 日本語を含んでも失敗しないファイル名
            r = c.get(url, params={"download": True}, headers=admin)
            cd = r.headers["content-disposition"]
            assert r.status_code == 200 and "attachment" in cd and f"terminal_admin_{name}_" in cd and ".txt" in cd
            # 見たこと・持ち出したことは操作履歴に残る
            views = c.get("/api/audit/logs", params={"action": "audit.view_recording", "q": name}, headers=admin).json()
            assert views["total"] >= 2 and "テキスト" in str(views["items"][0]["detail"])
            # 管理者だけ
            assert c.get(url, headers=op).status_code == 403
            assert c.get("/api/audit/terminal-sessions/nope/text", headers=admin).status_code == 404

            # 検索: 打ったコマンドや出力の文字列からセッションを探す
            def search(**kw):
                return c.post("/api/audit/terminal-sessions/search", json=kw, headers=admin)

            res = search(query="hostname r1", device=name).json()
            assert res["searched"] == 1 and [x["id"] for x in res["items"]] == [item["id"]]
            hit = res["items"][0]
            assert hit["count"] >= 1 and hit["username"] == "admin" and hit["device_name"] == name
            line = hit["lines"][0]
            assert [line["text"][a:b] for a, b in line["ranges"]] == ["hostname R1"]
            assert search(query="hostname r1", device=name, case_sensitive=True).json()["items"] == []
            assert len(search(query=r"^R1#show\s+running", mode="regex", device=name).json()["items"]) == 1
            assert search(query="no-such-text-" + tag, device=name).json()["items"] == []
            assert search(query="hostname", device=name, username="nobody").json()["searched"] == 0
            assert search(query="(", mode="regex").status_code == 422 and search(query="  ").status_code == 422
            assert c.post("/api/audit/terminal-sessions/search", json={"query": "x"}, headers=op).status_code == 403
            # 検索したことは残すが、検索語は残さない
            logs = c.get("/api/audit/logs", params={"action": "audit.search_recording"}, headers=admin).json()
            assert logs["total"] >= 1 and "no-such-text-" + tag not in json.dumps(logs, ensure_ascii=False)
        finally:
            c.delete(f"/api/devices/{d['id']}", headers=admin)


def test_text_setting_plain_and_purge(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "TERMINAL_LOG_PATH", str(tmp_path))
    started = utcnow()
    # 平文で記録する設定なら、テキストも平文（.txt）
    monkeypatch.setattr(settings, "TERMINAL_LOG_ENCRYPT", False)
    rec = TerminalRecorder("s-plain", started, 80, 24, "t")
    rec.output("R1#shwo\b \b\b \bow\r\n\r\nline2\r\n")
    rec.close()
    assert rec.write_text() is True
    out = text_path_for(rec.path)
    assert out.name == "s-plain.txt" and out.read_text(encoding="utf-8") == "R1#show\n\nline2\n"
    # 暗号化する設定: 空行も保ったまま読み戻せる
    monkeypatch.setattr(settings, "TERMINAL_LOG_ENCRYPT", True)
    rec = TerminalRecorder("s-enc", started, 80, 24, "t")
    rec.output("a\r\n\r\nb\r\n")
    rec.close()
    assert rec.write_text() is True
    from app.services.audit import read_text_log
    enc = text_path_for(rec.path)
    assert enc.name == "s-enc.txt.enc" and read_text_log(enc) == "a\n\nb\n"
    # 無効にすると作らない
    monkeypatch.setattr(settings, "TERMINAL_LOG_TEXT", False)
    rec = TerminalRecorder("s-off", started, 80, 24, "t")
    rec.output("x\r\n")
    rec.close()
    assert rec.write_text() is False and not text_path_for(rec.path).exists()

    # 保持期間を過ぎたら、再生用の記録と一緒にテキストも消す
    async def run():
        old = utcnow() - timedelta(days=400)
        sid = str(uuid.uuid4())
        cast = tmp_path / "old" / f"{sid}.cast.enc"
        cast.parent.mkdir(parents=True, exist_ok=True)
        cast.write_text("x\n")
        text = text_path_for(cast)
        text.write_text("x\n")
        async with AsyncSessionLocal() as db:
            db.add(TerminalSession(id=sid, started_at=old, log_file=f"old/{sid}.cast.enc", bytes_out=0, truncated=False,
                                   cols=80, rows=24))
            await db.commit()
            await purge_old(db)
        return cast.exists(), text.exists()

    assert asyncio.run(run()) == (False, False)
