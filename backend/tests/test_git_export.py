"""コンフィグ履歴の外部 Git への push（手元の bare リポジトリを相手にする）"""
import json
import os
import subprocess
import uuid
from pathlib import Path

import git
import pytest
import redis
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.main import app
from app.services import config_service as cs
from app.services import git_export


def login(c, u, p):
    return {"Authorization": "Bearer " + c.post("/api/auth/token", data={"username": u, "password": p}).json()["access_token"]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    remote = tmp_path / "remote.git"
    git.Repo.init(remote, bare=True)
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", str(remote))
    monkeypatch.setattr(settings, "GIT_EXPORT_PATH", str(tmp_path / "export"))
    monkeypatch.setattr(settings, "GIT_EXPORT_BRANCH", "main")
    r = redis.Redis.from_url(settings.REDIS_URL)  # システム状態（API）と同じ Redis を使う
    r.delete(git_export.STATE_KEY, git_export.PENDING_KEY)
    monkeypatch.setattr(worker, "_redis", lambda: r)
    with TestClient(app) as c:
        admin = login(c, "admin", "initial-pass-123")
        t = uuid.uuid4().hex[:6]
        g = c.post("/api/device-groups/", json={"name": f"本社/{t}"}, headers=admin).json()
        devs = [c.post("/api/devices/", json=dict(name=f"gx-{n}-{t}", hostname=f"10.70.0.{i}", platform="cisco_ios",
                                                  username="u", password="p", group_id=g["id"] if n == "a" else None),
                       headers=admin).json() for i, n in enumerate(("a", "b"), 1)]
        yield {"c": c, "admin": admin, "remote": remote, "devs": devs, "group": g, "t": t, "r": r}
        for d in devs:
            c.delete(f"/api/devices/{d['id']}", headers=admin)
        r.delete(git_export.STATE_KEY, git_export.PENDING_KEY)


def system_component(env):
    """システム状態の「外部 Git への push」（テストの API は偽の Redis を使うため、worker が書いた記録を渡して確かめる）"""
    import asyncio

    from app.services import login_limit, system

    class Client:
        async def get(self, key):
            return env["r"].get(key)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(login_limit, "client", lambda: Client())
        return asyncio.run(system.check_git_export())


def remote_files(remote: Path) -> dict[str, str]:
    repo = git.Repo(remote)
    tree = repo.commit("main").tree
    return {b.path: b.data_stream.read().decode() for b in tree.traverse() if b.type == "blob"}


def test_sync_pushes_readable_tree(env):
    c, admin, a, b, t = env["c"], env["admin"], env["devs"][0], env["devs"][1], env["t"]
    cs.save_config(a["id"], "hostname a\ninterface Gi0/1\n", "manual")
    cs.save_config(b["id"], "hostname b\n", "manual")
    res = worker.git_export_sync.apply().get()
    assert res["ok"] and res["committed"] and res["pushed"]
    files = remote_files(env["remote"])
    # グループ名の「/」はファイル名に使えないので「_」。グループなしは「未分類」
    assert files[f"本社_{t}/gx-a-{t}.txt"] == "hostname a\ninterface Gi0/1\n"
    assert files[f"未分類/gx-b-{t}.txt"] == "hostname b\n"
    assert f"[gx-a-{t}]" in files["README.md"]
    # 変わっていなければコミットも push もしない
    head = git.Repo(env["remote"]).commit("main").hexsha
    assert worker.git_export_sync.apply().get()["committed"] is False
    assert git.Repo(env["remote"]).commit("main").hexsha == head
    # 変更・改名・削除
    cs.save_config(a["id"], "hostname a\ninterface Gi0/2\n", "schedule")
    c.put(f"/api/devices/{b['id']}", json={"name": f"gx-b2-{t}"}, headers=admin)
    worker.git_export_sync.apply().get()
    commit = git.Repo(env["remote"]).commit("main")
    assert f"gx-a-{t}" in commit.message and f"gx-b2-{t}" in commit.message
    files = remote_files(env["remote"])
    assert "Gi0/2" in files[f"本社_{t}/gx-a-{t}.txt"]
    assert f"未分類/gx-b-{t}.txt" not in files and f"未分類/gx-b2-{t}.txt" in files
    c.delete(f"/api/devices/{a['id']}", headers=admin)
    worker.git_export_sync.apply().get()
    files = remote_files(env["remote"])
    assert not any(p.startswith(f"本社_{t}/") for p in files)
    # システム状態とアクティビティ
    comp = system_component(env)
    assert comp.status == "ok" and comp.detail["branch"] == "main"
    acts = c.get("/api/activity/logs", params={"event": "export.pushed"}, headers=admin).json()["items"]
    assert acts and "push しました" in acts[0]["message"]


def test_push_failure_is_reported(env, monkeypatch, tmp_path):
    c, admin = env["c"], env["admin"]
    cs.save_config(env["devs"][0]["id"], "hostname a\n", "manual")
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", str(tmp_path / "no-such-repo.git"))
    res = worker.git_export_sync.apply().get()
    assert res["ok"] is False and "リポジトリが見つかりません" in res["error"]
    comp = system_component(env)
    assert comp.status == "error" and "push に失敗しています" in comp.summary
    acts = c.get("/api/activity/logs", params={"event": "export.failed"}, headers=admin).json()["items"]
    n = len(acts)
    assert n >= 1
    # 同じ失敗が続いてもアクティビティは増やさない
    worker.git_export_sync.apply().get()
    assert len(c.get("/api/activity/logs", params={"event": "export.failed"}, headers=admin).json()["items"]) == n
    # 相手のブランチが先に進んでいる（直接変更された）と、push を拒否された旨を出す
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", str(env["remote"]))
    assert worker.git_export_sync.apply().get()["ok"]
    other = tmp_path / "other"
    o = git.Repo.clone_from(str(env["remote"]), other, branch="main")
    (other / "x.txt").write_text("x")
    o.index.add(["x.txt"])
    o.index.commit("直接の変更")
    o.remote().push("HEAD:refs/heads/main")
    cs.save_config(env["devs"][0]["id"], "hostname a2\n", "manual")
    res = worker.git_export_sync.apply().get()
    assert res["ok"] is False and "こちらに無いコミット" in res["error"]
    # 今すぐ push（管理者のみ）
    with pytest.MonkeyPatch.context() as mp:
        called = []
        mp.setattr(worker.git_export_sync, "delay", lambda: called.append(1))
        assert c.post("/api/system/git-export", headers=admin).status_code == 202 and called
        mp.setattr(settings, "GIT_EXPORT_URL", "")
        assert c.post("/api/system/git-export", headers=admin).status_code == 409


def test_schedule_is_debounced(env, monkeypatch):
    calls = []
    monkeypatch.setattr(worker.git_export_sync, "apply_async", lambda **kw: calls.append(kw))
    worker.schedule_git_export()
    worker.schedule_git_export()
    assert calls == [{"countdown": settings.GIT_EXPORT_DELAY_SEC}]
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "")
    env["r"].delete(git_export.PENDING_KEY)
    worker.schedule_git_export()
    assert len(calls) == 1


def test_helpers(tmp_path):
    assert git_export.mask_url("https://user:secret@gitlab.local/a.git") == "https://***@gitlab.local/a.git"
    assert git_export.safe_name("../a:b*c") == "_a_b_c" and git_export.safe_name("...") == "_"
    D = git_export.DeviceFile
    layout = git_export._layout([D("11111111-x", "sw/1", "h", "p", None), D("22222222-y", "sw:1", "h", "p", None)])
    assert sorted(layout) == ["未分類/sw_1.txt", "未分類/sw_1_22222222.txt"]
    # HTTPS の認証情報は環境変数から返す（URL や設定ファイルに書かない）
    script = git_export._askpass_script(str(tmp_path))
    env = {**os.environ, "NCM_GIT_USERNAME": "oauth2", "NCM_GIT_TOKEN": "tok-123"}
    assert subprocess.run([script, "Username for 'https://x'"], env=env, capture_output=True, text=True).stdout == "oauth2"
    assert subprocess.run([script, "Password for 'https://x'"], env=env, capture_output=True, text=True).stdout == "tok-123"
    assert json.loads(json.dumps({"ok": True}))["ok"]
