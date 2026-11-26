"""コンフィグ履歴の外部 Git への push（手元の bare リポジトリを相手にする）"""
import json
import os
import subprocess
import uuid
from pathlib import Path

import fakeredis
import git
import pytest
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
    r = fakeredis.FakeRedis()  # worker が結果を書く Redis（システム状態の確認では system_component で渡す）
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
    env = {**os.environ, "NCM_GIT_USERNAME": "oauth2", "NCM_GIT_TOKEN": "tok-123", "NCM_GIT_SCHEME": "https",
           "NCM_GIT_HOST": "git.example.test:8443"}

    def ask(prompt, **kw):
        r = subprocess.run([script, prompt], env={**env, **kw}, capture_output=True, text=True)
        return r.returncode, r.stdout

    # 宛先の Git サーバーについての問いには答える
    assert ask("Username for 'https://git.example.test:8443': ") == (0, "oauth2")
    assert ask("Password for 'https://oauth2@git.example.test:8443': ") == (0, "tok-123")
    assert ask("Password for 'https://oauth2@git.example.test:8443/net/a.git': ") == (0, "tok-123")
    # プロキシ・ほかのホスト・別のポート・別の scheme の問いには答えない（トークンを渡さない）
    for prompt in ("Password for 'http://user01@proxy.example.test:3128': ", "Username for 'http://proxy.example.test:3128': ",
                   "Password for 'https://oauth2@git.example.test': ", "Password for 'https://oauth2@git.example.test:8443.evil.test': ",
                   "Password for 'http://oauth2@git.example.test:8443': ", "Password for 'https://git.example.test:84430': ",
                   "Password: ", ""):
        assert ask(prompt) == (1, ""), prompt
    assert ask("Password for 'https://oauth2@git.example.test:8443': ", NCM_GIT_HOST="") == (1, "")
    # ホストに sh の特別な文字があっても、文字どおりに比べる（パターンとして解釈しない）
    assert ask("Password for 'https://oauth2@a.example.test': ", NCM_GIT_HOST="*") == (1, "")
    assert json.loads(json.dumps({"ok": True}))["ok"]


def test_url_credentials_are_not_stored(tmp_path, monkeypatch):
    """#14: GIT_EXPORT_URL に書いた認証情報は .git/config・エラー表示に残さず、システム状態で注意を出す"""
    split = git_export.split_url
    assert split("https://u%40x:p%2Fw@gitlab.local:8443/a.git") == ("https://gitlab.local:8443/a.git", "u@x", "p/w")
    assert split("https://tok@gitlab.local/a.git") == ("https://gitlab.local/a.git", "tok", "")
    assert split("git@gitea.local:net/a.git") == ("git@gitea.local:net/a.git", "", "")  # SSH の git@ は対象外
    assert split("https://gitlab.local/a.git")[1:] == ("", "")
    assert git_export.url_has_credentials(" https://u:p@h/a.git ") and not git_export.url_has_credentials("/srv/a.git")

    repo = git.Repo.init(tmp_path / "w")
    (tmp_path / "w" / "a.txt").write_text("x")
    repo.index.add(["a.txt"])
    repo.index.commit("init")
    repo.create_remote("origin", "https://u:old-secret@127.0.0.1:1/a.git")  # 以前の版で保存された URL
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://u:new-secret@127.0.0.1:1/a.git")
    monkeypatch.setattr(settings, "GIT_EXPORT_TOKEN", "")
    monkeypatch.setattr(settings, "GIT_EXPORT_TIMEOUT", 10)
    with pytest.raises(RuntimeError) as e:
        git_export.push(repo)  # つながらない相手。push の前に origin を書き直している
    assert "secret" not in str(e.value)
    config = (tmp_path / "w" / ".git" / "config").read_text()
    assert "secret" not in config and "https://127.0.0.1:1/a.git" in config


def test_status_warns_url_credentials(env, monkeypatch):
    env["r"].set(git_export.STATE_KEY, json.dumps({"ok": True, "message": "push しました"}))
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://u:secret@gitlab.local/a.git")
    comp = system_component(env)
    assert comp.status == "warn" and "GIT_EXPORT_TOKEN" in comp.summary and "secret" not in json.dumps(comp.detail)


# ---------------------------------------------------------------- プロキシ（OUTBOUND_PROXY）と追加の CA


PX_USER, PX_PASS = "git-proxy-MARKU", "pw@MARK:P"
PX_ENC = "pw%40MARK%3AP"


def _no_secret(text: str) -> bool:
    import base64

    tok = base64.b64encode(f"{PX_USER}:{PX_PASS}".encode()).decode()
    return not any(s in text for s in ("MARKU", "MARK:P", PX_ENC, tok))


@pytest.fixture
def outbound_settings(monkeypatch):
    for k in ("OUTBOUND_PROXY", "OUTBOUND_NO_PROXY", "OUTBOUND_CA_FILE", "GIT_EXPORT_CA_FILE", "GIT_EXPORT_TOKEN",
              "GIT_EXPORT_SSH_KEY"):
        monkeypatch.setattr(settings, k, "")
    monkeypatch.setattr(settings, "GIT_EXPORT_TIMEOUT", 20)
    # コンテナの環境に何か入っていても使わないこと（git のプロセスへは明示的に空を渡す）
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
    monkeypatch.setenv("https_proxy", "http://env-proxy.invalid:1")


@pytest.mark.parametrize("url,proxied", [
    ("https://git.example.test/net/configs.git", True),
    ("https://user:tok@git.example.test/net/configs.git", True),
    ("https://intranet.example.test/net/configs.git", False),  # OUTBOUND_NO_PROXY
    ("https://localhost:8443/net/configs.git", False),  # 内向き
    ("git@git.example.test:net/configs.git", False),  # SSH は HTTP のプロキシを通せない（直接）
    ("ssh://git@git.example.test/net/configs.git", False),
    ("/srv/git/configs.git", False),
])
def test_proxy_env_for_git(outbound_settings, monkeypatch, url, proxied):
    proxy = f"http://{PX_USER}:{PX_ENC}@proxy.example.test:3128"
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", proxy)
    monkeypatch.setattr(settings, "OUTBOUND_NO_PROXY", "intranet.example.test")
    env = git_export.proxy_env(git_export.split_url(url)[0])
    assert set(env) == {*git_export._PROXY_VARS, "GIT_HTTP_PROXY_AUTHMETHOD"}  # 使わないときも、すべて（空で）渡す
    vars_ = {k: v for k, v in env.items() if k != "GIT_HTTP_PROXY_AUTHMETHOD"}
    if proxied:
        assert env["https_proxy"] == env["HTTPS_PROXY"] == proxy
        assert all(vars_[k] == "" for k in vars_ if k.lower() != "https_proxy")
        assert env["GIT_HTTP_PROXY_AUTHMETHOD"] == "basic"  # 認証情報があれば最初の CONNECT から Basic
    else:
        assert all(v == "" for v in vars_.values()) and env["GIT_HTTP_PROXY_AUTHMETHOD"] == "anyauth"
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "")
    env = git_export.proxy_env(url)
    assert all(v == "" for k, v in env.items() if k != "GIT_HTTP_PROXY_AUTHMETHOD")
    assert env["GIT_HTTP_PROXY_AUTHMETHOD"] == "anyauth"
    # 認証なしのプロキシ・空のパスワードを明示したプロキシ
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy.example.test:3128")
    if proxied:
        assert git_export.proxy_env(url)["GIT_HTTP_PROXY_AUTHMETHOD"] == "anyauth"
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://user01:@proxy.example.test:3128")
        assert git_export.proxy_env(url)["GIT_HTTP_PROXY_AUTHMETHOD"] == "basic"


def test_plain_http_git_is_not_sent_via_proxy(outbound_settings, monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy.example.test:3128")
    with pytest.raises(RuntimeError, match="平文"):
        git_export.proxy_env("http://git.example.test/a.git")
    monkeypatch.setattr(settings, "OUTBOUND_NO_PROXY", "git.example.test")
    assert git_export.proxy_env("http://git.example.test/a.git")["http_proxy"] == ""


def _work_repo(tmp_path):
    repo = git.Repo.init(tmp_path / "w")
    (tmp_path / "w" / "a.txt").write_text("x")
    repo.index.add(["a.txt"])
    repo.index.commit("init")
    return repo


def test_push_passes_proxy_by_env_only_and_scrubs_stderr(outbound_settings, monkeypatch, tmp_path, caplog):
    """プロキシは環境変数だけで渡す（引数・.git/config に無い）。git の stderr の URL・認証情報は伏せる"""
    import logging

    caplog.set_level(logging.DEBUG)
    proxy = f"http://{PX_USER}:{PX_ENC}@proxy.example.test:3128"
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", proxy)
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://git.example.test/net/configs.git")
    seen = {}

    real_execute = git.Git.execute

    def fake_execute(self, command, **kw):
        if "push" not in command:
            return real_execute(self, command, **kw)
        seen["cmd"], seen["env"] = list(command), dict(self._environment)
        raise git.GitCommandError(command, 128, stderr=(
            f"fatal: unable to access 'https://git.example.test/net/configs.git/': "
            f"Received HTTP code 407 from proxy after CONNECT ({proxy}) Proxy-Authorization: Basic xyzxyzxyz"))

    monkeypatch.setattr(git.Git, "execute", fake_execute)
    repo = _work_repo(tmp_path)
    with pytest.raises(RuntimeError) as e:
        git_export.push(repo)
    msg = str(e.value)
    assert "プロキシの認証に失敗しました" in msg and _no_secret(msg) and "xyzxyzxyz" not in msg
    assert seen["env"]["https_proxy"] == proxy and seen["env"]["no_proxy"] == "" and seen["env"]["ALL_PROXY"] == ""
    assert _no_secret(" ".join(seen["cmd"])) and "proxy" not in " ".join(seen["cmd"]).lower()
    assert _no_secret((tmp_path / "w" / ".git" / "config").read_text())
    assert "proxy" not in (tmp_path / "w" / ".git" / "config").read_text()
    assert _no_secret(caplog.text)


def test_sync_error_has_no_proxy_secrets(env, outbound_settings, monkeypatch, caplog):
    """last_error（Redis）・システム状態・アクティビティ・ログにプロキシの認証情報を残さない"""
    import logging

    caplog.set_level(logging.DEBUG)
    c, admin = env["c"], env["admin"]
    proxy = f"http://{PX_USER}:{PX_ENC}@proxy.example.test:3128"
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", proxy)
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://git.example.test/net/configs.git")

    real_execute = git.Git.execute

    def fake_execute(self, command, **kw):
        if "push" not in command:
            return real_execute(self, command, **kw)
        raise git.GitCommandError(command, 128, stderr=f"fatal: unable to access via {proxy}: Could not resolve proxy")

    cs.save_config(env["devs"][0]["id"], "hostname a\n", "manual")
    with monkeypatch.context() as mp:
        mp.setattr(git.Git, "execute", fake_execute)
        res = worker.git_export_sync.apply().get()
    assert res["ok"] is False and "接続できません" in res["error"]
    comp = system_component(env)
    acts = c.get("/api/activity/logs", params={"event": "export.failed"}, headers=admin).text
    st = c.get("/api/system/status", headers=admin).text
    for text in (json.dumps(res, ensure_ascii=False), env["r"].get(git_export.STATE_KEY).decode(),
                 json.dumps(comp.detail, ensure_ascii=False), comp.summary, acts, st, caplog.text):
        assert _no_secret(text), text


@pytest.fixture(params=["body", "anyauth"])
def authmethod(request, monkeypatch):
    """本物の git の試験を 2 通りで回す: body=本体の proxy_env のまま（認証情報があれば basic）／
    anyauth=GIT_HTTP_PROXY_AUTHMETHOD を上書きして「認証なしの CONNECT → 407 → 認証つきの CONNECT」の流れにする
    （新しい git＝libcurl の既定の動き。手元の古い git でも同じ流れを確かめるため）"""
    if request.param == "anyauth":
        real = git_export.proxy_env
        monkeypatch.setattr(git_export, "proxy_env", lambda url: {**real(url), "GIT_HTTP_PROXY_AUTHMETHOD": "anyauth"})
    return request.param


def _any_connect_has(px, header: str) -> bool:
    return any(header in c for c in px.connects)


def _real_push(repo, monkeypatch):
    monkeypatch.setattr(settings, "GIT_EXPORT_URL", "https://git.example.test/net/configs.git")
    with pytest.raises(RuntimeError) as e:
        git_export.push(repo)
    return str(e.value)


def test_real_git_goes_through_proxy_with_ca_bundle(outbound_settings, monkeypatch, tmp_path, authmethod):
    """本物の git（curl）: 環境変数のプロキシへ CONNECT し（Basic）、追加の CA を束ねたもので TLS を検証する"""
    import base64

    from fake_proxy import FakeProxy, TestCA

    ca = TestCA("Example Corp CA")
    repo = _work_repo(tmp_path)
    tok = base64.b64encode(f"{PX_USER}:{PX_PASS}".encode()).decode()
    # 407: プロキシの認証に失敗（認証情報は CONNECT にだけ載り、文には出ない）
    with FakeProxy(ca, mode="407") as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(PX_USER, PX_ENC))
        msg = _real_push(repo, monkeypatch)
    assert px.connects and all(c.startswith("CONNECT git.example.test:443") for c in px.connects)
    assert _any_connect_has(px, f"Proxy-Authorization: Basic {tok}")
    if authmethod == "body":
        assert f"Proxy-Authorization: Basic {tok}" in px.connects[0]  # basic: 最初の CONNECT から付ける
    else:  # anyauth: 認証なしの CONNECT → 407 → 認証つきの CONNECT（新しい git の既定の流れ）を通っている
        assert "Proxy-Authorization" not in px.connects[0] and len(px.connects) >= 2
    assert "プロキシの認証に失敗しました" in msg and _no_secret(msg), msg

    def not_found(method, path, headers, body):
        return 404, {"Content-Type": "text/plain"}, b"not found"

    # HTTPS を検査するプロキシ: 追加の CA なしでは証明書エラー、OUTBOUND_CA_FILE があれば宛先（ここでは 404）まで届く
    with FakeProxy(ca, auth=(PX_USER, PX_PASS), respond=not_found) as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(PX_USER, PX_ENC))
        msg = _real_push(repo, monkeypatch)
        assert "証明書を確認できません" in msg and "OUTBOUND_CA_FILE" in msg, msg
        ca_file = ca.write_pem(tmp_path / "corp-ca.pem")
        monkeypatch.setattr(settings, "OUTBOUND_CA_FILE", str(ca_file))
        bundles = []
        real_bundle = git_export._ca_bundle

        def spy(url, tmp):
            env, opts = real_bundle(url, tmp)
            bundles.append((env, opts, Path(env["GIT_SSL_CAINFO"]).read_bytes()))
            return env, opts

        monkeypatch.setattr(git_export, "_ca_bundle", spy)
        msg = _real_push(repo, monkeypatch)
        assert "証明書" not in msg and "リポジトリが見つかりません" in msg, msg
        assert px.inner and px.inner[0]["path"].startswith("/net/configs.git/info/refs")
        assert _any_connect_has(px, f"Proxy-Authorization: Basic {tok}")  # プロキシの認証が通って宛先まで届いた
    env_, opts, data = bundles[0]
    assert not opts and ca.pem() in data and data.count(b"BEGIN CERTIFICATE") > 1  # OS の束＋追加の CA
    assert not Path(env_["GIT_SSL_CAINFO"]).exists()  # 終わったら消す
    assert _no_secret(msg)


def test_ca_bundle_with_git_export_ca_file(outbound_settings, monkeypatch, tmp_path):
    from fake_proxy import TestCA

    corp, own = TestCA("Example Corp CA"), TestCA("Example Git CA")
    own_file = own.write_pem(tmp_path / "git-ca.pem")
    monkeypatch.setattr(settings, "GIT_EXPORT_CA_FILE", str(own_file))
    url = "https://git.example.test/a.git"
    # 追加の CA なし: 今までどおり（GIT_EXPORT_CA_FILE を http.sslCAInfo に）
    assert git_export._ca_bundle(url, str(tmp_path)) == ({}, ["-c", f"http.sslCAInfo={own_file}"])
    # 両方: GIT_EXPORT_CA_FILE ＋ OUTBOUND_CA_FILE を束ねて http.sslCAInfo に（OS の信頼は使わない）
    monkeypatch.setattr(settings, "OUTBOUND_CA_FILE", str(corp.write_pem(tmp_path / "corp.pem")))
    env, opts = git_export._ca_bundle(url, str(tmp_path))
    bundle = Path(opts[1].split("=", 1)[1])
    assert env == {} and bundle.read_bytes() == own.pem() + corp.pem()
    # SSH・ローカルのパスでは束ねない
    assert git_export._ca_bundle("git@git.example.test:a.git", str(tmp_path)) == ({}, ["-c", f"http.sslCAInfo={own_file}"])


def _spy_askpass(monkeypatch, tmp_path):
    """askpass への問いを記録する（本物の askpass へそのまま渡す）"""
    log = tmp_path / "askpass.log"
    real = git_export._askpass_script

    def wrapper(tmp):
        inner = real(tmp)
        p = os.path.join(tmp, "askpass-spy.sh")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$1" >> "{log}"\nexec "{inner}" "$1"\n')
        os.chmod(p, 0o700)
        return p

    monkeypatch.setattr(git_export, "_askpass_script", wrapper)
    return log


def test_git_token_is_never_sent_to_proxy(outbound_settings, monkeypatch, tmp_path, authmethod):
    """H1: ユーザー名だけのプロキシで git がプロキシのパスワードを聞いても、askpass は GIT_EXPORT_TOKEN を答えない"""
    import base64

    from fake_proxy import FakeProxy, TestCA

    token = "glpat-TOKEN-MARK"
    monkeypatch.setattr(settings, "GIT_EXPORT_TOKEN", token)
    monkeypatch.setattr(settings, "GIT_EXPORT_USERNAME", "oauth2")
    log = _spy_askpass(monkeypatch, tmp_path)
    repo = _work_repo(tmp_path)
    with FakeProxy(TestCA(), mode="407") as px:
        # 設定の検査では弾く形（ユーザー名だけ）を、検査をすり抜けた想定で git に直接渡す
        user_only = f"http://user01@127.0.0.1:{px.port}"
        with pytest.raises(ValueError, match="パスワードも書いてください"):
            from app.core import outbound
            outbound.parse_proxy(user_only)
        method = "anyauth" if authmethod == "anyauth" else "basic"
        monkeypatch.setattr(git_export, "proxy_env", lambda url: {**dict.fromkeys(git_export._PROXY_VARS, ""),
                                                                  "https_proxy": user_only, "HTTPS_PROXY": user_only,
                                                                  "GIT_HTTP_PROXY_AUTHMETHOD": method})
        msg = _real_push(repo, monkeypatch)
    prompts = log.read_text() if log.exists() else ""
    assert f"127.0.0.1:{px.port}" in prompts  # git はプロキシのパスワードを聞いた（試験が成り立っている）
    leaked = base64.b64encode(f"user01:{token}".encode()).decode()
    # askpass が答えないので、git は接続の前にやめる（接続したとしても、トークンは載らない）
    assert not any(leaked in c or token in c for c in px.connects)
    assert token not in msg


def test_git_empty_proxy_password_is_not_asked(outbound_settings, monkeypatch, tmp_path, authmethod):
    """user:@（空のパスワードを明示）なら、git はプロキシのパスワードを聞き返さず、空のパスワードで Basic を送る"""
    import base64

    from fake_proxy import FakeProxy, TestCA

    monkeypatch.setattr(settings, "GIT_EXPORT_TOKEN", "glpat-TOKEN-MARK")
    log = _spy_askpass(monkeypatch, tmp_path)
    repo = _work_repo(tmp_path)
    with FakeProxy(TestCA(), mode="407") as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", f"http://user01:@127.0.0.1:{px.port}")
        _real_push(repo, monkeypatch)
    assert px.connects and _any_connect_has(px, "Proxy-Authorization: Basic " + base64.b64encode(b"user01:").decode())
    assert not any("TOKEN-MARK" in c for c in px.connects)
    assert f"127.0.0.1:{px.port}" not in (log.read_text() if log.exists() else "")


def test_git_destination_prompt_is_still_answered(outbound_settings, monkeypatch, tmp_path, authmethod):
    """宛先の Git サーバーの認証（401）には、今までどおり askpass がトークンを答える（プロキシ経由でも）"""
    import base64

    from fake_proxy import FakeProxy, TestCA

    token = "glpat-TOKEN-MARK"
    monkeypatch.setattr(settings, "GIT_EXPORT_TOKEN", token)
    monkeypatch.setattr(settings, "GIT_EXPORT_USERNAME", "oauth2")
    ca = TestCA("Example Corp CA")
    monkeypatch.setattr(settings, "OUTBOUND_CA_FILE", str(ca.write_pem(tmp_path / "ca.pem")))

    def respond(method, path, headers, body):
        if "authorization" not in headers:
            return 401, {"WWW-Authenticate": 'Basic realm="git"'}, b""
        return 404, {}, b""

    repo = _work_repo(tmp_path)
    with FakeProxy(ca, auth=(PX_USER, PX_PASS), respond=respond) as px:
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", px.url(PX_USER, PX_ENC))
        msg = _real_push(repo, monkeypatch)
    sent = [i["headers"].get("authorization") for i in px.inner]
    assert "Basic " + base64.b64encode(f"oauth2:{token}".encode()).decode() in sent
    tok = base64.b64encode(f"{PX_USER}:{PX_PASS}".encode()).decode()
    assert _any_connect_has(px, f"Proxy-Authorization: Basic {tok}")  # プロキシの認証が通った
    leaked = base64.b64encode(f"oauth2:{token}".encode()).decode()
    assert not any(token in c or leaked in c for c in px.connects)  # プロキシへの CONNECT にはトークンを載せない
    assert token not in msg and _no_secret(msg)
