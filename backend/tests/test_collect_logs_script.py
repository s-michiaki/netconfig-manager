"""scripts/collect_logs.sh（調査用ログの収集）のテスト

podman の代わりに偽のコマンド（CONTAINER_CMD）を使う。コンテナが動いている場合・止まっている場合・
podman 自体が無い場合のどれでも最後まで進むこと、秘密の値を伏せること、大きさを抑えることを確かめる
"""
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "collect_logs.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")

WEBHOOK = "https://hooks.slack.com/services/T000/B000/abcdefSECRETxyz"
_TEAMS_PATH = "/powerautomate/automations/direct/workflows/WFIDEXAMPLE{n}/triggers/manual/paths/invoke?api-version=1&sig=SIGEXAMPLE{n}"
# 実際の URL は :443 が付く形。付かない形・大文字のホストも伏せる
TEAMS_WEBHOOKS = [
    "https://xxxx.environment.api.powerplatform.com:443" + _TEAMS_PATH.format(n=1),
    "https://xxxx.environment.api.powerplatform.com" + _TEAMS_PATH.format(n=2),
    "HTTPS://XXXX.Environment.Api.PowerPlatform.com:443" + _TEAMS_PATH.format(n=3),
]
TEAMS_WEBHOOK = " ".join(TEAMS_WEBHOOKS)
FAKE = r"""#!/bin/bash
# 偽の podman。呼ばれた引数を記録し、それらしい出力を返す
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$1" in
  version) echo "podman version 5.4.0" ;;
  ps)
    if [[ "$*" == *service=* ]]; then
      for s in $FAKE_DOWN; do [[ "$*" == *"service=$s"* ]] && exit 0; done
      [[ "$*" == *service=backend* ]] && echo bect
      [[ "$*" == *service=db* ]] && echo dbct
      [[ "$*" == *service=redis* ]] && echo rdct
    elif [[ "$*" == *-aq* ]]; then
      echo bect; echo wkct
    else
      echo "bect  ncm_backend_1  Up 2 hours  localhost/ncm_backend"
    fi ;;
  inspect)
    if [[ "$*" == *"{{.Name}}"* && "$*" != *State* ]]; then
      [[ "${@: -1}" == bect ]] && echo "/ncm_backend_1" || echo "/ncm_worker_1"
    else
      echo "名前          : /ncm_x"; echo "状態          : exited"; echo "終了コード    : 137"; echo "メモリ不足    : true"
    fi ;;
  logs)
    echo "2026-11-16T10:00:00Z INFO 起動しました"
    echo "2026-11-16T10:00:01Z ERROR 通知に失敗 url=$FAKE_WEBHOOK teams=$FAKE_TEAMS"
    echo "2026-11-16T10:00:02Z DEBUG connect postgresql+asyncpg://netconfig:Pg-Secret-99@db:5432/netconfig"
    echo "2026-11-16T10:00:03Z WARN password=Hunter2-plain token: abcDEF123"
    echo "2026-11-16T10:00:04Z INFO Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl" ;;
  exec)
    shift; [ "$1" = "-i" ] && shift; shift
    case "$*" in
      *selfcheck*) echo "[OK] worker"; echo "[OK] beat" ;;
      *alembic_version*) [ "$1" = python ] && echo "DB のマイグレーションの版: 0025_credential_profile_owner" || { cat >/dev/null; echo "DB の大きさ: 12 MB"; } ;;
      *"pip freeze"*) echo "fastapi==0.162.2" ;;
      *pg_isready*) echo "/var/run/postgresql:5432 - accepting connections" ;;
      *psql*) cat > "$FAKE_SQL"; echo "2026-11-16 09:00:00  error  collect.failed  same-fw  認証に失敗しました" ;;
      *redis-cli*) echo PONG ;;
    esac ;;
  images|volume|system) echo "(fake $1)" ;;
esac
"""


@pytest.fixture
def env(tmp_path):
    install = tmp_path / "ncm"
    (install / "backend" / "app").mkdir(parents=True)
    (install / "certs").mkdir()
    (install / "backend" / "app" / "main.py").write_text('app = FastAPI(title="x", version="1.42.0")\n')
    (install / ".env").write_text(
        "# コメント\nHTTP_PORT=8080\nPOSTGRES_PASSWORD=Pg-Secret-99\nDEVICE_ENCRYPTION_KEY=enc-key-value\n"
        "SECRET_KEY=jwt-secret-value\nADMIN_PASSWORD=\nPUBLIC_URL=https://10.20.0.10\n"
        "BACKUP_POST_COMMAND=rsync -e 'ssh -i /root/.ssh/id' x nas:/b\nTIMEZONE=Asia/Tokyo\n")
    fake = tmp_path / "podman"
    fake.write_text(FAKE)
    fake.chmod(0o755)
    e = {**os.environ, "INSTALL_DIR": str(install), "PROJECT_NAME": "ncm", "CONTAINER_CMD": str(fake), "SUDO": "",
         "COLLECT_OUT_DIR": str(tmp_path / "out"), "FAKE_LOG": str(tmp_path / "calls.log"),
         "FAKE_SQL": str(tmp_path / "sql.txt"), "FAKE_DOWN": "", "FAKE_WEBHOOK": WEBHOOK,
         "FAKE_TEAMS": TEAMS_WEBHOOK}
    return tmp_path, e


def run(e, *args, **extra):
    return subprocess.run(["bash", str(SCRIPT), *args], env={**e, **extra}, capture_output=True, text=True, timeout=180)


def bundle(tmp_path) -> dict[str, str]:
    """できたファイルを展開して {相対パス: 中身} にする"""
    files = sorted((tmp_path / "out").glob("netconfig-logs-*.tar.gz"))
    assert files, "ファイルができていない"
    out = {}
    with tarfile.open(files[-1]) as tar:
        for m in tar.getmembers():
            if m.isfile():
                out[m.name.split("/", 1)[1]] = tar.extractfile(m).read().decode("utf-8", errors="replace")
    return out


def test_collects_and_redacts(env):
    tmp_path, e = env
    r = run(e)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "✅ ログを集めました" in r.stdout and "netconfig-logs-" in r.stdout and "圧縮前" in r.stdout
    f = bundle(tmp_path)
    # 概要: 版、対象の期間、入っているファイルの一覧
    assert "アプリの版   : 1.42.0" in f["summary.txt"] and "直近 3 日" in f["summary.txt"]
    assert "containers/ncm_backend_1.log" in f["summary.txt"]
    # コンテナ: 一覧・状態（止まった理由が分かる項目）・ログ（止まっているコンテナの分も）
    assert "ncm_backend_1" in f["containers/ps.txt"]
    assert "終了コード    : 137" in f["containers/ncm_worker_1.state.txt"] and "メモリ不足" in f["containers/ncm_worker_1.state.txt"]
    log = f["containers/ncm_backend_1.log"]
    assert "起動しました" in log and "containers/ncm_worker_1.log" in f
    # 秘密の値は伏せる（Webhook の URL・URL に埋め込んだパスワード・パスワード・トークン）
    whole = "\n".join(f.values())
    teams_secrets = [f"{k}EXAMPLE{n}" for n in (1, 2, 3) for k in ("SIG", "WFID")]
    for secret in ("abcdefSECRETxyz", "Pg-Secret-99", "Hunter2-plain", "abcDEF123", *teams_secrets, "enc-key-value",
                   "jwt-secret-value", "c2lnbmF0dXJlLXZhbHVl", "/root/.ssh/id"):
        assert secret not in whole, secret
    assert log.lower().count("powerplatform.com/***") == 3  # :443 付き・なし・大文字のホスト
    assert "hooks.slack.com/services/***" in log and "netconfig:***@db:5432" in log and "password=***" in log
    # .env: 秘密は伏せ、それ以外は読める。空の値は空と分かる。コメントは入れない
    env_txt = f["app/env.txt"]
    assert "HTTP_PORT=8080" in env_txt and "TIMEZONE=Asia/Tokyo" in env_txt and "PUBLIC_URL=https://10.20.0.10" in env_txt
    assert "POSTGRES_PASSWORD=***（12 文字）" in env_txt and "ADMIN_PASSWORD=（空）" in env_txt and "コメント" not in env_txt
    # 動いているコンテナに聞いたもの
    assert "[OK] worker" in f["app/selfcheck.txt"] and "0025_credential_profile_owner" in f["app/migration.txt"]
    assert "accepting connections" in f["app/db-ready.txt"] and "PONG" in f["app/redis.txt"]
    assert "collect.failed" in f["app/activity-warnings.txt"]
    assert "interval '3 days'" in (tmp_path / "sql.txt").read_text()
    # ログは期間と行数で絞る（podman logs の --since は時間で指定する）
    calls = (tmp_path / "calls.log").read_text()
    assert "logs --timestamps --since 72h --tail 5000 bect" in calls
    # 機器のコンフィグ・DB のダンプ・ターミナルの記録は集めない
    assert "pg_dump" not in calls and "terminal" not in calls and "configs" not in calls
    # ファイルは実行した人だけが読める
    out = sorted((tmp_path / "out").glob("*.tar.gz"))[-1]
    assert oct(out.stat().st_mode)[-3:] == "600"


def test_options_and_rotation(env):
    tmp_path, e = env
    assert run(e, "--days", "7", "--lines", "200").returncode == 0
    calls = (tmp_path / "calls.log").read_text()
    assert "--since 168h --tail 200 bect" in calls
    (tmp_path / "calls.log").unlink()
    r = run(e, "--full", "--out", str(tmp_path / "other"))
    assert r.returncode == 0 and list((tmp_path / "other").glob("netconfig-logs-*.tar.gz"))
    assert "logs --timestamps --since 72h bect" in (tmp_path / "calls.log").read_text()  # 行数の上限なし
    # 古いものは消す（保存先にたまり続けない）
    out = tmp_path / "out"
    for old in out.glob("netconfig-logs-*.tar.gz"):  # ここまでに作ったものは片付けて、古いものだけの状態から始める
        old.unlink()
    for i in range(6):
        p = out / f"netconfig-logs-20260101-00000{i}.tar.gz"
        p.write_bytes(b"x")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
    assert run(e, "--keep", "2").returncode == 0
    left = sorted(x.name for x in out.glob("netconfig-logs-*.tar.gz"))
    # 残るのは、いま作ったものと、古いものの中でいちばん新しい 1 つ
    assert len(left) == 2 and left[0] == "netconfig-logs-20260101-000005.tar.gz" and left[1] > "netconfig-logs-2026"
    # 引数の誤り
    assert run(e, "--days", "abc").returncode == 1 and run(e, "--nope").returncode == 1
    assert "使い方" in run(e, "--help").stdout


def test_works_when_things_are_broken(env):
    tmp_path, e = env
    # コンテナが全部止まっている: 止まっていることを記録して、ログは集める
    r = run(e, FAKE_DOWN="backend db redis")
    assert r.returncode == 0, r.stdout + r.stderr
    f = bundle(tmp_path)
    assert "backend コンテナが動いていません" in f["app/selfcheck.txt"] and "動いていません" in f["app/db.txt"]
    assert "backend コンテナが動いていません" in f["collect-errors.txt"] and "集められなかったもの" in r.stdout
    assert "起動しました" in f["containers/ncm_backend_1.log"]
    # podman が無い・.env も無い（setup.sh が途中で止まった状態）でも、最後まで進んでファイルを作る
    (Path(e["INSTALL_DIR"]) / ".env").unlink()
    shutil.rmtree(tmp_path / "out")
    r = run(e, CONTAINER_CMD=str(tmp_path / "no-such-podman"))
    assert r.returncode == 0, r.stdout + r.stderr
    f = bundle(tmp_path)
    assert "見つかりません" in f["containers/ps.txt"] and ".env がありません" in f["app/env.txt"]
    assert "収集日時" in f["summary.txt"] and "system/df.txt" in f


def test_output_is_never_readable_by_others_while_being_written(env):
    """#39: 以前は保存先に tee で（umask のまま 644 で）書いてから chmod 600 していたので、その間はほかの人が読めた。
    いまは自分だけが読める作業用のディレクトリで作り、install -m 600 で置く。書き込み中の権限を偽の tee・gzip で確かめる"""
    tmp_path, e = env
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    # 保存先へ tee で書く形を使わない（使われたら目印を残す）
    (stubs / "tee").write_text(f'#!/bin/bash\nfor a in "$@"; do [[ "$a" == {tmp_path}/out/* ]] && touch {tmp_path}/tee-used; done\nexec /usr/bin/tee "$@"\n')
    (stubs / "tee").chmod(0o755)
    r = run(e, PATH=f"{stubs}:{os.environ['PATH']}")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "tee-used").exists()
    [f] = list((tmp_path / "out").glob("netconfig-logs-*.tar.gz"))
    assert f.stat().st_mode & 0o777 == 0o600
    assert bundle(tmp_path)["summary.txt"]
