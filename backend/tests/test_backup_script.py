"""scripts/backup.sh の流れ（外部へのコピー・後処理のコマンド・結果の報告）のテスト

podman の代わりに偽のコマンド（CONTAINER_CMD）を使う。偽のコマンドは pg_dump・tar に適当な中身を返し、
app.tools.backup_report の呼び出しを記録する。systemd・実際の NAS は使わない
"""
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "backup.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")

FAKE = """#!/bin/bash
# 偽の podman: ps -q でコンテナ ID を返し、exec の中身を真似る
case "$1" in
  ps)
    for s in $FAKE_DOWN; do [[ "$*" == *"service=$s"* ]] && exit 0; done
    [[ "$*" == *service=db* ]] && echo dbct || echo bect ;;
  exec)
    shift 2
    case "$1" in
      pg_dump) [ -n "$FAKE_PGFAIL" ] && exit 1; echo "PGDMP fake dump" ;;
      tar) tar -C "$FAKE_EMPTY" -cf - . ;;
      python) shift 3; printf '%s\\n' "$*" >> "$FAKE_LOG" ;;
    esac ;;
esac
"""


@pytest.fixture
def env(tmp_path):
    install = tmp_path / "install"
    (install / "certs").mkdir(parents=True)
    (install / ".env").write_text("DEVICE_ENCRYPTION_KEY=abc\n")
    (install / "certs" / "server.crt").write_text("crt")
    fake = tmp_path / "podman"
    fake.write_text(FAKE)
    fake.chmod(0o755)
    (tmp_path / "empty").mkdir()
    e = {**os.environ, "INSTALL_DIR": str(install), "PROJECT_NAME": "ncm", "CONTAINER_CMD": str(fake),
         "BACKUP_DIR": str(tmp_path / "backups"), "FAKE_EMPTY": str(tmp_path / "empty"),
         "FAKE_LOG": str(tmp_path / "report.log"), "FAKE_DOWN": "", "FAKE_PGFAIL": ""}
    return tmp_path, e


def run(e, *args, **extra):
    return subprocess.run(["bash", str(SCRIPT), *args], env={**e, **extra}, capture_output=True, text=True, timeout=60)


def reports(tmp_path) -> list[str]:
    log = tmp_path / "report.log"
    return log.read_text().splitlines() if log.exists() else []


def arg(line: str, name: str) -> str:
    """記録した引数から --name の値を取り出す（値に空白が無いものだけ）"""
    parts = line.split()
    return parts[parts.index(name) + 1] if name in parts and parts.index(name) + 1 < len(parts) else ""


def test_backup_without_offsite(env):
    tmp, e = env
    r = run(e)
    assert r.returncode == 0, r.stdout + r.stderr
    files = list((tmp / "backups").glob("netconfig-backup-*.tar.gz"))
    assert len(files) == 1 and oct(files[0].stat().st_mode & 0o777) == "0o600"
    # アーカイブの形式は restore.sh が読むまま（manifest・db.dump・env・certs.tar を含む）
    with tarfile.open(files[0]) as tar:
        names = tar.getnames()
    assert {"./manifest.txt", "./db.dump", "./env", "./certs.tar", "./configs.tar"} <= set(names)
    [line] = reports(tmp)
    assert line.startswith("result --status ok") and arg(line, "--copy") == "none" and arg(line, "--post") == "none"
    assert arg(line, "--file") == files[0].name and int(arg(line, "--size")) == files[0].stat().st_size
    result = json.loads((tmp / "backups" / "last-result.json").read_text())
    assert result["status"] == "ok" and result["file"] == files[0].name
    assert "最後の結果" in run(e, "--list").stdout


def test_copy_to_mounted_dir_and_prune(env):
    tmp, e = env
    dest = tmp / "nas"
    dest.mkdir()
    old = dest / "netconfig-backup-20200101-000000.tar.gz"
    old.write_text("old")
    os.utime(old, (1_600_000_000, 1_600_000_000))
    other = dest / "keep-me.txt"
    other.write_text("x")
    # 同じディスクの一時ディレクトリなので、マウントの確認は外して試す
    r = run(e, BACKUP_COPY_DIR=str(dest), BACKUP_COPY_REQUIRE_MOUNT="false", BACKUP_COPY_KEEP_DAYS="3")
    assert r.returncode == 0, r.stdout + r.stderr
    copies = list(dest.glob("netconfig-backup-2*.tar.gz"))
    assert len(copies) == 1 and not old.exists() and other.exists()  # 古い世代だけ消える
    local = next((tmp / "backups").glob("netconfig-backup-*.tar.gz"))
    assert copies[0].name == local.name and copies[0].read_bytes() == local.read_bytes()
    assert oct(copies[0].stat().st_mode & 0o777) == "0o600" and not list(dest.glob(".*.part"))
    assert "root 相当の人だけが読める" in r.stdout
    line = reports(tmp)[-1]
    assert arg(line, "--status") == "ok" and arg(line, "--copy") == "ok" and arg(line, "--copy-dir") == str(dest)


def test_copy_failures_keep_local_backup(env):
    tmp, e = env
    # マウントが外れている（コピー先がサーバーのディスク上）→ コピーしない。サーバー内のバックアップは残り、終了コード 2
    dest = tmp / "nas"
    dest.mkdir()
    r = run(e, BACKUP_COPY_DIR=str(dest))
    assert r.returncode == 2, r.stdout + r.stderr
    assert not list(dest.iterdir()) and len(list((tmp / "backups").glob("*.tar.gz"))) == 1
    line = reports(tmp)[-1]
    assert arg(line, "--status") == "ok" and arg(line, "--copy") == "failed" and "マウントが外れている" in line
    # コピー先が無い
    r = run(e, BACKUP_COPY_DIR=str(tmp / "missing"))
    assert r.returncode == 2 and "がありません" in reports(tmp)[-1]
    # 書き込めない（root ではテストできない）
    if os.geteuid() != 0:
        dest.chmod(0o500)
        try:
            r = run(e, BACKUP_COPY_DIR=str(dest), BACKUP_COPY_REQUIRE_MOUNT="false")
            assert r.returncode == 2 and "コピーに失敗しました" in reports(tmp)[-1]
        finally:
            dest.chmod(0o700)


@pytest.mark.skipif(not Path("/dev/shm").is_dir(), reason="別のファイルシステム（/dev/shm）が必要")
def test_copy_to_other_filesystem_passes_mount_check(env, tmp_path):
    tmp, e = env
    if os.stat("/dev/shm").st_dev == os.stat(tmp).st_dev:
        pytest.skip("/dev/shm が同じファイルシステム")
    dest = Path(f"/dev/shm/ncm-test-{os.getpid()}")
    dest.mkdir()
    try:
        r = run(e, BACKUP_COPY_DIR=str(dest))
        assert r.returncode == 0, r.stdout + r.stderr
        assert len(list(dest.glob("netconfig-backup-*.tar.gz"))) == 1
    finally:
        shutil.rmtree(dest)


def test_post_command(env):
    tmp, e = env
    marker = tmp / "posted.txt"
    r = run(e, BACKUP_POST_COMMAND=f'cp "$BACKUP_FILE" {tmp}/posted.tar.gz && echo done > {marker}')
    assert r.returncode == 0, r.stdout + r.stderr
    assert marker.read_text() == "done\n" and (tmp / "posted.tar.gz").exists()
    assert arg(reports(tmp)[-1], "--post") == "ok"
    r = run(e, BACKUP_POST_COMMAND="exit 3")
    assert r.returncode == 2
    line = reports(tmp)[-1]
    assert arg(line, "--status") == "ok" and arg(line, "--post") == "failed" and "終了コード 3" in line


def test_failures_are_reported(env):
    tmp, e = env
    # DB のダンプに失敗 → バックアップは残らず、失敗を報告する
    r = run(e, FAKE_PGFAIL="1")
    assert r.returncode != 0
    assert not list((tmp / "backups").glob("*.tar.gz")) and not list((tmp / "backups").glob(".work-*"))
    line = reports(tmp)[-1]
    assert arg(line, "--status") == "failed" and "「DB のダンプ」で失敗しました" in line
    assert json.loads((tmp / "backups" / "last-result.json").read_text())["status"] == "failed"
    # DB のコンテナだけが止まっている → backend 経由で失敗を報告できる
    r = run(e, FAKE_DOWN="db")
    assert r.returncode != 0 and "コンテナ（db）が起動していません" in r.stderr
    assert "「コンテナの確認」で失敗しました" in reports(tmp)[-1]
    # backend も止まっている → 画面には伝えられない（ファイルにだけ残す）
    n = len(reports(tmp))
    r = run(e, FAKE_DOWN="backend db")
    assert r.returncode != 0 and len(reports(tmp)) == n and "画面に伝えられません" in r.stdout
    # 設定の誤り
    r = run(e, BACKUP_COPY_KEEP_DAYS="x")
    assert r.returncode == 1 and "BACKUP_COPY_KEEP_DAYS" in r.stdout
