"""scripts/setup.sh 全体の流れ（初回・更新・失敗・対象外の OS）を、偽のコマンドで通すテスト

test_os_scripts.py は lib/os.sh の関数と初回の OS 判定だけを確かめる。ここでは setup.sh を最初から最後まで走らせ、
呼ばれたコマンドの記録（FAKE_LOG）を検査する。

作り:
- 一時ディレクトリの中に「導入先」（リポジトリの scripts・compose・Dockerfile の写し。.git は空のディレクトリ）を作り、
  その中の scripts/setup.sh を実行する（リポジトリの中の setup.sh は、隣の lib と、上の階層を導入先として使う）
- PATH は「偽のコマンド」「導入済みのコマンド」「必要な本物の最小限のコマンド」の 3 か所だけ。本物の git・podman・
  systemctl・curl には届かない。dnf / apt-get が「入れた」ことにしたコマンドは、導入済みの置き場に増える
- 偽の sudo は呼び出しを記録し、本物のパス（/opt・/etc・/root・/var など。一時ディレクトリの外）を引数に持つ呼び出しは
  実行せず 99 で落とす（記録に VIOLATION が残り、テストが失敗する）
- /root・/etc/systemd への書き込みは、setup.sh の環境変数（NCM_ENV_BACKUP_DIR・NCM_SYSTEMD_UNIT_DIR）で一時ディレクトリへ向ける
- sleep は偽物（起動確認の待ちを待たない）。ネットワークには出ない
"""
import base64
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from test_os_scripts import ALMA, LIB, UBUNTU

REPO = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")

# 偽のコマンド。呼ばれた名前と引数を $FAKE_LOG に 1 行ずつ記録する。動きは環境変数で変える
#   FAKE_FAIL_ON    "|" 区切りで「コマンド名 引数」の一部。当てはまる呼び出しは 1 で失敗する
STUB = r"""#!/bin/bash
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >> "$FAKE_LOG"
IFS='|' read -ra pats <<<"${FAKE_FAIL_ON:-}"
for pat in "${pats[@]}"; do
  if [ -n "$pat" ] && [[ "$name $*" == *"$pat"* ]]; then echo "fake $name: 失敗させました" >&2; exit 1; fi
done
case "$name" in
  dnf|apt-get)
    # install の引数のパッケージを「入れた」ことにする（同じ名前の偽のコマンドを導入済みの置き場に作る）
    if [[ " $* " == *" install "* ]]; then
      for a in "$@"; do
        case "$a" in -*|install|update) ;; *) cp "$FAKE_STUB_SRC" "$FAKE_INSTALLED/$a"; chmod 755 "$FAKE_INSTALLED/$a" ;; esac
      done
    fi ;;
  rpm) [ -e "$FAKE_INSTALLED/${*: -1}" ]; exit $? ;;
  dpkg) [ -e "$FAKE_INSTALLED/${*: -1}" ]; exit $? ;;
  git)
    if [ "$1" = -C ]; then
      case "$3" in
        pull) [ -n "${FAKE_PULL_CHANGES_SELF:-}" ] && echo "# 更新された" >> "$2/scripts/setup.sh" ;;
        log) echo "abc1234 fake commit" ;;
      esac
    elif [ "$1" = clone ]; then
      cp -a "$FAKE_REPO_SRC" "${*: -1}"
    fi ;;
  podman)
    case "$1" in
      volume) [ "$2" = exists ] && [ -n "${FAKE_VOLUME_EXISTS:-}" ] && exit 0 || exit 1 ;;
      ps) if [ "$2" = -q ]; then [ -n "${FAKE_NO_BACKEND:-}" ] || echo backendct; else echo "ncm_backend_1	Up"; fi ;;
      image) [ "$2" = inspect ] && echo "2026-11-20T00:00:00Z" ;;
      exec) [[ "$*" == *selfcheck* ]] && exit "${FAKE_SELFCHECK_RC:-0}" ;;
    esac ;;
  curl) [ -n "${FAKE_CURL_FAIL:-}" ] && exit 22; echo '{"status":"ok"}' ;;
  ufw) [ "$1" = status ] && cat "${FAKE_UFW_STATUS:-/dev/null}" ;;
  systemctl)
    case "$1" in
      is-active) exit "${FAKE_FIREWALLD_RC:-3}" ;;   # 0 = firewalld が動いている
      list-unit-files) [ -n "${FAKE_RESTART_UNIT:-}" ] && echo "podman-restart.service enabled" ; exit 0 ;;
      cat) exit 0 ;;
    esac ;;
  systemd-analyze) exit "${FAKE_ANALYZE_RC:-0}" ;;
  ip) echo "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0" ;;
  hostname) echo 192.0.2.10 ;;
esac
exit 0
"""
# 偽の sudo: 記録して、本物のパスに触れる呼び出しは実行しない。check_env.sh は偽の結果を返す
SUDO = r"""#!/bin/bash
printf 'sudo %s\n' "$*" >> "$FAKE_LOG"
while [[ "${1:-}" == -* ]]; do case "$1" in -v) [ -n "${FAKE_SUDO_V_FAIL:-}" ] && exit 1; exit 0 ;; -u) shift 2 ;; *) shift ;; esac; done
[ $# -gt 0 ] || exit 0
# 引数のどこかに、一時ディレクトリの外の本物のパスが含まれていれば（--opt=/etc/x や sh -c '... /etc/crontab' も）実行しない
for a in "$@"; do
  pre="$FAKE_ROOT/"
  b="${a//"$pre"/@R@:}"   # 一時ディレクトリの中（その下の opt・etc を含む）は、本物のパスと見分けられる形にしておく
  b="${b//"$FAKE_ROOT"/@R@}"
  case "$b" in
    *"/etc/"*|*"/opt/"*|*"/root/"*|*"/var/"*|*"/usr/"*|*"/run/"*|*"/sys/"*|*"/home/"*|*"/mnt/"*|*"/lib/"*|*"/boot/"*|*"/srv/"*|/etc|/opt|/root|/var|/usr|/run|/sys|*=/etc|*=/opt|*=/root|*=/var|*=/usr|*=/run|*=/sys)
      echo "VIOLATION sudo $*" >> "$FAKE_LOG"
      echo "fake sudo: 本物のパスには触れません: $a" >&2
      exit 99 ;;
  esac
done
if [ "$1" = bash ] && [[ "${2:-}" == */check_env.sh ]]; then
  echo "[ ${FAKE_CHECK_ENV:-OK} ] fake check_env"
  [ "${FAKE_CHECK_ENV:-OK}" = OK ]; exit $?
fi
exec "$@"
"""
# install: 所有者の指定（-o root -g root）は root でないと失敗するので外し、あとは本物を使う
INSTALL = r"""#!/bin/bash
printf 'install %s\n' "$*" >> "$FAKE_LOG"
args=()
while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
exec "$FAKE_REAL_INSTALL" "${args[@]}"
"""
RM = r"""#!/bin/bash
printf 'rm %s\n' "$*" >> "$FAKE_LOG"
exec "$FAKE_REAL_RM" "$@"
"""
# 本物のまま使ってよいコマンド（ファイルの読み書き・文字列の加工だけ）
REAL_TOOLS = ["bash", "sh", "sed", "awk", "grep", "tr", "head", "tail", "cut", "base64", "sort", "mktemp", "date", "stat",
              "id", "basename", "dirname", "cat", "tee", "mkdir", "chmod", "cp", "env", "readlink", "wc", "seq",
              "sha256sum", "uniq", "ls", "test", "[", "touch", "true", "false"]
# OS ごとに「ある」コマンド（dnf と apt-get が両方ある環境は無い）
OS_COMMANDS = {
    "alma": ["dnf", "rpm", "firewall-cmd"],
    "ubuntu": ["apt-get", "dpkg", "ufw"],
}
COMMON_COMMANDS = ["systemctl", "systemd-analyze", "ip", "hostname", "sleep"]
BASE_PKGS = ["git", "podman", "podman-compose", "curl"]
UBUNTU_EXTRA = ["netavark", "aardvark-dns", "uidmap"]
OLD_ENV = ("POSTGRES_PASSWORD=pgpass\nSECRET_KEY=secretkey\nDEVICE_ENCRYPTION_KEY=Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo=\n"
           "ADMIN_USERNAME=admin\nADMIN_PASSWORD=admin-password-1\nSSH_HOST_KEY_POLICY=tofu\nALLOWED_ORIGINS=\n"
           "HTTP_PORT=80\nHTTPS_PORT=443\nPUBLIC_URL=http://192.0.2.10\n")
# 破壊的な操作（通常の導入・更新では呼ばれない）
DESTRUCTIVE = [r"\brm\b.* -[a-zA-Z]*[rR]", r"system prune", r"volume (rm|remove|prune)", r"\bdown\b.* (-v\b|--volumes)",
               r"\bpodman (rm|rmi|kill|stop)\b", r"\bimage rm\b", r"\bnetwork (rm|prune)", r"\bpod rm\b",
               r"\bsystemctl (stop|disable|mask)\b.*podman-restart",
               r"\b(dnf|yum) (remove|autoremove|erase)\b", r"\bapt(-get)? (remove|purge|autoremove)\b",
               r"\brpm (-\w*e\w*|--erase)\b", r"\bdpkg (-r|-P|--remove|--purge)\b"]


def real_command(name):
    """本物のコマンドの場所（PATH の先頭に rm を包む仕組みがある環境でも、包みではなく本体を使う）"""
    for d in ("/usr/bin", "/bin"):
        if os.access(f"{d}/{name}", os.X_OK):
            return f"{d}/{name}"
    return shutil.which(name)


def stub(path, text):
    path.write_text(text)
    path.chmod(0o755)


class Box:
    """一時ディレクトリの中の導入先・偽のコマンド・記録。os は alma / ubuntu"""

    def __init__(self, tmp, os_name):
        self.tmp = tmp
        self.os = os_name
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.install = tmp / "opt" / "netconfig-manager"
        self.installed = tmp / "installed"
        self.stubs = tmp / "stubs"
        self.realbin = tmp / "realbin"
        self.workdir = tmp / "work"
        self.backup_dir = tmp / "rootbackup"
        self.units = tmp / "systemd"
        self.dropin = tmp / "dropin"
        for d in (self.installed, self.stubs, self.realbin, self.workdir, self.units, self.tmp / "tmp"):
            d.mkdir(parents=True, exist_ok=True)
        stub(self.tmp / "stub-src", STUB)
        for n in REAL_TOOLS:
            p = shutil.which(n)
            if p:
                (self.realbin / n).symlink_to(p)
        for n in OS_COMMANDS[os_name] + COMMON_COMMANDS:
            stub(self.stubs / n, STUB)
        stub(self.stubs / "sudo", SUDO)
        stub(self.stubs / "install", INSTALL)
        stub(self.stubs / "rm", RM)
        self.release_file = tmp / "os-release"
        self.release_file.write_text(ALMA if os_name == "alma" else UBUNTU)
        self.make_source()

    def make_source(self):
        """導入先（リポジトリの写し）と、clone で取得される元（FAKE_REPO_SRC）を作る"""
        src = self.tmp / "repo-src"
        for rel in ("scripts", "docker-compose.prod.yml", "docker-compose.yml", "backend/Dockerfile", "frontend/Dockerfile"):
            dst = src / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if (REPO / rel).is_dir():
                shutil.copytree(REPO / rel, dst, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy(REPO / rel, dst)
        self.src = src
        self.install.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, self.install)
        (self.install / ".git").mkdir()

    def preinstall(self, *names):
        for n in names:
            stub(self.installed / n, STUB)

    def env_file(self, text=OLD_ENV):
        (self.install / ".env").write_text(text)
        return self.install / ".env"

    def env(self, **extra):
        base = {k: v for k, v in os.environ.items() if k not in ("DEBIAN_FRONTEND", "NETCONFIG_SETUP_REEXEC")}
        base.update(
            PATH=f"{self.stubs}:{self.installed}:{self.realbin}",
            HOME=str(self.tmp / "home"), TMPDIR=str(self.tmp / "tmp"), LC_ALL="C",
            FAKE_LOG=str(self.log), FAKE_ROOT=str(self.tmp), FAKE_INSTALLED=str(self.installed),
            FAKE_STUB_SRC=str(self.tmp / "stub-src"), FAKE_REPO_SRC=str(self.src),
            FAKE_REAL_INSTALL=real_command("install"), FAKE_REAL_RM=real_command("rm"),
            NCM_OS_RELEASE_FILE=str(self.release_file), NCM_ENV_BACKUP_DIR=str(self.backup_dir),
            NCM_SYSTEMD_UNIT_DIR=str(self.units), NCM_SYSTEMD_DROPIN_DIR=str(self.dropin),
            FAKE_RESTART_UNIT="1",
        )
        base.update(extra)
        return {k: v for k, v in base.items() if v is not None}

    def run(self, args=(), stdin="", script=None, cwd=None, **extra):
        return subprocess.run(["bash", str(script or self.install / "scripts" / "setup.sh"), *args], env=self.env(**extra),
                              input=stdin, capture_output=True, text=True, timeout=60, cwd=cwd or self.workdir)

    def calls(self):
        return self.log.read_text().splitlines()

    def index(self, prefix, start=0):
        """記録の中で、prefix で始まる最初の行の位置（無ければ -1）"""
        for i, c in enumerate(self.calls()[start:], start):
            if c.startswith(prefix):
                return i
        return -1

    def count(self, prefix):
        return len([c for c in self.calls() if c.startswith(prefix)])


@pytest.fixture(params=["alma", "ubuntu"])
def box(request, tmp_path):
    return Box(tmp_path, request.param)


@pytest.fixture
def alma(tmp_path):
    return Box(tmp_path, "alma")


@pytest.fixture
def ubuntu(tmp_path):
    return Box(tmp_path, "ubuntu")


def all_installed(b):
    """更新（2 回目以降）の前提: 必要なパッケージは導入済み"""
    b.preinstall(*BASE_PKGS)
    if b.os == "ubuntu":
        b.preinstall(*UBUNTU_EXTRA)


def pulled_images(b):
    return sorted(c.split()[-1] for c in b.calls() if c.startswith("podman pull "))


def expected_images():
    """compose と Dockerfile から、別の書き方（正規表現）でイメージを取り出す（タグの更新で固定の一覧が古くならないように）"""
    out = set()
    text = (REPO / "docker-compose.prod.yml").read_text(encoding="utf-8")
    out.update(re.findall(r"^\s*image:\s*(\S+)", text, re.M))
    for f in ("backend/Dockerfile", "frontend/Dockerfile"):
        out.update(re.findall(r"^FROM\s+(\S+)", (REPO / f).read_text(encoding="utf-8"), re.M))
    return sorted(i for i in out if "/" in i)


def assert_safe(b):
    """どの流れでも守ること: 本物のパスに触れない・消す操作をしない・触ってはいけないものに触れない"""
    calls = b.calls()
    assert not [c for c in calls if c.startswith("VIOLATION")], [c for c in calls if c.startswith("VIOLATION")]
    for c in calls:
        for pat in DESTRUCTIVE:
            assert not re.search(pat, c), f"消す操作が呼ばれました: {c}"
    # rm は一時ファイルの後始末（rm -f <mktemp の名前>）だけ
    for c in calls:
        if c.startswith("rm "):
            assert re.fullmatch(r"rm -f \S*/tmp/tmp\.\S+", c), c
    # podman image prune -f（使われなくなった古いイメージ）以外の prune は呼ばない
    for c in calls:
        if "prune" in c:
            assert c in ("sudo podman image prune -f", "podman image prune -f"), c
    # 同じサーバーで動いている endfield-news-bot・root の crontab・python3-pip には触れない
    for c in calls:
        assert "endfield" not in c and "crontab" not in c and "pip" not in c, c


# ------------------------------------------------------------------ (a) 初回
def test_first_install_flow(box):
    """初回（.env が無い）: パッケージ → チェック → .env → バックアップ → ポート → ビルド・起動 → 自動起動 → 確認"""
    r = box.run(stdin="\n" * 8)  # 入力は全部 Enter（既定の値を採用）
    assert r.returncode == 0, r.stdout + r.stderr
    calls = box.calls()
    assert_safe(box)

    # パッケージ（足りないものを、その OS のコマンドで 1 回で入れる）
    if box.os == "alma":
        assert "dnf install -y epel-release" in calls  # podman-compose は EPEL にある
        assert "dnf install -y git podman podman-compose curl" in calls
        assert not [c for c in calls if c.startswith(("apt", "dpkg", "ufw"))]
        assert box.index("dnf install -y epel-release") < box.index("dnf install -y git")
    else:
        assert "apt-get update" in calls
        assert "apt-get install -y git podman podman-compose curl netavark aardvark-dns uidmap" in calls
        assert not [c for c in calls if c.startswith(("dnf", "rpm", "firewall-cmd"))]

    # 導入前チェック（初回だけ）→ .env → バックアップ
    assert box.index("sudo bash") >= 0 and "check_env.sh -m prod" in calls[box.index("sudo bash")]
    env = (box.install / ".env").read_text()
    kv = dict(line.split("=", 1) for line in env.splitlines() if "=" in line and not line.startswith("#"))
    for k in ("POSTGRES_PASSWORD", "SECRET_KEY", "DEVICE_ENCRYPTION_KEY", "ADMIN_USERNAME", "ADMIN_PASSWORD",
              "SSH_HOST_KEY_POLICY", "HTTP_PORT", "HTTPS_PORT", "PUBLIC_URL"):
        assert kv.get(k), f"{k} が .env に無い"
    assert len(kv["POSTGRES_PASSWORD"]) == 32 and len(kv["SECRET_KEY"]) == 64 and len(kv["ADMIN_PASSWORD"]) == 20
    assert len(base64.urlsafe_b64decode(kv["DEVICE_ENCRYPTION_KEY"])) == 32  # Fernet の鍵
    assert (kv["ADMIN_USERNAME"], kv["SSH_HOST_KEY_POLICY"], kv["HTTP_PORT"], kv["HTTPS_PORT"]) == ("admin", "tofu", "80", "443")
    assert kv["PUBLIC_URL"] == "http://192.0.2.10"
    assert (box.install / ".env").stat().st_mode & 0o777 == 0o600
    backups = list(box.backup_dir.glob("env-*"))
    # .env のバックアップは PUBLIC_URL を自動設定する前に取る（中身はそれ以外が同じ。次の更新のバックアップには入る）
    assert len(backups) == 1 and backups[0].read_text() == env.replace("PUBLIC_URL=http://192.0.2.10", "PUBLIC_URL=")
    assert f"パスワード: {kv['ADMIN_PASSWORD']}" in r.stdout  # 初期管理者の案内
    assert (box.install / "certs").is_dir()

    # イメージの取り直し → ビルド → コンテナの再作成 → 自動起動 → 確認
    assert pulled_images(box) == expected_images() and len(pulled_images(box)) >= 5
    build = box.index("podman-compose -f docker-compose.prod.yml build")
    up = box.index("podman-compose -f docker-compose.prod.yml up -d --force-recreate")
    enable = box.index("systemctl enable --now podman-restart.service")
    health = box.index("curl ")
    selfcheck = box.index("podman exec backendct python -m app.tools.selfcheck")
    report = box.index("podman exec backendct python -m app.tools.image_report")
    assert 0 <= box.index("podman pull") < build < up < enable < health < selfcheck < report
    assert "systemctl enable --now netconfig-backup.timer" in calls
    assert "[INFO] Pulling" in r.stdout and "✅ 完了" in r.stdout
    assert "FAKE" not in r.stdout
    # 定期バックアップのユニットは、差し替えた置き場にだけ書く
    assert f"ExecStart=/bin/bash {box.install}/scripts/backup.sh" in (box.units / "netconfig-backup.service").read_text()
    assert "OnCalendar=*-*-* 03:15:00" in (box.units / "netconfig-backup.timer").read_text()


def test_first_install_firewall_and_autostart_by_os(box):
    # 既定のポート（80・443）。firewalld・ufw が動いているとき
    box.preinstall(*BASE_PKGS, *(UBUNTU_EXTRA if box.os == "ubuntu" else []))
    ufw_status = box.tmp / "ufw-status"
    ufw_status.write_text("Status: active\n")
    r = box.run(stdin="\n" * 8, FAKE_FIREWALLD_RC="0", FAKE_UFW_STATUS=str(ufw_status))
    assert r.returncode == 0, r.stdout + r.stderr
    calls = box.calls()
    assert_safe(box)
    if box.os == "alma":
        assert "firewall-cmd --permanent --add-service=http" in calls and "firewall-cmd --permanent --add-service=https" in calls
        assert "firewall-cmd --reload" in calls
        assert not box.dropin.exists()  # RHEL 系は podman-restart.service をそのまま有効にする
        assert "dnf" not in " ".join(c.split()[0] for c in calls)
    else:
        assert "ufw allow 80/tcp" in calls and "ufw allow 443/tcp" in calls
        assert not [c for c in calls if c.startswith("firewall-cmd")]
        # unless-stopped のコンテナも起動するドロップインを置く
        assert "unless-stopped" in (box.dropin / "10-netconfig-manager.conf").read_text()
        assert box.index("systemctl daemon-reload") < box.index("systemctl enable --now podman-restart.service")
    assert "systemctl enable --now podman-restart.service" in calls


def test_first_install_custom_ports_and_answers(box):
    """入力した値（IP・ポート・管理者）が .env・ファイアウォール・案内に反映される"""
    box.preinstall(*BASE_PKGS, *(UBUNTU_EXTRA if box.os == "ubuntu" else []))
    ufw_status = box.tmp / "ufw-status"
    ufw_status.write_text("Status: active\n")
    answers = ["", "203.0.113.5", "8080", "8443", "netadmin", "long-password-123", "strict"]
    r = box.run(stdin="\n".join(answers) + "\n", FAKE_FIREWALLD_RC="0", FAKE_UFW_STATUS=str(ufw_status))
    assert r.returncode == 0, r.stdout + r.stderr
    assert_safe(box)
    env = (box.install / ".env").read_text()
    for line in ("HTTP_PORT=8080", "HTTPS_PORT=8443", "ADMIN_USERNAME=netadmin", "ADMIN_PASSWORD=long-password-123",
                 "SSH_HOST_KEY_POLICY=strict", "PUBLIC_URL=http://203.0.113.5:8080"):
        assert line in env.splitlines(), line
    calls = box.calls()
    if box.os == "alma":
        assert "firewall-cmd --permanent --add-port=8080/tcp" in calls and "firewall-cmd --permanent --add-port=8443/tcp" in calls
    else:
        assert "ufw allow 8080/tcp" in calls and "ufw allow 8443/tcp" in calls
    assert "http://203.0.113.5:8080/" in r.stdout


@pytest.mark.parametrize("stdin,message", [
    ("\n\n99999\n", "HTTP_PORT が不正です"),
    ("\n\n8080\n8080\n", "HTTPS_PORT と HTTP_PORT が同じです"),
    ("\n\n\n\nadmin\nshort\n", "10文字以上"),
    ("\n\n\n\nadmin\nlong-password-123\nloose\n", "tofu か strict"),
])
def test_first_install_rejects_bad_answers(alma, stdin, message):
    alma.preinstall(*BASE_PKGS)
    r = alma.run(stdin=stdin)
    assert r.returncode == 1 and message in r.stdout, r.stdout + r.stderr
    assert not (alma.install / ".env").exists()
    assert alma.count("podman") == 0 and alma.count("dnf") == 0
    assert_safe(alma)


def test_first_install_stops_when_check_env_fails_and_user_declines(alma):
    alma.preinstall(*BASE_PKGS)
    r = alma.run(stdin="\n" * 7 + "n\n", FAKE_CHECK_ENV="NG")
    assert r.returncode == 1 and "中止しました" in r.stdout
    assert not (alma.install / ".env").exists() and alma.count("podman-compose") == 0
    # 続行すると最後まで進む
    r = alma.run(stdin="\n" * 7 + "y\n", FAKE_CHECK_ENV="NG")
    assert r.returncode == 0 and (alma.install / ".env").exists(), r.stdout + r.stderr
    assert_safe(alma)


def test_first_install_stops_when_old_database_volume_remains(box):
    """.env が無いのに DB のボリュームが残っているときは、.env を作らず・消さずに止まる"""
    box.preinstall(*BASE_PKGS, *(UBUNTU_EXTRA if box.os == "ubuntu" else []))
    r = box.run(stdin="\n" * 8, FAKE_VOLUME_EXISTS="1")
    assert r.returncode == 1 and "既存のデータベース" in r.stdout
    assert "netconfig-manager_postgres_data" in r.stdout
    assert not (box.install / ".env").exists()
    assert box.count("podman-compose") == 0
    assert_safe(box)  # down -v は案内の文字として出るだけで、実行されない


def test_first_install_from_outside_the_repo_clones_it(alma):
    """リポジトリの外に置いた setup.sh の初回: git だけを入れて clone し、そのリポジトリの lib で続ける"""
    shutil.rmtree(alma.install)  # 導入先はまだ無い
    out = alma.tmp / "downloaded"
    out.mkdir()
    shutil.copy(REPO / "scripts" / "setup.sh", out / "setup.sh")
    # clone されるリポジトリには .git が要る（本物の clone は作る）
    (alma.src / ".git").mkdir()
    r = alma.run(stdin=f"{alma.install}\n" + "\n" * 8, script=out / "setup.sh", cwd=out)
    assert r.returncode == 0, r.stdout + r.stderr
    assert_safe(alma)
    calls = alma.calls()
    assert "dnf install -y git" in calls  # lib を読む前に、git だけを先に入れる
    clone = alma.index("git clone --branch master https://github.com/s-michiaki/netconfig-manager.git")
    assert 0 <= alma.index("dnf install -y git") < clone < alma.index("podman-compose -f docker-compose.prod.yml build")
    assert alma.count("git clone") == 1  # 後の「ソース取得」で繰り返さない
    assert (alma.install / ".env").exists()


# ------------------------------------------------------------------ (b) 更新
def test_update_keeps_env_byte_for_byte(box):
    """更新（.env がある）: 質問せず、.env は 1 バイトも変えない。git pull → 取り直し → 再ビルド → コンテナの再作成"""
    all_installed(box)
    env_file = box.env_file()
    before = env_file.read_bytes()
    r = box.run(stdin="")  # 入力は一切無い（聞かれたら EOF で落ちる）
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_file.read_bytes() == before
    assert_safe(box)
    calls = box.calls()
    assert f"git -C {box.install} pull --ff-only" in calls and box.count("git -C") >= 1
    assert box.count("git clone") == 0 and box.count("sudo bash") == 0  # 導入前チェックは初回だけ
    assert not [c for c in calls if c.startswith(("dnf", "apt-get"))]  # 揃っているので何も入れない
    assert pulled_images(box) == expected_images()
    pull = box.index(f"git -C {box.install} pull")
    build = box.index("podman-compose -f docker-compose.prod.yml build")
    up = box.index("podman-compose -f docker-compose.prod.yml up -d --force-recreate")
    assert 0 <= pull < box.index("podman pull") < build < up < box.index("systemctl enable --now podman-restart.service")
    assert "更新しました" in r.stdout and "パスワード:" not in r.stdout
    # .env のバックアップは、更新でも取る（中身は同じ）
    assert [p.read_text() for p in box.backup_dir.glob("env-*")] == [before.decode()]
    assert not (box.install / ".env.new").exists()


def test_update_adds_only_missing_keys_to_an_old_env(box):
    """古い .env（ポート・PUBLIC_URL が無い）への更新は、足りないキーを足すだけで、既存の行は変えない"""
    all_installed(box)
    old = "".join(line for line in OLD_ENV.splitlines(True) if not line.startswith(("HTTP_PORT", "HTTPS_PORT")))
    old = old.replace("PUBLIC_URL=http://192.0.2.10\n", "PUBLIC_URL=\n")
    box.env_file(old)
    r = box.run()
    assert r.returncode == 0, r.stdout + r.stderr
    new = (box.install / ".env").read_text().splitlines()
    for line in old.splitlines():
        if not line.startswith("PUBLIC_URL"):
            assert line in new, line
    assert "HTTP_PORT=80" in new and "HTTPS_PORT=443" in new and "PUBLIC_URL=http://192.0.2.10" in new
    assert_safe(box)


def test_update_reruns_itself_when_setup_script_changed(box):
    """git pull で setup.sh 自身が変わったら、新しい内容で最初からやり直す（pull は 1 回、ビルドも 1 回）"""
    all_installed(box)
    box.env_file()
    r = box.run(FAKE_PULL_CHANGES_SELF="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "setup.sh が更新されました。新しい内容でやり直します" in r.stdout
    assert_safe(box)
    assert box.count("git -C") == 2 and box.count(f"git -C {box.install} pull") == 1  # もう 1 回は log
    assert box.count("podman-compose -f docker-compose.prod.yml build") == 1
    assert box.count("podman-compose -f docker-compose.prod.yml up -d --force-recreate") == 1
    assert r.stdout.count("Updating source") == 1


def test_update_stops_when_git_pull_fails(box):
    all_installed(box)
    env_file = box.env_file()
    before = env_file.read_bytes()
    r = box.run(FAKE_FAIL_ON="git -C")
    assert r.returncode == 1 and "git pull に失敗" in r.stdout
    assert env_file.read_bytes() == before
    assert box.count("podman") == 0 and box.count("sudo podman") == 0
    assert_safe(box)


def test_update_without_git_stops(alma):
    alma.preinstall("podman", "podman-compose", "curl")
    alma.env_file()
    r = alma.run()
    assert r.returncode == 1 and "git が見つかりません" in r.stdout
    assert alma.count("dnf") == 0 and alma.count("podman") == 0


def test_update_reconfigure_asks_again_and_applies_ports(alma):
    all_installed(alma)
    alma.env_file()
    r = alma.run(args=["--reconfigure"], stdin="\n\n9090\n9443\n")
    assert r.returncode == 0, r.stdout + r.stderr
    env = (alma.install / ".env").read_text().splitlines()
    assert "HTTP_PORT=9090" in env and "HTTPS_PORT=9443" in env
    assert "DEVICE_ENCRYPTION_KEY=Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo=" in env  # キーは変えない
    assert "firewall-cmd" not in " ".join(alma.calls())  # firewalld が動いていないので何もしない
    assert_safe(alma)


def test_update_image_pull_failure_only_warns(box):
    all_installed(box)
    box.env_file()
    img = expected_images()[0]
    r = box.run(FAKE_FAIL_ON=f"podman pull -q {img}")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"{img} を取り直せませんでした" in r.stdout
    assert any(c.startswith("podman exec backendct python -m app.tools.image_report") and f"--pull-failed {img}" in c
               for c in box.calls())
    assert box.count("podman-compose -f docker-compose.prod.yml up -d --force-recreate") == 1
    assert_safe(box)


# ------------------------------------------------------------------ (c) 途中の失敗
@pytest.mark.parametrize("fail_on,stopped_before", [
    ("podman-compose -f docker-compose.prod.yml build", ["podman-compose -f docker-compose.prod.yml up", "systemctl enable",
                                                         "curl", "podman exec"]),
    ("podman-compose -f docker-compose.prod.yml up", ["systemctl enable", "curl", "podman exec"]),
])
def test_failure_stops_the_flow(box, fail_on, stopped_before):
    """ビルド・起動・自動起動の失敗は、0 以外で終わり、そのあとの手順を呼ばない"""
    all_installed(box)
    env_file = box.env_file()
    before = env_file.read_bytes()
    r = box.run(FAKE_FAIL_ON=fail_on)
    assert r.returncode != 0, r.stdout
    assert "✅ 完了" not in r.stdout
    for later in stopped_before:
        assert box.index(later) == -1, f"{later} が呼ばれました"
    assert env_file.read_bytes() == before  # 失敗しても .env は無事
    assert not [c for c in box.calls() if re.search(r"\bdown\b|\bstop\b", c)]  # 動いているコンテナを止めない
    assert_safe(box)


def test_autostart_failure_on_almalinux_stops(alma):
    all_installed(alma)
    alma.env_file()
    r = alma.run(FAKE_FAIL_ON="systemctl enable --now podman-restart.service")
    assert r.returncode != 0 and "✅ 完了" not in r.stdout
    for later in ("systemctl enable --now netconfig-backup", "curl", "podman exec"):
        assert alma.index(later) == -1, later
    assert_safe(alma)


def test_autostart_failure_on_ubuntu_only_warns(ubuntu):
    all_installed(ubuntu)
    ubuntu.env_file()
    r = ubuntu.run(FAKE_FAIL_ON="systemctl enable --now podman-restart.service")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[WARN] podman-restart.service を有効にできませんでした" in r.stdout
    assert ubuntu.index("podman exec backendct python -m app.tools.selfcheck") >= 0


def test_failed_health_check_exits_nonzero_and_shows_logs(box):
    all_installed(box)
    box.env_file()
    r = box.run(FAKE_CURL_FAIL="1")
    assert r.returncode == 1 and "起動を確認できませんでした" in r.stdout
    assert box.count("curl ") == 60  # 3 秒待ちを 60 回（sleep は偽物なので待たない）
    assert box.index("podman-compose -f docker-compose.prod.yml logs --tail 30 backend") >= 0
    assert box.index("podman exec") == -1  # 画面が応答しないうちは、動作確認も報告もしない
    assert_safe(box)


def test_failed_background_check_exits_nonzero(box):
    all_installed(box)
    box.env_file()
    r = box.run(FAKE_SELFCHECK_RC="1")
    assert r.returncode == 1 and "バックグラウンド処理が動いていません" in r.stdout
    assert box.index("podman exec backendct python -m app.tools.image_report") == -1
    assert_safe(box)


# ------------------------------------------------------------------ (d) 対象外の OS
UNSUPPORTED = ['ID=arch\nPRETTY_NAME="Arch Linux"\n', 'ID=opensuse-leap\nID_LIKE="suse opensuse"\nPRETTY_NAME="openSUSE Leap"\n', ""]


@pytest.mark.parametrize("text", UNSUPPORTED)
def test_unsupported_os_stops_without_package_manager(tmp_path, text):
    b = Box(tmp_path, "alma")
    for n in OS_COMMANDS["alma"]:
        (b.stubs / n).unlink()  # dnf も apt-get も無い OS
    b.release_file.write_text(text)
    b.preinstall(*BASE_PKGS)
    r = b.run(stdin="\n" * 8)
    assert r.returncode == 1 and "対象外の OS です" in r.stdout, r.stdout + r.stderr
    assert not (b.install / ".env").exists() and b.count("podman") == 0
    assert_safe(b)


@pytest.mark.parametrize("text", UNSUPPORTED[:2])
def test_unsupported_os_stops_even_when_dnf_exists(alma, text):
    """リポジトリの中の setup.sh も、対象外の OS では（dnf があっても）パッケージを入れる前に止まる"""
    alma.release_file.write_text(text)
    r = alma.run(stdin="\n" * 8)
    assert r.returncode == 1 and "対象外の OS です: " in r.stdout and "対応しているのは" in r.stdout, r.stdout
    assert not [c for c in alma.calls() if c.startswith(("dnf", "apt-get", "git", "podman"))]
    assert not (alma.install / ".env").exists()


@pytest.mark.parametrize("text", UNSUPPORTED[:2])
def test_unsupported_os_first_run_outside_repo_stops_before_clone(tmp_path, text):
    b = Box(tmp_path, "alma")
    shutil.rmtree(b.install)
    out = tmp_path / "downloaded"
    out.mkdir()
    shutil.copy(REPO / "scripts" / "setup.sh", out / "setup.sh")
    b.release_file.write_text(text)
    r = b.run(stdin=f"{b.install}\n" + "\n" * 8, script=out / "setup.sh", cwd=out)
    assert r.returncode == 1 and "対象外の OS です" in r.stdout
    assert not [c for c in b.calls() if c.startswith(("git", "dnf", "apt-get"))]
    assert not b.install.exists()


def test_unconfirmed_os_runs_with_warning(tmp_path):
    """未確認の OS（Rocky 9）は警告を出して、AlmaLinux と同じ手順で最後まで進む"""
    b = Box(tmp_path, "alma")
    b.release_file.write_text('ID="rocky"\nVERSION_ID="9.5"\nPRETTY_NAME="Rocky Linux 9.5"\n')
    b.preinstall(*BASE_PKGS)
    r = b.run(stdin="\n" * 8)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[WARN] README の手順は RHEL 10 前提です" in r.stdout
    assert_safe(b)


# ------------------------------------------------------------------ (e)(f) 触ってはいけないもの・消す操作
def test_fake_sudo_refuses_real_paths(alma):
    """テスト自体の安全装置: 本物のパス（/opt・/etc・/root・/var）に触れる sudo は実行されず、記録に残る"""
    cases = [["mkdir", "-p", "/opt/netconfig-manager/x"], ["mkdir", "-p", "/etc/systemd/system/x"], ["mkdir", "/root/x"],
             ["mkdir", "-p", "/var/backups/x"], ["mkdir", "/run/x"], ["mkdir", "/sys/x"], ["mkdir", "/usr/local/x"],
             ["mkdir", "/home/someone/x"], ["mkdir", "--opt=/etc/x"],                                  # 引数の途中に本物のパス
             ["sh", "-c", "echo x >> /etc/crontab"]]                     # 文字列の中に本物のパス
    for args in cases:
        r = subprocess.run([str(alma.stubs / "sudo"), *args], env=alma.env(), capture_output=True, text=True)
        assert r.returncode == 99, args
    assert len([c for c in alma.calls() if c.startswith("VIOLATION")]) == len(cases)
    # 一時ディレクトリの中は通る
    ok = subprocess.run([str(alma.stubs / "sudo"), "mkdir", "-p", str(alma.tmp / "inside")], env=alma.env())
    assert ok.returncode == 0 and (alma.tmp / "inside").is_dir()
    for target in ("/opt/netconfig-manager/x", "/etc/systemd/system/x", "/var/backups/x"):
        assert not os.path.lexists(target), target  # /root は root でないと調べられないので、sudo の記録だけで確かめる


def test_flow_never_calls_destructive_or_forbidden_commands(box):
    """初回 → 更新 → 設定を聞き直す更新の全部の記録に、消す操作・触れてはいけないものが 1 つも無い"""
    box.run(stdin="\n" * 8)
    box.run()
    box.run(args=["--reconfigure"], stdin="\n" * 6)
    assert box.count("podman-compose -f docker-compose.prod.yml up -d --force-recreate") == 3
    assert_safe(box)
    text = "\n".join(box.calls())
    for word in ("endfield", "crontab", "python3-pip", "rm -rf", "system prune", "volume rm", "down -v"):
        assert word not in text, word


def test_setup_script_text_has_no_forbidden_operations():
    """記録に出ない分岐のための、スクリプトの文面の確認（コメント・案内文の行は除く）"""
    code = [line for line in (REPO / "scripts" / "setup.sh").read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith(("#", "echo"))]
    text = "\n".join(code)
    for word in ("endfield", "crontab", "python3-pip", "rm -rf", "system prune", "volume rm", "volume prune", "down -v"):
        assert word not in text, word
    # 本番で固定している既定値が、環境変数の差し替えを入れても変わっていない
    assert 'ENV_BACKUP_DIR="${NCM_ENV_BACKUP_DIR:-/root/netconfig-manager-backup}"' in text
    assert 'SYSTEMD_UNIT_DIR="${NCM_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"' in text
    assert 'INSTALL_DIR="/opt/netconfig-manager"' in text


# ------------------------------------------------------------------ .env の書き方いろいろ（更新で 1 バイトも変えない）
def _env_variants():
    base = OLD_ENV
    tricky = (base.replace("SECRET_KEY=secretkey", "SECRET_KEY=a=b#c$d e\"f'g")
                  .replace("ADMIN_PASSWORD=admin-password-1", "ADMIN_PASSWORD='p#ss $word = \"x\"'")
                  .replace("ALLOWED_ORIGINS=", "ALLOWED_ORIGINS=https://a.example,https://b.example:8443,http://10.0.0.1"))
    quoted = base.replace("HTTP_PORT=80", 'HTTP_PORT="80"').replace("HTTPS_PORT=443", "HTTPS_PORT='443'")
    return {
        "plain": base,
        "tricky-values": tricky,
        "no-final-newline": base.rstrip("\n"),
        "crlf": base.replace("\n", "\r\n"),
        "quoted-ports": quoted,
        "crlf-and-quoted-ports": quoted.replace("\n", "\r\n"),
        "crlf-no-final-newline": base.replace("\n", "\r\n").rstrip("\r\n"),
        "comments-and-blank-lines": "# memo\n\n" + base + "\n# end\n",
    }


@pytest.mark.parametrize("name", list(_env_variants()))
def test_update_leaves_any_env_byte_for_byte(box, name):
    all_installed(box)
    text = _env_variants()[name]
    env_file = box.install / ".env"
    env_file.write_bytes(text.encode())  # 改行を変換せずに書く
    r = box.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_file.read_bytes() == text.encode()
    assert [p.read_bytes() for p in box.backup_dir.glob("env-*")] == [text.encode()]
    assert box.count("sed -i") == 0 and not [c for c in box.calls() if "tee -a" in c]  # 書き換える操作そのものが無い
    assert_safe(box)


def test_update_with_invalid_quoted_port_still_stops_without_touching_env(alma):
    all_installed(alma)
    text = OLD_ENV.replace("HTTP_PORT=80", 'HTTP_PORT="abc"').replace("\n", "\r\n")
    alma.install.joinpath(".env").write_bytes(text.encode())
    r = alma.run()
    assert r.returncode == 1 and "HTTP_PORT が不正です: abc" in r.stdout
    assert (alma.install / ".env").read_bytes() == text.encode()
    assert alma.count("podman-compose") == 0


def test_update_env_without_final_newline_gets_missing_keys_on_new_lines(box):
    """末尾に改行が無い古い .env（最後の行が DEVICE_ENCRYPTION_KEY）: 既存の行はそのまま、足りないキーは別の行になる"""
    all_installed(box)
    lines = [line for line in OLD_ENV.splitlines() if not line.startswith(("HTTP_PORT", "HTTPS_PORT", "PUBLIC_URL", "DEVICE_ENC"))]
    key = "DEVICE_ENCRYPTION_KEY=Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo="
    original = ("\n".join([*lines, key])).encode()  # 末尾の改行なし
    (box.install / ".env").write_bytes(original)
    r = box.run()
    assert r.returncode == 0, r.stdout + r.stderr
    after = (box.install / ".env").read_bytes()
    assert after.startswith(original + b"\n")  # 既存の内容は 1 バイトも変わらない
    new_lines = after.decode().splitlines()
    assert key in new_lines  # 暗号化キーの行が無傷
    assert new_lines[-3:] == ["HTTP_PORT=80", "HTTPS_PORT=443", "PUBLIC_URL=http://192.0.2.10"]
    assert not any(line.split("=", 1)[1].startswith(("HTTP_PORT", "PUBLIC_URL")) for line in new_lines if "=" in line)
    # 追記の前に取ったバックアップは、元の内容のまま（壊れる前の内容が残る）
    assert [p.read_bytes() for p in box.backup_dir.glob("env-*")] == [original]
    assert (box.backup_dir.stat().st_mode & 0o777) == 0o700
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in box.backup_dir.glob("env-*"))
    assert_safe(box)


def test_update_backup_is_taken_before_the_first_change(alma):
    all_installed(alma)
    alma.env_file(OLD_ENV.replace("HTTPS_PORT=443\n", ""))
    r = alma.run(args=["--reconfigure"], stdin="\n\n9090\n9443\n")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = alma.calls()
    backup = next(i for i, c in enumerate(calls) if c.startswith("sudo install -m 600 ") and "/env-" in c)
    first_change = next(i for i, c in enumerate(calls) if c.startswith(("sudo sed -i", "sudo tee -a")))
    assert backup < first_change


def test_update_empty_env_gets_no_blank_line(alma):
    all_installed(alma)
    (alma.install / ".env").write_bytes(b"")
    r = alma.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert (alma.install / ".env").read_text().splitlines()[0] == "HTTP_PORT=80"


def test_import_cert_style_append_adds_newline(alma):
    """lib の ncm_env_append（import_cert.sh も使う）: 末尾の改行を補う・空のファイルには補わない・既存の行は変えない"""
    f = alma.tmp / "e"
    for original, expect in [(b"A=1\nB=2", b"A=1\nB=2\nC=3\n"), (b"A=1\n", b"A=1\nC=3\n"), (b"", b"C=3\n")]:
        f.write_bytes(original)
        r = subprocess.run(["bash", "-c", f'set -euo pipefail; . "{LIB}"; ncm_env_append "{f}" C=3'], env=alma.env(),
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert f.read_bytes() == expect


def test_env_append_writes_dash_lines_and_never_creates_the_file(alma):
    f = alma.tmp / "e"
    f.write_bytes(b"A=1\n")
    for line in ("-n", "-e foo", "-n x=1"):
        r = subprocess.run(["bash", "-c", f'set -euo pipefail; . "{LIB}"; ncm_env_append "{f}" "$1"', "bash", line],
                           env=alma.env(), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    assert f.read_bytes() == b"A=1\n-n\n-e foo\n-n x=1\n"
    missing = alma.tmp / "missing"
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ncm_env_append "{missing}" C=3'], env=alma.env(), capture_output=True, text=True)
    assert r.returncode != 0 and not missing.exists()


def test_fake_sudo_allows_temp_dir_even_when_it_lives_under_home(alma):
    """一時ディレクトリ自体が /home の下（CI のランナー）でも、その中の呼び出しは通り、外の /home は落ちる"""
    root = "/home/runner/work/_temp/pytest"  # 実在しなくてよい（true は引数を使わない）
    env = alma.env(FAKE_ROOT=root)
    ok = subprocess.run([str(alma.stubs / "sudo"), "true", f"{root}/opt/netconfig-manager/.env", f"{root}/etc/x", root],
                        env=env, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    ng = subprocess.run([str(alma.stubs / "sudo"), "true", "/home/runner/other/x"], env=env, capture_output=True, text=True)
    assert ng.returncode == 99


# ------------------------------------------------------------------ テスト用の差し替えの警告
def test_warns_when_test_overrides_are_set(alma):
    all_installed(alma)
    alma.env_file()
    r = alma.run()
    for v in ("NCM_ENV_BACKUP_DIR", "NCM_SYSTEMD_UNIT_DIR", "NCM_OS_RELEASE_FILE", "NCM_SYSTEMD_DROPIN_DIR"):
        assert f"[WARN] テスト用の差し替え（{v}）が設定されています" in r.stdout
    assert r.stdout.index("[WARN] テスト用の差し替え") < r.stdout.index("=== EXECUTE sudo -v")


def test_no_override_warning_without_overrides(alma):
    """差し替えが無いときは警告しない（本番）。本物の /root・/etc に書く前に、sudo -v の失敗で止める"""
    all_installed(alma)
    alma.env_file()
    r = alma.run(NCM_SYSTEMD_UNIT_DIR=None, NCM_SYSTEMD_DROPIN_DIR=None, NCM_OS_RELEASE_FILE=None, NCM_ENV_BACKUP_DIR=None,
                 FAKE_SUDO_V_FAIL="1")
    assert r.returncode != 0 and "テスト用の差し替え" not in r.stdout
    assert alma.calls() == ["sudo -v"]  # sudo -v の先へは進んでいない（実際の /root・/etc には触れていない）
