"""scripts/lib/os.sh（OS の判定と、OS ごとに違う操作）と、それを使う scripts/ のテスト

偽の os-release（NCM_OS_RELEASE_FILE）と、PATH の先頭に置いた偽のコマンド（dnf・apt-get・ufw・firewall-cmd・
systemctl・sudo など）で動かす。実際のパッケージの導入・ファイアウォールの変更は行わない。
確かめること: AlmaLinux 10 では dnf と firewalld だけを使い、Ubuntu 24.04 では apt-get と ufw だけを使う。
対象外の OS では止まる（警告する）。check_env.sh は Ubuntu 24.04 を OK とする
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
LIB = SCRIPTS / "lib" / "os.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")

ALMA = 'ID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.0"\nPRETTY_NAME="AlmaLinux 10.0 (Purple Lion)"\n'
UBUNTU = 'PRETTY_NAME="Ubuntu 24.04.2 LTS"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n'

# 偽のコマンド。呼ばれた名前と引数を $FAKE_LOG に 1 行ずつ記録する。動きは環境変数で変える
STUB = r"""#!/bin/bash
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >> "$FAKE_LOG"
[ "$name" = apt-get ] && printf 'DEBIAN_FRONTEND=%s\n' "${DEBIAN_FRONTEND:-}" >> "$FAKE_LOG"
case "$name" in
  rpm) exit "${FAKE_RPM_RC:-1}" ;;                 # 1 = epel-release は未導入
  dpkg) exit "${FAKE_DPKG_RC:-1}" ;;               # 1 = netavark などは未導入
  curl) echo 200 ;;
  ufw) [ "$1" = status ] && cat "${FAKE_UFW_STATUS:-/dev/null}" ;;
  aa-status) echo "apparmor module is loaded." ;;
  systemctl)
    case "$1" in
      is-active) exit "${FAKE_FIREWALLD_RC:-3}" ;;  # 0 = firewalld が動いている
      list-unit-files) [ -n "${FAKE_RESTART_UNIT:-}" ] && echo "podman-restart.service enabled" ; exit 0 ;;
      enable) exit "${FAKE_ENABLE_RC:-0}" ;;
      cat) [ -n "${FAKE_UNIT_TEXT:-}" ] && cat "$FAKE_UNIT_TEXT" ; exit 0 ;;
    esac ;;
esac
exit 0
"""
SUDO_STUB = r"""#!/bin/bash
while [[ "${1:-}" == -* ]]; do case "$1" in -u) shift 2 ;; *) shift ;; esac; done
exec "$@"
"""
COMMANDS = ["dnf", "apt-get", "apt", "rpm", "dpkg", "ufw", "firewall-cmd", "systemctl", "curl", "aa-status"]
PROXY_ENV = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY",
             "GIT_SSL_CAINFO", "OUTBOUND_CA_FILE", "NCM_OS_CA_BUNDLE")


@pytest.fixture
def box(tmp_path):
    """偽のコマンドの置き場・記録・os-release を作る"""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for n in COMMANDS:
        (stubs / n).write_text(STUB)
        (stubs / n).chmod(0o755)
    (stubs / "sudo").write_text(SUDO_STUB)
    (stubs / "sudo").chmod(0o755)

    class Box:
        dir = tmp_path
        log = tmp_path / "calls.log"

        def release(self, text):
            f = tmp_path / "os-release"
            f.write_text(text)
            return f

        def env(self, release, **extra):
            # DEBIAN_FRONTEND は、lib が apt-get に渡すかを確かめるため、呼び出し側の環境からは外しておく
            # 実行する人の環境のプロキシ（開発機・CI の設定）も外す（check_env.sh が拾うため）
            base = {k: v for k, v in os.environ.items() if k != "DEBIAN_FRONTEND" and k not in PROXY_ENV}
            return {**base, "PATH": f"{stubs}:{os.environ['PATH']}", "FAKE_LOG": str(self.log),
                    "NCM_OS_RELEASE_FILE": str(release), "LC_ALL": "C",
                    "NCM_SYSTEMD_DROPIN_DIR": str(tmp_path / "dropin"), **extra}

        def calls(self):
            return self.log.read_text().splitlines() if self.log.exists() else []

    return Box()


def sh(box, release, code, **extra):
    """lib を読み込んで code を実行する（本番のスクリプトと同じ set -euo pipefail の下で）"""
    return subprocess.run(["bash", "-c", f'set -euo pipefail; . "{LIB}"; {code}'], env=box.env(release, **extra),
                          capture_output=True, text=True, timeout=60)


# ------------------------------------------------------------------ OS の判定
CASES = [
    # (os-release, 系統, 対応, 注意に含まれる文字)
    (ALMA, "rhel", "ok", ""),
    ('ID="rhel"\nVERSION_ID="10.1"\nPRETTY_NAME="Red Hat Enterprise Linux 10.1"\n', "rhel", "ok", ""),
    ('ID="rocky"\nVERSION_ID="9.5"\nPRETTY_NAME="Rocky Linux 9.5"\n', "rhel", "warn", "RHEL 10 前提"),
    ('ID=fedora\nVERSION_ID=42\nPRETTY_NAME="Fedora Linux 42"\n', "rhel", "warn", "Fedora"),
    (UBUNTU, "ubuntu", "ok", "実機での導入は未確認"),
    ('ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n', "ubuntu", "warn", "24.04 LTS を想定"),
    ('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n', "ubuntu", "warn", "Debian は未確認"),
    ('ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11"\n', "ubuntu", "warn", "Debian 12 以降"),
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\nPRETTY_NAME="Linux Mint 22"\n', "ubuntu", "warn", "未確認"),
    ('ID=almalinux-derivative\nID_LIKE="rhel fedora"\nVERSION_ID="10"\nPRETTY_NAME="Example 10"\n', "rhel", "warn", "未確認"),
    ('ID=arch\nPRETTY_NAME="Arch Linux"\n', "unknown", "unsupported", "対応しているのは"),
    ("", "unknown", "unsupported", "対応しているのは"),
]


@pytest.mark.parametrize("text,family,level,note", CASES)
def test_detect_os(box, text, family, level, note):
    r = sh(box, box.release(text), 'echo "$NCM_OS_FAMILY|$NCM_OS_LEVEL|$NCM_OS_NOTE"')
    assert r.returncode == 0, r.stderr
    fam, lvl, nt = r.stdout.strip().split("|", 2)
    assert (fam, lvl) == (family, level)
    assert note in nt
    if level == "ok" and family == "rhel":
        assert nt == ""


def test_detect_os_missing_file(box):
    r = sh(box, box.dir / "nothing", 'echo "$NCM_OS_FAMILY|$NCM_OS_LEVEL"')
    assert r.stdout.strip() == "unknown|unsupported"


def test_detect_os_does_not_leak_os_release_variables(box):
    # os-release を source すると ID・VERSION などが呼び出し側に入ってしまうため、読むだけにしている
    r = sh(box, box.release(UBUNTU), 'echo "[${ID:-}][${VERSION_ID:-}][${PRETTY_NAME:-}]"')
    assert r.stdout.strip() == "[][][]"


# ------------------------------------------------------------------ パッケージ
def test_install_on_almalinux_uses_dnf_and_epel(box):
    r = sh(box, box.release(ALMA), "ncm_require_pkg_manager; ncm_install_packages git podman podman-compose curl")
    assert r.returncode == 0, r.stderr
    calls = box.calls()
    assert "dnf install -y epel-release" in calls
    assert "dnf install -y git podman podman-compose curl" in calls
    assert not [c for c in calls if "apt" in c or "dpkg" in c]


def test_install_on_almalinux_skips_epel_when_present_or_not_needed(box):
    r = sh(box, box.release(ALMA), "ncm_install_packages git podman podman-compose", FAKE_RPM_RC="0")
    assert r.returncode == 0
    assert not [c for c in box.calls() if "epel-release" in c.replace("rpm -q epel-release", "")]
    box.log.unlink()
    sh(box, box.release(ALMA), "ncm_install_packages openssl")
    assert box.calls() == ["dnf install -y openssl"]


def test_extra_packages_are_empty_on_almalinux(box):
    r = sh(box, box.release(ALMA), "ncm_extra_packages")
    assert r.stdout == "" and box.calls() == []


def test_install_on_ubuntu_uses_apt_get(box):
    code = 'EXTRA=(); mapfile -t EXTRA < <(ncm_extra_packages); ncm_install_packages git podman podman-compose "${EXTRA[@]}"'
    r = sh(box, box.release(UBUNTU), code)
    assert r.returncode == 0, r.stderr
    calls = box.calls()
    assert "apt-get update" in calls
    assert "DEBIAN_FRONTEND=noninteractive" in calls  # 質問で止まらないようにする
    # コンテナ同士が名前で引けるようにするもの（netavark・aardvark-dns）と rootless 用の uidmap も入れる
    assert "apt-get install -y git podman podman-compose netavark aardvark-dns uidmap" in calls
    assert not [c for c in calls if c.startswith(("dnf", "dnf", "rpm")) or "epel" in c]


def test_extra_packages_skip_installed_ones_on_ubuntu(box):
    r = sh(box, box.release(UBUNTU), "ncm_extra_packages", FAKE_DPKG_RC="0")
    assert r.stdout == ""


def test_package_name_and_hint_differ_by_os(box):
    assert sh(box, box.release(ALMA), "ncm_install_hint gpg").stdout.strip() == "sudo dnf install -y gnupg2"
    assert sh(box, box.release(UBUNTU), "ncm_install_hint gpg").stdout.strip() == "sudo apt-get install -y gnupg"
    assert sh(box, box.release(UBUNTU), "ncm_install_hint podman podman-compose").stdout.strip() == \
        "sudo apt-get install -y podman podman-compose"
    box.log.unlink(missing_ok=True)
    sh(box, box.release(UBUNTU), "ncm_install_packages gpg")
    assert "apt-get install -y gnupg" in box.calls()


def _isolated_path(box, *tools):
    """指定したコマンドだけを置いた PATH（dnf・apt-get が無い環境を作る）"""
    d = box.dir / "isolated"
    d.mkdir(exist_ok=True)
    for t in ("bash", "env", "sed", "tail", "tr", "cat", "grep", *tools):
        if not (d / t).exists():
            (d / t).symlink_to(shutil.which(t))
    return str(d)


@pytest.mark.parametrize("text,missing,message", [
    (ALMA, "dnf", "dnf required"),
    ('ID=arch\nPRETTY_NAME="Arch"\n', "dnf", "dnf required"),   # 対象外の OS は、これまでどおり dnf を前提に止まる
    (UBUNTU, "apt-get", "apt-get required"),
])
def test_stops_without_package_manager(box, text, missing, message):
    e = box.env(box.release(text))
    e["PATH"] = _isolated_path(box)
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ncm_require_pkg_manager'], env=e, capture_output=True, text=True)
    assert r.returncode == 1 and message in r.stdout, r.stdout + r.stderr


def test_package_manager_found_passes(box):
    assert sh(box, box.release(UBUNTU), "ncm_require_pkg_manager").returncode == 0
    assert sh(box, box.release(ALMA), "ncm_require_pkg_manager").returncode == 0


# ------------------------------------------------------------------ ファイアウォール
def test_firewall_on_almalinux_uses_firewalld(box):
    r = sh(box, box.release(ALMA), "ncm_firewall_open 80 443", FAKE_FIREWALLD_RC="0")
    assert r.returncode == 0, r.stderr
    assert "Port 80/tcp, 443/tcp opened in firewalld" in r.stdout
    calls = box.calls()
    assert "firewall-cmd --permanent --add-service=http" in calls
    assert "firewall-cmd --permanent --add-service=https" in calls
    assert "firewall-cmd --reload" in calls
    assert not [c for c in calls if "ufw" in c]


def test_firewall_on_almalinux_non_default_ports_and_stopped(box):
    sh(box, box.release(ALMA), "ncm_firewall_open 8080 8443", FAKE_FIREWALLD_RC="0")
    assert "firewall-cmd --permanent --add-port=8080/tcp" in box.calls()
    assert "firewall-cmd --permanent --add-port=8443/tcp" in box.calls()
    box.log.unlink()
    r = sh(box, box.release(ALMA), "ncm_firewall_open 80 443", FAKE_FIREWALLD_RC="3")
    assert "firewalld is not running, skipping" in r.stdout
    assert not [c for c in box.calls() if "firewall-cmd" in c]


def test_firewall_on_ubuntu_uses_ufw_only_when_active(box):
    status = box.dir / "ufw_active"
    status.write_text("Status: active\n")
    r = sh(box, box.release(UBUNTU), "ncm_firewall_open 80 8443", FAKE_UFW_STATUS=str(status))
    assert r.returncode == 0, r.stderr
    calls = box.calls()
    assert "ufw allow 80/tcp" in calls and "ufw allow 8443/tcp" in calls
    assert "Port 80/tcp, 8443/tcp opened in ufw" in r.stdout
    assert not [c for c in calls if "firewall-cmd" in c or "is-active" in c]


def test_firewall_on_ubuntu_does_nothing_when_ufw_inactive(box):
    status = box.dir / "ufw_inactive"
    status.write_text("Status: inactive\n")
    r = sh(box, box.release(UBUNTU), "ncm_firewall_open 80 443", FAKE_UFW_STATUS=str(status))
    assert "ufw is not active, skipping" in r.stdout
    assert not [c for c in box.calls() if c.startswith("ufw allow") or "firewall-cmd" in c]


def test_firewall_on_ubuntu_without_ufw_installed(box):
    e = box.env(box.release(UBUNTU))
    e["PATH"] = _isolated_path(box)  # ufw も sudo も無い
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ncm_firewall_open 80 443'], env=e, capture_output=True, text=True)
    assert r.returncode == 0 and "skipping" in r.stdout


# ------------------------------------------------------------------ 自動起動
def test_autostart_on_almalinux_is_unchanged(box):
    r = sh(box, box.release(ALMA), "ncm_enable_autostart")
    assert r.returncode == 0
    assert box.calls() == ["systemctl enable --now podman-restart.service"]
    assert sh(box, box.release(ALMA), "ncm_enable_autostart", FAKE_ENABLE_RC="1").returncode != 0  # RHEL 系は失敗で止める


def test_autostart_on_ubuntu_warns_instead_of_stopping(box):
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1")
    assert r.returncode == 0 and "systemctl enable --now podman-restart.service" in box.calls()
    box.log.unlink()
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_ENABLE_RC="1")
    assert r.returncode == 0 and "[WARN]" in r.stdout
    box.log.unlink()
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart")  # ユニットが無い
    assert r.returncode == 0 and "[WARN] podman-restart.service が見つかりません" in r.stdout
    assert not [c for c in box.calls() if "enable" in c]


UNIT_PLAIN = "[Service]\nType=oneshot\nExecStart=/usr/bin/podman start --all --filter restart-policy=always\n"
UNIT_DONE = UNIT_PLAIN + "\n# /etc/systemd/system/podman-restart.service.d/x.conf\n[Service]\nExecStart=\nExecStart=/usr/bin/podman start --all --filter restart-policy=always --filter restart-policy=unless-stopped\n"


def test_autostart_on_ubuntu_adds_unless_stopped_dropin(box):
    unit = box.dir / "unit.txt"
    unit.write_text(UNIT_PLAIN.replace("/usr/bin/podman", "/usr/local/bin/podman"))
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_UNIT_TEXT=str(unit))
    assert r.returncode == 0, r.stderr
    conf = (box.dir / "dropin" / "10-netconfig-manager.conf").read_text()
    # 元の ExecStart を空にしてから、元の podman のパスで両方のフィルターを指定する
    assert conf == ("[Service]\nExecStart=\nExecStart=/usr/local/bin/podman start --all "
                    "--filter restart-policy=always --filter restart-policy=unless-stopped\n")
    calls = box.calls()
    assert calls.index("systemctl daemon-reload") < calls.index("systemctl enable --now podman-restart.service")
    # 2 回目（同じ内容が置いてある）は書き直さず、daemon-reload もしない
    box.log.unlink()
    mtime = (box.dir / "dropin" / "10-netconfig-manager.conf").stat().st_mtime_ns
    sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_UNIT_TEXT=str(unit))
    assert (box.dir / "dropin" / "10-netconfig-manager.conf").stat().st_mtime_ns == mtime
    assert "systemctl daemon-reload" not in box.calls()


def test_autostart_on_ubuntu_leaves_unit_that_already_starts_unless_stopped(box):
    unit = box.dir / "unit.txt"
    unit.write_text("[Service]\nExecStart=/usr/bin/podman start --all --filter restart-policy=always --filter restart-policy=unless-stopped\n")
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_UNIT_TEXT=str(unit))
    assert r.returncode == 0
    assert not (box.dir / "dropin").exists()
    assert "systemctl daemon-reload" not in box.calls()
    assert "systemctl enable --now podman-restart.service" in box.calls()


def test_autostart_on_almalinux_never_writes_dropin(box):
    unit = box.dir / "unit.txt"
    unit.write_text(UNIT_PLAIN)
    sh(box, box.release(ALMA), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_UNIT_TEXT=str(unit))
    assert not (box.dir / "dropin").exists()
    assert box.calls() == ["systemctl enable --now podman-restart.service"]


def test_autostart_dropin_failure_only_warns_on_ubuntu(box):
    unit = box.dir / "unit.txt"
    unit.write_text(UNIT_PLAIN)
    (box.dir / "dropin").write_text("ファイルがあるのでディレクトリを作れない")
    r = sh(box, box.release(UBUNTU), "ncm_enable_autostart", FAKE_RESTART_UNIT="1", FAKE_UNIT_TEXT=str(unit))
    assert r.returncode == 0 and "[WARN] podman-restart.service に unless-stopped" in r.stdout


def test_os_release_with_crlf_is_read(box):
    r = sh(box, box.release(UBUNTU.replace("\n", "\r\n")), 'echo "$NCM_OS_FAMILY|$NCM_OS_LEVEL|$NCM_OS_VERSION"')
    assert r.stdout.strip() == "ubuntu|ok|24.04"


def test_setup_first_run_without_lib_stops_on_unsupported_os(box):
    """リポジトリの外に置いた setup.sh の初回は、対象外の OS なら clone の前に止まる"""
    import stat
    out = box.dir / "outside"
    out.mkdir()
    (out / "setup.sh").write_text((SCRIPTS / "setup.sh").read_text(encoding="utf-8"))
    (box.dir / "stubs" / "git").write_text(STUB)
    (box.dir / "stubs" / "git").chmod(stat.S_IRWXU)
    e = box.env(box.release('ID=arch\nPRETTY_NAME="Arch"\n'))
    r = subprocess.run(["bash", str(out / "setup.sh")], env=e, input="\n" * 20, capture_output=True, text=True, timeout=60,
                       cwd=out)
    assert r.returncode == 1 and "対象外の OS です" in r.stdout, r.stdout + r.stderr
    assert not [c for c in box.calls() if c.startswith(("git", "apt-get", "dnf"))]


# ------------------------------------------------------------------ check_env.sh
def run_check(box, text, **extra):
    e = box.env(box.release(text), **extra)
    return subprocess.run(["bash", str(SCRIPTS / "check_env.sh")], env=e, capture_output=True, text=True, timeout=120)


def test_check_env_accepts_ubuntu_2404(box):
    r = run_check(box, UBUNTU)
    assert "[ OK ] OS: Ubuntu 24.04.2 LTS" in r.stdout
    assert "実機での導入は未確認" in r.stdout
    # 案内は apt（dnf ではない）
    assert "dnf" not in r.stdout


def test_check_env_accepts_almalinux_10(box):
    r = run_check(box, ALMA)
    assert "[ OK ] OS: AlmaLinux 10.0 (Purple Lion)" in r.stdout
    assert "apt-get" not in r.stdout


def test_check_env_warns_for_unsupported_os(box):
    r = run_check(box, 'ID=arch\nPRETTY_NAME="Arch Linux"\n')
    assert "[WARN] OS: Arch Linux（対象外の OS です" in r.stdout


def test_check_env_reads_ufw_state_on_ubuntu(box):
    status = box.dir / "ufw"
    status.write_text("Status: active\n\nTo   Action  From\n--   ------  ----\n80/tcp  ALLOW  Anywhere\n")
    r = run_check(box, UBUNTU, FAKE_UFW_STATUS=str(status))
    assert "ufw: 80/tcp は許可済み" in r.stdout
    assert "[WARN] ufw: 443/tcp が未許可" in r.stdout


# ------------------------------------------------------------------ collect_logs.sh
def test_collect_logs_shows_os_and_apparmor_on_ubuntu(box):
    import tarfile
    install = box.dir / "ncm"
    (install / "backend" / "app").mkdir(parents=True)
    fake = box.dir / "podman"
    fake.write_text("#!/bin/bash\nexit 0\n")
    fake.chmod(0o755)
    out = box.dir / "out"
    e = box.env(box.release(UBUNTU), INSTALL_DIR=str(install), PROJECT_NAME="ncm", CONTAINER_CMD=str(fake), SUDO="",
                COLLECT_OUT_DIR=str(out))
    r = subprocess.run(["bash", str(SCRIPTS / "collect_logs.sh")], env=e, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    with tarfile.open(next(out.glob("netconfig-logs-*.tar.gz"))) as tar:
        files = {m.name.split("/", 1)[1]: tar.extractfile(m).read().decode() for m in tar.getmembers() if m.isfile()}
    assert "Ubuntu 24.04.2 LTS（系統: ubuntu、対応: ok）" in files["summary.txt"]
    assert "system/apparmor.txt" in files and "apparmor module is loaded" in files["system/apparmor.txt"]
    assert "system/ufw.txt" in files


# ------------------------------------------------------------------ 全スクリプト
def test_all_scripts_pass_syntax_check_and_use_lf():
    for f in [*SCRIPTS.glob("*.sh"), *(SCRIPTS / "lib").glob("*.sh")]:
        assert b"\r" not in f.read_bytes(), f"{f.name} の改行が LF ではありません"
        r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, f"{f.name}: {r.stderr}"


def test_os_specific_commands_live_only_in_the_lib():
    """OS ごとの操作は lib にまとめ、各スクリプトに直接書かない（書き足すと OS の分岐が漏れる）"""
    for name in ("import_cert.sh", "check_env.sh", "backup.sh", "restore.sh"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "dnf install" not in text.replace("echo \"dnf install gnupg2\"", ""), name
        assert "apt-get install" not in text, name
    setup = (SCRIPTS / "setup.sh").read_text(encoding="utf-8")
    assert "firewall-cmd" not in setup and "rpm -q" not in setup and "enable --now podman-restart" not in setup
