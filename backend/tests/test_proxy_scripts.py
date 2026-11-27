"""導入・更新のプロキシ対応（scripts/lib/proxy.sh と、それを使う setup.sh・check_env.sh・collect_logs.sh）のテスト

test_setup_script.py の Box（偽のコマンド・偽の sudo・PATH の差し替え）で setup.sh を最初から最後まで通し、
偽のコマンドが受け取った環境変数（FAKE_ENV_LOG）と引数（FAKE_LOG）・画面の出力を調べる。偽の sudo は本物と同じく
プロキシの環境変数を落とし、--preserve-env=名前,... で引き継いだものだけを残す。
認証情報が漏れていないかは、パスワードに入れた目印の文字列（MARK）で確かめる（環境変数として渡るのはよい）。
"""
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
from test_os_scripts import ALMA, COMMANDS, PROXY_ENV, SUDO_STUB, UBUNTU
from test_os_scripts import STUB as OS_STUB
from test_setup_script import OLD_ENV, Box, all_installed, assert_safe, import_box, run_import, stub

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
PROXY_LIB = SCRIPTS / "lib" / "proxy.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash が必要")

MARK = "Mk9PwZq"                                   # パスワードの目印（出力・引数に出てはいけない）
PASSWORD = f"{MARK}%40x%23y"                       # 記号（@ と #）を URL エンコードしたパスワード
AUTH_URL = f"http://user01:{PASSWORD}@proxy.example.test:3128"
MASKED = "http://***@proxy.example.test:3128"
PLAIN_URL = "http://proxy.example.test:8080"
ALWAYS = ["localhost", "127.0.0.1", "::1", "db", "redis", "backend", "worker", "beat", "frontend"]
PX_KEYS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")

CA_BODY = "MIIBexampleCorpCA" + "A" * 40 + "BBBBexampleCorpCA"   # Example Corp CA（偽物の本文）
CA_PEM = f"-----BEGIN CERTIFICATE-----\n{CA_BODY[:48]}\n{CA_BODY[48:]}\n-----END CERTIFICATE-----\n"
OTHER_PEM = "-----BEGIN CERTIFICATE-----\nMIIBpublicRootCAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n-----END CERTIFICATE-----\n"
# 同じ証明書を、改行の位置を変えて書いたもの（OS の束に登録済みかの判定は、改行の位置に左右されない）
CA_PEM_REWRAPPED = f"-----BEGIN CERTIFICATE-----\r\n{CA_BODY[:20]}\r\n{CA_BODY[20:]}\r\n-----END CERTIFICATE-----\r\n"


# ------------------------------------------------------------------ フィクスチャ
@pytest.fixture(params=["alma", "ubuntu"])
def box(request, tmp_path):
    return Box(tmp_path, request.param)


@pytest.fixture
def alma(tmp_path):
    return Box(tmp_path, "alma")


@pytest.fixture
def osb(tmp_path):
    """check_env.sh・collect_logs.sh 用（test_os_scripts.py の box と同じ作り: PATH の先頭に偽のコマンド）"""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for n in COMMANDS:
        stub(stubs / n, OS_STUB)
    stub(stubs / "sudo", SUDO_STUB)

    class OsBox:
        dir = tmp_path
        log = tmp_path / "calls.log"

        def release(self, text):
            f = tmp_path / "os-release"
            f.write_text(text)
            return f

        def env(self, release, **extra):
            base = {k: v for k, v in os.environ.items() if k != "DEBIAN_FRONTEND" and k not in PROXY_ENV}
            base.update(PATH=f"{stubs}:{os.environ['PATH']}", FAKE_LOG=str(self.log), NCM_OS_RELEASE_FILE=str(release),
                        LC_ALL="C")
            base.update({k: v for k, v in extra.items() if v is not None})
            return base

        def calls(self):
            return self.log.read_text().splitlines() if self.log.exists() else []

    return OsBox()


# ------------------------------------------------------------------ 準備
# 偽の openssl: x509 -noout は、標準入力に BROKEN を含めば読めないことにする
OPENSSL = r"""#!/bin/bash
printf 'openssl %s\n' "$*" >> "$FAKE_LOG"
in=$(cat)
[ "$1" = x509 ] && [[ "$in" == *BROKEN* ]] && exit 1
exit 0
"""
# 偽の podman-compose: FAKE_COMPOSE_LINE を出す。FAKE_COMPOSE_FAIL（up / build）のとき FAKE_COMPOSE_RC で終わる
COMPOSE_STUB = r"""#!/bin/bash
printf 'podman-compose %s\n' "$*" >> "$FAKE_LOG"
[ -n "${FAKE_COMPOSE_LINE:-}" ] && echo "$FAKE_COMPOSE_LINE"
[ -n "${FAKE_COMPOSE_LINE:-}" ] && echo "$FAKE_COMPOSE_LINE" >&2
for a in "$@"; do [ "$a" = "${FAKE_COMPOSE_FAIL:-none}" ] && exit "${FAKE_COMPOSE_RC:-1}"; done
exit 0
"""


def env_calls(b):
    """偽のコマンドが受け取った環境（1 回の呼び出しで 1 件）: [{"cmd": "podman pull", "http_proxy": ..., ...}]"""
    out = []
    f = b.tmp / "env.log"
    if not f.exists():
        return out
    for line in f.read_text().splitlines():
        cmd, *pairs = line.split("\t")
        d = {"cmd": cmd}
        for p in pairs:
            k, _, v = p.partition("=")
            d[k] = v
        out.append(d)
    return out


def env_of(b, prefix):
    found = [c for c in env_calls(b) if c["cmd"].startswith(prefix)]
    assert found, f"{prefix} が呼ばれていません: {[c['cmd'] for c in env_calls(b)]}"
    return found


def run(b, **extra):
    extra.setdefault("FAKE_ENV_LOG", str(b.tmp / "env.log"))
    stdin = extra.pop("stdin", "\n" * 8)
    return b.run(stdin=stdin, **extra)


def no_leak(b, r):
    """目印のパスワードが、画面・コマンドの引数（ps に見えるもの）のどこにも出ていない"""
    assert MARK not in r.stdout and MARK not in r.stderr, "画面にパスワードが出ています"
    leaked = [c for c in b.calls() if MARK in c]
    assert not leaked, f"コマンドの引数にパスワードが出ています: {leaked}"


def assert_proxy_passed(b, prefix, url):
    for c in env_of(b, prefix):
        for k in PX_KEYS:
            assert c[k] == url, (prefix, k, c)
        for k in ("no_proxy", "NO_PROXY"):
            entries = c[k].split(",")
            for a in ALWAYS:
                assert a in entries, (prefix, k, a)


def assert_proxy_not_passed(b, prefix):
    for c in env_of(b, prefix):
        for k in (*PX_KEYS, "no_proxy", "NO_PROXY"):
            assert c[k] == "", (prefix, k, c)


def package_prefix(b):
    return "dnf install" if b.os == "alma" else "apt-get install"


def make_ca(b, name="outbound-ca.pem", text=CA_PEM):
    d = b.install / "certs-outbound"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text)
    return d / name


def os_bundle(b, *pems):
    f = b.tmp / "os-ca-bundle.crt"
    f.write_text("".join(pems))
    return f


def sh_lib(code, **env):
    """lib/proxy.sh を読み込んで code を実行する（本番と同じ set -euo pipefail の下で）"""
    base = {k: v for k, v in os.environ.items() if k not in PROXY_ENV}
    base.update(env)
    return subprocess.run(["bash", "-c", f'set -euo pipefail; . "{PROXY_LIB}"; {code}'], env=base,
                          capture_output=True, text=True, timeout=60)


# ------------------------------------------------------------------ 形式の検査・伏せ字（lib の関数）
@pytest.mark.parametrize("url", [
    "http://proxy.example.test:3128", "http://proxy.example.test:3128/", AUTH_URL, "http://user01:@proxy.example.test:3128",
    "http://192.0.2.1:8080", "http://[2001:db8::1]:3128", "http://user01:pa:ss@proxy.example.test:1",
    "http://u-1.x_y~z:p%25w!*+,;=&()@proxy.example.test:65535",
])
def test_check_accepts_http_proxy_forms(url):
    r = sh_lib('ncm_proxy_check "$U"', U=url)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("url,reason", [
    (f"https://user01:{PASSWORD}@proxy.example.test:3128", "https:// のプロキシには対応していません"),
    (f"HTTPS://user01:{PASSWORD}@proxy.example.test:3128", "https:// のプロキシには対応していません"),
    (f"socks5://user01:{PASSWORD}@proxy.example.test:1080", "SOCKS のプロキシには対応していません"),
    (f"socks5h://{MARK}@proxy.example.test:1080", "SOCKS"),
    (f"ftp://{MARK}@proxy.example.test:21", "http:// で始まる形"),
    (f"{MARK}.example.test:3128", "http:// で始まる形"),
    (f"http://user01:{PASSWORD}@proxy.example.test", "ポート番号がありません"),
    (f"http://user01:{PASSWORD}@proxy.example.test:0", "1〜65535"),
    (f"http://user01:{PASSWORD}@proxy.example.test:70000", "1〜65535"),
    (f"http://user01:{MARK}@x@proxy.example.test:3128", "%40"),
    (f"http://user01:{MARK}$x@proxy.example.test:3128", "URL エンコード"),
    (f"http://user01:{MARK}#x@proxy.example.test:3128", "パスなど"),
    (f"http://user01:{MARK} x@proxy.example.test:3128", "URL エンコード"),
    (f"http://user01:{MARK}%zz@proxy.example.test:3128", "16 進数 2 桁"),
    (f"http://user01:{MARK}@proxy.example.test:3128/path", "パスなど"),
    (f"http://user01:{MARK}@proxy_example:3128", "ホスト名が正しくありません"),
    (f"http://{MARK}@proxy.example.test:3128", "ユーザー名だけでパスワードがありません"),   # アプリと同じ（H1）
    (f"http://us%3Aer:{MARK}@proxy.example.test:3128", "ユーザー名に : （%3A）"),
    (f"http://user01:{MARK}%0A@proxy.example.test:3128", "制御文字"),
])
def test_check_rejects_without_showing_value(url, reason):
    r = sh_lib('ncm_proxy_check "$U" || { echo "NG: $(ncm_proxy_error)"; exit 3; }', U=url)
    assert r.returncode == 3 and reason in r.stdout, r.stdout + r.stderr
    assert MARK not in r.stdout + r.stderr


@pytest.mark.parametrize("url,masked", [
    (AUTH_URL, MASKED), ("http://user01:@proxy.example.test:3128", MASKED), (PLAIN_URL, PLAIN_URL),
    ("http://proxy.example.test:8080/", PLAIN_URL), ("", ""),
])
def test_mask(url, masked):
    r = sh_lib('ncm_proxy_mask "$U"', U=url)
    assert r.stdout.strip() == masked


NO_PROXY_ITEMS = [
    "intranet.example.test", ".example.test", "*.example.test", "Example.TEST", "host.example.test.", "a_b.example.test", "*",
    "10.0.0.1", "10.0.0.0/8", "10.0.0.0/255.0.0.0", "10.0.0.0/0.255.255.255", "10.0.0.0/255.0.255.0", "10.0.0.0/33",
    "10.0.0.0/", "0.0.0.0/8", "300.1.1.1", "010.0.0.1", "010.0.0.0/8", "::1", "::", "[::1]", "[2001:db8::1]", "2001:db8::/32",
    "2001:DB8:0:0:0:0:0:1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", ":::", "::ffff:192.0.2.1", "fe80::1%eth0",
    "2001:db8::/129", "fe80::1%eth0/64", "fe80::1%", "fe80::1%a%b", "[::1]:80", "10.*", "*example.test", "<local>", "host.example.test:8080", "例え.example.test",
    "-bad.example.test", "bad-.example.test", "a" * 63 + ".test", "a" * 64 + ".test", ".", "*.", "a..b", "http://x",
]


@pytest.mark.parametrize("item", NO_PROXY_ITEMS)
def test_noproxy_item_matches_app_rules(item):
    """setup.sh の NO_PROXY の検査は、アプリ（app.core.outbound.parse_no_proxy）と同じものを受け付ける"""
    from app.core.outbound import parse_no_proxy
    try:
        parse_no_proxy(item)
        app_ok = True
    except ValueError:
        app_ok = False
    r = sh_lib('ncm_proxy_noproxy_item "$I"', I=item)
    assert (r.returncode == 0) == app_ok, (item, r.stdout, app_ok)
    if app_ok:
        parse_no_proxy(r.stdout.strip())  # 正規化した形もアプリが受け付ける


def test_no_proxy_always_has_loopback_and_service_names(tmp_path):
    r = sh_lib(f'ncm_proxy_load "{tmp_path}"; ncm_proxy_apply --no-sudo; echo "$no_proxy|$NO_PROXY|$_NCM_PX_NO_USER"',
               https_proxy=PLAIN_URL, no_proxy=" intranet.example.test, localhost,*.svc.example.test,,db,10.0.0.0/8 ")
    assert r.returncode == 0, r.stderr
    full, upper, user = r.stdout.strip().split("|")
    assert full == upper
    assert full.split(",")[:len(ALWAYS)] == ALWAYS
    # 利用者の分は重複を除いて後ろに付く（*.x は .x に直す。* はファイル名に展開しない）。各コマンドへは .x に x も足す
    assert user == "intranet.example.test,.svc.example.test,10.0.0.0/8"
    assert full == ",".join(ALWAYS) + ",intranet.example.test,.svc.example.test,10.0.0.0/8,svc.example.test"


def test_lib_does_not_print_value_under_xtrace(tmp_path):
    """bash -x の下で関数を呼んでも、値（パスワード）は表示されない"""
    envf = tmp_path / ".env"
    envf.write_text(f"OUTBOUND_PROXY={AUTH_URL}\n")
    r = sh_lib(f'set -x; ncm_proxy_load "{tmp_path}"; ncm_proxy_apply --no-sudo; ncm_proxy_describe; ncm_proxy_mask; '
               'ncm_proxy_env_lines >/dev/null; echo "after"')
    assert r.returncode == 0, r.stderr
    assert MARK not in r.stdout + r.stderr and MASKED in r.stdout
    assert "+ echo after" in r.stderr  # 関数を抜けたら、表示（set -x）は元に戻る


def test_no_settings_changes_nothing(tmp_path):
    r = sh_lib(f'ncm_proxy_load "{tmp_path}"; ncm_proxy_apply; ncm_proxy_describe; env | grep -ciE "^(https?|no)_proxy=|GIT_SSL" || true')
    assert r.returncode == 0 and r.stdout.strip() == "0", r.stdout + r.stderr


# ------------------------------------------------------------------ setup.sh: プロキシ未設定
def test_setup_without_proxy_passes_nothing(box):
    r = run(box)
    assert r.returncode == 0, r.stdout + r.stderr
    for prefix in ("git -C", package_prefix(box), "podman pull", "podman-compose -f docker-compose.prod.yml build",
                   "podman-compose -f docker-compose.prod.yml up"):
        assert_proxy_not_passed(box, prefix)
        for c in env_of(box, prefix):
            assert c["GIT_SSL_CAINFO"] == ""
    assert "プロキシ" not in r.stdout and "OUTBOUND" not in (box.install / ".env").read_text()
    assert not [c for c in box.calls() if "preserve-env" in c]  # sudo の呼び方も今までと同じ
    assert not (box.install / "backend" / "build-ca").exists()  # ビルド用の CA の写しも作らない
    assert_safe(box)


# ------------------------------------------------------------------ setup.sh: 初回（環境変数で渡す）
def test_first_install_with_env_proxy_passes_it_everywhere_and_saves_to_env(box):
    r = run(box, https_proxy=AUTH_URL, no_proxy="intranet.example.test,10.0.0.0/8")
    assert r.returncode == 0, r.stdout + r.stderr
    for prefix in ("git -C", package_prefix(box), "podman pull", "podman-compose -f docker-compose.prod.yml build"):
        assert_proxy_passed(box, prefix, AUTH_URL)
    # 起動（コンテナを作る）には渡さない（podman がコンテナの環境変数に入れてしまうため）
    assert_proxy_not_passed(box, "podman-compose -f docker-compose.prod.yml up")
    up = next(c for c in box.calls() if c.startswith("sudo env ") and " up -d" in c)
    assert "-u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY" in up
    # 起動確認（localhost）はプロキシを通さない
    assert "localhost" in env_of(box, "curl")[0]["no_proxy"].split(",")
    # sudo には値ではなく名前だけ
    assert [c for c in box.calls() if c.startswith("sudo --preserve-env=http_proxy,https_proxy,HTTP_PROXY,HTTPS_PROXY,no_proxy,NO_PROXY ")]
    # .env に書き込む（常に入れる宛先は保存しない）。画面は伏せ字
    env = (box.install / ".env").read_text().splitlines()
    assert f"OUTBOUND_PROXY={AUTH_URL}" in env and "OUTBOUND_NO_PROXY=intranet.example.test,10.0.0.0/8" in env
    assert not [line for line in env if line.startswith("OUTBOUND_CA_FILE")]
    assert f"外部への接続にプロキシを使います: {MASKED}（環境変数 https_proxy）" in r.stdout
    assert f".env に保存しました: OUTBOUND_PROXY={MASKED}" in r.stdout
    # 導入前チェックにも渡る（sudo で落とさない）
    assert [c for c in box.calls() if c.startswith("sudo --preserve-env=") and "check_env.sh -m prod" in c]
    no_leak(box, r)
    assert_safe(box)


@pytest.mark.parametrize("var", ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"])
def test_first_install_reads_any_proxy_variable(alma, var):
    r = run(alma, **{var: PLAIN_URL})
    assert r.returncode == 0, r.stdout + r.stderr
    assert_proxy_passed(alma, "dnf install", PLAIN_URL)
    assert f"OUTBOUND_PROXY={PLAIN_URL}" in (alma.install / ".env").read_text().splitlines()
    assert f"（環境変数 {var}）" in r.stdout


def test_first_install_from_outside_the_repo_passes_proxy_before_lib_exists(alma):
    """setup.sh だけをダウンロードした初回: lib が無いあいだ（git の導入・clone）も、プロキシを名前で sudo に引き継ぐ"""
    shutil.rmtree(alma.install)
    out = alma.tmp / "downloaded"
    out.mkdir()
    shutil.copy(SCRIPTS / "setup.sh", out / "setup.sh")
    (alma.src / ".git").mkdir()
    r = run(alma, stdin=f"{alma.install}\n" + "\n" * 8, script=out / "setup.sh", cwd=out, https_proxy=AUTH_URL)
    assert r.returncode == 0, r.stdout + r.stderr
    git_install = env_of(alma, "dnf install -y git")[0]
    assert all(git_install[k] == "" for k in ("http_proxy", "HTTP_PROXY"))  # lib が無いあいだは渡された変数だけ
    assert git_install["https_proxy"] == AUTH_URL
    assert env_of(alma, "git clone")[0]["https_proxy"] == AUTH_URL
    # 取得のあとは lib を読み、すべての名前で渡す・.env に保存する
    assert_proxy_passed(alma, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)
    assert f"OUTBOUND_PROXY={AUTH_URL}" in (alma.install / ".env").read_text().splitlines()
    no_leak(alma, r)
    assert_safe(alma)


def test_first_install_from_outside_the_repo_without_preserve_env(alma):
    shutil.rmtree(alma.install)
    out = alma.tmp / "downloaded"
    out.mkdir()
    shutil.copy(SCRIPTS / "setup.sh", out / "setup.sh")
    (alma.src / ".git").mkdir()
    r = run(alma, stdin=f"{alma.install}\n" + "\n" * 8, script=out / "setup.sh", cwd=out, https_proxy=PLAIN_URL,
            FAKE_SUDO_NO_PRESERVE="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_of(alma, "dnf install -y git")[0]["https_proxy"] == PLAIN_URL
    assert env_of(alma, "git clone")[0]["https_proxy"] == PLAIN_URL


def test_first_install_under_xtrace_does_not_print_password(alma):
    """bash -x setup.sh でも、パスワードは表示されない"""
    r = subprocess.run(["bash", "-x", str(alma.install / "scripts" / "setup.sh")],
                       env=alma.env(https_proxy=AUTH_URL, FAKE_ENV_LOG=str(alma.tmp / "env.log")),
                       input="\n" * 8, capture_output=True, text=True, timeout=120, cwd=alma.workdir)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-3000:]
    assert "+ " in r.stderr  # 表示はされている
    no_leak(alma, r)
    assert_proxy_passed(alma, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)


# ------------------------------------------------------------------ setup.sh: 更新（.env にある）
def test_update_with_proxy_in_env_file_passes_it_and_keeps_env_byte_for_byte(box):
    all_installed(box)
    text = OLD_ENV + f"OUTBOUND_PROXY={AUTH_URL}\nOUTBOUND_NO_PROXY=.corp.example.test\n"
    env_file = box.env_file(text)
    r = run(box, stdin="")
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_file.read_bytes() == text.encode()
    for prefix in ("git -C", "podman pull", "podman-compose -f docker-compose.prod.yml build"):
        assert_proxy_passed(box, prefix, AUTH_URL)
        assert ".corp.example.test" in env_of(box, prefix)[0]["no_proxy"].split(",")
    assert_proxy_not_passed(box, "podman-compose -f docker-compose.prod.yml up")
    assert "（.env の OUTBOUND_PROXY）" in r.stdout and MASKED in r.stdout
    assert ".env に保存しました" not in r.stdout
    no_leak(box, r)
    assert_safe(box)


def test_update_env_file_wins_over_environment(alma):
    all_installed(alma)
    alma.env_file(OLD_ENV + f"OUTBOUND_PROXY={PLAIN_URL}\n")
    r = run(alma, stdin="", https_proxy=AUTH_URL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert_proxy_passed(alma, "podman pull", PLAIN_URL)
    no_leak(alma, r)


def test_update_adds_missing_keys_from_environment_without_touching_other_lines(box):
    all_installed(box)
    original = OLD_ENV.rstrip("\n")  # 末尾に改行の無い古い .env
    (box.install / ".env").write_bytes(original.encode())
    r = run(box, stdin="", https_proxy=AUTH_URL, no_proxy="intranet.example.test")
    assert r.returncode == 0, r.stdout + r.stderr
    after = (box.install / ".env").read_bytes()
    assert after.startswith(original.encode() + b"\n")
    assert after.decode().splitlines()[-2:] == [f"OUTBOUND_PROXY={AUTH_URL}", "OUTBOUND_NO_PROXY=intranet.example.test"]
    assert f".env に保存しました: OUTBOUND_PROXY={MASKED}" in r.stdout
    # 足す前のバックアップは元の内容のまま
    assert [p.read_bytes() for p in box.backup_dir.glob("env-*")] == [original.encode()]
    no_leak(box, r)
    assert_safe(box)


def test_update_normalizes_environment_no_proxy_before_saving(box):
    from app.core.outbound import parse_no_proxy
    all_installed(box)
    box.env_file()
    noproxy = ("localhost,10.*,host.example.test:8080,<local>,[::1]:80,例え.example.test,*example.test,"
               "*.Corp.Example.Test,Intranet.example.test.,192.0.2.0/24,[2001:db8::1],127.0.0.1,db")
    r = run(box, stdin="", https_proxy=PLAIN_URL, no_proxy=noproxy)
    assert r.returncode == 0, r.stdout + r.stderr
    saved = [line for line in (box.install / ".env").read_text().splitlines() if line.startswith("OUTBOUND_NO_PROXY=")]
    assert saved == ["OUTBOUND_NO_PROXY=.corp.example.test,intranet.example.test,192.0.2.0/24,2001:db8::1"]
    parse_no_proxy(saved[0].split("=", 1)[1])  # アプリが起動時に受け付ける（不正なら ValueError）
    for item in ("10.*", "host.example.test:8080", "<local>", "[::1]:80", "*example.test"):
        assert item in r.stdout  # 何を除いたかを画面に出す
    assert "アプリが受け付けない形式のため除きました" in r.stdout
    # 各コマンドへは .corp.example.test に corp.example.test も足す
    entries = env_of(box, "podman pull")[0]["no_proxy"].split(",")
    assert ".corp.example.test" in entries and "corp.example.test" in entries
    assert_safe(box)


def test_update_does_not_add_when_key_is_empty_but_uses_environment_this_time(alma):
    all_installed(alma)
    text = OLD_ENV + "OUTBOUND_PROXY=\n"
    env_file = alma.env_file(text)
    r = run(alma, stdin="", https_proxy=AUTH_URL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_file.read_bytes() == text.encode()
    assert ".env の OUTBOUND_PROXY が空のため" in r.stdout
    assert_proxy_passed(alma, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)
    no_leak(alma, r)


def test_update_without_environment_does_not_add_empty_values(alma):
    all_installed(alma)
    env_file = alma.env_file()
    r = run(alma, stdin="", no_proxy="intranet.example.test")  # プロキシ無しで no_proxy だけ
    assert r.returncode == 0, r.stdout + r.stderr
    assert env_file.read_bytes() == OLD_ENV.encode()
    assert_proxy_not_passed(alma, "podman pull")


def test_update_rerun_after_self_update_keeps_proxy(box):
    """git pull で setup.sh 自身が変わり、新しい内容でやり直しても、プロキシは引き継がれる"""
    all_installed(box)
    box.env_file()
    r = run(box, stdin="", https_proxy=AUTH_URL, FAKE_PULL_CHANGES_SELF="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "新しい内容でやり直します" in r.stdout
    assert_proxy_passed(box, "git -C", AUTH_URL)
    assert_proxy_passed(box, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)
    # .env に 1 回だけ足す（やり直しの前は .env に触れない）
    assert (box.install / ".env").read_text().count("OUTBOUND_PROXY=") == 1
    no_leak(box, r)
    assert_safe(box)


def test_vuln_https_proxy_left_in_env_is_reported(alma):
    all_installed(alma)
    alma.env_file(OLD_ENV + f"VULN_HTTPS_PROXY={PLAIN_URL}\n")
    r = run(alma, stdin="")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VULN_HTTPS_PROXY は廃止しました" in r.stdout and "OUTBOUND_PROXY" in r.stdout
    assert_proxy_not_passed(alma, "podman pull")  # 廃止した設定は使わない


# ------------------------------------------------------------------ setup.sh: 不正な形式
@pytest.mark.parametrize("url,reason", [
    (f"https://user01:{PASSWORD}@proxy.example.test:3128", "https:// のプロキシには対応していません"),
    (f"socks5://user01:{PASSWORD}@proxy.example.test:1080", "SOCKS のプロキシには対応していません"),
    (f"http://user01:{PASSWORD}@proxy.example.test", "ポート番号がありません"),
])
def test_invalid_proxy_from_environment_is_ignored_on_first_install(box, url, reason):
    """環境変数の値が不正なら止めない: 警告して使わず、今までどおり直接つなぐ（値は表示しない）"""
    r = run(box, https_proxy=url)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "環境変数 https_proxy のプロキシは形式が違うため使いません" in r.stdout and reason in r.stdout
    no_leak(box, r)
    assert "OUTBOUND" not in (box.install / ".env").read_text()
    assert_proxy_not_passed(box, "podman-compose -f docker-compose.prod.yml build")
    assert not [c for c in box.calls() if "preserve-env" in c]


@pytest.mark.parametrize("url", ["proxy.example.test:3128", f"user01:{MARK}@proxy.example.test:3128",
                                 f"http://{MARK}@proxy.example.test:3128"])
def test_update_with_unusable_environment_proxy_keeps_working_as_before(box, url):
    """サーバーの環境（/etc/environment など）のスキームの無い http_proxy などで、今まで更新できていた環境が止まらない"""
    all_installed(box)
    env_file = box.env_file()
    r = run(box, stdin="", http_proxy=url, HTTP_PROXY=url)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "形式が違うため使いません" in r.stdout and "直接つなぎます" in r.stdout
    assert env_file.read_bytes() == OLD_ENV.encode()
    assert box.count("podman-compose -f docker-compose.prod.yml up -d --force-recreate") == 1
    no_leak(box, r)
    assert_safe(box)


def test_failure_with_unusable_environment_proxy_mentions_its_format(alma):
    all_installed(alma)
    alma.env_file()
    r = run(alma, stdin="", https_proxy="proxy.example.test:3128", FAKE_FAIL_ON="podman-compose -f docker-compose.prod.yml build")
    assert r.returncode == 1
    assert "環境変数 https_proxy のプロキシは形式が違うため使わず、直接つないでいます" in r.stdout


@pytest.mark.parametrize("line,message", [
    (f"OUTBOUND_PROXY=http://{MARK}@proxy.example.test:3128", "（.env の OUTBOUND_PROXY）が正しくありません: ユーザー名だけ"),
    ("OUTBOUND_NO_PROXY=intranet.example.test,10.*,host.example.test:8080", ".env の OUTBOUND_NO_PROXY に正しくない項目があります: 10.* host.example.test:8080"),
    ("OUTBOUND_NO_PROXY=<local>", "OUTBOUND_NO_PROXY に正しくない項目"),
])
def test_invalid_value_in_env_file_stops_before_containers_are_recreated(box, line, message):
    """.env の値が不正なら、今のコンテナが動いているうちに（pull・ビルド・作り直しの前に）止める。どのキーかを示す"""
    all_installed(box)
    text = OLD_ENV + line + "\n"
    box.env_file(text)
    r = run(box, stdin="", https_proxy=PLAIN_URL)
    assert r.returncode == 1 and message in r.stdout, r.stdout + r.stderr
    assert box.count("podman-compose") == 0 and box.count("git -C") == 0
    assert (box.install / ".env").read_bytes() == text.encode()
    no_leak(box, r)


@pytest.mark.parametrize("line,reason", [
    ("OUTBOUND_PROXY=http://proxy.example.test:3128 # 社内のプロキシ", "パスなどを付けないでください"),
    ("OUTBOUND_PROXY=HTTP://proxy.example.test:3128", "http:// は小文字で書いてください（HTTP:// のような"),
    (f"OUTBOUND_PROXY=Http://user01:{PASSWORD}@proxy.example.test:3128", "http:// は小文字で書いてください"),
])
def test_env_file_proxy_error_adds_common_causes(alma, line, reason):
    """アプリより厳しい検査（行末のコメント・大文字のスキーム）で止まるとき、よくある原因を添える（値は出さない）"""
    all_installed(alma)
    text = OLD_ENV + line + "\n"
    alma.env_file(text)
    r = run(alma, stdin="")
    assert r.returncode == 1 and reason in r.stdout, r.stdout + r.stderr
    assert "行末にコメントを書けません" in r.stdout and "http:// は小文字で書いてください" in r.stdout
    assert "proxy.example.test" not in r.stdout and "社内のプロキシ" not in r.stdout  # 値は出さない
    no_leak(alma, r)
    assert alma.count("podman-compose") == 0 and alma.count("git -C") == 0
    assert (alma.install / ".env").read_bytes() == text.encode()


def test_invalid_proxy_in_env_file_stops_update(alma):
    all_installed(alma)
    text = OLD_ENV + f"OUTBOUND_PROXY=socks5://user01:{PASSWORD}@proxy.example.test:1080\n"
    alma.env_file(text)
    r = run(alma, stdin="")
    assert r.returncode == 1 and "（.env の OUTBOUND_PROXY）" in r.stdout and "SOCKS" in r.stdout
    no_leak(alma, r)
    assert alma.count("git -C") == 0 and alma.count("podman") == 0
    assert (alma.install / ".env").read_bytes() == text.encode()


# ------------------------------------------------------------------ setup.sh: sudo が名前の引き継ぎを許さないとき
def test_sudo_without_preserve_env_passes_values_through_private_file(box):
    """名前で引き継げない sudo の設定: 値は 0600 の一時ファイルで渡し、sudo の引数（ログ・ps）には出さない"""
    r = run(box, https_proxy=AUTH_URL, FAKE_SUDO_NO_PRESERVE="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "一時ファイル（root だけが読めるもの）で sudo に渡します" in r.stdout
    assert_proxy_passed(box, package_prefix(box), AUTH_URL)
    assert_proxy_passed(box, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)
    via_file = [c for c in box.calls() if c.startswith("sudo bash -c ")]
    assert via_file and all("/tmp/tmp." in c for c in via_file)
    assert not [c for c in box.calls() if c.startswith("sudo env http")]
    no_leak(box, r)  # 目印のパスワードは、どのコマンドの引数にも出ない
    assert_safe(box)  # 一時ファイルは終了時に消す（rm -f <mktemp の名前>）
    assert not list((box.tmp / "tmp").iterdir())


def test_sudo_without_preserve_env_with_user_option(alma):
    """sudo -u <所有者> の形（git pull）でも、root の中の sudo で名前を引き継いで値が届く"""
    alma.preinstall("git")
    code = (f'. "{PROXY_LIB}"; ncm_proxy_load "{alma.tmp}"; ncm_proxy_apply; ncm_sudo_out -u nobody git -C /x pull; '
            'ls "$_NCM_PX_ENVFILE" >/dev/null; stat -c %a "$_NCM_PX_ENVFILE"; ncm_proxy_cleanup')
    r = subprocess.run(["bash", "-c", code], env=alma.env(https_proxy=AUTH_URL, FAKE_SUDO_NO_PRESERVE="1",
                                                        FAKE_ENV_LOG=str(alma.tmp / "env.log")),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip().endswith("600"), r.stdout + r.stderr
    assert env_of(alma, "git -C")[0]["https_proxy"] == AUTH_URL
    assert not [c for c in alma.calls() if MARK in c]


# ------------------------------------------------------------------ setup.sh: 追加の CA
CA_HINT = {
    "alma": "sudo cp {ca} /etc/pki/ca-trust/source/anchors/netconfig-outbound-ca.pem && sudo update-ca-trust",
    "ubuntu": "sudo cp {ca} /usr/local/share/ca-certificates/netconfig-outbound-ca.crt && sudo update-ca-certificates",
}


def test_ca_is_bundled_for_git_staged_for_build_and_os_hint_is_shown(box):
    all_installed(box)
    ca = make_ca(box)
    bundle = os_bundle(box, OTHER_PEM)
    box.env_file(OLD_ENV + f"OUTBOUND_PROXY={AUTH_URL}\nOUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(box, stdin="", NCM_OS_CA_BUNDLE=str(bundle))
    assert r.returncode == 0, r.stdout + r.stderr
    # git: OS の束＋追加の CA を束ねた一時ファイル
    git = env_of(box, "git -C")[0]
    assert git["GIT_SSL_CAINFO"] and "/tmp/tmp." in git["GIT_SSL_CAINFO"]
    gitca = (box.tmp / "env.log.gitca").read_text()
    assert OTHER_PEM in gitca and CA_PEM in gitca and gitca.index(OTHER_PEM) < gitca.index(CA_PEM)
    assert not Path(git["GIT_SSL_CAINFO"]).exists()  # 終了時に消す
    # ビルド: 各ビルドコンテキストの build-ca/ に置く
    for ctx in ("backend", "frontend"):
        assert (box.install / ctx / "build-ca" / "outbound-ca.crt").read_text() == CA_PEM
    # OS に未登録 → OS に合わせた登録の手順（OS の設定は変えない）
    assert "OS の信頼ストアに登録されていないようです" in r.stdout
    assert CA_HINT[box.os].format(ca=ca) in r.stdout
    other = CA_HINT["ubuntu" if box.os == "alma" else "alma"].format(ca=ca)
    assert other not in r.stdout
    assert not [c for c in box.calls() if "update-ca-trust" in c or "update-ca-certificates" in c]
    assert f"追加で信頼する CA: {ca}（.env の OUTBOUND_CA_FILE）" in r.stdout
    no_leak(box, r)
    assert_safe(box)


def test_ca_already_registered_in_os_shows_no_hint(alma):
    all_installed(alma)
    make_ca(alma)
    bundle = os_bundle(alma, OTHER_PEM, CA_PEM_REWRAPPED)  # 改行の位置が違っても同じ証明書
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="", NCM_OS_CA_BUNDLE=str(bundle))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OS の信頼ストアに登録済みです" in r.stdout and "登録されていないようです" not in r.stdout
    # プロキシ無し・CA だけ（透過型の検査）でも git・ビルドには渡す
    assert env_of(alma, "git -C")[0]["GIT_SSL_CAINFO"]
    assert_proxy_not_passed(alma, "podman pull")
    assert (alma.install / "backend" / "build-ca" / "outbound-ca.crt").exists()


def test_ca_turned_off_removes_build_copies(alma):
    all_installed(alma)
    alma.env_file()
    for ctx in ("backend", "frontend"):
        d = alma.install / ctx / "build-ca"
        d.mkdir(parents=True)
        (d / "README.md").write_text("x")
        (d / "outbound-ca.crt").write_text(CA_PEM)
    r = run(alma, stdin="")
    assert r.returncode == 0, r.stdout + r.stderr
    for ctx in ("backend", "frontend"):
        assert sorted(p.name for p in (alma.install / ctx / "build-ca").iterdir()) == ["README.md"]
    assert "ビルド用の写し" in r.stdout
    assert_safe(alma)


@pytest.mark.parametrize("text,message", [
    (None, "のファイルがありません"),
    ("not a certificate\n", "PEM 形式の証明書ではありません"),
])
def test_ca_missing_or_not_pem_stops_update(alma, text, message):
    all_installed(alma)
    if text is not None:
        make_ca(alma, text=text)
    env_text = OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n"
    alma.env_file(env_text)
    r = run(alma, stdin="")
    assert r.returncode == 1 and message in r.stdout, r.stdout + r.stderr
    assert alma.count("git -C") == 0 and alma.count("podman") == 0
    assert (alma.install / ".env").read_bytes() == env_text.encode()


def test_first_install_with_ca_from_environment_imports_it(alma):
    src = alma.tmp / "example-corp-ca.pem"
    src.write_text(CA_PEM)
    bundle = os_bundle(alma, OTHER_PEM)
    r = run(alma, https_proxy=AUTH_URL, OUTBOUND_CA_FILE=str(src), NCM_OS_CA_BUNDLE=str(bundle))
    assert r.returncode == 0, r.stdout + r.stderr
    dst = alma.install / "certs-outbound" / "outbound-ca.pem"
    assert dst.read_text() == CA_PEM and (dst.stat().st_mode & 0o777) == 0o644
    env = (alma.install / ".env").read_text().splitlines()
    assert "OUTBOUND_CA_FILE=outbound-ca.pem" in env and f"OUTBOUND_PROXY={AUTH_URL}" in env
    assert ".env に保存しました: OUTBOUND_CA_FILE=outbound-ca.pem" in r.stdout
    assert (alma.install / "backend" / "build-ca" / "outbound-ca.crt").read_text() == CA_PEM
    # 導入前チェックには引数で CA を渡す（まだ .env が無いため）
    assert [c for c in alma.calls() if "check_env.sh -m prod -c " in c and str(dst) in c]
    # 起動（podman-compose up）には OUTBOUND_CA_FILE（ホストの絶対パス）を渡さない
    assert all("OUTBOUND_CA_FILE" not in c for c in alma.calls() if "podman-compose" in c)
    no_leak(alma, r)
    assert_safe(alma)


def test_ca_with_private_key_is_rejected(alma):
    all_installed(alma)
    make_ca(alma, text=CA_PEM + "-----BEGIN PRIVATE KEY-----\nMIIEsecret\n-----END PRIVATE KEY-----\n")
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="")
    assert r.returncode == 1 and "秘密鍵が入っています。証明書だけのファイルにしてください" in r.stdout
    assert "MIIEsecret" not in r.stdout
    assert alma.count("podman") == 0 and not (alma.install / "backend" / "build-ca").exists()


def test_ca_size_limit_is_the_same_as_the_app():
    """setup.sh の CA の大きさの上限は、アプリ（起動時の検査）の値と同じ"""
    from app.core import outbound

    r = sh_lib('echo "$NCM_PROXY_CA_MAX_BYTES"')
    assert r.returncode == 0 and int(r.stdout) == outbound.CA_MAX_BYTES == 5 * 1024 * 1024


def _ca_of_size(n):
    """CA_PEM の前に、説明の行（証明書のブロックの外）を足して、ちょうど n バイトにする"""
    pad = n - len(CA_PEM.encode())
    return "#" * (pad - 1) + "\n" + CA_PEM


def test_ca_over_size_limit_stops_before_containers_are_recreated(alma):
    all_installed(alma)
    from app.core import outbound

    make_ca(alma, text=_ca_of_size(outbound.CA_MAX_BYTES + 1))
    env_text = OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n"
    alma.env_file(env_text)
    r = run(alma, stdin="")
    assert r.returncode == 1 and "CA のファイルが大きすぎます（上限 5MB" in r.stdout, r.stdout + r.stderr
    assert alma.count("git -C") == 0 and alma.count("podman") == 0
    assert (alma.install / ".env").read_bytes() == env_text.encode()
    assert not (alma.install / "backend" / "build-ca").exists()


def test_ca_at_size_limit_is_accepted(alma):
    all_installed(alma)
    from app.core import outbound

    make_ca(alma, text=_ca_of_size(outbound.CA_MAX_BYTES))
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="", NCM_OS_CA_BUNDLE=str(os_bundle(alma, OTHER_PEM)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "大きすぎます" not in r.stdout


def test_ca_build_copy_has_certificate_blocks_only_and_openssl_checks_each(alma):
    all_installed(alma)
    stub(alma.installed / "openssl", OPENSSL)
    make_ca(alma, text="Example Corp CA の説明\r\n" + CA_PEM.replace("\n", "\r\n") + "コメント\n" + OTHER_PEM)
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="", NCM_OS_CA_BUNDLE=str(os_bundle(alma, OTHER_PEM)))
    assert r.returncode == 0, r.stdout + r.stderr
    assert (alma.install / "backend" / "build-ca" / "outbound-ca.crt").read_text() == CA_PEM + OTHER_PEM
    assert len([c for c in alma.calls() if c == "openssl x509 -noout"]) == 2  # 証明書ごとに確かめる
    assert "openssl が無いため" not in r.stdout


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl が必要")
def test_ca_check_with_real_openssl(tmp_path):
    """本物の openssl で: 作った CA（Example Corp CA）は通り、本文を壊したものは読めないとして止まる"""
    certs = tmp_path / "certs-outbound"
    certs.mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Example Corp CA",
                    "-keyout", str(tmp_path / "ca.key"), "-out", str(certs / "outbound-ca.pem")], check=True, capture_output=True)
    good = (certs / "outbound-ca.pem").read_text()
    (tmp_path / ".env").write_text("OUTBOUND_CA_FILE=outbound-ca.pem\n")
    code = f'ncm_proxy_load "{tmp_path}" && echo OK || ncm_proxy_error'
    assert sh_lib(code).stdout.strip() == "OK"
    lines = good.splitlines()
    lines[3] = "A" * len(lines[3])   # 本文を壊す（base64 としては読める）
    (certs / "outbound-ca.pem").write_text("\n".join(lines) + "\n")
    assert "証明書として読めないもの" in sh_lib(code).stdout


def test_ca_unreadable_by_openssl_is_rejected(alma):
    all_installed(alma)
    stub(alma.installed / "openssl", OPENSSL)
    make_ca(alma, text=CA_PEM + CA_PEM.replace("MIIB", "BROKEN"))
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="")
    assert r.returncode == 1 and "証明書として読めないものがあります" in r.stdout
    assert alma.count("podman") == 0


def test_ca_without_openssl_is_checked_by_form_only(alma):
    all_installed(alma)
    make_ca(alma)
    alma.env_file(OLD_ENV + "OUTBOUND_CA_FILE=outbound-ca.pem\n")
    r = run(alma, stdin="")
    assert r.returncode == 0 and "openssl が無いため" in r.stdout


def test_ca_from_environment_with_private_key_is_not_imported(alma):
    src = alma.tmp / "example-corp-ca.pem"
    src.write_text(CA_PEM + "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n")
    r = run(alma, OUTBOUND_CA_FILE=str(src))
    assert r.returncode == 1 and "秘密鍵が入っています" in r.stdout
    assert not (alma.install / "certs-outbound").exists() and not (alma.install / ".env").exists()


def test_without_ca_nothing_is_added(alma):
    all_installed(alma)
    alma.env_file(OLD_ENV + f"OUTBOUND_PROXY={PLAIN_URL}\n")
    r = run(alma, stdin="")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (alma.install / "backend" / "build-ca").exists() and not (alma.install / "certs-outbound").exists()
    assert all(c["GIT_SSL_CAINFO"] == "" for c in env_calls(alma))
    assert "追加で信頼する CA" not in r.stdout and "OS の信頼ストア" not in r.stdout


# ------------------------------------------------------------------ setup.sh: 失敗したときの案内
def test_build_failure_with_proxy_shows_hint_without_password(box):
    all_installed(box)
    box.env_file(OLD_ENV + f"OUTBOUND_PROXY={AUTH_URL}\n")
    r = run(box, stdin="", FAKE_FAIL_ON="podman-compose -f docker-compose.prod.yml build")
    assert r.returncode == 1
    assert "コンテナのビルド に失敗しました" in r.stdout and "407" in r.stdout and "証明書のエラー" in r.stdout
    assert CA_HINT[box.os].format(ca=f"{box.install}/certs-outbound/outbound-ca.pem") in r.stdout
    no_leak(box, r)


def test_pull_failure_without_proxy_shows_no_extra_hint(alma):
    all_installed(alma)
    alma.env_file()
    r = run(alma, stdin="", FAKE_FAIL_ON="git -C")
    assert r.returncode == 1 and "git pull に失敗" in r.stdout
    assert "407" not in r.stdout and "証明書のエラー" not in r.stdout  # プロキシが無ければ今までと同じ


# ------------------------------------------------------------------ podman-compose の出力の伏せ字
# podman-compose 1.0.6 の up の実際の出力（--dry-run で取った形。値は目印に置き換え）
COMPOSE_LINE = ("podman run --name=netconfig-manager_backend_1 -d --label io.podman.compose.project=netconfig-manager "
                f"-e DATABASE_URL=postgresql+asyncpg://netconfig:pg{MARK}@db:5432/netconfig -e REDIS_URL=redis://redis:6379/0 "
                f"-e SECRET_KEY=sk{MARK} -e DEVICE_ENCRYPTION_KEY=dk{MARK} -e ADMIN_PASSWORD=a b {MARK} -e HTTP_PORT=80 "
                f"-e OUTBOUND_PROXY={AUTH_URL} -e OUTBOUND_NO_PROXY=intranet.example.test -e GIT_EXPORT_TOKEN= "
                f"-e GIT_EXPORT_URL=https://user01:{MARK}@git.example.test/x.git --net netconfig-manager_default "
                "--network-alias backend localhost/netconfig-manager_backend:latest uvicorn app.main:app")


def test_redact_output_hides_secrets_in_compose_output():
    lines = [COMPOSE_LINE, f"['podman', 'run', '-e', 'SECRET_KEY=x{MARK}', '--env', 'OUTBOUND_PROXY={AUTH_URL}']",
             f"podman run --env=ADMIN_PASSWORD={MARK} img", "exit code: 0"]
    r = subprocess.run(["bash", "-c", f'. "{PROXY_LIB}"; ncm_redact_output'], input="\n".join(lines) + "\n",
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0
    assert MARK not in r.stdout, r.stdout
    out = r.stdout.splitlines()
    assert "-e SECRET_KEY=*** -e DEVICE_ENCRYPTION_KEY=*** -e ADMIN_PASSWORD=*** -e HTTP_PORT=80" in out[0]
    assert "-e OUTBOUND_PROXY=*** -e OUTBOUND_NO_PROXY=*** " in out[0]
    assert "GIT_EXPORT_URL=https://***@git.example.test/x.git --net" in out[0]
    assert out[0].endswith("localhost/netconfig-manager_backend:latest uvicorn app.main:app")  # 秘密でない引数は残る
    assert out[3] == "exit code: 0"


@pytest.mark.skipif(shutil.which("podman-compose") is None or shutil.which("podman") is None, reason="podman-compose が必要")
def test_redact_output_with_real_podman_compose_dry_run(tmp_path):
    """本物の podman-compose（--dry-run。コンテナは作らない）の出力に、目印の値が残らない"""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  t:\n    image: docker.io/library/alpine:3.20\n    environment:\n"
        f"      SECRET_KEY: sk{MARK}\n      OUTBOUND_PROXY: {AUTH_URL}\n      ADMIN_PASSWORD: 'a b {MARK}'\n"
        f"      DATABASE_URL: postgresql://n:pg{MARK}@db:5432/n\n")
    r = subprocess.run(["bash", "-c", f'set -o pipefail; . "{PROXY_LIB}"; podman-compose --dry-run up -d 2>&1 | ncm_redact_output'],
                       cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert "podman run" in r.stdout and "OUTBOUND_PROXY=***" in r.stdout, r.stdout + r.stderr
    assert MARK not in r.stdout + r.stderr


def test_setup_hides_compose_output_and_keeps_exit_code(alma):
    all_installed(alma)
    stub(alma.installed / "podman-compose", COMPOSE_STUB)
    alma.env_file(OLD_ENV + f"OUTBOUND_PROXY={AUTH_URL}\n")
    r = run(alma, stdin="", FAKE_COMPOSE_LINE=COMPOSE_LINE)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "podman run --name=netconfig-manager_backend_1" in r.stdout and "OUTBOUND_PROXY=***" in r.stdout
    no_leak(alma, r)
    # 失敗したときの終了コードは podman-compose のもの（up・build とも）
    for step, rc in (("up", 7), ("build", 5)):
        r = run(alma, stdin="", FAKE_COMPOSE_LINE=COMPOSE_LINE, FAKE_COMPOSE_FAIL=step, FAKE_COMPOSE_RC=str(rc))
        assert r.returncode == rc, (step, r.returncode)
        no_leak(alma, r)
    assert "コンテナのビルド に失敗しました" in r.stdout


# ------------------------------------------------------------------ check_env.sh
# 偽の curl: -w の書式どおりに「HTTP の応答コード CONNECT の応答コード」を出し、FAKE_CURL_RC で終わる
CURL = r"""#!/bin/bash
printf 'curl %s\n' "$*" >> "$FAKE_LOG"
printf 'curl-env https_proxy=%s cacert=%s\n' "${https_proxy:-}" "$(for a in "$@"; do [ "$prev" = --cacert ] && echo "$a"; prev="$a"; done)" >> "$FAKE_LOG"
printf '%s' "${FAKE_CURL_OUT:-200 000}"
exit "${FAKE_CURL_RC:-0}"
"""


def check(osb, release=UBUNTU, env_text=None, args=(), **extra):
    """リポジトリの写し（scripts/ と .env）の中の check_env.sh を、偽の curl で実行する"""
    stub(osb.dir / "stubs" / "curl", CURL)
    stub(osb.dir / "stubs" / "openssl", OPENSSL)  # 偽の証明書を使うため（本物の openssl での確認は test_ca_check_with_real_openssl）
    repo = osb.dir / "repo"
    if not repo.exists():
        shutil.copytree(SCRIPTS, repo / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    if env_text is not None:
        (repo / ".env").write_text(env_text)
    return subprocess.run(["bash", str(repo / "scripts" / "check_env.sh"), *args], env=osb.env(osb.release(release), **extra),
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("out,rc,message", [
    ("000 407", "56", "プロキシの認証に失敗しました（407）"),
    ("000 403", "56", "プロキシが https://github.com/ への接続を拒否しました（CONNECT に HTTP 403）"),
    ("000 000", "7", "プロキシに接続できません"),
    ("000 000", "5", "プロキシのホスト名を解決できません"),
    ("000 200", "60", "証明書を検証できません"),
])
def test_check_env_classifies_proxy_failures(osb, out, rc, message):
    r = check(osb, https_proxy=AUTH_URL, FAKE_CURL_OUT=out, FAKE_CURL_RC=rc)
    assert f"[ NG ] GitHub: {message}" in r.stdout, r.stdout
    assert f"プロキシ: {MASKED}（環境変数 https_proxy" in r.stdout
    assert MARK not in r.stdout + r.stderr
    curl_args = [c for c in osb.calls() if c.startswith("curl ")]
    assert curl_args and not [c for c in curl_args if MARK in c]  # プロキシは環境変数で渡し、引数に出さない
    assert [c for c in osb.calls() if c.startswith(f"curl-env https_proxy={AUTH_URL}")]
    if rc == "60":
        assert "OUTBOUND_CA_FILE" in r.stdout  # CA の案内


def test_check_env_success_and_env_file_setting(osb):
    r = check(osb, env_text=f"OUTBOUND_PROXY={AUTH_URL}\n", FAKE_CURL_OUT="200 200")
    assert "[ OK ] GitHub に接続可能 (HTTP 200)" in r.stdout
    assert f"プロキシ: {MASKED}（.env の OUTBOUND_PROXY" in r.stdout
    assert "localhost,127.0.0.1,::1,db,redis,backend,worker,beat,frontend" in r.stdout
    assert MARK not in r.stdout + r.stderr


def test_check_env_without_proxy_keeps_old_messages(osb):
    r = check(osb, FAKE_CURL_OUT="000", FAKE_CURL_RC="7")
    assert "[ NG ] GitHub に接続できません (https://github.com/)" in r.stdout
    assert "プロキシ: なし（直接接続）" in r.stdout
    r = check(osb, FAKE_CURL_OUT="200")  # 古い書式（コードだけ）でも OK と読む
    assert "[ OK ] GitHub に接続可能 (HTTP 200)" in r.stdout


def test_check_env_invalid_proxy_is_reported_without_value(osb):
    # 環境変数の値: 使わない（直接）と警告する
    r = check(osb, https_proxy=f"socks5://user01:{PASSWORD}@proxy.example.test:1080", FAKE_CURL_OUT="200 000")
    assert "[WARN] 環境変数 https_proxy のプロキシは形式が違うため使いません（SOCKS" in r.stdout
    assert "プロキシ: なし（直接接続）" in r.stdout
    assert MARK not in r.stdout + r.stderr
    # .env の値: NG
    r = check(osb, env_text=f"OUTBOUND_PROXY=socks5://user01:{PASSWORD}@proxy.example.test:1080\n", FAKE_CURL_OUT="200 000")
    assert "[ NG ] プロキシの設定（.env の OUTBOUND_PROXY）が正しくありません: SOCKS" in r.stdout
    assert MARK not in r.stdout + r.stderr


@pytest.mark.parametrize("release,hint", [(ALMA, CA_HINT["alma"]), (UBUNTU, CA_HINT["ubuntu"])])
def test_check_env_ca_option_passes_bundle_to_curl_and_shows_os_hint(osb, release, hint):
    ca = osb.dir / "example-corp-ca.pem"
    ca.write_text(CA_PEM)
    bundle = osb.dir / "os-bundle.crt"
    bundle.write_text(OTHER_PEM)
    r = check(osb, release=release, args=("-c", str(ca)), https_proxy=PLAIN_URL, NCM_OS_CA_BUNDLE=str(bundle),
              FAKE_CURL_OUT="200 200", TMPDIR=str(osb.dir))
    assert f"[WARN] 追加の CA: {ca} が OS の信頼ストアに未登録" in r.stdout, r.stdout
    assert hint.format(ca=ca) in r.stdout
    cacert = next(c for c in osb.calls() if c.startswith("curl-env ")).split("cacert=")[1]
    assert cacert.startswith(f"{osb.dir}/tmp.")  # OS の束＋追加の CA の一時ファイル
    assert not os.path.exists(cacert)  # 終了時に消す
    # 登録済みなら OK
    bundle.write_text(OTHER_PEM + CA_PEM_REWRAPPED)
    r = check(osb, release=release, args=("-c", str(ca)), https_proxy=PLAIN_URL, NCM_OS_CA_BUNDLE=str(bundle), FAKE_CURL_OUT="200 200")
    assert f"[ OK ] 追加の CA: {ca}（OS の信頼ストアにも登録済み）" in r.stdout


# ------------------------------------------------------------------ collect_logs.sh
def test_collect_logs_hides_proxy_values(osb):
    install = osb.dir / "ncm"
    (install / "backend" / "app").mkdir(parents=True)
    (install / ".env").write_text(
        f"POSTGRES_PASSWORD=pg\nOUTBOUND_PROXY={AUTH_URL}\r\nOUTBOUND_NO_PROXY=intranet.example.test,10.0.0.0/8\n"
        f"OUTBOUND_CA_FILE=outbound-ca.pem\nVULN_HTTPS_PROXY=http://old.example.test:3128\nPUBLIC_URL=http://192.0.2.10\n")
    fake = osb.dir / "podman"
    fake.write_text("#!/bin/bash\n[ \"$1\" = logs ] && echo \"start https_proxy=http://u:p@inner.example.test:1 no_proxy=intranet.example.test\"\n"
                    "[ \"$1\" = ps ] && [ \"$2\" = -aq ] && echo ct1\nexit 0\n")
    fake.chmod(0o755)
    out = osb.dir / "out"
    e = osb.env(osb.release(UBUNTU), INSTALL_DIR=str(install), PROJECT_NAME="ncm", CONTAINER_CMD=str(fake), SUDO="",
                   COLLECT_OUT_DIR=str(out))
    r = subprocess.run(["bash", str(SCRIPTS / "collect_logs.sh")], env=e, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    with tarfile.open(next(out.glob("netconfig-logs-*.tar.gz"))) as tar:
        files = {m.name.split("/", 1)[1]: tar.extractfile(m).read().decode() for m in tar.getmembers() if m.isfile()}
    env = files["app/env.txt"]
    # 認証情報だけを伏せ、host:port は残す（起動時のログ・システム状態の画面と同じ）
    assert f"OUTBOUND_PROXY={MASKED}" in env.splitlines()
    assert "OUTBOUND_NO_PROXY=***（2 件）" in env
    assert "OUTBOUND_CA_FILE=outbound-ca.pem" in env
    assert "VULN_HTTPS_PROXY=http://old.example.test:3128" in env.splitlines()
    for word in (MARK, "user01", "intranet.example.test"):
        assert word not in env, word
    logs = [v for k, v in files.items() if k.startswith("containers/") and k.endswith(".log")]
    assert logs and "https_proxy=http://***@inner.example.test:1" in logs[0]
    assert MARK not in "\n".join(files.values())


# ------------------------------------------------------------------ Dockerfile・リポジトリの決まり
def test_dockerfiles_never_bake_proxy_into_image():
    """プロキシは ARG / ENV / LABEL に書かない（podman build が RUN にだけ渡す。書くとイメージの設定・履歴に残る）"""
    for f in ("backend/Dockerfile", "frontend/Dockerfile"):
        for line in (REPO / f).read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*(ARG|ENV|LABEL)\b", line):
                assert not re.search(r"proxy", line, re.I), f"{f}: {line}"
    for f in ("docker-compose.yml", "docker-compose.prod.yml"):
        text = (REPO / f).read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*args:.*$", text, re.M):
            assert "proxy" not in m.group(0).lower(), f"{f}: {m.group(0)}"


def _steps(dockerfile):
    """Dockerfile の命令を、継続行をつないで 1 行ずつ"""
    text = (REPO / dockerfile).read_text(encoding="utf-8")
    text = re.sub(r"\\\n", " ", text)
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


@pytest.mark.parametrize("dockerfile,network_runs", [
    ("backend/Dockerfile", ["apt-get install", "pip install", "apt-get upgrade"]),
    ("frontend/Dockerfile", ["npm ci", "apk upgrade"]),
])
def test_build_ca_is_copied_before_network_steps(dockerfile, network_runs):
    steps = _steps(dockerfile)
    for word in network_runs:
        i = next(n for n, s in enumerate(steps) if s.startswith("RUN") and word in s)
        stage_start = max(n for n, s in enumerate(steps[:i + 1]) if s.startswith("FROM"))
        copies = [s for s in steps[stage_start:i] if s.startswith("COPY build-ca/")]
        assert copies or "netconfig-build" in steps[i], f"{dockerfile}: {word} の前に build-ca/ がありません"


def test_build_ca_placeholders_and_gitignore():
    gi = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    for ctx in ("backend", "frontend"):
        assert (REPO / ctx / "build-ca" / "README.md").is_file()
        assert f"{ctx}/build-ca/*" in gi and f"!{ctx}/build-ca/README.md" in gi
        # .dockerignore で build-ca を外していない（外すと COPY が失敗する）
        di = REPO / ctx / ".dockerignore"
        if di.exists():
            assert "build-ca" not in di.read_text(encoding="utf-8")


def test_dockerfile_ca_steps_do_nothing_without_ca(tmp_path):
    """CA が無いとき（build-ca/ は README.md だけ）の RUN は何も残さない。あるときは信頼させる（本物の sh で、置き場所を一時ディレクトリに替えて確かめる）"""
    steps = _steps("backend/Dockerfile")
    run_ca = next(s for s in steps if s.startswith("RUN cd /usr/local/share/ca-certificates/netconfig-build"))[4:]
    for with_ca in (False, True):
        root = tmp_path / ("ca" if with_ca else "noca")
        d = root / "usr/local/share/ca-certificates/netconfig-build"
        d.mkdir(parents=True)
        (d / "README.md").write_text("x")
        if with_ca:
            (d / "outbound-ca.crt").write_text(CA_PEM)
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        stub(bindir / "update-ca-certificates", f"#!/bin/sh\necho called >> {tmp_path}/update.log\n")
        script = run_ca.replace("/usr/local/share/ca-certificates/netconfig-build", str(d))
        r = subprocess.run(["sh", "-c", script], env={"PATH": f"{bindir}:/usr/bin:/bin"}, capture_output=True, text=True, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        if with_ca:
            assert sorted(p.name for p in d.iterdir()) == ["outbound-ca.crt"]
        else:
            assert not d.exists()  # ディレクトリごと消える（CA なしのビルドと同じ）
    assert (tmp_path / "update.log").read_text().splitlines() == ["called"]  # CA のあるときだけ


def test_new_scripts_use_lf_and_pass_syntax_check():
    for f in (PROXY_LIB, SCRIPTS / "setup.sh", SCRIPTS / "check_env.sh", SCRIPTS / "collect_logs.sh", SCRIPTS / "lib" / "os.sh"):
        assert b"\r" not in f.read_bytes(), f
        assert subprocess.run(["bash", "-n", str(f)]).returncode == 0, f


def test_proxy_values_never_go_on_sudo_command_lines():
    """sudo に値を引数で渡す形（sudo env 変数=値）は使わない（ps と sudo のログに残るため）"""
    for f in (PROXY_LIB, SCRIPTS / "setup.sh", SCRIPTS / "lib" / "os.sh"):
        code = [line for line in f.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith(("#", "echo"))]
        assert not [line for line in code if re.search(r"\bsudo\b.*\benv\b.*(kv|_proxy=|\$\{!)", line)], f


# ------------------------------------------------------------------ import_cert.sh の作り直し（setup.sh と同じ手順。lib/compose.sh）
def _import_with_proxy(tmp_path, compose_stub=True, **extra):
    """compose_stub: 出力に秘密の値を出す偽の podman-compose（環境変数は記録しない）。False なら記録する偽物（test_setup_script の STUB）"""
    tmp_path.mkdir(parents=True, exist_ok=True)
    b = import_box(tmp_path, "alma", env=OLD_ENV + f"OUTBOUND_PROXY={AUTH_URL}\n")
    if compose_stub:
        stub(b.installed / "podman-compose", COMPOSE_STUB)
        extra.setdefault("FAKE_COMPOSE_LINE", COMPOSE_LINE)
    extra.setdefault("FAKE_ENV_LOG", str(b.tmp / "env.log"))
    return b, run_import(b, **extra)


def test_import_cert_recreate_uses_proxy_for_build_only_and_hides_secrets(tmp_path):
    """PUBLIC_URL を変える（http → https）とコンテナを作り直す。以前は sudo podman-compose build をそのまま実行していたので、
    プロキシを引き継がず（sudo が落とす）、OS_UPGRADE も無く、出力に秘密の値が出ていた"""
    b, r = _import_with_proxy(tmp_path / "env", compose_stub=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert_proxy_passed(b, "podman-compose -f docker-compose.prod.yml build", AUTH_URL)
    assert_proxy_not_passed(b, "podman-compose -f docker-compose.prod.yml up")
    calls = b.calls()
    build = next(c for c in calls if c.startswith("sudo") and "podman-compose -f docker-compose.prod.yml build" in c)
    assert "OS_UPGRADE=" in build  # setup.sh と同じ層のキャッシュ（同じ日なら外へ出ない）
    up = next(c for c in calls if c.startswith("sudo") and " up -d --force-recreate" in c)
    assert "-u https_proxy" in up and "-u HTTP_PROXY" in up
    assert calls.index(build) < calls.index(up)
    no_leak(b, r)
    # podman-compose の出力（podman run の -e キー=値）は伏せ字にする
    b, r = _import_with_proxy(tmp_path / "out")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OUTBOUND_PROXY=***" in r.stdout and "SECRET_KEY=***" in r.stdout
    no_leak(b, r)


@pytest.mark.parametrize("step", ["build", "up"])
def test_import_cert_recreate_failure_explains_state(tmp_path, step):
    """作り直しの失敗: 証明書と .env は変更済み・コンテナは古いまま、であることと、直し方を出して 1 で終わる"""
    b, r = _import_with_proxy(tmp_path, FAKE_COMPOSE_FAIL=step, FAKE_COMPOSE_RC="3")
    assert r.returncode == 1
    assert "証明書の配置と .env の変更は済んでいますが、コンテナは古いままです" in r.stdout
    assert f"bash {b.install}/scripts/setup.sh" in r.stdout and "logs --tail 50 backend" in r.stdout
    if step == "build":
        assert "「コンテナのビルド」で止まりました" in r.stdout and "コンテナのビルド に失敗しました" in r.stdout
        assert b.count("podman-compose -f docker-compose.prod.yml up") == 0
    else:
        assert "「コンテナの作り直し（up -d --force-recreate）」で止まりました" in r.stdout
    assert "✅ 完了" not in r.stdout
    no_leak(b, r)


def test_import_cert_stops_on_invalid_proxy_before_touching_anything(tmp_path):
    b = import_box(tmp_path, "alma", env=OLD_ENV + "OUTBOUND_PROXY=https://proxy.example.test:3128\n")
    text = (b.install / ".env").read_bytes()
    r = run_import(b)
    assert r.returncode == 1 and "値は表示していません" in r.stdout
    assert (b.install / ".env").read_bytes() == text and not (b.install / "certs").exists() and not b.backup_dir.exists()
