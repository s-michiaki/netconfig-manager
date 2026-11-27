"""scripts/check_env.sh の宛先の扱い（#39: コマンドインジェクション）のテスト

以前は -d・-j・-f のファイルから受け取った宛先を `bash -c "exec 3<>/dev/tcp/$host/$port"` の文字列に埋め込んでいたため、
他人が作った機器の一覧に `$(...)` があると動いた（sudo を付けていれば root で）。いまは形を検査し、引数として渡す。
偽の curl（test_proxy_scripts.py の check）で実行し、外部へは通信しない。TCP の接続は 127.0.0.1 の閉じたポートだけ
"""
import socket

import pytest
from test_proxy_scripts import check, osb  # noqa: F401  （osb はフィクスチャ）


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.parametrize("bad", [
    "$(touch {m})", "`touch {m}`", "127.0.0.1/1;touch {m}", "127.0.0.1:22$(touch {m})", "x;touch {m}", "[::1]:22$(touch {m})",
    "-x", "127.0.0.1:99999", "127.0.0.1:0",
])
def test_targets_are_never_executed_and_bad_forms_are_reported(osb, tmp_path, bad):  # noqa: F811
    marker = tmp_path / "pwned"
    target = bad.format(m=marker)
    lst = tmp_path / "devices.txt"
    lst.write_text(f"{target}\n")
    for args in (["-f", str(lst)], ["-d", target], ["-j", target]):
        r = check(osb, args=args)
        assert not marker.exists(), (args, r.stdout)
        assert "の宛先の形式が正しくありません" in r.stdout, (args, r.stdout)
        assert r.returncode == 1


def test_valid_targets_are_still_probed(osb, tmp_path):  # noqa: F811
    port = closed_port()
    lst = tmp_path / "devices.txt"
    lst.write_text(f"# コメント\n127.0.0.1:{port}  # 末尾のコメント\nlocalhost:{port}\n[::1]:{port}\n")
    r = check(osb, args=["-f", str(lst), "-j", f"127.0.0.1:{port}"])
    assert "の宛先の形式が正しくありません" not in r.stdout, r.stdout
    assert f"踏み台 127.0.0.1:{port} に TCP 接続できません" in r.stdout
    # 踏み台を使う構成では、直接届かない機器は「踏み台経由で使う想定なら問題なし」
    assert f"機器 127.0.0.1:{port}: サーバーからは直接届きません" in r.stdout
    r = check(osb, args=["-d", f"[::1]:{port}"])
    assert f"機器 [::1]:{port} に TCP 接続できません" in r.stdout


def test_ipv6_zone_and_line_numbers(osb, tmp_path):  # noqa: F811
    """IPv6 のゾーンつき（fe80::1%lo）を受け付ける。形式の誤りは値ではなく出どころ（ファイルの何行目・-d の何個目）で示す"""
    port = closed_port()
    lst = tmp_path / "devices.txt"
    lst.write_text(f"fe80::1%lo\n# c\n[fe80::1%lo]:{port}\n\x1b[31mred\x1b[0m\nhost%x\n")
    r = check(osb, args=["-f", str(lst), "-d", "$(id)"])
    out = r.stdout
    assert "[fe80::1%lo]:22 に TCP 接続できません" in out and f"[fe80::1%lo]:{port} に TCP 接続できません" in out
    assert "機器（devices.txt の 4 行目）の宛先の形式が正しくありません" in out
    assert "機器（devices.txt の 5 行目）の宛先の形式が正しくありません" in out   # IPv6 でないものにゾーンは付けられない
    assert "機器（-d の 1 個目）の宛先の形式が正しくありません" in out
    assert "\x1b" not in out and "$(id)" not in out
