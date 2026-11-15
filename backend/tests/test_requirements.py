"""依存パッケージの .in とロックファイルの静的な確認

ロックが .in と合っているか（生成し直し忘れ・手での書き換え）は CI の scripts/lock_deps.sh --check で確かめる。
ここでは、意図して固定している版が消されていないこと、ロックの形（全部固定・ハッシュ付き）を確かめる
"""
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;\\]+)", re.M)


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(name: str) -> dict[str, str]:
    return {norm(k): v for k, v in PIN.findall((BACKEND / name).read_text(encoding="utf-8"))}


def test_intended_pins_are_kept():
    direct = pins("requirements.in")
    # kombu 5.7.0 は Redis 用モジュールの依存（packaging）を宣言しておらず、本番の worker が動かない
    assert direct["kombu"] == "5.6.2"
    # paramiko 5 は ssh-rsa を廃止し、古い機器へ接続できなくなる（3.5 系に留める）
    assert direct["paramiko"].startswith("3.5.")


def test_direct_dependencies_are_locked_with_same_version():
    lock = pins("requirements.txt")
    for name, version in pins("requirements.in").items():
        assert lock.get(name) == version, name
    dev_lock = pins("requirements-dev.txt")
    for name, version in pins("requirements-dev.in").items():
        assert dev_lock.get(name) == version, name


def test_dev_lock_uses_same_versions_as_production():
    lock, dev_lock = pins("requirements.txt"), pins("requirements-dev.txt")
    assert set(lock) <= set(dev_lock)  # 開発用のロックは本番の依存も含む
    assert {k: dev_lock[k] for k in lock} == lock


def test_lock_files_are_fully_pinned_with_hashes():
    for name in ("requirements.txt", "requirements-dev.txt"):
        text = (BACKEND / name).read_text(encoding="utf-8")
        # 行頭がパッケージ名の行（要件）はすべて == で固定し、直後にハッシュがある
        entries = re.findall(r"^([A-Za-z0-9].*?)(?:\n(?=[A-Za-z0-9#])|\Z)", text, re.M | re.S)
        assert entries, name
        for entry in entries:
            assert PIN.match(entry), entry.splitlines()[0]
            assert "--hash=sha256:" in entry, entry.splitlines()[0]
