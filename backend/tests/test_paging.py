"""ページング（--More--）が無効化できていない機器の検出テスト"""
import time

import pytest

import fake_sshd
from app.services import config_service as cs
from test_device_auth import dev


@pytest.mark.parametrize("pager", [" --More-- ", "  ---- More ----", "---(more 45%)---"])
def test_pager_detected_quickly(pager):
    port, _, _ = fake_sshd.start(pager=pager)
    t0 = time.time()
    r = cs.collect_config_sync(dev(port))
    assert not r.success and not r.retryable, r
    assert "ページング" in r.error and "show running-config" in r.error, r.error
    assert time.time() - t0 < 20  # 応答待ち時間（120秒）いっぱい待たない


@pytest.mark.parametrize("line,hit", [
    (" --More-- ", True), ("  ---- More ----", True), ("---(more)---", True), ("---(more 45%)---", True),
    ("lines 1-40 ", True),
    ("description --more info--", False), ("banner motd ^C more ^C", False), ("set lines 1", False),
    ("interface Gi0/1", False), ("line vty 0 4", False),
])
def test_pager_regex(line, hit):
    assert bool(cs.PAGER_RE.search(line)) is hit
