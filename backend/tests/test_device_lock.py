"""機器ごとのロックの延長・途中で外れたときの記録、待つときに worker を占有しないこと、タスクの時間の上限（#33）

- LockKeeper: 期限（LOCK_TTL）より長い処理でもロックが外れない。worker が落ちた（延長が止まった）ら期限で外れる。
  途中で外れたら lost に残る
- コマンド実行・収集・FW ヒット数: ロックを延長し続ける。途中で外れていたらアクティビティ（ssh.lock_lost）に残す。
  ほかの SSH 処理を待つときはブロックせず、結果を待機中に戻して再試行（retry(countdown)）に回す
- コマンド実行の同時実行の枠（COMMAND_RUN_WORKER_SLOTS）: 枠が埋まっていれば機器へ接続せずに待つ
- Celery のタスクの時間の上限: 正当な最長の処理より長い
"""
import sqlite3
import time
import uuid
from datetime import timedelta
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.main import app
from app.services import command_run as command_run_svc
from app.services import config_service as cs
from app.services import device_lock


@pytest.fixture
def r():
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr):
        yield fr


@pytest.fixture(scope="module")
def env():
    made: list[str] = []
    with mock.patch("app.api.commands.enqueue_command_run"), \
            mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE_PER_USER", 10_000), \
            mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE", 10_000), TestClient(app) as c:
        tok = c.post("/api/auth/token", data={"username": "admin", "password": "initial-pass-123"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        yield {"c": c, "h": h, "made": made}
        for did in made:  # 同じ DB をほかのテストも使うので、作った機器は消す
            c.delete(f"/api/devices/{did}", headers=h)


def _device(env, port, platform="cisco_ios"):
    d = env["c"].post("/api/devices/", json=dict(name=f"lk-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=port,
                                                 platform=platform, username="admin", password="pw"), headers=env["h"])
    assert d.status_code == 201, d.text
    env["made"].append(d.json()["id"])
    return d.json()


def _db():
    con = sqlite3.connect(f"{TMP}/t.db")
    con.row_factory = sqlite3.Row
    return con


def _new_run(env, did):
    r = env["c"].post("/api/commands/runs", json={"device_ids": [did], "commands": ["show clock"]}, headers=env["h"])
    assert r.status_code in (200, 201), r.text
    run_id = r.json()["id"]
    rid = _db().execute("select id from command_results where run_id=?", (run_id,)).fetchone()[0]
    return run_id, rid


def _result(rid):
    return _db().execute("select status, started_at, error from command_results where id=?", (rid,)).fetchone()


def _activity(event, did):
    return _db().execute("select level, message, detail from activity_logs where event=? and device_id=?",
                         (event, did)).fetchall()


# ---------------------------------------------------------------- LockKeeper


def test_keeper_extends_lock_beyond_ttl_and_releases(r):
    """期限（1 秒）より長く（2 秒）持っても外れない。解放したら次の処理が取れる"""
    lock = device_lock.make_lock(r, "netconfig:ssh:test-keep", ttl=1)
    assert lock.acquire(blocking=False)
    keeper = device_lock.LockKeeper(interval=0.2)
    keeper.hold("ssh", lock)
    time.sleep(2.0)
    assert not device_lock.make_lock(r, "netconfig:ssh:test-keep").acquire(blocking=False)  # まだ持っている
    keeper.release(lock)
    keeper.close()
    assert keeper.lost == []
    other = device_lock.make_lock(r, "netconfig:ssh:test-keep")
    assert other.acquire(blocking=False)
    other.release()


def test_lock_expires_when_extension_stops(r):
    """worker が落ちる（延長が止まる）と、期限で自然に外れる（長時間残らない）"""
    lock = device_lock.make_lock(r, "netconfig:ssh:test-dead", ttl=1)
    assert lock.acquire(blocking=False)
    time.sleep(1.3)  # 延長する者がいない
    assert device_lock.make_lock(r, "netconfig:ssh:test-dead").acquire(blocking=False)
    assert device_lock.LOCK_TTL <= 300  # 既定の期限も短い（以前の 900 秒の固定ではない）


def test_keeper_reports_lost_lock(r):
    """期限が切れてほかの処理が取ったら、延長でも解放でも「外れていた」と分かる（握りつぶさない）"""
    lock = device_lock.make_lock(r, "netconfig:ssh:test-lost", ttl=60)
    assert lock.acquire(blocking=False)
    keeper = device_lock.LockKeeper(interval=60)
    keeper.hold("ssh", lock)
    r.delete("netconfig:ssh:test-lost")  # 期限切れの代わり
    other = device_lock.make_lock(r, "netconfig:ssh:test-lost")
    assert other.acquire(blocking=False)  # ほかの処理が取った
    keeper.extend_now()
    assert keeper.lost == ["ssh"]
    keeper.close()
    assert r.get("netconfig:ssh:test-lost") is not None  # ほかの処理のロックは消さない
    # 解放のときに初めて分かる場合も同じ
    lock2 = device_lock.make_lock(r, "netconfig:ssh:test-lost2", ttl=60)
    assert lock2.acquire(blocking=False)
    k2 = device_lock.LockKeeper(interval=60)
    k2.hold("collect", lock2)
    r.delete("netconfig:ssh:test-lost2")
    k2.close()
    assert k2.lost == ["collect"]


# ---------------------------------------------------------------- コマンド実行


def test_command_run_keeps_lock_during_long_run_and_records_lost(env, r):
    """応答の遅い機器へのコマンド実行（期限より長い）でもロックが外れず、収集が割り込めない。
    途中で外れていたら（Redis の再起動など）アクティビティに残す"""
    port, _, _ = fake_sshd.start(show_any=True)
    d = _device(env, port)
    seen = {}

    def slow(device, commands):
        time.sleep(1.5)  # 期限（0.6 秒）より長い
        seen["held"] = not device_lock.make_lock(r, f"netconfig:ssh:{device.id}").acquire(blocking=False)
        return ["12:00"]

    with mock.patch.object(device_lock, "LOCK_TTL", 0.6), mock.patch.object(device_lock, "EXTEND_INTERVAL", 0.15), \
            mock.patch.object(cs, "run_commands", side_effect=slow):
        _, rid = _new_run(env, d["id"])
        assert worker.run_command_device.apply(args=(rid,)).get() == {"status": "ok"}
    assert seen["held"] is True
    assert _activity("ssh.lock_lost", d["id"]) == []
    assert device_lock.make_lock(r, f"netconfig:ssh:{d['id']}").acquire(blocking=False)  # 終わったら放している
    r.delete(f"netconfig:ssh:{d['id']}")

    def stolen(device, commands):
        r.delete(f"netconfig:ssh:{device.id}")  # 期限切れの代わり
        assert device_lock.make_lock(r, f"netconfig:ssh:{device.id}").acquire(blocking=False)  # 収集が取った
        return ["12:00"]

    with mock.patch.object(cs, "run_commands", side_effect=stolen):
        _, rid = _new_run(env, d["id"])
        assert worker.run_command_device.apply(args=(rid,)).get() == {"status": "ok"}
    rows = _activity("ssh.lock_lost", d["id"])
    assert len(rows) == 1 and rows[0]["level"] == "warning" and "ロックが外れていました" in rows[0]["message"]
    assert r.get(f"netconfig:ssh:{d['id']}") is not None  # ほかの処理のロックは消さない


def _hold(r, name):
    lk = device_lock.make_lock(r, name)
    assert lk.acquire(blocking=False)
    return lk


def test_command_run_waits_for_ssh_lock_without_blocking_and_real_retry(env, r):
    """同じ機器の別の SSH 処理の途中なら、ブロックせず、結果を待機中に戻して再試行に回す（本物の retry を通す）。
    再試行の回数（request.retries）が多くても MaxRetriesExceededError にならない（Celery の max_retries=None は
    無制限ではなくタスクの既定値の意味。H2）。待っている間は枠を放し、次の機器を投入する"""
    port, state, _ = fake_sshd.start(show_any=True)
    d = _device(env, port)
    _, rid = _new_run(env, d["id"])
    other = _hold(r, f"netconfig:ssh:{d['id']}")
    real_unclaim = worker._unclaim_command_result
    seen = {}

    async def unclaim_then_free(result_id):  # 待ちに戻した直後に、ほかの SSH 処理が終わる
        await real_unclaim(result_id)
        seen["queued"] = _result(result_id)["status"]
        seen["slot_free"] = not r.exists("netconfig:cmdrun:slot:0")
        other.release()

    t0 = time.monotonic()
    with mock.patch.object(worker, "_unclaim_command_result", unclaim_then_free):
        res = worker.run_command_device.apply(args=(rid,), retries=50)
    assert time.monotonic() - t0 < 10  # 300 秒もブロックしない
    assert res.state != "FAILURE", res.result
    assert seen["queued"] == "queued"
    assert _result(rid)["status"] == "ok" and state["commands"]  # 2 回目（再試行）で実行できた
    assert not r.exists("netconfig:cmdrun:slot:0") and not r.exists("netconfig:cmdrun:slot:1")


def test_command_run_gives_up_after_waiting_and_dispatches_next(env, r):
    """SSH_LOCK_WAIT 秒ぶん待っても空かなければ、その機器を失敗にし、次の機器を投入する（待機中のまま残らない）。
    待っている間に放した枠は、ほかの機器に回る"""
    port, _state, _ = fake_sshd.start(show_any=True)
    a, b, x = _device(env, port), _device(env, port), _device(env, port)
    run = env["c"].post("/api/commands/runs", json={"device_ids": [a["id"], b["id"], x["id"]], "commands": ["show clock"]},
                        headers=env["h"]).json()
    rows = dict(_db().execute("select device_id, id from command_results where run_id=?", (run["id"],)).fetchall())
    other = _hold(r, f"netconfig:ssh:{a['id']}")
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 2), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run["id"], [rows[a["id"]], rows[b["id"]], rows[x["id"]]])
        call_a, call_b = delay.call_args_list
        assert call_a.args[0] == rows[a["id"]] and call_b.args[0] == rows[b["id"]]
        delay.reset_mock()
        # 待てる回数（lock_waits）を使い切った回（20 回目の再試行）
        res = worker.run_command_device.apply(
            args=call_a.args, kwargs={**call_a.kwargs, "lock_waits": worker._lock_wait_limit()}, retries=20)
        assert res.state != "FAILURE" and res.get() == {"status": "failed"}
        assert [c.args[0] for c in delay.call_args_list] == [rows[x["id"]]]  # 放した枠で次の機器が流れる
    row = _result(rows[a["id"]])
    assert row["status"] == "failed" and row["error"] == worker.LOCK_WAIT_FAILED
    other.release()


def test_command_run_retry_failure_does_not_leave_queued(env, r):
    """再試行を予約できなかったとき（broker の停止など）も、待機中のまま残さず失敗にして、次を投入する"""
    port, _, _ = fake_sshd.start(show_any=True)
    d = _device(env, port)
    _, rid = _new_run(env, d["id"])
    other = _hold(r, f"netconfig:ssh:{d['id']}")
    with mock.patch.object(worker.run_command_device, "retry", side_effect=OSError("broker down")), \
            mock.patch.object(worker, "pump_command_queue") as pump:
        assert worker.run_command_device.apply(args=(rid,)).state != "FAILURE"
    row = _result(rid)
    assert row["status"] == "failed" and row["error"] == worker.RETRY_FAILED and pump.called
    other.release()


def test_command_slots_are_handed_out_by_the_dispatcher(env, r):
    """枠（COMMAND_RUN_WORKER_SLOTS）は投入の側で配る。埋まっていれば投入せず、待つタスクを回し続けない。
    枠が空いたら、古い実行から、実行の間で交互に投入する（M1）"""
    port, _state, _ = fake_sshd.start(show_any=True)
    devs = [_device(env, port) for _ in range(5)]
    c, h = env["c"], env["h"]

    def run_of(ds):
        run = c.post("/api/commands/runs", json={"device_ids": [x["id"] for x in ds], "commands": ["show clock"]},
                     headers=h).json()
        ids = dict(_db().execute("select device_id, id from command_results where run_id=?", (run["id"],)).fetchall())
        return run["id"], [ids[x["id"]] for x in ds]

    run_a, ids_a = run_of(devs[:3])
    run_b, ids_b = run_of(devs[3:])
    order = []
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 1), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run_a, ids_a)
        worker.enqueue_command_run(run_b, ids_b)
        assert len(delay.call_args_list) == 1  # 枠は 1 つ。残りは投入しない（Redis の待ち行列で待つ）
        assert r.llen(worker._pending_key(run_a)) == 2 and r.llen(worker._pending_key(run_b)) == 2
        while delay.call_args_list:
            call = delay.call_args_list.pop(0)
            order.append(call.args[0])
            assert worker.run_command_device.apply(args=call.args, kwargs=call.kwargs).get() == {"status": "ok"}
    assert sorted(order) == sorted(ids_a + ids_b)
    assert order.index(ids_b[0]) < order.index(ids_a[2])  # 後の実行も、前の実行が全部終わる前に回ってくる
    assert order[0] == ids_a[0]  # 古い実行から
    assert not r.exists("netconfig:cmdrun:slot:0")


def test_command_run_without_slot_goes_back_to_queue_head(env, r):
    """枠を取れない（予約が切れた・以前の版で投入されたタスク）ときは、接続せずに待ち行列の先頭へ戻す"""
    port, state, _ = fake_sshd.start(show_any=True)
    d = _device(env, port)
    run_id, rid = _new_run(env, d["id"])
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 1):
        busy = device_lock.make_lock(r, "netconfig:cmdrun:slot:0")
        assert busy.acquire(blocking=False, token="other-run:x")
        r.rpush(worker._pending_key(run_id), "later")
        assert worker.run_command_device.apply(args=(rid,), kwargs={"lock_waits": 2}).get() == {"status": "waiting"}
        assert _result(rid)["status"] == "queued" and "commands" not in state
        assert r.lindex(worker._pending_key(run_id), 0) == f"{rid}|2".encode()  # 先頭に、待った回数つきで戻る
        r.lrem(worker._pending_key(run_id), 0, "later")
        busy.release()
        with mock.patch.object(worker.run_command_device, "delay") as delay:
            assert worker.pump_command_queue() == 1
        assert delay.call_args.args == (rid,) and delay.call_args.kwargs["lock_waits"] == 2
        assert worker.run_command_device.apply(args=delay.call_args.args, kwargs=delay.call_args.kwargs).get() \
            == {"status": "ok"}


def test_fail_stale_does_not_fail_runs_that_only_wait_for_a_slot(env, r):
    """遅い実行が枠を占めている間、枠を待っているだけの実行を「止まった」として失敗にしない。全体が止まっていれば失敗にする"""
    import asyncio
    from datetime import timedelta

    from app.core.timeutil import utcnow
    d = _device(env, 22)
    run_id, rid = _new_run(env, d["id"])
    future = utcnow() + timedelta(days=1)  # 実行の作成・ほかの機器の動きから STALE_IDLE を過ぎた時点

    # 全体が止まっている（枠を使っている処理も、最近の動きも無い）なら、待っている実行も失敗にする
    async def check(**kw):
        async with worker._sessionmaker()() as db:
            await command_run_svc.fail_stale(db, now=future, **kw)
            row = await db.get(command_run_svc.CommandResult, rid)
            status = row.status
            await db.rollback()
            return status
    assert asyncio.run(check(waiting_runs={run_id}, system_active=True)) == "queued"
    assert asyncio.run(check(waiting_runs={run_id}, system_active=False)) == "failed"
    assert asyncio.run(check()) == "failed"  # 待ち行列に無い（取りこぼし）実行は今までどおり
    # 実行中のまま止まった機器の時間は、コマンド実行の時間の上限より長い
    assert worker.COMMAND_STALE_RUNNING.total_seconds() > worker.run_command_device.time_limit


def test_periodic_task_pumps_and_passes_waiting_runs(env, r):
    """5 分ごとの定期処理が、枠を待っている実行を fail_stale に渡し、取りこぼした機器を投入する"""
    r.rpush(worker._pending_key("run-x"), "res-x")
    r.zadd(worker.CMD_QUEUE_KEY, {"run-x": 1})
    seen = {}

    async def fake(waiting, active):
        seen["args"] = (waiting, active)
        return 0

    with mock.patch.object(worker, "_fail_stale_runs", fake), mock.patch.object(worker.run_command_device, "delay") as delay:
        assert worker.fail_stale_command_runs.apply().get() == 0
        assert delay.call_args.args == ("res-x",)  # 先に投入する（recover → pump → fail_stale）
    assert seen["args"] == ({"run-x"}, True)  # 投入した機器が枠を予約している（全体が進んでいる）


def test_recover_does_nothing_while_another_recover_runs(env, r):
    """保険の処理が重なっても（起動時と 5 分ごと）、同じ機器を 2 回戻さない: ロックを持っている間は何もしない"""
    r.rpush(worker._pending_key("run-old"), "res-old")  # 以前の版の待ち行列（ZSET に無い）
    r.set(worker.RECOVER_LOCK, "other", ex=60)
    with mock.patch.object(worker, "_queued_results") as queued:
        assert worker.recover_command_queue()["skipped"] is True
    assert not queued.called and r.zscore(worker.CMD_QUEUE_KEY, "run-old") is None
    r.delete(worker.RECOVER_LOCK)
    assert worker.recover_command_queue()["runs"] == 1 and r.zscore(worker.CMD_QUEUE_KEY, "run-old") is not None
    assert not r.exists(worker.RECOVER_LOCK)  # 終わったら放す


def _old_waiting_run(env, n=1):
    """STALE_IDLE を過ぎて待っている実行（作成から 2 時間、機器は 1 台も動いていない）"""
    from app.core.timeutil import utcnow
    run_id, ids = _run_ids(env, n, 22)
    old = (utcnow() - timedelta(hours=2)).isoformat(sep=" ")
    con = _db()
    con.execute("update command_runs set created_at=? where id=?", (old, run_id))
    con.commit()
    return run_id, ids


def test_periodic_task_dispatches_before_failing_a_long_waiting_run(env, r):
    """worker の再起動のあと（枠は空いたが、ほかの実行の機器が DB で「実行中」のまま）、60 分以上待っている実行は、
    この回で投入されるので失敗にしない（recover → pump → fail_stale）"""
    run_id, (rid,) = _old_waiting_run(env)
    r.rpush(worker._pending_key(run_id), rid)
    r.zadd(worker.CMD_QUEUE_KEY, {run_id: 1})
    future = command_run_svc.utcnow() + command_run_svc.STALE_IDLE + timedelta(minutes=1)  # ほかのテストの機器の動きも古い時点
    with mock.patch.object(command_run_svc, "utcnow", return_value=future), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.fail_stale_command_runs.apply().get()
    assert _result(rid)["status"] == "queued"  # 失敗にしていない
    assert delay.call_args.args[0] == rid  # この回で投入した
    _cleanup(run_id)


def _cleanup(run_id):
    con = _db()
    con.execute("update command_results set status='failed' where run_id=? and status='queued'", (run_id,))
    con.commit()


def test_periodic_task_keeps_waiting_run_when_a_slot_is_free_but_not_yet_dispatched(env, r):
    """投入が最後まで動き、いま空いた枠があって待ち行列に機器が残っている実行（1 つの実行の同時実行数の上限などで、
    この回か次の回で投入される）は、STALE_IDLE を過ぎていても失敗にしない"""
    run_id, ids = _old_waiting_run(env, 2)
    r.rpush(worker._pending_key(run_id), *ids)
    r.zadd(worker.CMD_QUEUE_KEY, {run_id: 1})
    future = command_run_svc.utcnow() + command_run_svc.STALE_IDLE + timedelta(minutes=1)
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 2), mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 1), \
            mock.patch.object(command_run_svc, "utcnow", return_value=future), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.fail_stale_command_runs.apply().get()
        assert len(delay.call_args_list) == 1  # 1 台は投入、もう 1 台は同時実行数の上限で待っている（枠は 1 つ空いている）
        assert r.llen(worker._pending_key(run_id)) == 1
        # 投入した 1 台の予約が切れた（枠が 2 つとも空いた）あとの回でも、待っている 1 台は失敗にしない
        r.delete(worker._slot_key(0), worker._slot_key(1))
        delay.side_effect = None
        with mock.patch.object(worker, "pump_command_queue", return_value=0):  # この回は投入されなかった（上限など）
            worker.fail_stale_command_runs.apply().get()
    assert [_result(i)["status"] for i in ids] == ["queued", "queued"]
    _cleanup(run_id)


def test_periodic_task_still_fails_when_nothing_can_be_dispatched(env, r):
    """worker・broker が動いていない（枠も動きも無く、投入しても送れない）ときは、待っている実行も今までどおり失敗にする"""
    run_id, (rid,) = _old_waiting_run(env)
    r.rpush(worker._pending_key(run_id), rid)
    r.zadd(worker.CMD_QUEUE_KEY, {run_id: 1})
    # 前のテストが同じ DB で別の時点（＋61 分）に失敗にした機器の時刻より、さらに STALE_IDLE 以上あとの時点で見る
    future = command_run_svc.utcnow() + 3 * command_run_svc.STALE_IDLE
    with mock.patch.object(command_run_svc, "utcnow", return_value=future), \
            mock.patch.object(worker.run_command_device, "delay", side_effect=OSError("broker down")):
        assert worker.fail_stale_command_runs.apply().get() >= 1
    assert _result(rid)["status"] == "failed"


def test_worker_ready_warns_when_slots_use_up_the_worker():
    assert worker.check_command_slots(4) is True  # 既定の 2 は -c 4 に収まる
    assert worker.check_command_slots(None) is True
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 4), mock.patch.object(worker.logger, "warning") as warn:
        assert worker.check_command_slots(4) is False
    assert "COMMAND_RUN_WORKER_SLOTS" in warn.call_args.args[0]
    from pydantic import ValidationError

    from app.core.config import Settings
    with pytest.raises(ValidationError):
        Settings(COMMAND_RUN_WORKER_SLOTS=0)


# ---------------------------------------------------------------- 収集・FW ヒット数


def test_collect_waits_without_blocking_and_real_retry(env, r):
    """収集も、ほかの SSH 処理の途中ならブロックせずに再試行に回す（本物の retry を通す）。
    request.retries が多くても MaxRetriesExceededError にならない（H1）"""
    port, _, _ = fake_sshd.start()
    d = _device(env, port)
    other = _hold(r, f"netconfig:ssh:{d['id']}")
    real_mark = worker.collect_state.mark
    states = []

    def mark(rr, device_id, state, *a, **kw):
        states.append(state)
        real_mark(rr, device_id, state, *a, **kw)
        if state == "queued" and device_id == d["id"]:
            other.release()  # 待ちに戻した直後に、ほかの SSH 処理が終わる

    t0 = time.monotonic()
    with mock.patch.object(worker.collect_state, "mark", mark):
        res = worker.collect_device_config.apply(args=(d["id"], "schedule", "スケジュール「s」", "ref-1"),
                                                 kwargs={"lock_waits": 2}, retries=2)
    assert time.monotonic() - t0 < 10
    assert res.state != "FAILURE", res.result
    assert "queued" in states
    assert [tuple(x) for x in _db().execute("select status from collect_logs where device_id=?", (d["id"],))] == [("success",)]
    assert not r.exists(f"netconfig:collect:state:{d['id']}") and not r.exists(f"netconfig:collect:waiting:{d['id']}")


def test_collect_gives_up_after_waiting_with_records_and_resets_waits_on_failure_retry(env, r):
    """待っても空かなければ失敗（再試行できる失敗）。失敗の再試行では待ちの回数を 0 に戻す（毎回 SSH_LOCK_WAIT 秒待てる。M3）。
    最後は収集ログ・collect.failed・失敗の通知が残り、「収集待ち」のまま残らない"""
    port, _, _ = fake_sshd.start()
    d = _device(env, port)
    other = _hold(r, f"netconfig:ssh:{d['id']}")
    queued = []
    real_mark = worker.collect_state.mark

    def mark(rr, device_id, state, *a, **kw):
        if device_id == d["id"] and state == "queued":
            queued.append(1)
        real_mark(rr, device_id, state, *a, **kw)

    async def yes(event):
        return True

    with mock.patch.object(worker, "SSH_LOCK_WAIT", worker.SSH_LOCK_RETRY_SEC), \
            mock.patch.object(worker.collect_state, "mark", mark), \
            mock.patch.object(worker, "queue_failure_notification") as notice, mock.patch.object(worker, "_wants", yes):
        res = worker.collect_device_config.apply(args=(d["id"], "schedule", "スケジュール「s」", "ref-2"), retries=5)
    assert res.state != "FAILURE", res.result
    assert len(queued) == 1 + worker.collect_device_config.max_retries  # 試行のたびに待つ（待ちの回数は引き継がない）
    logs = _db().execute("select status, message from collect_logs where device_id=?", (d["id"],)).fetchall()
    assert len(logs) == 3 and all(s == "failed" and "SSH" in m for s, m in logs)
    acts = _activity("collect.failed", d["id"])
    assert [a["level"] for a in acts] == ["warning", "warning", "error"]
    assert notice.call_count == 1
    assert not r.exists(f"netconfig:collect:state:{d['id']}") and not r.exists(f"netconfig:collect:waiting:{d['id']}")
    other.release()


def test_collect_retry_failure_is_recorded(env, r):
    """再試行を予約できない（broker の停止など）ときも、最終の失敗として残し、「収集待ち」のまま残さない"""
    port, _, _ = fake_sshd.start()
    d = _device(env, port)
    other = _hold(r, f"netconfig:ssh:{d['id']}")
    with mock.patch.object(worker.collect_device_config, "retry", side_effect=OSError("broker down")):
        res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert res["success"] is False and "予約できなかった" in res["error"]
    assert _activity("collect.failed", d["id"])[-1]["level"] == "error"
    assert not r.exists(f"netconfig:collect:state:{d['id']}")
    other.release()


def test_collect_request_is_skipped_while_another_collect_waits(env, r):
    """ほかの SSH 処理を待っている収集がある間（収集のロックは放している）に来た依頼はスキップする（2 回収集しない）"""
    port, _, _ = fake_sshd.start()
    d = _device(env, port)
    r.set(f"netconfig:collect:waiting:{d['id']}", "another-task", ex=60)
    res = worker.collect_device_config.apply(args=(d["id"],)).get()
    assert res["skipped"] is True
    assert _activity("collect.skipped", d["id"])
    r.delete(f"netconfig:collect:waiting:{d['id']}")
    assert worker.collect_device_config.apply(args=(d["id"],)).get()["success"]


def test_collect_state_ttl_covers_the_longest_collect():
    assert worker.collect_state.TTL["running"] > worker.collect_device_config.time_limit


def test_collect_keeps_locks_during_long_collect(env, r):
    port, _, _ = fake_sshd.start()
    d = _device(env, port)
    seen = {}
    real = cs.collect_config_sync

    def slow(device, *a, **kw):
        time.sleep(1.5)
        seen["ssh"] = r.exists(f"netconfig:ssh:{device.id}")
        seen["collect"] = r.exists(f"netconfig:collect:{device.id}")
        return real(device, *a, **kw)

    with mock.patch.object(device_lock, "LOCK_TTL", 0.6), mock.patch.object(device_lock, "EXTEND_INTERVAL", 0.15), \
            mock.patch.object(worker, "collect_config_sync", side_effect=slow):
        assert worker.collect_device_config.apply(args=(d["id"],)).get()["success"]
    assert seen == {"ssh": 1, "collect": 1}
    assert _activity("ssh.lock_lost", d["id"]) == []
    assert not r.exists(f"netconfig:ssh:{d['id']}") and not r.exists(f"netconfig:collect:{d['id']}")


def test_fw_hits_keeps_lock_and_records_lost(env, r):
    from app.services import fw_hits
    port, _, _ = fake_sshd.start()
    d = _device(env, port, platform="fortinet")

    def stolen(device):
        r.delete(f"netconfig:ssh:{device.id}")
        assert device_lock.make_lock(r, f"netconfig:ssh:{device.id}").acquire(blocking=False)
        return fw_hits.FwHitResult(rules=[], error=None)

    with mock.patch.object(fw_hits, "collect_fw_hits", side_effect=stolen):
        assert worker.collect_fw_hits_device.apply(args=(d["id"],)).get() == {"rules": 0, "error": None}
    assert len(_activity("ssh.lock_lost", d["id"])) == 1


# ---------------------------------------------------------------- タスクの時間の上限


def test_tasks_have_time_limits_longer_than_the_longest_legitimate_run():
    longest_read = worker.MAX_READ_TIMEOUT
    cmd = worker.run_command_device
    # コマンド実行: 接続 ＋ 5 コマンド × 応答待ちの最長 より長い。hard は soft より長い
    assert cmd.soft_time_limit > worker.CONNECT_SECONDS + command_run_svc.MAX_COMMANDS * longest_read
    assert cmd.time_limit > cmd.soft_time_limit
    # 実行中のまま止まった機器を失敗にする時間（2 時間）より短い（上限で止まった機器は fail_stale を待たずに失敗になる）
    assert cmd.time_limit < command_run_svc.STALE_RUNNING.total_seconds()
    col = worker.collect_device_config
    assert col.soft_time_limit > worker.CONNECT_SECONDS + worker._collect_reads() * longest_read
    assert col.time_limit > col.soft_time_limit
    fw = worker.collect_fw_hits_device
    assert fw.soft_time_limit > worker.CONNECT_SECONDS + 2 * longest_read and fw.time_limit > fw.soft_time_limit
    # 応答待ち時間の上限（API の検証）と、計算に使う値が同じ
    from app.api.devices import ReadTimeoutSec
    assert [m.le for m in ReadTimeoutSec.__metadata__[0].metadata if hasattr(m, "le")] == [longest_read]
    assert settings.model_fields["SSH_READ_TIMEOUT"].metadata[-1].le == longest_read


def test_soft_time_limit_is_not_retried():
    d = cs.DeviceConnectionInfo(id="x", name="r1", hostname="192.0.2.1", platform="cisco_ios", port=22, username="u",
                                password="p", enable_secret=None)
    msg, retryable = cs.describe_failure(SoftTimeLimitExceeded(), d)
    assert "時間の上限" in msg and retryable is False


# ---------------------------------------------------------------- 取りこぼしの保険（更新の直後・投入の途中で落ちた）


def _run_ids(env, n, port):
    devs = [_device(env, port) for _ in range(n)]
    run = env["c"].post("/api/commands/runs", json={"device_ids": [d["id"] for d in devs], "commands": ["show clock"]},
                        headers=env["h"]).json()
    rows = dict(_db().execute("select device_id, id from command_results where run_id=?", (run["id"],)).fetchall())
    return run["id"], [rows[d["id"]] for d in devs]


def test_old_version_pending_list_is_dispatched_after_upgrade(env, r):
    """N1: 以前の版は待ち行列（netconfig:cmdrun:<実行>:pending）にだけ残りの機器を置いた（「待っている実行」に入れていない）。
    保険の処理（5 分ごと・worker の起動時）が見つけて、残りの機器も投入する"""
    port, _, _ = fake_sshd.start(show_any=True)
    run_id, ids = _run_ids(env, 3, port)
    r.rpush(worker._pending_key(run_id), *ids[1:])  # 以前の版の形（先頭の 1 台は直接投入済み）
    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 2), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        assert worker.run_command_device.apply(args=(ids[0],)).get() == {"status": "ok"}  # 以前の版が投入したタスク
        assert delay.call_args_list == []  # pump は「待っている実行」しか見ないので、まだ流れない
        worker.fail_stale_command_runs.apply().get()
        assert sorted(c.args[0] for c in delay.call_args_list) == sorted(ids[1:])  # 2 台とも投入される
        calls = list(delay.call_args_list)
    assert r.llen(worker._pending_key(run_id)) == 0
    for call in calls:
        assert worker.run_command_device.apply(args=call.args, kwargs=call.kwargs).get() == {"status": "ok"}
    # worker の起動時にも同じ確認をする
    run2, ids2 = _run_ids(env, 1, port)
    r.rpush(worker._pending_key(run2), ids2[0])
    with mock.patch.object(worker.run_command_device, "delay") as delay:
        worker._log_outbound(sender=None)
    assert [c.args[0] for c in delay.call_args_list] == ids2
    worker.run_command_device.apply(args=delay.call_args.args, kwargs=delay.call_args.kwargs).get()


def test_lost_queued_result_is_requeued_only_after_reserve_ttl(env, r):
    """L1: DB では待機中なのに、待ち行列にも枠の予約にも再試行の印にも無い機器（LPOP のあと投入の前に落ちた・Redis の
    再起動で待ち行列が消えた）は、SLOT_RESERVE_TTL 秒より長く続いたら待ち行列へ戻す。予約・印がある機器は戻さない"""
    port, _, _ = fake_sshd.start(show_any=True)
    run_id, (lost, reserved, retrying) = _run_ids(env, 3, port)
    r.set(worker._slot_key(0), worker._slot_token(run_id, reserved), ex=600)  # 予約済み（broker の中で待っている）
    r.set(worker._retrying_key(retrying), "1", ex=600)  # SSH ロックを待って再試行中
    t0 = time.time()

    def mine():  # 共有の DB にはほかのテストの待機中の機器もあるので、この実行の待ち行列だけを見る
        return sorted(x.decode() for x in r.lrange(worker._pending_key(run_id), 0, -1))

    with mock.patch.object(settings, "COMMAND_RUN_WORKER_SLOTS", 1):
        worker.recover_command_queue(now=t0)  # 1 回目は覚えるだけ
        assert mine() == []
        worker.recover_command_queue(now=t0 + 60)  # 予約の期限より短い間は戻さない
        assert mine() == []
        worker.recover_command_queue(now=t0 + worker.SLOT_RESERVE_TTL + 1)
        assert mine() == [lost]
        worker.recover_command_queue(now=t0 + 2 * worker.SLOT_RESERVE_TTL)  # 待ち行列にあるので二重に戻さない
        assert mine() == [lost]
        # Redis の再起動で待ち行列が消え、予約も切れた（タスクが失われた）: 長く続けば戻す
        r.delete(worker._slot_key(0))
        r.delete(worker._pending_key(run_id))
        worker.recover_command_queue(now=t0 + 3 * worker.SLOT_RESERVE_TTL)
        assert mine() == []
        worker.recover_command_queue(now=t0 + 5 * worker.SLOT_RESERVE_TTL)
        assert mine() == sorted([lost, reserved])  # 再試行の印がある機器は戻さない
        r.delete(worker.CMD_QUEUE_KEY)  # ほかのテストの実行は流さない
        r.zadd(worker.CMD_QUEUE_KEY, {run_id: 0})
        with mock.patch.object(worker.run_command_device, "delay") as delay:
            worker.pump_command_queue()
        assert delay.call_args.args[0] in (lost, reserved)
        assert worker.run_command_device.apply(args=delay.call_args.args, kwargs=delay.call_args.kwargs).get() \
            == {"status": "ok"}
    assert _result(retrying)["status"] == "queued"


def test_claim_is_atomic(env, r):
    """L3: 着手は「待機中なら実行中にする」1 つの UPDATE。すでに実行中・終わった機器は取れない（2 つ目のタスクは何もしない）"""
    import asyncio
    _, (rid,) = _run_ids(env, 1, 22)
    first = asyncio.run(worker._claim_command_result(rid))
    assert first["claimed"] is True and _result(rid)["status"] == "running"
    assert asyncio.run(worker._claim_command_result(rid))["claimed"] is False
    con = _db()
    con.execute("update command_results set status='ok' where id=?", (rid,))
    con.commit()
    assert asyncio.run(worker._claim_command_result(rid))["claimed"] is False
    assert _result(rid)["status"] == "ok"


def test_collect_wait_mark_outlives_the_wait():
    """L4: 収集が SSH ロックを待っている印の期限は、待つ上限（SSH_LOCK_WAIT）より長い（worker が埋まっていても切れない）"""
    assert worker.COLLECT_WAIT_MARK_TTL > worker.SSH_LOCK_WAIT + worker.SSH_LOCK_RETRY_SEC
