"""コマンド実行（表示コマンドの一括実行）のテスト

- 検証の表: 機種ごとに、送れるコマンドと送れないコマンド（設定を変えるもの・危険な書き方）
- API: 権限・対象の指定・機種の混在・上限・監査ログ・暗号化・同じ出力のまとめ・出力
- worker: 偽の SSH 機器への実行・実行直前の再検証・失敗・ロック・同時実行数・保持期間の掃除・出力の上限
"""
import json
import sqlite3
import uuid
from unittest import mock

import fake_sshd
import fakeredis
import pytest
from conftest import TMP
from fastapi.testclient import TestClient

from app import worker
from app.core.config import settings
from app.core.permissions import ROLE_PERMISSIONS, Perm, Role
from app.main import app
from app.services import command_run as svc
from app.services.config_service import PLATFORMS

# ---------------------------------------------------------------- 検証の表（services/command_run.py）

# (機種, コマンド): 送れる
ALLOWED = [
    ("cisco_ios", "show running-config"),
    ("cisco_ios", "sh run"),
    ("cisco_ios", "sho ver"),
    ("cisco_ios", "SHOW IP INTERFACE BRIEF"),
    ("cisco_ios", "show ip interface brief | include up"),
    ("cisco_ios", "show running-config | section interface | count"),
    ("cisco_ios", "show run | begin router"),
    ("cisco_ios", "show ip interface brief | i up"),  # 絞り込み語の省略形（Cisco 系）
    ("cisco_ios", "show ip interface brief | inc up"),
    ("cisco_ios", "show run | sec ospf"),
    ("cisco_ios", "show ip interface brief | e down"),
    ("cisco_ios", "show run | beg router"),
    ("cisco_xr", "show running-config"),
    ("cisco_nxos", "show interface | last 10"),
    ("cisco_nxos", "show running-config | head 20"),
    ("cisco_nxos", "show running-config | include vlan"),
    ("juniper_junos", "show log messages | last 20"),
    ("juniper_junos", "show configuration | display set | count"),
    ("cisco_ios", "  show clock  "),
    ("cisco_xe", "show version"),
    ("cisco_nxos", "show interface status | grep connected"),
    ("cisco_nxos", "show ip route | json"),
    ("cisco_asa", "show running-config | include access-list"),
    ("arista_eos", "show running-config | grep vlan"),
    ("arista_eos", "show version | json"),
    ("juniper_junos", "show configuration | display set"),
    ("juniper_junos", "show interfaces terse | match ge-"),
    ("juniper_junos", "show route | except 10.0.0 | no-more"),
    ("juniper_junos", "show configuration | display set | match ntp | count"),
    ("juniper_screenos", "get config"),
    ("juniper_screenos", "get system"),
    ("fortinet", "get system status"),
    ("fortinet", "show"),
    ("fortinet", "show system interface"),
    ("fortinet", "get system status | grep Version"),
    ("paloalto_panos", "show system info"),
    ("paloalto_panos", "show interface all | match ethernet"),
    ("huawei", "display current-configuration"),
    ("huawei", "dis cur"),
    ("huawei", "display ip routing-table | include 10.0"),
    ("huawei_vrpv8", "display version"),
    ("hp_comware", "display interface brief | exclude DOWN"),
    ("hp_procurve", "show running-config"),
    ("aruba_aoscx", "show interface brief"),
    ("allied_telesis_awplus", "show running-config"),
    ("yamaha", "show config"),
    ("yamaha", "show environment | grep temp"),
    ("vyos", "show interfaces"),
    ("vyos", "show ip route | match 10.0.0.1"),
    ("ubiquiti_edgerouter", "show configuration commands"),
    ("nokia_sros", "show router interface"),
    ("nokia_sros", "admin show configuration"),
    ("netscaler", "show ns runningConfig | grep add"),
    ("extreme_exos", "show ports"),
    ("dell_os10", "show running-configuration"),
]

# (機種, コマンド): 送れない（設定を変える・機器の状態を変える・ファイルへ出す・シェルなどへ抜ける）
DENIED = [
    # 設定モード・特権モードへ入る、保存・再起動・消去など。省略形も同じ
    ("cisco_ios", "conf t"),
    ("cisco_ios", "conf"),
    ("cisco_ios", "configure terminal"),
    ("cisco_ios", "enable"),
    ("cisco_ios", "en"),
    ("cisco_ios", "reload"),
    ("cisco_ios", "write memory"),
    ("cisco_ios", "wr"),
    ("cisco_ios", "copy running-config startup-config"),
    ("cisco_ios", "copy run tftp:"),
    ("cisco_ios", "delete flash:config.text"),
    ("cisco_ios", "clear counters"),
    ("cisco_ios", "debug all"),
    ("cisco_ios", "undebug all"),
    ("cisco_ios", "terminal length 0"),
    ("cisco_ios", "ping 192.0.2.1"),
    ("cisco_ios", "traceroute 192.0.2.1"),
    ("cisco_ios", "ssh -l admin 192.0.2.1"),
    ("cisco_ios", "telnet 192.0.2.1"),
    ("cisco_ios", "erase startup-config"),
    ("cisco_ios", "no shutdown"),
    ("cisco_ios", "interface Gi0/1"),
    ("cisco_ios", "dis"),  # Cisco では disable。display の省略形は使えない
    ("cisco_ios", "display version"),
    ("cisco_ios", "showrun"),  # show の省略形ではない
    ("cisco_ios", "shut"),
    ("cisco_nxos", "request system reboot"),
    ("juniper_junos", "request system reboot"),
    ("juniper_junos", "configure"),
    ("juniper_junos", "edit"),
    ("juniper_junos", "set system host-name x"),
    ("juniper_junos", "commit"),
    ("juniper_junos", "load override x"),
    ("juniper_junos", "file delete /var/tmp/x"),
    ("paloalto_panos", "set cli pager off"),
    ("paloalto_panos", "configure"),
    ("paloalto_panos", "request restart system"),
    ("paloalto_panos", "debug dataplane"),
    ("paloalto_panos", "delete x"),
    ("fortinet", "execute reboot"),
    ("fortinet", "config system global"),
    ("fortinet", "diagnose debug enable"),
    ("fortinet", "set admintimeout 5"),
    ("juniper_screenos", "set interface ethernet0/0 ip 192.0.2.1/24"),
    ("juniper_screenos", "save config"),
    ("huawei", "system-view"),
    ("huawei", "sys"),
    ("huawei", "reset counters interface"),
    ("huawei", "save"),
    ("huawei", "reboot"),
    ("huawei", "undo shutdown"),
    ("huawei", "show version"),  # Huawei は display
    ("hp_comware", "system-view"),
    ("hp_comware", "save force"),
    ("arista_eos", "configure terminal"),
    ("arista_eos", "bash"),
    ("arista_eos", "reload now"),
    ("vyos", "configure"),
    ("vyos", "set interfaces ethernet eth0 address 192.0.2.1/24"),
    ("vyos", "reboot"),
    ("vyos", "show interfaces | grep eth0"),  # bash の grep は使えない（match だけ）
    ("vyos", "show interfaces | tee /tmp/x"),
    ("ubiquiti_edgerouter", "configure"),
    ("nokia_sros", "admin reboot"),
    ("nokia_sros", "admin save"),
    ("nokia_sros", "configure router"),
    ("nokia_sros", "admin"),
    ("yamaha", "administrator"),
    ("yamaha", "save"),
    ("yamaha", "restart"),
    # パイプ・リダイレクト・連結・置き換え
    ("cisco_ios", "show run | redirect flash:x"),
    ("cisco_ios", "show run | tee flash:x"),
    ("cisco_ios", "show run | append flash:x"),
    ("cisco_ios", "show run | save x"),
    ("cisco_ios", "show run | file x"),
    ("cisco_ios", "show run | write x"),
    ("cisco_ios", "show run | copy x"),
    ("cisco_ios", "show run | tftp x"),
    ("cisco_ios", "show run | include a | redirect x"),
    ("cisco_ios", "show run | include a|b"),  # 正規表現の「|」は区切りとして扱う（絞り込みの語ではない）
    ("cisco_ios", "show run |"),
    ("cisco_ios", "show run | "),
    ("cisco_ios", "show run || include x"),
    ("cisco_ios", "show run > flash:x"),
    ("cisco_ios", "show run >> flash:x"),
    ("cisco_ios", "show run < x"),
    ("cisco_ios", "show run; reload"),
    ("cisco_ios", "show run ; reload"),
    ("cisco_ios", "show run && reload"),
    ("cisco_ios", "show run & reload"),
    ("cisco_ios", "show run `reload`"),
    ("cisco_ios", "show $(reload)"),
    ("cisco_ios", "show ${x}"),
    ("cisco_ios", "show run \\ reload"),
    ("cisco_ios", "show ?"),
    ("cisco_ios", "show ip ?"),
    ("juniper_junos", "show x | save /var/tmp/x"),
    ("juniper_junos", "show x | display set | save y"),
    ("juniper_junos", "show x | display bogus"),
    ("juniper_junos", "show x | request message all"),
    ("juniper_junos", "show x | hold"),
    ("juniper_junos", "show x | include y"),  # Junos の絞り込みは match
    ("cisco_nxos", "show x | awk '{print}'"),
    ("cisco_nxos", "show x | tee bootflash:x"),
    ("arista_eos", "show x | awk x"),
    ("fortinet", "get system status | include x"),
    ("paloalto_panos", "show x | save y"),
    ("paloalto_panos", "show x | less"),
    # 空・形式
    ("cisco_ios", ""),
    ("cisco_ios", "   "),
    ("cisco_ios", "show\nreload"),
    ("cisco_ios", "show run\r\nreload"),
    ("cisco_ios", "show\treload"),
    ("cisco_ios", "\tshow run"),
    ("cisco_ios", "show run\x00"),
    ("cisco_ios", "show run\x1b[A"),
    ("cisco_ios", "show run\x7f"),
    ("cisco_ios", "show 日本語"),
    ("cisco_ios", "show　run"),  # 全角の空白
    ("cisco_ios", "show​run"),  # 幅のない空白
    ("cisco_ios", "ｓｈｏｗ run"),  # 全角の英字
    ("cisco_ios", "show " + "a" * 200),  # 長すぎる
    ("cisco_ios", "-show run"),
    ("cisco_ios", "!show run"),
    ("cisco_ios", "/show run"),
    ("cisco_ios", "show-run"),
    ("zzz_unknown", "show version"),
]


# 先頭語を完全一致だけにする機種（省略形を許さない）。sh は /bin/sh として動きうる
EXACT_ONLY = ["vyos", "ubiquiti_edgerouter", "checkpoint_gaia", "dell_os10", "cisco_viptela", "juniper_junos", "fortinet",
              "paloalto_panos", "hp_procurve", "aruba_aoscx", "allied_telesis_awplus", "yamaha", "netscaler", "nokia_sros",
              "extreme_exos", "mellanox_mlnxos", "tplink_jetstream", "eltex"]
SHELL = ["vyos", "ubiquiti_edgerouter", "checkpoint_gaia"]
EXTRA_DENIED = (
    [(p, c) for p in EXACT_ONLY for c in ("sh -c reboot", "sh /path/script", "sh run", "sho version", "s", "sh")]
    + [(p, c) for p in SHELL for c in (
        "show -c x", "show interfaces -a", "show x $HOME", "show x 'a'", 'show x "a"', "show x *", "show x {a}",
        "show x ~", "show x | match -f /config/config.boot", "show x | match a b", "show x | no-more x",
        "show file /etc/shadow | match -r x", r"show x\y")]
    # パイプの後ろの引数: ちょうど 1 個・「-」で始まらない・「/」「:」を含まない・引数なしの語には付けない・数字の語は数字 1 個
    + [("cisco_ios", c) for c in (
        "show run | include a b", "show run | include", "show run | include -v a", "show run | include /etc/shadow",
        "show run | include http://x", "show run | include bootflash:x", "show run | count 3", "show run | section a b",
        "show run | in", "show run | s ospf", "show run | se ospf", "show run | exc", "show run | x up", "show run | begin")]
    + [("cisco_nxos", c) for c in (
        "show run | grep x /etc/shadow", "show run | grep -r . /", "show run | grep --file=bootflash:a x",
        "show run | grep -f x", "show run | last x", "show run | last 10 20", "show run | head -5", "show run | json x",
        "show run | e down", "show run | grep a*", 'show run | grep "a"', "show run | grep {a}", "show run | last",
        "show run | tail 5 6")]
    + [("arista_eos", c) for c in ("show run | grep a*", 'show run | grep "a"', "show run | grep -i a", "show run | grep /etc/x")]
    + [("netscaler", c) for c in ("show ns x | grep 'a'", "show ns x | grep a b", "show ns x | grep {a}")]
    + [("fortinet", c) for c in ("get system status | grep -f x", "get system status | grep a*", "show | grep a b")]
    + [("juniper_junos", c) for c in (
        "show x | display", "show x | display set xml", "show x | display set x", "show x | last", "show x | match -f x",
        "show x | match a b", "show x | find /var/x", "show x | count 1", "show x | trim x", "show x | no-more 1")]
    + [("paloalto_panos", c) for c in ("show x | match a b", "show x | last x", "show x | match /x")]
    + [("huawei", c) for c in ("display x | include a b", "display x | include -x")]
    # tech-support（とその省略形）は全機種で拒否
    + [(p, c) for p in ("cisco_ios", "cisco_nxos", "juniper_junos", "vyos", "fortinet", "huawei", "arista_eos", "dell_os10")
       for c in ("show tech-support", "show tech", "show tech-s", "show techsupport", "show tech-support | include a",
                 "display tech-support", "SHOW TECH")]
    # diagnostic-information（ファイル名を付けると機器内へ書き出せる）とその省略形（diag 以上）は全機種で拒否
    + [(p, c) for p in ("huawei", "huawei_vrpv8", "hp_comware")
       for c in ("display diagnostic-information", "display diagnostic-information flash:/diag.txt", "dis diag",
                 "dis diagnostic-information x.txt", "display diagnostic", "dis diagn | include a")]
    + [(p, c) for p in ("cisco_ios", "juniper_junos", "vyos", "dell_os10") for c in ("show diag", "show diagnostic-information")]
    # 省略形の機種では tec 以上の前方一致（tech-support の省略形）も拒否
    + [(p, c) for p in ("cisco_ios", "cisco_nxos", "arista_eos", "huawei", "hp_comware")
       for c in ("sh tec", "show tec", "show tech", "sho tech-s")]
    # NX-OS・Arista は絞り込み語の短縮を認めない（完全一致のみ）
    + [(p, c) for p in ("cisco_nxos", "arista_eos")
       for c in ("show run | i vlan", "show run | inc vlan", "show run | e vlan", "show run | b vlan", "show run | sec vlan")]
    # $ と ~ は全機種で拒否
    + [("cisco_ios", c) for c in ("show run | include foo$", "show ~", "show $x")]
    # 対象外の MikroTik
    + [("mikrotik_routeros", c) for c in (
        "/ip address print", "/ping print", "/system backup save print", "/tool e-mail send print", "/export", "show version",
        "print")]
)


@pytest.mark.parametrize("platform,command", EXTRA_DENIED)
def test_more_denied_commands(platform, command):
    with pytest.raises(svc.CommandError) as e:
        svc.check(platform, command)
    assert any(ord(c) > 127 for c in e.value.reason)


def test_mikrotik_is_out_of_scope():
    assert svc.rule_for("mikrotik_routeros") is None
    with pytest.raises(svc.CommandError, match="対象外"):
        svc.check("mikrotik_routeros", "/ip address print")
    assert "mikrotik_routeros" in svc.UNSUPPORTED


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa", "arista_eos", "huawei",
                                      "huawei_vrpv8", "hp_comware"])
def test_abbreviations_only_on_listed_platforms(platform):
    assert platform in svc.ABBREV_PLATFORMS
    word = "dis" if platform.startswith(("huawei", "hp_comware")) else "sh"
    assert svc.check(platform, f"{word} version") == f"{word} version"


def test_abbreviation_platform_list_is_explicit():
    assert set(svc.ABBREV_PLATFORMS) == {"cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa", "arista_eos",
                                         "huawei", "huawei_vrpv8", "hp_comware"}
    assert set(svc.SHELL_PLATFORMS) == {"vyos", "ubiquiti_edgerouter", "checkpoint_gaia"}
    for p, r in svc.RULES.items():
        if p not in svc.ABBREV_PLATFORMS:
            assert r.heads <= {"show", "get"} and not r.abbrev, p
        assert r.shell == (p in svc.SHELL_PLATFORMS)


@pytest.mark.parametrize("platform,command", ALLOWED)
def test_allowed_commands(platform, command):
    assert svc.check(platform, command) == command.strip()


@pytest.mark.parametrize("platform,command", DENIED)
def test_denied_commands(platform, command):
    with pytest.raises(svc.CommandError) as e:
        svc.check(platform, command)
    assert e.value.reason  # 理由は日本語で返す（空にしない）
    assert any(ord(c) > 127 for c in e.value.reason)


def test_every_platform_has_a_rule_and_denies_config_commands():
    """すべての機種に決まりがあり、どの機種でも設定モードに入るコマンドを送れない"""
    for p in PLATFORMS:
        if p in svc.UNSUPPORTED:
            continue
        assert svc.rule_for(p) is not None
        for bad in ("configure terminal", "conf t", "system-view", "reload", "write memory", "enable", "set x y", "delete x"):
            with pytest.raises(svc.CommandError):
                svc.check(p, bad)
    assert svc.rule_for("zzz_unknown") is None


def test_exactly_the_documented_heads():
    """先頭に使える語は表のとおり（変わったらこのテストで気づく）"""
    heads = {p: sorted(svc.rule_for(p).heads) for p in PLATFORMS if p not in svc.UNSUPPORTED}
    assert heads["cisco_ios"] == ["sh", "sho", "show"]
    assert heads["huawei"] == ["dis", "disp", "displ", "displa", "display"]
    assert heads["fortinet"] == ["get", "show"]  # 省略形は許さない
    assert heads["vyos"] == ["show"] and heads["dell_os10"] == ["show"] and heads["cisco_viptela"] == ["show"]
    everything = set().union(*(set(h) for h in heads.values()))
    assert everything <= {"sh", "sho", "show", "dis", "disp", "displ", "displa", "display", "get"}


def test_count_and_length_limits():
    ok = [f"show version {i}" for i in range(svc.MAX_COMMANDS)]
    assert svc.check_universal_all(ok) == ok
    with pytest.raises(svc.CommandError, match="5 個まで"):
        svc.check_universal_all([*ok, "show clock"])
    with pytest.raises(svc.CommandError, match="1 つ以上"):
        svc.check_universal_all([])
    with pytest.raises(svc.CommandError) as e:
        svc.check_universal_all(["show clock", "show\nreload"])
    assert e.value.index == 1 and "2 個目" in str(e.value)
    assert svc.check_universal("show " + "a" * (svc.MAX_COMMAND_LENGTH - 5))
    with pytest.raises(svc.CommandError, match="長すぎ"):
        svc.check_universal("show " + "a" * (svc.MAX_COMMAND_LENGTH - 4))
    with pytest.raises(svc.CommandError):
        svc.check_universal(None)  # type: ignore[arg-type]


def test_validate_for_platform_reports_position():
    with pytest.raises(svc.CommandError) as e:
        svc.validate_for_platform("cisco_ios", ["show clock", "conf t"])
    assert e.value.index == 1 and e.value.command == "conf t"
    assert svc.validate_for_platform("cisco_ios", [" show clock "]) == ["show clock"]


def test_output_clip_and_group():
    items, used = svc.build_outputs(["a", "b"], ["x" * 10, "y" * 10], run_budget=15)
    assert [i["output"] for i in items] == ["x" * 10, "y" * 5] and used == 15
    assert [i["truncated"] for i in items] == [False, True] and items[1]["chars"] == 10
    with mock.patch.object(settings, "COMMAND_RUN_MAX_OUTPUT", 4):
        items, used = svc.build_outputs(["a"], ["abcdefgh"], run_budget=1000)
    assert items[0]["output"] == "abcd" and items[0]["truncated"] and used == 4
    items, used = svc.build_outputs(["a"], ["abc"], run_budget=0)
    assert items[0]["output"] == "" and items[0]["truncated"]
    # 行末の空白・末尾の空行・CRLF の違いは同じ出力として扱う。中身が違えば別
    res = [
        {"result_id": "r1", "device_id": "1", "device_name": "Core-SW01", "outputs": [{"output": "a  \r\nb\n\n", "truncated": False}]},
        {"result_id": "r2", "device_id": "2", "device_name": "Core-SW02", "outputs": [{"output": "a\nb", "truncated": False}]},
        {"result_id": "r3", "device_id": "3", "device_name": "Core-SW03", "outputs": [{"output": "a\nc", "truncated": False}]},
        {"result_id": "r4", "device_id": "4", "device_name": "Core-SW04", "outputs": [{"output": "a\nb", "truncated": True}]},
    ]
    groups = svc.group_outputs(["show clock"], res)[0]["groups"]
    assert [g["count"] for g in groups] == [2, 1, 1]
    assert [d["name"] for d in groups[0]["devices"]] == ["Core-SW01", "Core-SW02"]
    assert groups[0]["result_id"] == "r1" and "output" not in groups[0]  # 本文は重ねて持たず、結果を参照する
    assert svc.loads_outputs(None) == [] and svc.loads_outputs("壊れた{") == []


def test_command_run_permission_is_only_for_roles_that_read_configs():
    """出力に設定の中身が含まれるため、コンフィグの閲覧権限を持たないロールには付けない"""
    assert Perm.COMMAND_RUN.value == "command:run"
    assert Perm.COMMAND_RUN not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Perm.COMMAND_RUN in ROLE_PERMISSIONS[Role.OPERATOR] and Perm.COMMAND_RUN in ROLE_PERMISSIONS[Role.ADMIN]
    for role, perms in ROLE_PERMISSIONS.items():
        if Perm.COMMAND_RUN in perms:
            assert Perm.CONFIG_READ in perms and Perm.DEVICE_READ in perms, role


# ---------------------------------------------------------------- API


@pytest.fixture(scope="module")
def env():
    with mock.patch("app.api.commands.enqueue_command_run") as enq, \
            mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE_PER_USER", 10_000), \
            mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE", 10_000), TestClient(app) as c:
        admin = _login(c, "admin", "initial-pass-123")
        for name, role in [("cmd-op", "operator"), ("cmd-view", "viewer")]:
            assert c.post("/api/users/", json={"username": name, "password": "password-1234", "role": role},
                          headers=admin).status_code == 201
        made = {"devices": [], "groups": []}
        yield {"c": c, "admin": admin, "op": _login(c, "cmd-op", "password-1234"),
               "viewer": _login(c, "cmd-view", "password-1234"), "enqueue": enq, "made": made}
        # 同じ DB をほかのテストも使うので、作った機器・グループは消す（ダッシュボードの件数などに影響させない）
        for did in made["devices"]:
            c.delete(f"/api/devices/{did}", headers=admin)
        for gid in made["groups"]:
            c.delete(f"/api/device-groups/{gid}", headers=admin)


def _login(c, username, password):
    r = c.post("/api/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _device(env, platform="cisco_ios", port=22, name=None, **kw):
    r = env["c"].post("/api/devices/", json=dict(
        name=name or f"Core-SW01-{uuid.uuid4().hex[:6]}", hostname="127.0.0.1", port=port, platform=platform,
        username="admin", password="pw", **kw), headers=env["admin"])
    assert r.status_code == 201, r.text
    env["made"]["devices"].append(r.json()["id"])
    return r.json()


def _group(env, name):
    g = env["c"].post("/api/device-groups/", json={"name": f"{name}-{uuid.uuid4().hex[:4]}"}, headers=env["admin"]).json()
    env["made"]["groups"].append(g["id"])
    return g


def _run(env, ids, commands, who="op", **kw):
    return env["c"].post("/api/commands/runs", json={"device_ids": ids, "commands": commands, **kw}, headers=env[who])


def _db():
    return sqlite3.connect(f"{TMP}/t.db")


def test_permissions(env):
    c = env["c"]
    d = _device(env)
    rid = _run(env, [d["id"]], ["show clock"]).json()["id"]
    calls = [
        ("get", "/api/commands/limits", None),
        ("get", "/api/commands/check?command=show%20clock", None),
        ("post", "/api/commands/runs", {"device_ids": [d["id"]], "commands": ["show clock"]}),
        ("get", "/api/commands/runs", None),
        ("get", f"/api/commands/runs/{rid}", None),
        ("get", f"/api/commands/runs/{rid}/export?format=txt", None),
        ("get", f"/api/commands/runs/{rid}/export?format=csv", None),
    ]
    for method, path, body in calls:
        kw = {"json": body} if body is not None else {}
        assert getattr(c, method)(path, headers=env["viewer"], **kw).status_code == 403, path  # 閲覧者には見せない
        assert getattr(c, method)(path, **kw).status_code == 401, path
        assert getattr(c, method)(path, headers=env["op"], **kw).status_code in (200, 201), path
        assert getattr(c, method)(path, headers=env["admin"], **kw).status_code in (200, 201), path
    me = c.get("/api/auth/me", headers=env["op"]).json()["permissions"]
    assert "command:run" in me
    assert "command:run" not in c.get("/api/auth/me", headers=env["viewer"]).json()["permissions"]


def test_check_endpoint(env):
    c = env["c"]
    g = lambda **p: c.get("/api/commands/check", params=p, headers=env["op"]).json()  # noqa: E731
    assert g(command="show clock") == {"ok": True, "reason": None}
    assert g(command="show clock", platform="cisco_ios")["ok"]
    r = g(command="conf t", platform="cisco_ios")
    assert not r["ok"] and "conf" in r["reason"]
    assert g(command="conf t")["ok"]  # 機種を指定しなければ、機種によらない検査だけ
    assert not g(command="show clock; reload")["ok"]
    assert not g(command="show run", platform="mikrotik_routeros")["ok"]
    limits = c.get("/api/commands/limits", headers=env["op"]).json()
    assert limits["max_commands"] == 5 and limits["max_command_length"] == 200 and limits["heads"]["huawei"] == "display"


def test_create_run_validates_before_saving(env):
    d = _device(env)
    before = _db().execute("select count(*) from command_runs").fetchone()[0]
    env["enqueue"].reset_mock()
    for cmds in (["conf t"], ["show clock", "reload"], ["show run; reload"], ["show run | redirect x"], [""], [],
                 ["show clock"] * 6, ["show\nreload"], ["show " + "a" * 200]):
        r = _run(env, [d["id"]], cmds)
        assert r.status_code == 422, (cmds, r.text)
        assert isinstance(r.json()["detail"], str) and any(ord(ch) > 127 for ch in r.json()["detail"])
    assert _db().execute("select count(*) from command_runs").fetchone()[0] == before  # 保存されない
    env["enqueue"].assert_not_called()  # 機器へ投入もされない
    assert "2 個目" in _run(env, [d["id"]], ["show clock", "reload"]).json()["detail"]


def test_create_run_targets(env):
    c = env["c"]
    d1, d2 = _device(env), _device(env)
    # 対象の指定: どちらか一方
    assert _run(env, [], ["show clock"]).status_code == 422
    assert c.post("/api/commands/runs", json={"commands": ["show clock"]}, headers=env["op"]).status_code == 422
    assert c.post("/api/commands/runs", json={"device_ids": [d1["id"]], "group_id": "x", "commands": ["show clock"]},
                  headers=env["op"]).status_code == 422
    assert _run(env, [d1["id"], "00000000-0000-0000-0000-000000000000"], ["show clock"]).status_code == 422
    assert c.post("/api/commands/runs", json={"group_id": "nothing", "commands": ["show clock"]},
                  headers=env["op"]).status_code == 404
    env["enqueue"].reset_mock()
    r = _run(env, [d1["id"], d2["id"], d1["id"]], ["show clock", "sh ver | include Version"])  # 重複は 1 台
    assert r.status_code == 201 and r.json()["total"] == 2 and r.json()["queued"] == 2
    run_id = r.json()["id"]
    # 投入は「実行の ID と、機器ごとの結果の ID」
    (rid, result_ids), _ = env["enqueue"].call_args
    assert rid == run_id and len(result_ids) == 2
    detail = c.get(f"/api/commands/runs/{run_id}", headers=env["op"]).json()
    assert detail["target"] == "devices" and detail["created_by"] == "cmd-op" and not detail["finished"]
    assert detail["commands"] == ["show clock", "sh ver | include Version"]
    assert {x["status"] for x in detail["results"]} == {"queued"} and detail["counts"]["queued"] == 2
    # グループ: 有効な機器だけが対象
    g = _group(env, "検証用グループ")
    gd = _device(env, group_id=g["id"])
    off = _device(env, group_id=g["id"], is_active=False)
    r = c.post("/api/commands/runs", json={"group_id": g["id"], "commands": ["show clock"]}, headers=env["op"])
    assert r.status_code == 201 and r.json()["total"] == 1
    detail = c.get(f"/api/commands/runs/{r.json()['id']}", headers=env["op"]).json()
    assert detail["target"] == "group" and "グループ" in detail["target_name"]
    assert [x["device_id"] for x in detail["results"]] == [gd["id"]]
    # 機器を直接選んだ無効な機器は「対象外」として結果に残る
    r = _run(env, [gd["id"], off["id"]], ["show clock"])
    detail = c.get(f"/api/commands/runs/{r.json()['id']}", headers=env["op"]).json()
    by = {x["device_id"]: x for x in detail["results"]}
    assert by[off["id"]]["status"] == "skipped" and "無効" in by[off["id"]]["error"]
    assert by[gd["id"]]["status"] == "queued" and r.json()["skipped"] == 1
    # 全部が対象外なら実行を作らない
    assert _run(env, [off["id"]], ["show clock"]).status_code == 422


def test_mixed_platforms_skip_only_incompatible_devices(env):
    c = env["c"]
    cisco, huawei, junos = _device(env), _device(env, "huawei"), _device(env, "juniper_junos")
    r = _run(env, [cisco["id"], huawei["id"], junos["id"]], ["display version"])
    assert r.status_code == 201 and r.json()["queued"] == 1 and r.json()["skipped"] == 2
    detail = c.get(f"/api/commands/runs/{r.json()['id']}", headers=env["op"]).json()
    by = {x["device_id"]: x for x in detail["results"]}
    assert by[huawei["id"]]["status"] == "queued"
    for d in (cisco, junos):
        assert by[d["id"]]["status"] == "skipped" and "対象外" in by[d["id"]]["error"] and "display" in by[d["id"]]["error"]
    assert detail["finished"] is False
    # どの機器にも送れないなら 422（理由に機種名を含める）
    r = _run(env, [cisco["id"], junos["id"]], ["display version"])
    assert r.status_code == 422 and "Cisco IOS" in r.json()["detail"] and "Juniper JunOS" in r.json()["detail"]
    # 機種ごとに通る形が違うコマンド（show ... | include / match）
    r = _run(env, [cisco["id"], junos["id"]], ["show interfaces | include up"])
    assert r.json()["queued"] == 1


def test_limits(env):
    c = env["c"]
    ds = [_device(env) for _ in range(3)]
    with mock.patch.object(settings, "COMMAND_RUN_MAX_DEVICES", 2):
        r = _run(env, [d["id"] for d in ds], ["show clock"])
        assert r.status_code == 422 and "2 台まで" in r.json()["detail"] and "3 台" in r.json()["detail"]
        assert _run(env, [d["id"] for d in ds[:2]], ["show clock"]).status_code == 201
        g = _group(env, "上限用")
        for d in ds:
            c.put(f"/api/devices/{d['id']}", json={"group_id": g["id"]}, headers=env["admin"])
        assert c.post("/api/commands/runs", json={"group_id": g["id"], "commands": ["show clock"]},
                      headers=env["op"]).status_code == 422
    with mock.patch.object(settings, "COMMAND_RUN_ENABLED", False):
        r = _run(env, [ds[0]["id"]], ["show clock"])
        assert r.status_code == 403 and "無効" in r.json()["detail"]
        assert c.get("/api/commands/runs", headers=env["op"]).status_code == 200  # 過去の結果は見られる


def test_enqueue_failure_marks_results_failed(env):
    c = env["c"]
    d = _device(env)
    env["enqueue"].side_effect = RuntimeError("redis down")
    try:
        r = _run(env, [d["id"]], ["show clock"])
    finally:
        env["enqueue"].side_effect = None
    assert r.status_code == 503
    runs = c.get("/api/commands/runs", headers=env["op"]).json()
    run = next(x for x in runs if x["counts"]["failed"] == 1 and x["target_name"] == d["name"])
    assert run["finished"] is True
    detail = c.get(f"/api/commands/runs/{run['id']}", headers=env["op"]).json()
    assert detail["results"][0]["status"] == "failed" and "投入" in detail["results"][0]["error"]


def _put_result(run_id, device_id, name, outputs, status="ok", error=None, platform="cisco_ios"):
    """結果を直接保存する（暗号化の型を通すため ORM を使う）"""
    import asyncio

    from app.core.timeutil import utcnow
    from app.models.command_run import CommandResult

    async def go():
        async with worker._sessionmaker()() as db:
            row = await db.get(CommandResult, _result_id(run_id, device_id))
            row.status, row.error, row.finished_at = status, error, utcnow()
            if outputs is not None:
                items, used = svc.build_outputs(["show clock", "show version"][: len(outputs)], outputs, 10**9)
                row.outputs, row.output_chars = svc.dumps_outputs(items), used
            await db.commit()

    asyncio.run(go())


def _result_id(run_id, device_id):
    return _db().execute("select id from command_results where run_id=? and device_id=?", (run_id, device_id)).fetchone()[0]


def test_results_are_encrypted_grouped_and_exported(env):
    c = env["c"]
    secret = "enable secret 9 $9$SECRETVALUE-12345"
    a, b, d = _device(env), _device(env), _device(env)
    r = _run(env, [a["id"], b["id"], d["id"]], ["show clock", "show version"])
    run_id = r.json()["id"]
    _put_result(run_id, a["id"], a["name"], [f"line1\n{secret}  ", "v1"])
    _put_result(run_id, b["id"], b["name"], [f"line1\n{secret}", "v1"])  # a と行末の空白だけが違う
    _put_result(run_id, d["id"], d["name"], None, status="failed", error="認証失敗")
    # DB の生の値に出力の文字列が無い（暗号化されている）
    raw = _db().execute("select outputs from command_results where run_id=? and outputs is not null", (run_id,)).fetchall()
    assert len(raw) == 2 and all(r[0].startswith("enc:") and "SECRETVALUE" not in r[0] for r in raw)
    detail = c.get(f"/api/commands/runs/{run_id}", headers=env["op"]).json()
    assert detail["counts"] == {"queued": 0, "running": 0, "ok": 2, "failed": 1, "skipped": 0}
    g0 = detail["groups"][0]
    assert g0["command"] == "show clock" and len(g0["groups"]) == 1 and g0["groups"][0]["count"] == 2
    assert {x["name"] for x in g0["groups"][0]["devices"]} == {a["name"], b["name"]}
    assert detail["groups"][1]["groups"][0]["count"] == 2
    gr = g0["groups"][0]
    assert "output" not in gr and gr["result_id"] in {x["id"] for x in detail["results"]}  # 本文は results の outputs を参照する
    rep = next(x for x in detail["results"] if x["id"] == gr["result_id"])
    assert rep["outputs"][0]["command"] == "show clock" and "SECRETVALUE" in rep["outputs"][0]["output"]
    assert [x["status"] for x in detail["results"] if x["device_id"] == d["id"]] == ["failed"]
    # 進み具合の確認用（outputs=false）は出力もまとめも返さない
    light = c.get(f"/api/commands/runs/{run_id}?outputs=false", headers=env["op"]).json()
    assert "groups" not in light and all(x["outputs"] is None for x in light["results"]) and "SECRETVALUE" not in json.dumps(light)
    # 書き出し（監査ログに残る。出力そのものは監査ログに入らない）
    txt = c.get(f"/api/commands/runs/{run_id}/export?format=txt", headers=env["op"])
    assert txt.status_code == 200 and secret in txt.text and a["name"] in txt.text and "認証失敗" in txt.text
    assert "attachment" in txt.headers["content-disposition"]
    csv_ = c.get(f"/api/commands/runs/{run_id}/export?format=csv", headers=env["op"])
    assert csv_.status_code == 200 and csv_.text.startswith("﻿機器名") and "SECRETVALUE" in csv_.text
    assert c.get(f"/api/commands/runs/{run_id}/export?format=pdf", headers=env["op"]).status_code == 422
    assert c.get("/api/commands/runs/none/export", headers=env["op"]).status_code == 404
    assert c.get("/api/commands/runs/none", headers=env["op"]).status_code == 404
    # 別のユーザーの実行も一覧・詳細で見える
    ids = [x["id"] for x in c.get("/api/commands/runs", headers=env["admin"]).json()]
    assert run_id in ids
    audit = c.get("/api/audit/logs", params={"action": "command.export"}, headers=env["admin"]).json()["items"]
    assert [x for x in audit if x["target_id"] == run_id] and "SECRETVALUE" not in json.dumps(audit)
    runlog = c.get("/api/audit/logs", params={"action": "command.run"}, headers=env["admin"]).json()["items"]
    mine = next(x for x in runlog if x["target_id"] == run_id)
    detail_json = json.loads(mine["detail"]) if isinstance(mine["detail"], str) else mine["detail"]
    assert detail_json["commands"] == ["show clock", "show version"] and detail_json["devices"] == 3
    assert set(detail_json["device_names"]) == {a["name"], b["name"], d["name"]} and mine["username"] == "cmd-op"
    assert "SECRETVALUE" not in json.dumps(runlog)
    assert "command.run" in c.get("/api/audit/actions", headers=env["admin"]).json()



def test_csv_export_neutralizes_formulas(env):
    c = env["c"]
    d = _device(env)
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    _put_result(run_id, d["id"], d["name"], ["=HYPERLINK(\"http://example.test\")"])
    assert "'=HYPERLINK" in c.get(f"/api/commands/runs/{run_id}/export?format=csv", headers=env["op"]).text


def test_device_delete_keeps_result_name(env):
    c = env["c"]
    d = _device(env)
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    assert c.delete(f"/api/devices/{d['id']}", headers=env["admin"]).status_code == 204
    res = c.get(f"/api/commands/runs/{run_id}", headers=env["op"]).json()["results"][0]
    assert res["device_id"] is None and res["device_name"] == d["name"]


# ---------------------------------------------------------------- worker


@pytest.fixture
def r():
    fr = fakeredis.FakeRedis()
    with mock.patch.object(worker, "_redis", return_value=fr):
        yield fr


def _exec(result_id):
    return worker.run_command_device.apply(args=(result_id,)).get()


def _row(run_id, device_id):
    con = _db()
    con.row_factory = sqlite3.Row
    return con.execute("select * from command_results where run_id=? and device_id=?", (run_id, device_id)).fetchone()


def _error_of(run_id):
    return _db().execute("select error from command_results where run_id=?", (run_id,)).fetchone()[0]


def _stored(run_id, device_id):
    """暗号化された出力を、モデルを通して読む"""
    import asyncio

    from app.models.command_run import CommandResult

    async def go():
        async with worker._sessionmaker()() as db:
            row = await db.get(CommandResult, _result_id(run_id, device_id))
            return svc.loads_outputs(row.outputs)

    return asyncio.run(go())


def test_worker_runs_commands_and_finishes_run(env, r):
    c = env["c"]
    cmds = ["show clock", "sh ip interface brief"]
    p1, s1, _ = fake_sshd.start(outputs={cmds[0]: "12:00:00 JST\r\nSame", cmds[1]: "Gi0/1 up\r\nGi0/2 down"})
    p2, _, _ = fake_sshd.start(outputs={cmds[0]: "12:00:00 JST\r\nSame", cmds[1]: "Gi0/1 up\r\nGi0/2 up"})
    p3, _, _ = fake_sshd.start(password="other")  # 認証に失敗する機器
    a, b = _device(env, port=p1), _device(env, port=p2)
    bad = _device(env, port=p3)
    off = _device(env, port=p1, is_active=False)
    run_id = _run(env, [a["id"], b["id"], bad["id"], off["id"]], cmds).json()["id"]
    ids = {d["id"]: _result_id(run_id, d["id"]) for d in (a, b, bad)}
    assert _exec(ids[a["id"]]) == {"status": "ok"}
    # 全台が終わるまでは、実行は終わらない
    assert c.get(f"/api/commands/runs/{run_id}?outputs=false", headers=env["op"]).json()["finished"] is False
    assert _exec(ids[b["id"]]) == {"status": "ok"}
    assert _exec(ids[bad["id"]]) == {"status": "failed"}
    detail = c.get(f"/api/commands/runs/{run_id}", headers=env["op"]).json()
    assert detail["finished"] is True and detail["counts"] == {"queued": 0, "running": 0, "ok": 2, "failed": 1, "skipped": 1}
    by = {x["device_id"]: x for x in detail["results"]}
    assert by[bad["id"]]["status"] == "failed" and "認証失敗" in by[bad["id"]]["error"] and by[bad["id"]]["outputs"] == []
    assert by[off["id"]]["status"] == "skipped"
    out = by[a["id"]]["outputs"]
    assert [o["command"] for o in out] == cmds and out[0]["output"].strip().endswith("Same") and "Gi0/2 down" in out[1]["output"]
    assert by[a["id"]]["started_at"] and by[a["id"]]["finished_at"]
    # 同じ出力の機器がまとまる（show clock は同じ。インタフェースの一覧は違う）
    g_clock, g_if = detail["groups"]
    assert len(g_clock["groups"]) == 1 and g_clock["groups"][0]["count"] == 2
    assert len(g_if["groups"]) == 2 and [g["count"] for g in g_if["groups"]] == [1, 1]
    # 機器へは、検証を通ったコマンドだけが届いている（enable・設定モードのコマンドは無い）
    assert cmds[0] in s1["commands"] and cmds[1] in s1["commands"]
    assert not any(x.split(" ")[0] in ("configure", "conf", "config", "enable", "reload", "write", "set")
                   for x in s1["commands"]), s1["commands"]
    # DB の生の値は暗号化されている
    assert _row(run_id, a["id"])["outputs"].startswith("enc:") and "Gi0/2" not in _row(run_id, a["id"])["outputs"]
    # もう一度実行しても（着手済み）何もしない
    assert _exec(ids[a["id"]]) == {"skipped": True}
    assert _exec("00000000-0000-0000-0000-000000000000") == {"error": "not found"}


def test_worker_rechecks_before_connecting(env, r):
    """キューに入ってから値が書き換わっても、実行直前の検証で止まる（機器へは何も送らない）"""
    c = env["c"]
    port, state, _ = fake_sshd.start(show_any=True)
    d = _device(env, port=port)
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    rid = _result_id(run_id, d["id"])
    con = _db()
    con.execute("update command_runs set commands=? where id=?", (json.dumps(["show clock", "conf t"]), run_id))
    con.commit()
    assert _exec(rid) == {"status": "skipped"}
    row = _row(run_id, d["id"])
    assert row["status"] == "skipped" and "送れないコマンド" in row["error"] and "2 個目" in row["error"]
    assert "commands" not in state  # 接続すらしていない
    assert c.get(f"/api/commands/runs/{run_id}?outputs=false", headers=env["op"]).json()["finished"] is True
    # 件数・文字・パイプの書き換えも同じ
    for evil in (["show run; reload"], ["show run | redirect x"], ["show x\nreload"], ["show clock"] * 6, ["reload"], [], [1]):
        run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
        con.execute("update command_runs set commands=? where id=?", (json.dumps(evil), run_id))
        con.commit()
        assert _exec(_result_id(run_id, d["id"])) == {"status": "skipped"}
    assert "commands" not in state
    # 機器の機種が変わっていたら、今の機種で検証し直す（Huawei は display だけ）
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    assert c.put(f"/api/devices/{d['id']}", json={"platform": "huawei"}, headers=env["admin"]).status_code == 200
    assert _exec(_result_id(run_id, d["id"])) == {"status": "skipped"} and "commands" not in state
    c.put(f"/api/devices/{d['id']}", json={"platform": "cisco_ios"}, headers=env["admin"])
    # 無効にされた機器・無効化された機能・削除された機器
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    c.put(f"/api/devices/{d['id']}", json={"is_active": False}, headers=env["admin"])
    assert _exec(_result_id(run_id, d["id"])) == {"status": "skipped"} and "無効な機器" in _row(run_id, d["id"])["error"]
    c.put(f"/api/devices/{d['id']}", json={"is_active": True}, headers=env["admin"])
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    with mock.patch.object(settings, "COMMAND_RUN_ENABLED", False):
        assert _exec(_result_id(run_id, d["id"])) == {"status": "skipped"}
    assert "無効" in _row(run_id, d["id"])["error"] and "commands" not in state
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    rid = _result_id(run_id, d["id"])
    c.delete(f"/api/devices/{d['id']}", headers=env["admin"])
    assert _exec(rid) == {"status": "skipped"} and "削除" in _error_of(run_id)


def test_worker_waits_for_ssh_lock(env, r):
    port, state, _ = fake_sshd.start(show_any=True)
    d = _device(env, port=port)
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    rid = _result_id(run_id, d["id"])
    lock = r.lock(f"netconfig:ssh:{d['id']}", timeout=60)
    lock.acquire()
    with mock.patch.object(worker, "SSH_LOCK_WAIT", 0.3):
        assert _exec(rid) == {"status": "failed"}
    assert "別の SSH 処理" in _row(run_id, d["id"])["error"] and "commands" not in state
    # 実行後はロックを解放している（収集など、ほかの SSH 処理を止めない）
    lock.release()
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    assert _exec(_result_id(run_id, d["id"])) == {"status": "ok"}
    got = r.lock(f"netconfig:ssh:{d['id']}", timeout=5)
    assert got.acquire(blocking=False)
    got.release()


def test_worker_failure_reasons_are_japanese_and_not_retried(env, r):
    d = _device(env, port=1)  # 接続できないポート
    run_id = _run(env, [d["id"]], ["show clock"]).json()["id"]
    res = worker.run_command_device.apply(args=(_result_id(run_id, d["id"]),))
    assert res.get() == {"status": "failed"} and res.state == "SUCCESS"  # 再試行（RETRY）にならない
    err = _row(run_id, d["id"])["error"]
    assert err and any(ord(ch) > 127 for ch in err)


def test_worker_output_limits(env, r):
    big = "\r\n".join(f"line {i} " + "x" * 50 for i in range(200))  # 約 11,000 文字
    port, _, _ = fake_sshd.start(outputs={"show clock": big, "show users": big, "show ntp status": big})
    a, b = _device(env, port=port), _device(env, port=port)
    run_id = _run(env, [a["id"], b["id"]], ["show clock", "show users"]).json()["id"]
    # 1 コマンドの上限で切る（切ったことを記録する）
    with mock.patch.object(settings, "COMMAND_RUN_MAX_OUTPUT", 1000):
        assert _exec(_result_id(run_id, a["id"])) == {"status": "ok"}
    out = _stored(run_id, a["id"])
    assert [len(o["output"]) for o in out] == [1000, 1000] and all(o["truncated"] for o in out)
    assert out[0]["chars"] > 10_000
    assert _row(run_id, a["id"])["output_chars"] == 2000
    # 実行全体の上限: すでに a で 2000 文字使っているので、残りの枠（500 文字）までに切る
    with mock.patch.object(settings, "COMMAND_RUN_MAX_OUTPUT", 1000), \
            mock.patch.object(settings, "COMMAND_RUN_MAX_RUN_OUTPUT", 2500):
        assert _exec(_result_id(run_id, b["id"])) == {"status": "ok"}
    out = _stored(run_id, b["id"])
    assert [len(o["output"]) for o in out] == [500, 0] and all(o["truncated"] for o in out)
    # 上限より小さい出力は切らない
    run_id = _run(env, [a["id"]], ["show ntp status"]).json()["id"]
    with mock.patch.object(settings, "COMMAND_RUN_MAX_OUTPUT", 50_000):
        _exec(_result_id(run_id, a["id"]))
    out = _stored(run_id, a["id"])
    assert not out[0]["truncated"] and out[0]["chars"] == len(out[0]["output"])


def test_worker_concurrency_dispatches_next_when_one_finishes(env, r):
    port, _, _ = fake_sshd.start(show_any=True)
    devs = [_device(env, port=port) for _ in range(4)]
    run_id = _run(env, [d["id"] for d in devs], ["show clock"]).json()["id"]
    ids = [_result_id(run_id, d["id"]) for d in devs]
    with mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 2), \
            mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run_id, ids)
        assert [c.args[0] for c in delay.call_args_list] == ids[:2]  # 同時に投入するのは 2 台まで
        assert r.llen(worker._pending_key(run_id)) == 2
        delay.reset_mock()
        assert _exec(ids[0]) == {"status": "ok"}  # 1 台終わると、待っていた次の 1 台が投入される
        assert [c.args[0] for c in delay.call_args_list] == [ids[2]]
        assert _exec(ids[1]) == {"status": "ok"}
        assert [c.args[0] for c in delay.call_args_list] == [ids[2], ids[3]]
        assert r.llen(worker._pending_key(run_id)) == 0


# ---------------------------------------------------------------- 保持期間の掃除


def test_purge_removes_expired_runs(env, r):
    c = env["c"]
    d = _device(env)
    old = _run(env, [d["id"]], ["show clock"]).json()["id"]
    fresh = _run(env, [d["id"]], ["show clock"]).json()["id"]
    _put_result(old, d["id"], d["name"], ["OLD-OUTPUT"])
    _put_result(fresh, d["id"], d["name"], ["FRESH-OUTPUT"])
    con = _db()
    keep = settings.COMMAND_RUN_RETENTION_DAYS
    con.execute("update command_runs set created_at=datetime('now', ?) where id=?", (f"-{keep + 1} days", old))
    con.execute("update command_runs set created_at=datetime('now', ?) where id=?", (f"-{keep - 1} days", fresh))
    con.commit()
    assert _row(old, d["id"]) is not None
    result = worker.purge_audit_logs.apply().get()
    assert result["command_runs"] >= 1
    assert c.get(f"/api/commands/runs/{old}", headers=env["op"]).status_code == 404
    assert _row(old, d["id"]) is None  # 出力ごと消えている
    assert c.get(f"/api/commands/runs/{fresh}", headers=env["op"]).status_code == 200
    # 保持日数を変えると、その日数で消える
    with mock.patch.object(settings, "COMMAND_RUN_RETENTION_DAYS", 1):
        con.execute("update command_runs set created_at=datetime('now', '-2 days') where id=?", (fresh,))
        con.commit()
        assert worker.purge_audit_logs.apply().get()["command_runs"] >= 1
    assert c.get(f"/api/commands/runs/{fresh}", headers=env["op"]).status_code == 404


def test_mikrotik_is_rejected_by_api(env):
    d = _device(env, "mikrotik_routeros")
    r = _run(env, [d["id"]], ["/ip address print"])
    assert r.status_code == 422 and "対象外" in r.json()["detail"]
    chk = env["c"].get("/api/commands/check", params={"command": "/ping print", "platform": "mikrotik_routeros"},
                       headers=env["op"]).json()
    assert not chk["ok"] and "対象外" in chk["reason"]
    assert "mikrotik_routeros" not in env["c"].get("/api/commands/limits", headers=env["op"]).json()["heads"]


# ---------------------------------------------------------------- 終わっていない実行の数の上限


def test_active_run_limits(env):
    c = env["c"]
    d = _device(env)
    con = _db()
    con.execute("update command_runs set finished_at=datetime('now') where finished_at is null")  # 前のテストの残りを終わらせる
    con.commit()
    with mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE_PER_USER", 2), mock.patch.object(settings, "COMMAND_RUN_MAX_ACTIVE", 3):
        assert _run(env, [d["id"]], ["show clock"]).status_code == 201
        assert _run(env, [d["id"]], ["show clock"]).status_code == 201
        r = _run(env, [d["id"]], ["show clock"])  # 1 人 2 件まで
        assert r.status_code == 429 and "2 件動いています" in r.json()["detail"] and "あなた" in r.json()["detail"]
        # 入力が不正なら 429 より 422 を先に返す
        assert _run(env, [d["id"]], ["show x; reload"]).status_code == 422
        # 別の人は動かせるが、全体の上限（3 件）に達したら断る
        assert _run(env, [d["id"]], ["show clock"], who="admin").status_code == 201
        r = _run(env, [d["id"]], ["show clock"], who="admin")
        assert r.status_code == 429 and "全体で 3 件" in r.json()["detail"]
        # 終わった実行は数えない
        con.execute("update command_runs set finished_at=datetime('now') where created_by='cmd-op'")
        con.commit()
        assert _run(env, [d["id"]], ["show clock"]).status_code == 201
    assert c.get("/api/commands/runs", headers=env["op"]).status_code == 200  # 一覧は上限に関係なく見られる


# ---------------------------------------------------------------- 止まった実行の後片付け（fail_stale）


def test_fail_stale_uses_per_device_times(env, r):
    c = env["c"]
    devs = [_device(env) for _ in range(3)]
    con = _db()

    def make(n):
        rid = _run(env, [d["id"] for d in devs[:n]], ["show clock"]).json()["id"]
        return rid, [_result_id(rid, d["id"]) for d in devs[:n]]

    def sql(q, *a):
        con.execute(q, a)
        con.commit()

    def state(rid):
        return {x["device_id"]: x for x in c.get(f"/api/commands/runs/{rid}?outputs=false", headers=env["op"]).json()["results"]}

    # 実行中のまま 3 時間たった機器は失敗。10 分前に始まった機器は、実行の作成が 3 時間前でも失敗にしない
    run_a, (a1, a2, _a3) = make(3)
    sql("update command_runs set created_at=datetime('now', '-3 hours') where id=?", run_a)
    sql("update command_results set status='running', started_at=datetime('now', '-3 hours') where id=?", a1)
    sql("update command_results set status='running', started_at=datetime('now', '-10 minutes') where id=?", a2)
    # 待機中でも、実行中の機器がいる実行の機器は失敗にしない（a3 は待機中のまま）
    assert worker.fail_stale_command_runs.apply().get() >= 1
    by = state(run_a)
    assert by[devs[0]["id"]]["status"] == "failed" and "途中で止まりました" in by[devs[0]["id"]]["error"]
    assert by[devs[1]["id"]]["status"] == "running" and by[devs[2]["id"]]["status"] == "queued"
    assert c.get(f"/api/commands/runs/{run_a}?outputs=false", headers=env["op"]).json()["finished"] is False

    # 台数が多く、実行は 3 時間前に作ったが、さっき 1 台が終わっている（動いている）実行は、待機中の機器を失敗にしない
    run_b, (b1, _b2) = make(2)
    sql("update command_runs set created_at=datetime('now', '-3 hours') where id=?", run_b)
    sql("update command_results set status='ok', started_at=datetime('now', '-2 minutes'), finished_at=datetime('now', '-1 minutes') "
        "where id=?", b1)
    worker.fail_stale_command_runs.apply().get()
    assert state(run_b)[devs[1]["id"]]["status"] == "queued"

    # 動きが 30 分以上なく、実行中の機器もいない実行の待機中の機器は失敗にして、実行を終わらせる
    run_c, (c1, _c2) = make(2)
    sql("update command_runs set created_at=datetime('now', '-3 hours') where id=?", run_c)
    sql("update command_results set status='ok', started_at=datetime('now', '-179 minutes'), finished_at=datetime('now', '-178 minutes') "
        "where id=?", c1)
    assert worker.fail_stale_command_runs.apply().get() >= 1
    by = state(run_c)
    assert by[devs[0]["id"]]["status"] == "ok" and by[devs[1]["id"]]["status"] == "failed"
    assert c.get(f"/api/commands/runs/{run_c}?outputs=false", headers=env["op"]).json()["finished"] is True
    # 作成直後の待機中は何もしない
    run_d, _ = make(1)
    assert worker.fail_stale_command_runs.apply().get() == 0 or state(run_d)[devs[0]["id"]]["status"] == "queued"
    assert state(run_d)[devs[0]["id"]]["status"] == "queued"
    assert "fail_stale_command_runs" in str(worker.celery_app.conf.beat_schedule["fail-stale-command-runs"])
    assert worker.celery_app.conf.beat_schedule["fail-stale-command-runs"]["schedule"] == 300.0


# ---------------------------------------------------------------- worker の例外でも次の機器が流れる


def _two_results(env, port, n=2):
    devs = [_device(env, port=port) for _ in range(n)]
    run_id = _run(env, [d["id"] for d in devs], ["show clock"]).json()["id"]
    return run_id, [_result_id(run_id, d["id"]) for d in devs], devs


def test_worker_failure_in_load_connection_info_still_dispatches_next(env, r):
    port, state, _ = fake_sshd.start(show_any=True)
    run_id, ids, devs = _two_results(env, port)
    with mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 1), mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run_id, ids)
        assert [c.args[0] for c in delay.call_args_list] == [ids[0]]
        delay.reset_mock()
        with mock.patch.object(worker, "load_connection_info", side_effect=RuntimeError("db down")):
            assert _exec(ids[0]) == {"status": "failed"}
        assert [c.args[0] for c in delay.call_args_list] == [ids[1]]  # 次の機器が流れる
    row = _row(run_id, devs[0]["id"])
    assert row["status"] == "failed" and "内部エラー" in row["error"] and "RuntimeError" in row["error"] and row["outputs"] is None
    assert "db down" not in row["error"]
    assert "commands" not in state  # 機器へは接続していない
    assert _exec(ids[1]) == {"status": "ok"}


def test_worker_failure_when_saving_still_fails_the_device_and_dispatches_next(env, r):
    port, _, _ = fake_sshd.start(show_any=True)
    run_id, ids, devs = _two_results(env, port)
    orig = worker._save_command_result
    calls = []

    async def flaky(*a, **k):  # 1 回目（成功の保存）だけ失敗する
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("write failed")
        return await orig(*a, **k)

    with mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 1), mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run_id, ids)
        delay.reset_mock()
        with mock.patch.object(worker, "_save_command_result", flaky):
            assert _exec(ids[0]) == {"status": "failed"}
        assert [c.args[0] for c in delay.call_args_list] == [ids[1]]
    row = _row(run_id, devs[0]["id"])
    assert row["status"] == "failed" and "内部エラー" in row["error"] and row["outputs"] is None
    # 保存がずっと失敗しても、次の機器は流れる（その機器は running のまま残り、fail_stale が後で失敗にする）
    run2, ids2, devs2 = _two_results(env, port)
    with mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 1), mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run2, ids2)
        delay.reset_mock()
        with mock.patch.object(worker, "_save_command_result", side_effect=RuntimeError("db down")):
            assert _exec(ids2[0]) == {"status": "failed"}
        assert [c.args[0] for c in delay.call_args_list] == [ids2[1]]
    assert _row(run2, devs2[0]["id"])["status"] == "running"


def test_filter_abbreviation_only_on_listed_platforms():
    for p in ("cisco_ios", "cisco_xe", "cisco_xr", "cisco_asa", "huawei", "huawei_vrpv8", "hp_comware"):
        assert svc.check(p, "show x | i y" if "huawei" not in p and p != "hp_comware" else "display x | i y")
    for p in ("cisco_nxos", "arista_eos"):
        assert svc.check(p, "show x | include y") == "show x | include y"
        with pytest.raises(svc.CommandError):
            svc.check(p, "show x | i y")


def test_fail_stale_finishes_runs_without_active_results(env, r):
    c = env["c"]
    d = _device(env)
    con = _db()
    rid = _run(env, [d["id"]], ["show clock"]).json()["id"]
    res_id = _result_id(rid, d["id"])
    # 機器の結果は終わっているのに、実行の終了時刻が空のまま残った状態
    con.execute("update command_results set status='failed', finished_at=datetime('now') where id=?", (res_id,))
    con.execute("update command_runs set created_at=datetime('now', '-10 minutes'), finished_at=NULL where id=?", (rid,))
    con.commit()
    assert worker.fail_stale_command_runs.apply().get() >= 1
    assert c.get(f"/api/commands/runs/{rid}?outputs=false", headers=env["op"]).json()["finished"] is True
    # 作成直後（1 分以内）は触らない
    rid2 = _run(env, [d["id"]], ["show clock"]).json()["id"]
    con.execute("update command_results set status='failed', finished_at=datetime('now') where run_id=?", (rid2,))
    con.commit()
    worker.fail_stale_command_runs.apply().get()
    assert c.get(f"/api/commands/runs/{rid2}?outputs=false", headers=env["op"]).json()["finished"] is False


def test_post_save_failure_does_not_overwrite_success(env, r):
    port, _, _ = fake_sshd.start(show_any=True)
    run_id, ids, devs = _two_results(env, port)
    with mock.patch.object(settings, "COMMAND_RUN_CONCURRENCY", 1), mock.patch.object(worker.run_command_device, "delay") as delay:
        worker.enqueue_command_run(run_id, ids)
        delay.reset_mock()
        with mock.patch.object(worker, "_finish_command_run", side_effect=RuntimeError("db down")):
            assert _exec(ids[0]) == {"status": "ok"}
        assert [c.args[0] for c in delay.call_args_list] == [ids[1]]  # 次の機器も流れる
    row = _row(run_id, devs[0]["id"])
    assert row["status"] == "ok" and row["outputs"] is not None
