# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Windows firewall backend: pure netsh command generation, policy parsing, and
apply/remove orchestration via a fake runner (winreg/ctypes are no-ops off
Windows, so this all runs on Linux)."""

from __future__ import annotations

import subprocess

import pytest
from torando_gui import winfw
from torando_gui.config import Config


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


def _cfg(**kw):
    return Config(target_uid=None, tor_path=r"C:\tor\tor.exe", **kw)


# --- pure command generation ------------------------------------------------
def test_set_policy_cmd():
    assert winfw.set_policy_cmd("publicprofile", "blockinbound", "blockoutbound") == [
        "netsh",
        "advfirewall",
        "set",
        "publicprofile",
        "firewallpolicy",
        "blockinbound,blockoutbound",
    ]


def test_allow_program_cmd_quotes_nothing_but_passes_path():
    cmd = winfw.allow_program_cmd(winfw.RULE_TOR, r"C:\tor\tor.exe")
    assert "action=allow" in cmd
    assert r"program=C:\tor\tor.exe" in cmd
    assert f"name={winfw.RULE_TOR}" in cmd


def test_allow_remoteip_cmd_with_protocol_ports():
    cmd = winfw.allow_remoteip_cmd(
        winfw.RULE_DHCP, "any", protocol="UDP", localport="68", remoteport="67"
    )
    assert "protocol=UDP" in cmd and "localport=68" in cmd and "remoteport=67" in cmd


def test_delete_rule_cmd():
    assert winfw.delete_rule_cmd(winfw.RULE_TOR) == [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={winfw.RULE_TOR}",
    ]


def test_proxy_server_value():
    assert winfw.proxy_server_value("127.0.0.1", 9050) == "socks=127.0.0.1:9050"


def test_parse_firewall_policy():
    out = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInboundAlways,AllowOutbound
"""
    parsed = winfw.parse_firewall_policy(out)
    assert parsed["domainprofile"] == "BlockInbound,AllowOutbound"
    assert parsed["privateprofile"] == "BlockInbound,AllowOutbound"
    assert parsed["publicprofile"] == "BlockInboundAlways,AllowOutbound"


# --- orchestration ----------------------------------------------------------
_SHOW = """
Domain Profile Settings:
Firewall Policy                       BlockInbound,AllowOutbound
Private Profile Settings:
Firewall Policy                       BlockInbound,AllowOutbound
Public Profile Settings:
Firewall Policy                       BlockInbound,AllowOutbound
"""


class FakeNetsh:
    def __init__(self, show=_SHOW):
        self.calls: list[list[str]] = []
        self._show = show

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:4] == ["netsh", "advfirewall", "show", "allprofiles"]:
            return _cp(argv, 0, out=self._show)
        return _cp(argv, 0)


def test_apply_captures_policy_blocks_outbound_and_whitelists(tmp_path):
    fake = FakeNetsh()
    fw = winfw.WindowsFirewall(runner=fake, state_dir=tmp_path)
    fw.apply(_cfg())
    # captured prior policy persisted for restore
    assert (tmp_path / "windows_fw_state.json").exists()
    # tor.exe whitelisted, loopback whitelisted
    assert any("program=C:\\tor\\tor.exe" in c for c in fake.calls)
    assert any("remoteip=127.0.0.1" in c for c in fake.calls)
    # every profile flipped to block outbound, preserving inbound
    for profile in winfw.PROFILES:
        assert [
            "netsh",
            "advfirewall",
            "set",
            profile,
            "firewallpolicy",
            "BlockInbound,blockoutbound",
        ] in fake.calls


def test_remove_restores_policy_and_deletes_rules(tmp_path):
    fake = FakeNetsh()
    fw = winfw.WindowsFirewall(runner=fake, state_dir=tmp_path)
    fw.apply(_cfg())
    fake.calls.clear()
    fw.remove(_cfg())
    # restored the captured allow-outbound policy
    assert [
        "netsh",
        "advfirewall",
        "set",
        "domainprofile",
        "firewallpolicy",
        "BlockInbound,AllowOutbound",
    ] in fake.calls
    # deleted our named rules only
    assert winfw.delete_rule_cmd(winfw.RULE_TOR) in fake.calls
    # state file removed
    assert not (tmp_path / "windows_fw_state.json").exists()


def test_apply_capture_once_survives_reconnect_without_clobbering_state(tmp_path):
    # First connect captures the real 'AllowOutbound' policy. A second apply
    # (e.g. after a crash where the state file survived) must NOT overwrite the
    # saved state with our own BlockOutbound — that would make restore a lockout.
    blocked = _SHOW.replace("AllowOutbound", "BlockOutbound")
    fake = FakeNetsh(show=blocked)  # netsh now reports the machine already blocked
    fw = winfw.WindowsFirewall(runner=fake, state_dir=tmp_path)
    # seed a state file as if a prior session captured the real policy
    (tmp_path / "windows_fw_state.json").write_text(
        '{"policy": {"domainprofile": "BlockInbound,AllowOutbound", '
        '"privateprofile": "BlockInbound,AllowOutbound", '
        '"publicprofile": "BlockInbound,AllowOutbound"}, "proxy": null}',
        encoding="utf-8",
    )
    fw.apply(_cfg())
    fw.remove(_cfg())
    # remove must have restored AllowOutbound (from the preserved original state)
    assert [
        "netsh",
        "advfirewall",
        "set",
        "domainprofile",
        "firewallpolicy",
        "BlockInbound,AllowOutbound",
    ] in fake.calls


def test_apply_rolls_back_when_a_whitelist_rule_fails(tmp_path):
    from torando_gui.firewall import FirewallError

    calls = []

    def flaky(argv):
        calls.append(argv)
        if argv[:4] == ["netsh", "advfirewall", "show", "allprofiles"]:
            return _cp(argv, 0, out=_SHOW)
        if "add" in argv and "rule" in argv:  # every whitelist add fails
            return _cp(argv, 1, err="denied")
        return _cp(argv, 0)

    fw = winfw.WindowsFirewall(runner=flaky, state_dir=tmp_path)
    with pytest.raises(FirewallError):
        fw.apply(_cfg())
    # must NEVER have flipped outbound to block (that would be a lockout with tor
    # not whitelisted): no set_policy ... blockoutbound call was issued.
    assert not any(
        "firewallpolicy" in " ".join(c) and "blockoutbound" in " ".join(c) for c in calls
    )


def test_remove_keeps_rules_and_raises_when_restore_fails(tmp_path):
    from torando_gui.firewall import FirewallError

    calls = []

    def runner(argv):
        calls.append(argv)
        if argv[:3] == ["netsh", "advfirewall", "set"]:  # policy restore fails
            return _cp(argv, 1, err="MpsSvc unavailable")
        return _cp(argv, 0)

    # Pre-seed state as if we were connected.
    (tmp_path / "windows_fw_state.json").write_text(
        '{"policy": {"domainprofile": "BlockInbound,AllowOutbound"}, "proxy": null}',
        encoding="utf-8",
    )
    fw = winfw.WindowsFirewall(runner=runner, state_dir=tmp_path)
    with pytest.raises(FirewallError):
        fw.remove(_cfg())
    # state file must survive so a retry / --restore-dns can finish the job
    assert (tmp_path / "windows_fw_state.json").exists()
    # the whitelist rules must NOT have been deleted while outbound is still blocked
    assert not any("delete" in c for c in calls)


def test_status_reports_killswitch_when_all_blocked(tmp_path):
    blocked = _SHOW.replace("AllowOutbound", "BlockOutbound")
    fw = winfw.WindowsFirewall(runner=FakeNetsh(show=blocked), state_dir=tmp_path)
    st = fw.status(_cfg())
    assert st["killswitch"] is True


def test_is_admin_false_off_windows():
    # ctypes.windll doesn't exist on Linux -> the helper must swallow it.
    assert winfw.is_admin() is False
