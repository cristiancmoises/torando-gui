# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""pf backend: anchor rule generation, pf.conf hooking, and pfctl orchestration
via a fake runner (so the whole thing is exercised on Linux)."""

from __future__ import annotations

import subprocess

from torando_gui import pf
from torando_gui import platform as plat
from torando_gui.config import Config


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


def _cfg(**kw):
    return Config(target_uid=1000, **kw)


# --- rule generation --------------------------------------------------------
def test_anchor_rules_freebsd_include_killswitch_and_v6():
    text = pf.build_anchor_rules(_cfg(), plat.FREEBSD, tor_user="_tor")
    assert "pass out quick on lo0 proto { tcp udp } user 1000 keep state" in text
    assert "pass out quick proto { tcp udp } user _tor keep state" in text
    assert "block drop out quick inet proto { tcp udp } all user 1000" in text
    assert "block drop out quick inet6 proto { tcp udp } all user 1000" in text
    assert pf.anchor_rule_count(_cfg(), tor_user="_tor") == 4


def test_anchor_rules_without_ipv6_killswitch():
    cfg = _cfg(ipv6_killswitch=False)
    text = pf.build_anchor_rules(cfg, plat.FREEBSD, tor_user="_tor")
    assert "inet6" not in text
    assert pf.anchor_rule_count(cfg, tor_user="_tor") == 3


def test_anchor_rules_omit_tor_exemption_when_no_tor_user():
    # A hard-coded _tor would make pfctl reject the ruleset on hosts without it;
    # the exemption line must simply be absent when no account is given.
    text = pf.build_anchor_rules(_cfg(), plat.MACOS, tor_user=None)
    assert "user _tor" not in text
    assert "pass out quick on lo0 proto { tcp udp } user 1000 keep state" in text
    assert pf.anchor_rule_count(_cfg(), tor_user=None) == 3  # loopback + v4 block + v6 block


def test_anchor_rules_respect_custom_tor_user():
    text = pf.build_anchor_rules(_cfg(), plat.OPENBSD, tor_user="tor")
    assert "user tor keep state" in text


# --- pf.conf wiring ---------------------------------------------------------
def test_wire_pf_conf_appends_and_is_idempotent():
    original = "set skip on lo0\npass\n"
    wired = pf.wire_pf_conf(original, "torando-gui", "/etc/torando-gui/torando-gui.pf")
    assert 'anchor "torando-gui"' in wired
    assert 'load anchor "torando-gui" from "/etc/torando-gui/torando-gui.pf"' in wired
    assert wired.startswith(original)
    # idempotent
    assert pf.wire_pf_conf(wired, "torando-gui", "/etc/torando-gui/torando-gui.pf") == wired


def test_unwire_removes_block():
    original = "set skip on lo0\n"
    wired = pf.wire_pf_conf(original, "torando-gui", "/x.pf")
    assert pf.ANCHOR_BEGIN in wired
    unwired = pf.unwire_pf_conf(wired)
    assert pf.ANCHOR_BEGIN not in unwired
    assert "set skip on lo0" in unwired


# --- orchestration with a fake pfctl ----------------------------------------
class FakePfctl:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["pfctl", "-s"] and "info" in argv:
            return _cp(argv, 0, out="Status: Enabled\n")
        if argv[:2] == ["pfctl", "-s"] and "rules" in argv:
            return _cp(argv, 0, out='anchor "torando-gui" all\n')
        if argv[:2] == ["pfctl", "-a"] and "-sr" in argv:
            out = (
                "pass out quick on lo0 proto { tcp udp } user 1000 keep state\n"
                "pass out quick proto { tcp udp } user _tor keep state\n"
                "block drop out quick inet proto { tcp udp } all user 1000\n"
                "block drop out quick inet6 proto { tcp udp } all user 1000\n"
            )
            return _cp(argv, 0, out=out)
        return _cp(argv, 0)


def test_apply_loads_anchor_and_wires_pf_conf(tmp_path):
    pf_conf = tmp_path / "pf.conf"
    pf_conf.write_text("set skip on lo0\npass\n", encoding="utf-8")
    fake = FakePfctl()
    fw = pf.PfFirewall(platform_id=plat.FREEBSD, runner=fake, pf_conf=pf_conf, anchor_dir=tmp_path)
    fw.apply(_cfg())
    # anchor file written
    assert (tmp_path / "torando-gui.pf").exists()
    # pf.conf now hooks the anchor
    assert 'anchor "torando-gui"' in pf_conf.read_text()
    # pfctl was told to load the anchor and to enable pf
    assert any(c[:3] == ["pfctl", "-a", "torando-gui"] and "-f" in c for c in fake.calls)
    assert any(c == ["pfctl", "-e"] for c in fake.calls)


def test_apply_refuses_when_hook_would_not_parse(tmp_path):
    pf_conf = tmp_path / "pf.conf"
    pf_conf.write_text("pass\n", encoding="utf-8")

    def bad_runner(argv):
        if "-n" in argv and "-f" in argv:  # validation fails
            return _cp(argv, 1, err="syntax error")
        return _cp(argv, 0)

    fw = pf.PfFirewall(
        platform_id=plat.FREEBSD, runner=bad_runner, pf_conf=pf_conf, anchor_dir=tmp_path
    )
    from torando_gui.firewall import FirewallError

    try:
        fw.apply(_cfg())
        raise AssertionError("expected FirewallError")
    except FirewallError as exc:
        assert "would not parse" in str(exc)
    # pf.conf must be left untouched (fail-safe)
    assert pf_conf.read_text() == "pass\n"


def test_status_reports_enabled_and_killswitch(tmp_path):
    fake = FakePfctl()
    fw = pf.PfFirewall(platform_id=plat.FREEBSD, runner=fake, anchor_dir=tmp_path)
    st = fw.status(_cfg())
    assert st["killswitch"] is True
    assert st["active"] is True


def test_macos_apply_sets_socks_proxy(tmp_path):
    pf_conf = tmp_path / "pf.conf"
    pf_conf.write_text('scrub-anchor "com.apple/*"\nanchor "com.apple/*"\n', encoding="utf-8")
    services_out = (
        "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\n"
    )
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(argv)
        if argv[:2] == ["networksetup", "-listallnetworkservices"]:
            return _cp(argv, 0, out=services_out)
        if "info" in argv:
            return _cp(argv, 0, out="Status: Enabled\n")
        return _cp(argv, 0)

    fw = pf.PfFirewall(platform_id=plat.MACOS, runner=runner, pf_conf=pf_conf, anchor_dir=tmp_path)
    fw.apply(_cfg())
    # Wi-Fi is enabled -> proxy set; the disabled Bluetooth PAN service is skipped
    assert ["networksetup", "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "9050"] in calls
    assert not any("Bluetooth PAN" in c for c in calls if len(c) > 2)
