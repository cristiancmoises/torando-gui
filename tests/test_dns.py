# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Per-platform DNS pinning: output parsers and the pinner orchestration."""

from __future__ import annotations

import subprocess

from torando_gui import dns
from torando_gui import platform as plat
from torando_gui.config import Config


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


# --- parsers ----------------------------------------------------------------
def test_parse_network_services_skips_header_and_disabled():
    out = (
        "An asterisk (*) denotes that a network service is disabled.\n"
        "Wi-Fi\n"
        "Thunderbolt Ethernet\n"
        "*Bluetooth PAN\n"
    )
    assert dns.parse_network_services(out) == ["Wi-Fi", "Thunderbolt Ethernet"]


def test_parse_dns_servers_dhcp_returns_empty():
    assert dns.parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.") == []


def test_parse_dns_servers_static():
    assert dns.parse_dns_servers("127.0.0.1\n9.9.9.9\n") == ["127.0.0.1", "9.9.9.9"]


def test_parse_interface_names_locale_independent():
    out = (
        "Idx     Met         MTU          State                Name\n"
        "---  ----------  ----------  ------------  ---------------------------\n"
        "  1          75  4294967295  connected     Loopback Pseudo-Interface 1\n"
        "  5          25        1500  connected     Wi-Fi\n"
        " 12          25        1500  disconnected  Ethernet 2\n"
    )
    names = dns.parse_interface_names(out)
    assert "Wi-Fi" in names
    assert "Ethernet 2" in names  # not filtered on State (setting DNS on it is harmless)
    assert "Loopback Pseudo-Interface 1" not in names  # loopback excluded
    # A localized State column must not drop every interface (the DNS-outage bug):
    localized = "  5          25        1500  Verbunden     Wi-Fi\n"
    assert dns.parse_interface_names(localized) == ["Wi-Fi"]


def test_parse_dns_config_dhcp_with_ip_is_not_captured_as_static():
    # netsh prints the DHCP-assigned server ON the DHCP line; capturing it as
    # static would freeze the adapter onto that resolver on restore.
    txt = "DNS servers configured through DHCP:  192.168.1.1\n"
    assert dns.parse_dns_config(txt) == {"dhcp": True, "servers": []}


# --- FileDns (Linux vs BSD immutability command) ----------------------------
def test_filedns_linux_uses_chattr(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
    calls: list[list[str]] = []
    pinner = dns.FileDns(platform_id=plat.LINUX, runner=lambda a: (calls.append(a), _cp(a))[1])
    pinner.lock(Config(resolv_path=str(resolv)))
    assert any(c[0] == "chattr" for c in calls)
    assert resolv.read_text() == "nameserver 127.0.0.1\n"


def test_filedns_bsd_uses_chflags(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 9.9.9.9\n", encoding="utf-8")
    calls: list[list[str]] = []
    pinner = dns.FileDns(platform_id=plat.FREEBSD, runner=lambda a: (calls.append(a), _cp(a))[1])
    pinner.lock(Config(resolv_path=str(resolv)))
    assert any(c[0] == "chflags" and c[1] == "schg" for c in calls)


# --- MacDns -----------------------------------------------------------------
class FakeNetworksetup:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["networksetup", "-listallnetworkservices"]:
            return _cp(argv, 0, out="header\nWi-Fi\n")
        if argv[:2] == ["networksetup", "-getdnsservers"]:
            return _cp(argv, 0, out="9.9.9.9\n")
        return _cp(argv, 0)


def test_macdns_lock_captures_and_pins(tmp_path):
    fake = FakeNetworksetup()
    pinner = dns.MacDns(runner=fake, state_dir=tmp_path)
    pinner.lock(Config())
    assert ["networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"] in fake.calls
    assert (tmp_path / "macos_dns_state.json").exists()


def test_macdns_restore_puts_back_captured(tmp_path):
    fake = FakeNetworksetup()
    pinner = dns.MacDns(runner=fake, state_dir=tmp_path)
    pinner.lock(Config())
    fake.calls.clear()
    pinner.restore(Config())
    assert ["networksetup", "-setdnsservers", "Wi-Fi", "9.9.9.9"] in fake.calls


def test_macdns_restore_empty_when_was_dhcp(tmp_path):
    class DhcpNetworksetup(FakeNetworksetup):
        def __call__(self, argv):
            self.calls.append(argv)
            if argv[:2] == ["networksetup", "-listallnetworkservices"]:
                return _cp(argv, 0, out="header\nWi-Fi\n")
            if argv[:2] == ["networksetup", "-getdnsservers"]:
                return _cp(argv, 0, out="There aren't any DNS Servers set on Wi-Fi.")
            return _cp(argv, 0)

    fake = DhcpNetworksetup()
    pinner = dns.MacDns(runner=fake, state_dir=tmp_path)
    pinner.lock(Config())
    pinner.restore(Config())
    assert ["networksetup", "-setdnsservers", "Wi-Fi", "Empty"] in fake.calls


# --- WindowsDns -------------------------------------------------------------
def test_windowsdns_lock_and_restore(tmp_path):
    show = (
        "Idx     Met         MTU          State                Name\n"
        "  5          25        1500  connected     Wi-Fi\n"
    )
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(argv)
        if argv[:5] == ["netsh", "interface", "ipv4", "show", "interfaces"]:
            return _cp(argv, 0, out=show)
        return _cp(argv, 0)

    pinner = dns.WindowsDns(runner=runner, state_dir=tmp_path)
    pinner.lock(Config())
    assert pinner.is_pinned(Config()) is True
    assert any("static" in c and "127.0.0.1" in c for c in calls)
    pinner.restore(Config())
    assert any("source=dhcp" in c for c in calls)
    assert pinner.is_pinned(Config()) is False


def test_macdns_restore_noop_without_state(tmp_path):
    # A never-connected Mac (no state file) must NOT reset services to DHCP.
    fake = FakeNetworksetup()
    pinner = dns.MacDns(runner=fake, state_dir=tmp_path)
    res = pinner.restore(Config())
    assert res["restored"] is False
    assert not any("-setdnsservers" in c for c in fake.calls)


def test_macdns_lock_capture_once(tmp_path):
    # A second lock (reconnect) must not overwrite the captured real resolver.
    fake = FakeNetworksetup()
    pinner = dns.MacDns(runner=fake, state_dir=tmp_path)
    pinner.lock(Config())
    import json as _json

    first = _json.loads((tmp_path / "macos_dns_state.json").read_text())
    pinner.lock(Config())  # reconnect
    second = _json.loads((tmp_path / "macos_dns_state.json").read_text())
    assert first == second == {"Wi-Fi": ["9.9.9.9"]}


def test_windowsdns_restore_noop_without_state(tmp_path):
    calls = []
    pinner = dns.WindowsDns(runner=lambda a: (calls.append(a), _cp(a))[1], state_dir=tmp_path)
    res = pinner.restore(Config())
    assert res["restored"] is False
    assert calls == []  # touched nothing


def test_parse_dns_config_static_and_dhcp():
    static = (
        "Statically Configured DNS Servers:  1.1.1.1\n                                    8.8.8.8\n"
    )
    assert dns.parse_dns_config(static) == {"dhcp": False, "servers": ["1.1.1.1", "8.8.8.8"]}
    dhcp = "DNS servers configured through DHCP:  None\n"
    assert dns.parse_dns_config(dhcp)["dhcp"] is True


# --- factory ----------------------------------------------------------------
def test_make_dns_dispatch():
    assert type(dns.make_dns(plat.LINUX)).__name__ == "FileDns"
    assert type(dns.make_dns(plat.FREEBSD)).__name__ == "FileDns"
    assert type(dns.make_dns(plat.MACOS)).__name__ == "MacDns"
    assert type(dns.make_dns(plat.WINDOWS)).__name__ == "WindowsDns"
