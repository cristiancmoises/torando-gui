# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Platform detection maps every sys.platform string to the right family."""

from __future__ import annotations

from torando_gui import platform as plat


def test_detect_maps_known_platforms():
    assert plat.detect("linux") == plat.LINUX
    assert plat.detect("linux2") == plat.LINUX
    assert plat.detect("darwin") == plat.MACOS
    assert plat.detect("freebsd13") == plat.FREEBSD
    assert plat.detect("openbsd7") == plat.OPENBSD
    assert plat.detect("netbsd") == plat.NETBSD
    assert plat.detect("win32") == plat.WINDOWS
    assert plat.detect("cygwin") == plat.WINDOWS
    assert plat.detect("aix") == plat.UNKNOWN


def test_family_predicates():
    assert plat.is_pf(plat.MACOS)
    assert plat.is_pf(plat.FREEBSD)
    assert plat.is_pf(plat.OPENBSD)
    assert not plat.is_pf(plat.LINUX)
    assert not plat.is_pf(plat.WINDOWS)
    assert plat.is_windows(plat.WINDOWS)
    assert plat.is_linux(plat.LINUX)
    assert plat.is_bsd(plat.FREEBSD)
    assert not plat.is_bsd(plat.MACOS)  # macOS is pf but not "bsd" for our purposes


def test_loopback_interface():
    assert plat.loopback_interface(plat.LINUX) == "lo"
    assert plat.loopback_interface(plat.MACOS) == "lo0"
    assert plat.loopback_interface(plat.FREEBSD) == "lo0"


def test_tor_user_defaults():
    assert plat.TOR_USER[plat.FREEBSD] == "_tor"
    assert plat.TOR_USER[plat.OPENBSD] == "_tor"


def test_kernel_has_ipv6_nonlinux_assumes_true(monkeypatch):
    monkeypatch.setattr(plat, "CURRENT", plat.WINDOWS)
    assert plat.kernel_has_ipv6() is True


def test_run_argv_suppresses_console_window_on_windows(monkeypatch):
    # On Windows every child (netsh/schtasks) would flash its own console when
    # the daemon runs under pythonw; CREATE_NO_WINDOW (0x08000000) suppresses it.
    import subprocess

    captured = {}

    def fake_run(argv, **kw):
        captured.update(kw)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    monkeypatch.setattr(plat, "CURRENT", plat.WINDOWS)
    plat.run_argv(["netsh", "x"])
    assert captured.get("creationflags") == 0x08000000

    captured.clear()
    monkeypatch.setattr(plat, "CURRENT", plat.LINUX)
    plat.run_argv(["iptables", "-L"])
    assert "creationflags" not in captured  # never set off Windows
