# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Per-platform default install/runtime locations, and the new config fields."""

from __future__ import annotations

from torando_gui import platform as plat
from torando_gui.config import Config, default_paths


def test_linux_paths_unchanged():
    # .as_posix() so the comparison is separator-agnostic when these Linux paths
    # are exercised on a Windows CI host (where str(Path) uses backslashes).
    p = default_paths(plat.LINUX)
    assert p["config_dir"].as_posix() == "/etc/torando-gui"
    assert p["runtime_dir"].as_posix() == "/run/torando-gui"
    assert p["torrc"].as_posix() == "/etc/tor/torrc"
    assert p["resolv"].as_posix() == "/etc/resolv.conf"


def test_freebsd_paths():
    p = default_paths(plat.FREEBSD)
    assert p["config_dir"].as_posix() == "/usr/local/etc/torando-gui"
    assert p["torrc"].as_posix() == "/usr/local/etc/tor/torrc"


def test_windows_paths(monkeypatch):
    monkeypatch.setenv("PROGRAMDATA", r"C:\ProgramData")
    p = default_paths(plat.WINDOWS)
    assert "torando-gui" in str(p["config_dir"])
    assert str(p["torrc"]).endswith("torrc")


def test_openbsd_paths():
    p = default_paths(plat.OPENBSD)
    assert p["torrc"].as_posix() == "/etc/tor/torrc"


def test_new_config_fields_have_safe_defaults():
    cfg = Config()
    assert cfg.ipv6_killswitch is True
    assert cfg.pf_anchor == "torando-gui"
    assert cfg.allow_dhcp is True
    assert cfg.allow_lan is False
    assert cfg.tor_user is None
    assert cfg.tor_path is None
    # round-trips through JSON serialization used for the API/config file
    assert Config.from_dict(cfg.sanitized()) == cfg


def test_unknown_keys_ignored_on_load():
    cfg = Config.from_dict({"ipv6_killswitch": False, "bogus_key": 123})
    assert cfg.ipv6_killswitch is False
