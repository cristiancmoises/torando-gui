# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""netcfg tests: the managed torrc block is deterministic and confined to its
markers; text outside the markers is preserved; writes are atomic."""

from __future__ import annotations

import os
import stat
import subprocess

from torando_gui.config import TORRC_BEGIN, TORRC_END, Config
from torando_gui.netcfg import (
    apply_torrc,
    lock_resolv,
    merge_torrc,
    render_torrc_block,
    resolv_is_pinned,
    restore_resolv,
    unlock_resolv,
)


def _ok_chattr(argv):
    return subprocess.CompletedProcess(argv, 0, "", "")


def test_resolv_pin_is_world_readable(tmp_path):
    # Regression: mkstemp creates 0600 and os.replace keeps it, which would make
    # resolv.conf root-only -> breaks DNS for non-root users. Must be 0644.
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.168.1.1\n")
    resolv.chmod(0o644)
    lock_resolv(Config(), path=resolv, runner=_ok_chattr, immutable=False)
    mode = stat.S_IMODE(os.stat(resolv).st_mode)
    assert mode == 0o644, oct(mode)
    assert resolv.read_text() == "nameserver 127.0.0.1\n"
    assert resolv_is_pinned(Config(), path=resolv) is True


def test_restore_with_no_backup_is_safe(tmp_path):
    # If the backup is gone but resolv is still pinned, restore must clear the
    # lock (best effort) and report that it could not put a resolver back.
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.1\n")
    out = restore_resolv(Config(), path=resolv, runner=_ok_chattr)
    assert out["restored"] is False
    assert "no backup" in out["note"]


def test_resolv_not_pinned_for_real_resolver(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("# comment\nnameserver 1.1.1.1\n")
    assert resolv_is_pinned(Config(), path=resolv) is False


def test_render_contains_core_directives():
    block = render_torrc_block(Config(trans_port=9040, dns_port=53, socks_port=9050))
    assert block.startswith(TORRC_BEGIN)
    assert block.rstrip().endswith(TORRC_END)
    assert "VirtualAddrNetwork 10.192.0.0/10" in block
    assert "AutomapHostsOnResolve 1" in block
    assert "TransPort 9040" in block
    assert "DNSPort 53" in block
    assert "SocksPort 9050" in block


def test_render_is_deterministic():
    c = Config(exit_country="de", use_bridges=True, bridges=["obfs4 1.2.3.4:1 ABCD"])
    assert render_torrc_block(c) == render_torrc_block(c)


def test_render_control_port_toggle():
    on = render_torrc_block(Config(enable_control_port=True, control_port=9051))
    off = render_torrc_block(Config(enable_control_port=False))
    assert "ControlPort 9051" in on
    assert "CookieAuthentication 1" in on
    assert "ControlPort" not in off


def test_render_exit_country_and_bridges():
    c = Config(exit_country="DE", use_bridges=True, bridges=["obfs4 9.9.9.9:443 KEY", "  "])
    block = render_torrc_block(c)
    assert "ExitNodes {de}" in block  # lower-cased, brace-wrapped
    assert "StrictNodes 1" in block
    assert "UseBridges 1" in block
    assert "Bridge obfs4 9.9.9.9:443 KEY" in block
    assert block.count("Bridge ") == 1  # blank bridge line dropped


def test_merge_inserts_when_absent():
    existing = "Log notice stdout\n"
    out = merge_torrc(existing, render_torrc_block(Config()))
    assert "Log notice stdout" in out
    assert out.count(TORRC_BEGIN) == 1
    assert out.count(TORRC_END) == 1


def test_merge_replaces_and_preserves_surrounding_text():
    head = "# my own settings\nLog notice stdout\n"
    tail = "\n# trailing user config\nSomeOption 1\n"
    old = head + render_torrc_block(Config(trans_port=1111)) + tail
    new = merge_torrc(old, render_torrc_block(Config(trans_port=2222)))
    assert "TransPort 2222" in new
    assert "TransPort 1111" not in new
    assert "# my own settings" in new
    assert "# trailing user config" in new
    assert new.count(TORRC_BEGIN) == 1


def test_merge_is_idempotent():
    block = render_torrc_block(Config())
    once = merge_torrc("Log notice stdout\n", block)
    twice = merge_torrc(once, block)
    assert once == twice
    assert twice.count(TORRC_BEGIN) == 1


def test_merge_collapses_duplicate_managed_blocks():
    # A torrc that somehow carries two managed blocks (stale duplicate) must
    # collapse to exactly one fresh block, with surrounding text preserved.
    b1 = render_torrc_block(Config(trans_port=1111))
    b2 = render_torrc_block(Config(trans_port=2222))
    corrupt = "Log notice stdout\n" + b1 + "\n# middle\n" + b2 + "\n# tail\n"
    new = merge_torrc(corrupt, render_torrc_block(Config(trans_port=3333)))
    assert new.count(TORRC_BEGIN) == 1
    assert new.count(TORRC_END) == 1
    assert "TransPort 3333" in new
    assert "TransPort 1111" not in new
    assert "TransPort 2222" not in new
    assert "# tail" in new


def test_apply_torrc_writes_block_and_backs_up(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text("Log notice stdout\n")
    apply_torrc(Config(trans_port=9040), path=torrc)
    text = torrc.read_text()
    assert "TransPort 9040" in text
    assert "Log notice stdout" in text
    bak = torrc.with_suffix(torrc.suffix + ".torando.bak")
    assert bak.exists()
    assert bak.read_text() == "Log notice stdout\n"
    # second apply keeps a single block and does not overwrite the backup
    apply_torrc(Config(trans_port=9051), path=torrc)
    assert torrc.read_text().count(TORRC_BEGIN) == 1
    assert bak.read_text() == "Log notice stdout\n"
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_lock_unlock_resolv_with_fake_chattr(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.168.1.1\n")
    calls: list[list[str]] = []

    def fake_chattr(argv):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    res = lock_resolv(Config(), path=resolv, runner=fake_chattr, immutable=True)
    assert resolv.read_text() == "nameserver 127.0.0.1\n"
    assert res["immutable"] is True
    assert any(c[:2] == ["chattr", "+i"] for c in calls)
    bak = resolv.with_suffix(resolv.suffix + ".torando.bak")
    assert bak.read_text() == "nameserver 192.168.1.1\n"

    out = unlock_resolv(Config(), path=resolv, runner=fake_chattr)
    assert out["restored"] is True
    assert resolv.read_text() == "nameserver 192.168.1.1\n"
    # backup is removed after a successful restore so the next lock recaptures
    # the resolver that is live then (it may have changed via DHCP meanwhile)
    assert not bak.exists()


def test_relock_after_unlock_recaptures_fresh_resolver(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.0.0.1\n")

    def ok_chattr(argv):
        return subprocess.CompletedProcess(argv, 0, "", "")

    bak = resolv.with_suffix(resolv.suffix + ".torando.bak")
    lock_resolv(Config(), path=resolv, runner=ok_chattr, immutable=True)
    unlock_resolv(Config(), path=resolv, runner=ok_chattr)
    assert resolv.read_text() == "nameserver 10.0.0.1\n"
    # resolver legitimately changes (e.g. new DHCP lease) while unlocked
    resolv.write_text("nameserver 10.9.9.9\n")
    lock_resolv(Config(), path=resolv, runner=ok_chattr, immutable=True)
    assert bak.read_text() == "nameserver 10.9.9.9\n"  # fresh, not the stale 10.0.0.1
    unlock_resolv(Config(), path=resolv, runner=ok_chattr)
    assert resolv.read_text() == "nameserver 10.9.9.9\n"


def test_lock_resolv_reports_failed_immutable(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.168.1.1\n")

    def failing_chattr(argv):
        rc = 1 if "+i" in argv else 0
        return subprocess.CompletedProcess(argv, rc, "", "operation not supported")

    res = lock_resolv(Config(), path=resolv, runner=failing_chattr, immutable=True)
    assert res["immutable"] is False
    assert "not supported" in res["note"]
    assert resolv.read_text() == "nameserver 127.0.0.1\n"  # write still happened
