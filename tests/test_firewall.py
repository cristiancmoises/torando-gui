# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""LinuxFirewall composes the v4 ruleset with the v6 killswitch, fail-closed:
if the kernel can do IPv6 but ip6tables can't, connect must refuse and leave
nothing armed."""

from __future__ import annotations

import pytest
from torando_gui import platform as plat
from torando_gui.config import Config
from torando_gui.firewall import FirewallError, LinuxFirewall, make_firewall


class FakeV4:
    def __init__(self, available=True):
        self._available = available
        self.applied = False
        self.removed = False

    def available(self):
        return self._available

    def apply_list(self, rules):
        self.applied = True
        return list(rules)  # pretend every rule was newly added

    def remove_list(self, rules):
        self.removed = True

    def apply(self, uid, trans, dns):
        self.applied = True

    def remove(self, uid, trans, dns):
        self.removed = True

    def status(self, uid, trans, dns):
        return {
            "rules_total": 7,
            "rules_present": 7 if self.applied else 0,
            "active": self.applied,
            "killswitch": self.applied,
        }


class FakeV6:
    def __init__(self, available=True, fail=False):
        self._available = available
        self._fail = fail
        self.applied = False
        self.removed = False

    def available(self):
        return self._available

    def apply_v6(self, uid):
        if self._fail:
            raise FirewallError("v6 boom")
        self.applied = True

    def remove_v6(self, uid):
        self.removed = True

    def status_v6(self, uid):
        return {
            "rules_total": 2,
            "rules_present": 2 if self.applied else 0,
            "active": self.applied,
            "killswitch": self.applied,
        }


def _cfg(**kw):
    return Config(target_uid=1000, **kw)


def test_apply_v4_and_v6_when_ipv6_present(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: True)
    v4, v6 = FakeV4(), FakeV6()
    fw = LinuxFirewall(engine=v4, engine6=v6)
    fw.apply(_cfg())
    assert v4.applied and v6.applied
    st = fw.status(_cfg())
    assert st["rules_total"] == 9  # 7 v4 + 2 v6
    assert st["active"] is True


def test_apply_skips_v6_when_toggle_off(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: True)
    v4, v6 = FakeV4(), FakeV6()
    fw = LinuxFirewall(engine=v4, engine6=v6)
    fw.apply(_cfg(ipv6_killswitch=False))
    assert v4.applied and not v6.applied


def test_apply_skips_v6_when_no_ipv6_kernel(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: False)
    v4, v6 = FakeV4(), FakeV6()
    fw = LinuxFirewall(engine=v4, engine6=v6)
    fw.apply(_cfg())
    assert v4.applied and not v6.applied


def test_fail_closed_when_ipv6_present_but_ip6tables_missing(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: True)
    v4 = FakeV4()
    v6 = FakeV6(available=False)
    fw = LinuxFirewall(engine=v4, engine6=v6)
    with pytest.raises(FirewallError, match="ip6tables is unavailable"):
        fw.apply(_cfg())
    # v4 must have been rolled back so nothing is left armed
    assert v4.removed is True


def test_v6_apply_failure_rolls_back_v4(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: True)
    v4 = FakeV4()
    v6 = FakeV6(fail=True)
    fw = LinuxFirewall(engine=v4, engine6=v6)
    with pytest.raises(FirewallError):
        fw.apply(_cfg())
    assert v4.removed is True


def test_remove_tears_down_both(monkeypatch):
    monkeypatch.setattr(plat, "kernel_has_ipv6", lambda: True)
    v4, v6 = FakeV4(), FakeV6()
    fw = LinuxFirewall(engine=v4, engine6=v6)
    fw.apply(_cfg())
    fw.remove(_cfg())
    assert v4.removed and v6.removed


def test_make_firewall_dispatches_by_platform():
    assert type(make_firewall(plat.LINUX)).__name__ == "LinuxFirewall"
    assert type(make_firewall(plat.MACOS)).__name__ == "PfFirewall"
    assert type(make_firewall(plat.FREEBSD)).__name__ == "PfFirewall"
    assert type(make_firewall(plat.WINDOWS)).__name__ == "WindowsFirewall"
