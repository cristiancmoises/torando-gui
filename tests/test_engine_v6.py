# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""IPv6 killswitch: the ip6tables ruleset shape, ordering, and transactional
apply/remove via a fake ip6tables."""

from __future__ import annotations

import subprocess

import pytest
from torando_gui.engine import (
    V6_RULE_COUNT,
    EngineError,
    Ip6Engine,
    Rule,
    build_v6_rules,
)


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeIp6tables:
    def __init__(self, fail_append_index: int | None = None) -> None:
        self.present: set[tuple] = set()
        self.calls: list[list[str]] = []
        self._fail_idx = fail_append_index
        self._appends = 0

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(argv)
        if "--version" in argv:
            return _cp(argv, 0)
        i = argv.index("-t")  # tolerate a leading "-w 5" lock-wait
        table, op, chain, spec = argv[i + 1], argv[i + 2], argv[i + 3], tuple(argv[i + 4 :])
        key = (table, chain, spec)
        if op == "-C":
            return _cp(argv, 0 if key in self.present else 1)
        if op == "-A":
            idx, self._appends = self._appends, self._appends + 1
            if self._fail_idx is not None and idx == self._fail_idx:
                return _cp(argv, 2, err="append refused")
            self.present.add(key)
            return _cp(argv, 0)
        if op == "-D":
            self.present.discard(key)
            return _cp(argv, 0)
        return _cp(argv, 0)


def test_v6_rules_shape_and_order():
    rules = build_v6_rules(1000)
    assert len(rules) == V6_RULE_COUNT == 2
    owner = ("-m", "owner", "--uid-owner", "1000")
    # loopback ACCEPT must precede the DROP
    assert rules[0] == Rule("filter", "OUTPUT", (*owner, "-o", "lo", "-j", "ACCEPT"))
    assert rules[1] == Rule("filter", "OUTPUT", (*owner, "-j", "DROP"))


def test_v6_rejects_bad_uid():
    with pytest.raises(EngineError):
        build_v6_rules(-1)


def test_v6_apply_then_status_active():
    fake = FakeIp6tables()
    eng = Ip6Engine(runner=fake)
    eng.apply_v6(1000)
    st = eng.status_v6(1000)
    assert st == {
        "rules_total": 2,
        "rules_present": 2,
        "active": True,
        "killswitch": True,
    }
    # the binary used must be ip6tables, not iptables
    assert all(c[0] == "ip6tables" for c in fake.calls)


def test_v6_apply_rolls_back_on_failure():
    fake = FakeIp6tables(fail_append_index=1)  # second append (the DROP) fails
    eng = Ip6Engine(runner=fake)
    with pytest.raises(EngineError):
        eng.apply_v6(1000)
    assert fake.present == set()  # the loopback ACCEPT was rolled back


def test_v6_remove_clears_all():
    fake = FakeIp6tables()
    eng = Ip6Engine(runner=fake)
    eng.apply_v6(1000)
    eng.remove_v6(1000)
    assert fake.present == set()
