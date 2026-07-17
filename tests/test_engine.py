# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Engine tests: the five rules must match upstream torando exactly, the UID
resolver must reject non-accounts, and apply() must roll back on failure."""

from __future__ import annotations

import subprocess
import sys

import pytest

if sys.platform == "win32":  # the iptables engine + pwd-based UID resolution are POSIX-only
    pytest.skip("iptables engine is POSIX-only", allow_module_level=True)

import os  # noqa: E402
import pwd  # noqa: E402

from torando_gui.engine import (  # noqa: E402
    Engine,
    EngineError,
    Rule,
    build_rules,
    resolve_uid,
)


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeIptables:
    """Stateful fake: -C reports membership, -A inserts, -D removes."""

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


# --- per-UID transparent-proxy + killswitch ruleset ------------------------
def test_build_rules_shape_and_order():
    rules = build_rules(1000, 9040, 53)
    assert len(rules) == 7
    owner = ("-m", "owner", "--uid-owner", "1000")
    # 1. loopback is never NAT'd (keeps GUI <-> daemon and local services alive)
    assert rules[0] == Rule("nat", "OUTPUT", (*owner, "-d", "127.0.0.0/8", "-j", "RETURN"))
    # 2. TCP -> Tor TransPort
    assert rules[1] == Rule(
        "nat",
        "OUTPUT",
        (*owner, "-p", "tcp", "-m", "tcp", "-j", "REDIRECT", "--to-ports", "9040"),
    )
    # 3. DNS (udp/53) -> Tor DNSPort
    assert rules[2] == Rule(
        "nat",
        "OUTPUT",
        (*owner, "-p", "udp", "-m", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"),
    )
    # 4. loopback output accepted (critical: the daemon UI is on 127.0.0.1)
    assert rules[3] == Rule("filter", "OUTPUT", (*owner, "-o", "lo", "-j", "ACCEPT"))
    # 5/6. torified TCP/DNS accepted
    assert rules[4] == Rule(
        "filter",
        "OUTPUT",
        (*owner, "-p", "tcp", "-m", "tcp", "--dport", "9040", "-j", "ACCEPT"),
    )
    assert rules[5] == Rule(
        "filter",
        "OUTPUT",
        (*owner, "-p", "udp", "-m", "udp", "--dport", "53", "-j", "ACCEPT"),
    )
    # 7. killswitch must be the LAST filter rule (drop everything else)
    assert rules[6] == Rule("filter", "OUTPUT", (*owner, "-j", "DROP"))


def test_loopback_is_exempt_before_drop():
    # The loopback ACCEPT (rule 4) must precede the DROP (rule 7) in the same
    # chain, or the GUI loses its connection to the daemon the moment it connects.
    rules = build_rules(1000, 9040, 53)
    filter_rules = [r for r in rules if r.table == "filter"]
    lo_idx = next(i for i, r in enumerate(filter_rules) if "lo" in r.spec)
    drop_idx = next(i for i, r in enumerate(filter_rules) if "DROP" in r.spec)
    assert lo_idx < drop_idx


def test_rule_count_constant_matches():
    from torando_gui.engine import RULE_COUNT

    assert RULE_COUNT == len(build_rules(1000, 9040, 53))


def test_build_rules_honours_custom_ports():
    rules = build_rules(1234, 9051, 5353)
    assert rules[1].spec[-1] == "9051"  # TransPort redirect
    assert rules[2].spec[-1] == "5353"  # DNSPort redirect
    assert rules[4].spec[-3] == "9051"  # accept TransPort
    assert rules[5].spec[-3] == "5353"  # accept DNSPort


def test_build_rules_rejects_bad_uid_and_ports():
    with pytest.raises(EngineError):
        build_rules(-1, 9040, 53)
    with pytest.raises(EngineError):
        build_rules(1000, 0, 53)
    with pytest.raises(EngineError):
        build_rules(1000, 9040, 70000)


# --- uid resolution (the injection choke point) ----------------------------
def test_resolve_uid_accepts_real_account():
    me = os.getuid()
    assert resolve_uid(me) == me
    assert resolve_uid(str(me)) == me
    name = pwd.getpwuid(me).pw_name
    assert resolve_uid(name) == me


def test_resolve_uid_rejects_unknown():
    with pytest.raises(EngineError):
        resolve_uid(4_000_000_000)  # no account with this uid
    with pytest.raises(EngineError):
        resolve_uid("definitely-not-a-real-user-xyz")


# --- apply / remove / status with a fake iptables --------------------------
def test_apply_adds_all_then_status_active():
    fake = FakeIptables()
    eng = Engine(runner=fake)
    eng.apply(1000, 9040, 53)
    st = eng.status(1000, 9040, 53)
    assert st == {"rules_total": 7, "rules_present": 7, "active": True, "killswitch": True}


def test_apply_is_idempotent():
    fake = FakeIptables()
    eng = Engine(runner=fake)
    eng.apply(1000, 9040, 53)
    appends_after_first = sum(1 for c in fake.calls if "-A" in c)
    eng.apply(1000, 9040, 53)  # second run must add nothing
    appends_total = sum(1 for c in fake.calls if "-A" in c)
    assert appends_after_first == 7
    assert appends_total == 7


def test_apply_rolls_back_added_rules_on_failure():
    fake = FakeIptables(fail_append_index=2)  # third append fails
    eng = Engine(runner=fake)
    with pytest.raises(EngineError):
        eng.apply(1000, 9040, 53)
    # the two rules added before the failure must have been deleted
    assert fake.present == set()
    assert any("-D" in c for c in fake.calls)


def test_rollback_preserves_preexisting_rules():
    fake = FakeIptables(fail_append_index=1)
    eng = Engine(runner=fake)
    rules = build_rules(1000, 9040, 53)
    pre = (rules[0].table, rules[0].chain, rules[0].spec)
    fake.present.add(pre)  # rule 0 already present, not ours to roll back
    with pytest.raises(EngineError):
        eng.apply(1000, 9040, 53)
    assert pre in fake.present  # survived rollback


def test_remove_deletes_everything():
    fake = FakeIptables()
    eng = Engine(runner=fake)
    eng.apply(1000, 9040, 53)
    eng.remove(1000, 9040, 53)
    assert fake.present == set()


def test_available_reports_missing_binary():
    def boom(argv):
        raise FileNotFoundError

    assert Engine(runner=boom).available() is False
