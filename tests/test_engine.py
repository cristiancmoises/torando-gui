# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Engine tests: the five rules must match upstream torando exactly, the UID
resolver must reject non-accounts, and apply() must roll back on failure."""

from __future__ import annotations

import os
import pwd
import subprocess

import pytest
from torando_gui.engine import Engine, EngineError, Rule, build_rules, resolve_uid


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
        table, op, chain, spec = argv[2], argv[3], argv[4], tuple(argv[5:])
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


# --- exact upstream reproduction -------------------------------------------
def test_build_rules_reproduces_upstream_five():
    rules = build_rules(1000, 9040, 53)
    assert len(rules) == 5
    assert rules[0] == Rule(
        "nat",
        "OUTPUT",
        (
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            "1000",
            "-m",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            "9040",
        ),
    )
    assert rules[1] == Rule(
        "nat",
        "OUTPUT",
        (
            "-p",
            "udp",
            "-m",
            "owner",
            "--uid-owner",
            "1000",
            "-m",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            "53",
        ),
    )
    assert rules[2] == Rule(
        "filter",
        "OUTPUT",
        (
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            "1000",
            "-m",
            "tcp",
            "--dport",
            "9040",
            "-j",
            "ACCEPT",
        ),
    )
    assert rules[3] == Rule(
        "filter",
        "OUTPUT",
        (
            "-p",
            "udp",
            "-m",
            "owner",
            "--uid-owner",
            "1000",
            "-m",
            "udp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ),
    )
    # rule 5 is the killswitch: drop everything else from this uid
    assert rules[4] == Rule(
        "filter",
        "OUTPUT",
        ("-m", "owner", "--uid-owner", "1000", "-j", "DROP"),
    )


def test_build_rules_honours_custom_ports():
    rules = build_rules(1234, 9051, 5353)
    assert "9051" in rules[0].spec
    assert rules[1].spec[-1] == "5353"
    assert rules[2].spec[-3] == "9051"


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
    assert st == {"rules_total": 5, "rules_present": 5, "active": True, "killswitch": True}


def test_apply_is_idempotent():
    fake = FakeIptables()
    eng = Engine(runner=fake)
    eng.apply(1000, 9040, 53)
    appends_after_first = sum(1 for c in fake.calls if c[3] == "-A")
    eng.apply(1000, 9040, 53)  # second run must add nothing
    appends_total = sum(1 for c in fake.calls if c[3] == "-A")
    assert appends_after_first == 5
    assert appends_total == 5


def test_apply_rolls_back_added_rules_on_failure():
    fake = FakeIptables(fail_append_index=2)  # third append fails
    eng = Engine(runner=fake)
    with pytest.raises(EngineError):
        eng.apply(1000, 9040, 53)
    # the two rules added before the failure must have been deleted
    assert fake.present == set()
    assert any(c[3] == "-D" for c in fake.calls)


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
