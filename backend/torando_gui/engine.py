# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Netfilter engine.

This reproduces, exactly, the five rules of upstream torando.sh / toroff.sh,
but builds them as argument vectors (never a shell string) and resolves the
target user to a validated numeric UID. That removes the command-injection
class that the upstream ``USERAQUI`` text-substitution exposed.

Upstream behaviour reproduced (per-UID transparent torification + killswitch):
  1. nat/OUTPUT    tcp                       -> REDIRECT to TransPort
  2. nat/OUTPUT    udp dport 53              -> REDIRECT to DNSPort
  3. filter/OUTPUT tcp dport TransPort       -> ACCEPT
  4. filter/OUTPUT udp dport DNSPort         -> ACCEPT
  5. filter/OUTPUT (everything else)         -> DROP   (the killswitch)

Added on top of upstream (correctness, not behaviour change): each rule is
checked with ``-C`` before being appended, and apply() rolls back every rule
it added if a later one fails, so the table is never left half-built.
"""

from __future__ import annotations

import contextlib
import pwd
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    # No shell, fixed argv, captured output. Never interpolates user text.
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


@dataclass(frozen=True)
class Rule:
    """One iptables rule: a table, a chain, and the matching/target spec."""

    table: str
    chain: str
    spec: tuple[str, ...]


class EngineError(RuntimeError):
    pass


def resolve_uid(user_or_uid: str | int) -> int:
    """Resolve a username or numeric id to a UID that exists on this host.

    Raises EngineError for anything that is not a real local account. This is
    the single choke point that makes the rest of the engine injection-proof:
    the value handed to iptables is always an ``int`` we just validated.
    """
    if isinstance(user_or_uid, int) or (isinstance(user_or_uid, str) and user_or_uid.isdigit()):
        uid = int(user_or_uid)
        try:
            pwd.getpwuid(uid)
        except KeyError as exc:
            raise EngineError(f"no account with uid {uid}") from exc
        if uid < 0:
            raise EngineError("uid must be non-negative")
        return uid
    try:
        return pwd.getpwnam(str(user_or_uid)).pw_uid
    except KeyError as exc:
        raise EngineError(f"no such user: {user_or_uid!r}") from exc


def build_rules(uid: int, trans_port: int, dns_port: int) -> list[Rule]:
    """Return the five rules for *uid*, in apply order."""
    if not isinstance(uid, int) or uid < 0:
        raise EngineError("build_rules requires a validated non-negative uid")
    for port in (trans_port, dns_port):
        if not 1 <= port <= 65535:
            raise EngineError(f"port out of range: {port}")
    u = str(uid)
    return [
        Rule(
            "nat",
            "OUTPUT",
            (
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                u,
                "-m",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(trans_port),
            ),
        ),
        Rule(
            "nat",
            "OUTPUT",
            (
                "-p",
                "udp",
                "-m",
                "owner",
                "--uid-owner",
                u,
                "-m",
                "udp",
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(dns_port),
            ),
        ),
        Rule(
            "filter",
            "OUTPUT",
            (
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                u,
                "-m",
                "tcp",
                "--dport",
                str(trans_port),
                "-j",
                "ACCEPT",
            ),
        ),
        Rule(
            "filter",
            "OUTPUT",
            (
                "-p",
                "udp",
                "-m",
                "owner",
                "--uid-owner",
                u,
                "-m",
                "udp",
                "--dport",
                str(dns_port),
                "-j",
                "ACCEPT",
            ),
        ),
        Rule("filter", "OUTPUT", ("-m", "owner", "--uid-owner", u, "-j", "DROP")),
    ]


class Engine:
    """Applies and removes the torando ruleset for a single UID."""

    def __init__(self, iptables: str = "iptables", runner: Runner | None = None) -> None:
        self._iptables = iptables
        self._run = runner or _default_runner

    def _argv(self, op: str, rule: Rule) -> list[str]:
        # op is one of -C (check), -A (append), -D (delete).
        return [self._iptables, "-t", rule.table, op, rule.chain, *rule.spec]

    def available(self) -> bool:
        try:
            return self._run([self._iptables, "--version"]).returncode == 0
        except FileNotFoundError:
            return False

    def rule_exists(self, rule: Rule) -> bool:
        return self._run(self._argv("-C", rule)).returncode == 0

    def _add(self, rule: Rule) -> None:
        if self.rule_exists(rule):
            return
        res = self._run(self._argv("-A", rule))
        if res.returncode != 0:
            raise EngineError(res.stderr.strip() or "iptables append failed")

    def _del(self, rule: Rule) -> None:
        # Delete every duplicate copy, ignore "rule does not exist".
        while self.rule_exists(rule):
            res = self._run(self._argv("-D", rule))
            if res.returncode != 0:
                raise EngineError(res.stderr.strip() or "iptables delete failed")

    def apply(self, uid: int, trans_port: int, dns_port: int) -> None:
        """Add all rules; on any failure, remove the ones already added."""
        rules = build_rules(uid, trans_port, dns_port)
        added: list[Rule] = []
        try:
            for rule in rules:
                existed = self.rule_exists(rule)
                self._add(rule)
                if not existed:
                    added.append(rule)
        except EngineError:
            for rule in reversed(added):
                # best-effort rollback; the original error is re-raised below
                with contextlib.suppress(EngineError):
                    self._del(rule)
            raise

    def remove(self, uid: int, trans_port: int, dns_port: int) -> None:
        """Remove all rules. Missing rules are not an error."""
        for rule in reversed(build_rules(uid, trans_port, dns_port)):
            self._del(rule)

    def status(self, uid: int, trans_port: int, dns_port: int) -> dict[str, object]:
        """Report which rules are currently present."""
        rules = build_rules(uid, trans_port, dns_port)
        present = [self.rule_exists(r) for r in rules]
        return {
            "rules_total": len(rules),
            "rules_present": sum(present),
            "active": all(present),
            "killswitch": present[-1],  # the DROP rule
        }
