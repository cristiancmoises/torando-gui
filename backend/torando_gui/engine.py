# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Netfilter engine.

This builds the per-UID transparent-torification + killswitch ruleset as
argument vectors (never a shell string) and resolves the target user to a
validated numeric UID. That removes the command-injection class that the
upstream ``USERAQUI`` text-substitution exposed.

The ruleset (per UID), in apply order:
  1. nat/OUTPUT    -d 127.0.0.0/8            -> RETURN   (never torify loopback)
  2. nat/OUTPUT    tcp                       -> REDIRECT to TransPort
  3. nat/OUTPUT    udp dport 53              -> REDIRECT to DNSPort
  4. filter/OUTPUT -o lo                     -> ACCEPT   (loopback stays local)
  5. filter/OUTPUT tcp dport TransPort       -> ACCEPT
  6. filter/OUTPUT udp dport DNSPort         -> ACCEPT
  7. filter/OUTPUT (everything else)         -> DROP     (the killswitch)

Rules 1 and 4 are the critical correction to the upstream five-rule script,
which DROP'd the UID's loopback too — that broke the GUI's own connection to
the daemon (both run on 127.0.0.1) and every local service the user relied on.
Exempting loopback does not weaken the killswitch: 127.0.0.0/8 never leaves the
host, so no clearnet egress is allowed. Tor's TransPort/DNSPort live on
loopback, so the redirected traffic is covered by rule 4 as well.

Each rule is checked with ``-C`` before being appended, and apply() rolls back
every rule it added if a later one fails, so the table is never left half-built.
"""

from __future__ import annotations

import contextlib
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

try:
    import pwd  # POSIX-only; absent on Windows (which never resolves a UID).
except ImportError:  # pragma: no cover - exercised only on Windows
    pwd = None  # type: ignore[assignment]

from . import platform as _plat

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    # No shell, fixed argv, captured output. Never interpolates user text.
    # Routed through platform.run_argv so Windows suppresses child console windows.
    return _plat.run_argv(argv)


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
    if pwd is None:
        raise EngineError("UID resolution is not available on this platform")
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


# Loopback network the redirect/killswitch must never touch.
LOOPBACK_CIDR = "127.0.0.0/8"


def build_rules(uid: int, trans_port: int, dns_port: int) -> list[Rule]:
    """Return the per-UID ruleset, in apply order (see module docstring)."""
    if not isinstance(uid, int) or uid < 0:
        raise EngineError("build_rules requires a validated non-negative uid")
    for port in (trans_port, dns_port):
        if not 1 <= port <= 65535:
            raise EngineError(f"port out of range: {port}")
    u = str(uid)
    owner = ("-m", "owner", "--uid-owner", u)
    return [
        # 1. Never NAT loopback traffic (keeps 127.0.0.1:8088 -> daemon working).
        Rule("nat", "OUTPUT", (*owner, "-d", LOOPBACK_CIDR, "-j", "RETURN")),
        # 2. Redirect the UID's TCP to Tor's TransPort.
        Rule(
            "nat",
            "OUTPUT",
            (*owner, "-p", "tcp", "-m", "tcp", "-j", "REDIRECT", "--to-ports", str(trans_port)),
        ),
        # 3. Redirect the UID's DNS (UDP/53) to Tor's DNSPort.
        Rule(
            "nat",
            "OUTPUT",
            (
                *owner,
                "-p",
                "udp",
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
        # 4. Accept the UID's loopback output (GUI <-> daemon, local services,
        #    and the redirected Tor traffic which lands on 127.0.0.1).
        Rule("filter", "OUTPUT", (*owner, "-o", "lo", "-j", "ACCEPT")),
        # 5. Accept the UID's TCP that is being torified (post-REDIRECT).
        Rule(
            "filter",
            "OUTPUT",
            (*owner, "-p", "tcp", "-m", "tcp", "--dport", str(trans_port), "-j", "ACCEPT"),
        ),
        # 6. Accept the UID's DNS that is being torified (post-REDIRECT).
        Rule(
            "filter",
            "OUTPUT",
            (*owner, "-p", "udp", "-m", "udp", "--dport", str(dns_port), "-j", "ACCEPT"),
        ),
        # 7. Killswitch: drop everything else from the UID (fail closed).
        Rule("filter", "OUTPUT", (*owner, "-j", "DROP")),
    ]


# Number of rules build_rules() emits (kept in sync by test_engine).
RULE_COUNT = 7


def build_v6_rules(uid: int) -> list[Rule]:
    """Return the per-UID IPv6 killswitch ruleset (ip6tables filter/OUTPUT).

    IPv4 is transparently torified; IPv6 is simply *blocked* for the UID. The
    v4 DNSPort already resolves AAAA records through Tor, so there is no v6
    anonymity to gain by torifying v6 — but an un-firewalled v6 path would let
    the UID's traffic escape Tor entirely, which is exactly the leak this closes.

      1. filter/OUTPUT  -o lo   -> ACCEPT   (loopback stays local)
      2. filter/OUTPUT  (rest)  -> DROP     (the v6 killswitch)

    Kernel-generated ICMPv6 (neighbour discovery, router solicitation) carries
    no socket owner, so a non-inverted ``--uid-owner`` DROP never matches it —
    v6 on-link connectivity for the rest of the system is unaffected.
    """
    if not isinstance(uid, int) or uid < 0:
        raise EngineError("build_v6_rules requires a validated non-negative uid")
    owner = ("-m", "owner", "--uid-owner", str(uid))
    return [
        Rule("filter", "OUTPUT", (*owner, "-o", "lo", "-j", "ACCEPT")),
        Rule("filter", "OUTPUT", (*owner, "-j", "DROP")),
    ]


# Number of rules build_v6_rules() emits.
V6_RULE_COUNT = 2


class Engine:
    """Applies and removes the torando ruleset for a single UID."""

    def __init__(self, iptables: str = "iptables", runner: Runner | None = None) -> None:
        self._iptables = iptables
        self._run = runner or _default_runner

    def _argv(self, op: str, rule: Rule) -> list[str]:
        # op is one of -C (check), -A (append), -D (delete). ``-w 5`` waits up to
        # 5s for the xtables lock instead of failing immediately, so a concurrent
        # firewalld/docker/NetworkManager run can't make us mis-report a rule as
        # absent (exit 4) and orphan or double-add it.
        return [self._iptables, "-w", "5", "-t", rule.table, op, rule.chain, *rule.spec]

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

    def apply_list(self, rules: list[Rule]) -> list[Rule]:
        """Add every rule in *rules*; on any failure, remove the ones added.

        This is the transactional primitive both the IPv4 ruleset and the IPv6
        killswitch use, so neither table is ever left half-built. Returns the
        rules this call actually appended (those not already present), so a
        caller can roll back exactly what it added and nothing it didn't.
        """
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
        return added

    def remove_list(self, rules: list[Rule]) -> None:
        """Remove every rule in *rules* (in reverse), best-effort. Missing rules
        are fine, and a failure to delete one never stops the others — teardown
        must always attempt the whole set so nothing is left stranded."""
        for rule in reversed(rules):
            with contextlib.suppress(EngineError):
                self._del(rule)

    def status_list(self, rules: list[Rule]) -> dict[str, object]:
        """Report which of *rules* are currently present."""
        present = [self.rule_exists(r) for r in rules]
        return {
            "rules_total": len(rules),
            "rules_present": sum(present),
            "active": all(present),
            "killswitch": bool(present) and present[-1],  # the DROP rule
        }

    def apply(self, uid: int, trans_port: int, dns_port: int) -> None:
        """Add the IPv4 transparent-proxy + killswitch ruleset (transactional)."""
        self.apply_list(build_rules(uid, trans_port, dns_port))

    def remove(self, uid: int, trans_port: int, dns_port: int) -> None:
        """Remove the IPv4 ruleset. Missing rules are not an error."""
        self.remove_list(build_rules(uid, trans_port, dns_port))

    def status(self, uid: int, trans_port: int, dns_port: int) -> dict[str, object]:
        """Report which IPv4 rules are currently present."""
        return self.status_list(build_rules(uid, trans_port, dns_port))


class Ip6Engine(Engine):
    """The IPv6 killswitch, applied with ``ip6tables`` (same argv machinery)."""

    def __init__(self, ip6tables: str = "ip6tables", runner: Runner | None = None) -> None:
        super().__init__(iptables=ip6tables, runner=runner)

    def apply_v6(self, uid: int) -> None:
        self.apply_list(build_v6_rules(uid))

    def remove_v6(self, uid: int) -> None:
        self.remove_list(build_v6_rules(uid))

    def status_v6(self, uid: int) -> dict[str, object]:
        return self.status_list(build_v6_rules(uid))
