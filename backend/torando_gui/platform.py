# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Platform detection and per-OS constants.

Torando Control runs on Linux, macOS, the BSDs and Windows, but the firewall,
DNS-pinning and service mechanisms are completely different on each. This module
is the single place that answers "which OS is this?" so the rest of the daemon
never sniffs ``sys.platform`` inline. Everything here is a pure lookup — no side
effects — so tests can pin the platform with ``monkeypatch``.

Semantics differ by family and the difference is deliberate, not incidental:

* **Linux** — a true per-UID transparent proxy: iptables (and, since 1.2.0,
  ip6tables) REDIRECT the chosen user's TCP/DNS into Tor and DROP the rest.
* **macOS / FreeBSD / OpenBSD** — a per-UID transparent proxy via ``pf``: the
  user's traffic is looped onto loopback where an ``rdr`` anchor redirects it to
  Tor, and a ``block out ... user`` rule is the killswitch.
* **Windows** — no driverless per-process redirect exists, so this is an
  honest *machine-wide* model: a system SOCKS proxy pointer plus a
  default-block-outbound firewall that only whitelists ``tor.exe`` and loopback.
  Cooperating apps go through Tor; everything else is blocked, never leaked.
"""

from __future__ import annotations

import os
import sys

LINUX = "linux"
MACOS = "macos"
FREEBSD = "freebsd"
OPENBSD = "openbsd"
NETBSD = "netbsd"
WINDOWS = "windows"
UNKNOWN = "unknown"

# The pf-based BSD/macOS family (transparent proxy via rdr anchor + killswitch).
PF_PLATFORMS = frozenset({MACOS, FREEBSD, OPENBSD, NETBSD})


def detect(platform_string: str | None = None) -> str:
    """Map ``sys.platform`` to one of the constants above.

    ``platform_string`` is injectable for tests; production passes ``None`` and
    reads the live ``sys.platform``.
    """
    p = (platform_string if platform_string is not None else sys.platform).lower()
    if p.startswith("linux"):
        return LINUX
    if p == "darwin":
        return MACOS
    if p.startswith("freebsd"):
        return FREEBSD
    if p.startswith("openbsd"):
        return OPENBSD
    if p.startswith("netbsd"):
        return NETBSD
    if p.startswith("win") or p == "cygwin":
        return WINDOWS
    return UNKNOWN


#: The platform this daemon is running on. Computed once at import.
CURRENT = detect()


def is_pf(platform_id: str | None = None) -> bool:
    return (platform_id or CURRENT) in PF_PLATFORMS


def is_windows(platform_id: str | None = None) -> bool:
    return (platform_id or CURRENT) == WINDOWS


def is_linux(platform_id: str | None = None) -> bool:
    return (platform_id or CURRENT) == LINUX


def is_bsd(platform_id: str | None = None) -> bool:
    return (platform_id or CURRENT) in (FREEBSD, OPENBSD, NETBSD)


# The account Tor's own daemon runs as, per platform. The killswitch is scoped
# to the *torified* user's UID, so Tor (a different account) is never caught by
# it — but the pf recipe still exempts this name for clarity/robustness.
TOR_USER = {
    MACOS: "_tor",
    FREEBSD: "_tor",
    OPENBSD: "_tor",
    NETBSD: "_tor",
}


def kernel_has_ipv6() -> bool:
    """True if this kernel can do IPv6 at all (Linux probe).

    ``/proc/sys/net/ipv6`` exists iff IPv6 is compiled in or loaded, even when
    ``disable_ipv6=1``. Its presence means "the kernel can carry IPv6 packets",
    which is exactly the condition under which an un-firewalled v6 path would be
    a leak. On non-Linux platforms we conservatively assume IPv6 is present.
    """
    if CURRENT == LINUX:
        return os.path.isdir("/proc/sys/net/ipv6")
    return True


def loopback_interface(platform_id: str | None = None) -> str:
    """Name of the loopback interface used in firewall rules."""
    p = platform_id or CURRENT
    if p in PF_PLATFORMS:
        return "lo0"
    return "lo"
