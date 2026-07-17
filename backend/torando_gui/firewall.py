# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Platform firewall abstraction.

Every OS torifies a user differently, but the daemon's orchestration
(:class:`~torando_gui.app.App`) must not care. It only needs a firewall object
that can ``apply``/``remove``/``status`` a per-UID transparent-proxy +
killswitch, and report whether the required tooling is ``available``. This
module defines that seam and provides the Linux implementation; ``pf.py`` and
``winfw.py`` supply the macOS/BSD and Windows ones.

The contract every backend upholds:

* **apply is transactional and fail-closed.** It either arms the *complete*
  ruleset (including the IPv6 killswitch where the kernel can carry IPv6) or it
  raises and leaves nothing behind. It must never return having armed a
  killswitch that still leaks — a silent partial state is worse than an error.
* **remove is unconditional and best-effort.** It tears down every rule the
  backend could have added, ignoring "already gone", so disconnect always
  fully restores egress.
"""

from __future__ import annotations

import contextlib
from typing import Protocol

from . import platform as _plat
from .config import Config
from .engine import Engine, Ip6Engine, build_rules, build_v6_rules


class Firewall(Protocol):
    def available(self) -> bool: ...
    def apply(self, cfg: Config) -> None: ...
    def remove(self, cfg: Config) -> None: ...
    def status(self, cfg: Config) -> dict[str, object]: ...


class FirewallError(RuntimeError):
    pass


class LinuxFirewall:
    """iptables IPv4 transparent proxy + killswitch, plus an ip6tables IPv6
    killswitch. This is the original, proven Linux path; the v6 half is the
    1.2.0 addition that closes the documented IPv6 leak."""

    def __init__(self, engine: Engine | None = None, engine6: Ip6Engine | None = None) -> None:
        self._v4 = engine or Engine()
        self._v6 = engine6 or Ip6Engine()

    def available(self) -> bool:
        return self._v4.available()

    def _v6_required(self, cfg: Config) -> bool:
        return bool(cfg.ipv6_killswitch) and _plat.kernel_has_ipv6()

    def _apply_v6(self, cfg: Config) -> None:
        if not self._v6_required(cfg):
            return
        if not self._v6.available():
            raise FirewallError(
                "IPv6 is enabled on this host but ip6tables is unavailable — refusing "
                "to connect with an unfiltered IPv6 path that would leak around Tor. "
                "Install ip6tables, or set ipv6_killswitch=false to accept the risk."
            )
        self._v6.apply_v6(cfg.target_uid)

    def apply(self, cfg: Config) -> None:
        uid, trans, dns = cfg.target_uid, cfg.trans_port, cfg.dns_port
        # apply_list returns exactly the rules THIS call appended, so a v6
        # failure rolls back only our additions — never a pre-existing armed
        # ruleset from an earlier session.
        added = self._v4.apply_list(build_rules(uid, trans, dns))
        try:
            self._apply_v6(cfg)
        except Exception:
            self._v4.remove_list(added)
            raise

    def remove(self, cfg: Config) -> None:
        uid = cfg.target_uid
        # Tear down both families best-effort: a failure removing one must never
        # stop the other (disconnect has already restored DNS by this point, so a
        # stranded killswitch would be the worst outcome). Always attempt v6 too,
        # regardless of the toggle, so a config change can't orphan v6 rules.
        with contextlib.suppress(Exception):
            if self._v6.available():
                self._v6.remove_v6(uid)
        self._v4.remove(uid, cfg.trans_port, cfg.dns_port)

    def status(self, cfg: Config) -> dict[str, object]:
        uid = cfg.target_uid
        v4 = self._v4.status(uid, cfg.trans_port, cfg.dns_port)
        total = int(v4["rules_total"])
        present = int(v4["rules_present"])
        active = bool(v4["active"])
        killswitch = bool(v4["killswitch"])
        if self._v6_required(cfg):
            if self._v6.available():
                v6 = self._v6.status_v6(uid)
                total += len(build_v6_rules(uid))
                present += int(v6["rules_present"])
                active = active and bool(v6["active"])
                # The v6 DROP is as load-bearing as the v4 one: if it's gone the
                # UID's IPv6 leaks, so it must count toward the killswitch verdict.
                killswitch = killswitch and bool(v6["killswitch"])
            else:
                # v6 is required but unverifiable/unarmed — report not-safe.
                active = False
                killswitch = False
        return {
            "rules_total": total,
            "rules_present": present,
            "active": active,
            "killswitch": killswitch,
        }


def make_firewall(platform_id: str | None = None) -> Firewall:
    """Return the firewall backend for *platform_id* (default: this host)."""
    p = platform_id or _plat.CURRENT
    if p == _plat.WINDOWS:
        from .winfw import WindowsFirewall

        return WindowsFirewall()
    if p in _plat.PF_PLATFORMS:
        from .pf import PfFirewall

        return PfFirewall(platform_id=p)
    return LinuxFirewall()
