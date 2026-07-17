# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""pf firewall backend for macOS, FreeBSD, OpenBSD and NetBSD.

Design rationale — why this is a killswitch + SOCKS proxy, not the Linux-style
transparent rdr redirect:

pf *can* transparently redirect a local user's outbound traffic, but only with
the fragile ``rdr`` + ``route-to``-onto-loopback trick, which (a) has a long
history of breaking across macOS releases, (b) is impossible on OpenBSD for
local outbound (``divert-to`` is inbound-only — pfctl rejects it on ``pass
out``), and (c) requires editing the *translation* section of the user's
``pf.conf``, which has strict rule-ordering constraints that are easy to break.
For a tool whose entire promise is "fail closed, never leak", shipping a redirect
that might silently fail open is the wrong trade.

So on pf platforms Torando Control routes exactly the way it does on Windows: a
**system SOCKS proxy** points cooperating apps at Tor's ``SocksPort`` (set with
``networksetup`` on macOS; via ``torsocks``/per-app config on the BSDs), and a
**per-UID pf killswitch** blocks every other egress from that user — so an app
that ignores the proxy is *blocked*, never leaked. The killswitch is filter-only
(no translation rules), which means it hooks into ``pf.conf`` with a single
``anchor`` reference in the filter section (always valid, no ordering hazard).

Everything that generates rule text is a pure function so it is unit-tested on
any OS; only :class:`PfFirewall` shells out to ``pfctl``.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from . import platform as _plat
from .config import Config

try:
    import pwd  # POSIX-only; pf platforms are all POSIX, so this is always present here.
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

ANCHOR_BEGIN = "# >>> torando-gui managed anchor refs (do not edit by hand) >>>"
ANCHOR_END = "# <<< torando-gui managed anchor refs <<<"


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


def default_pf_conf(platform_id: str | None = None) -> Path:
    """The main pf ruleset file we hook our anchor into."""
    # /etc/pf.conf is the default on macOS, FreeBSD and OpenBSD alike.
    return Path("/etc/pf.conf")


def build_anchor_rules(
    cfg: Config, platform_id: str | None = None, tor_user: str | None = None
) -> str:
    """Render the per-UID killswitch anchor (filter rules only). Deterministic.

    Rule order (pf is last-match-wins unless ``quick``; every rule here is
    ``quick`` so the first match is final):

      1. pass  loopback for the UID   — so app -> 127.0.0.1:SocksPort/DNSPort works
      2. pass  Tor's own egress       — ONLY when *tor_user* is a real account
      3. block the UID's other TCP/UDP — the IPv4 killswitch
      4. block the UID's IPv6 TCP/UDP  — the IPv6 killswitch (when enabled)

    The Tor-exemption rule (2) is emitted only when *tor_user* is given. pfctl
    resolves ``user <name>`` via getpwnam at parse time and rejects an unknown
    account, so a hard-coded ``_tor`` — which does not exist on stock macOS or
    NetBSD — would make the whole ruleset fail to load. The killswitch is scoped
    to the *torified* UID and Tor runs as a different account, so the exemption
    is belt-and-braces: omitting it is safe.

    pf's ``user`` token only tags TCP and UDP sockets, so ICMP for the UID is not
    covered — a documented limitation, harmless for egress anonymity.
    """
    p = platform_id or _plat.CURRENT
    lo = _plat.loopback_interface(p)
    uid = cfg.target_uid
    lines = [
        f"# torando-gui per-UID killswitch for uid {uid} (generated; do not edit)",
        f"pass out quick on {lo} proto {{ tcp udp }} user {uid} keep state",
    ]
    if tor_user:
        lines.append(f"pass out quick proto {{ tcp udp }} user {tor_user} keep state")
    lines.append(f"block drop out quick inet proto {{ tcp udp }} all user {uid}")
    if cfg.ipv6_killswitch:
        lines.append(f"block drop out quick inet6 proto {{ tcp udp }} all user {uid}")
    return "\n".join(lines) + "\n"


def anchor_rule_count(cfg: Config, tor_user: str | None = None) -> int:
    """How many rules build_anchor_rules() emits (comment lines excluded)."""
    n = 2  # loopback pass + v4 block
    if tor_user:
        n += 1
    if cfg.ipv6_killswitch:
        n += 1
    return n


def _managed_block(anchor: str, anchor_file: str) -> str:
    return (
        f"{ANCHOR_BEGIN}\n"
        f'anchor "{anchor}"\n'
        f'load anchor "{anchor}" from "{anchor_file}"\n'
        f"{ANCHOR_END}\n"
    )


def wire_pf_conf(existing: str, anchor: str, anchor_file: str) -> str:
    """Insert or refresh the managed ``anchor``/``load anchor`` references in
    *existing* pf.conf text and return the new text.

    Because our anchor holds only *filter* rules, both reference lines belong in
    the filter section, which is the last section of a pf.conf — so appending
    them at the end is always valid ordering. If a managed block is already
    present but references a *different* anchor name or file (e.g. the config
    changed), it is replaced — otherwise the daemon would load rules into an
    anchor the main ruleset never evaluates (a silent fail-open).
    """
    want = _managed_block(anchor, anchor_file)
    if ANCHOR_BEGIN in existing:
        if want in existing:
            return existing  # already exactly what we want
        existing = unwire_pf_conf(existing)  # strip the stale block, then re-add
    base = existing if (not existing or existing.endswith("\n")) else existing + "\n"
    return base + want


def unwire_pf_conf(existing: str) -> str:
    """Remove the managed anchor-reference block from pf.conf text.

    Exact inverse of the append in :func:`wire_pf_conf`: it removes the block and
    the single trailing newline the block owns, and nothing else (it never trims
    a blank line that was part of the user's original file).
    """
    begin = existing.find(ANCHOR_BEGIN)
    if begin == -1:
        return existing
    end = existing.find(ANCHOR_END, begin)
    if end == -1:
        return existing[:begin]
    end += len(ANCHOR_END)
    if existing[end : end + 1] == "\n":
        end += 1
    return existing[:begin] + existing[end:]


class PfFirewall:
    """Loads the killswitch anchor into pf and manages the pf.conf hook."""

    def __init__(
        self,
        platform_id: str | None = None,
        runner: Runner | None = None,
        pf_conf: Path | None = None,
        anchor_dir: Path | None = None,
    ) -> None:
        self._p = platform_id or _plat.CURRENT
        self._run = runner or _default_runner
        self._pf_conf = pf_conf or default_pf_conf(self._p)
        self._anchor_dir = anchor_dir or Path("/etc/torando-gui")
        self._macos = self._p == _plat.MACOS

    def _anchor_file(self, cfg: Config) -> Path:
        return self._anchor_dir / f"{cfg.pf_anchor}.pf"

    def _tor_user(self, cfg: Config) -> str | None:
        """The Tor account to exempt, but only if it actually exists.

        pfctl rejects a rule naming an unknown user, so a non-existent account
        (e.g. ``_tor`` on stock macOS) must not reach the ruleset. Returns None
        when there is no such account — the exemption is then simply omitted.
        """
        name = cfg.tor_user or _plat.TOR_USER.get(self._p)
        if not name or pwd is None:
            return None
        try:
            pwd.getpwnam(name)
        except KeyError:
            return None
        return name

    def available(self) -> bool:
        try:
            return self._run(["pfctl", "-s", "info"]).returncode == 0
        except FileNotFoundError:
            return False

    def _enable_pf(self) -> bool:
        # macOS pfctl supports the reference-counted -E; the BSDs only -e.
        flag = "-E" if self._macos else "-e"
        res = self._run(["pfctl", flag])
        # "pf already enabled" is success for our purposes (rc!=0 but harmless).
        return res.returncode == 0 or "already" in (res.stderr or "").lower()

    def apply(self, cfg: Config) -> None:
        from .firewall import FirewallError

        tor_user = self._tor_user(cfg)
        anchor_file = self._anchor_file(cfg)
        anchor_file.parent.mkdir(parents=True, exist_ok=True)
        anchor_file.write_text(build_anchor_rules(cfg, self._p, tor_user), encoding="utf-8")

        # Hook the anchor into the main ruleset, validating before we commit so a
        # broken pf.conf is never loaded (fail-safe, not fail-open).
        self._ensure_wired(cfg, anchor_file)

        if not self._enable_pf():
            raise FirewallError("pfctl could not enable pf — the killswitch would not be enforced")

        res = self._run(["pfctl", "-a", cfg.pf_anchor, "-f", str(anchor_file)])
        if res.returncode != 0:
            raise FirewallError(res.stderr.strip() or "pfctl failed to load the killswitch anchor")
        # Reload the main ruleset so the new anchor reference takes effect. If
        # this fails the anchor is loaded but unreferenced (not evaluated) — a
        # fail-open we must not hide, so flush the anchor and raise.
        reload = self._run(["pfctl", "-f", str(self._pf_conf)])
        if reload.returncode != 0:
            self._run(["pfctl", "-a", cfg.pf_anchor, "-F", "all"])
            raise FirewallError(
                reload.stderr.strip() or "pfctl could not reload pf.conf to reference the anchor"
            )

        if self._macos:
            self._set_socks_proxy(cfg, enable=True)

    def _ensure_wired(self, cfg: Config, anchor_file: Path) -> None:
        from .firewall import FirewallError

        existing = self._pf_conf.read_text(encoding="utf-8") if self._pf_conf.exists() else ""
        wired = wire_pf_conf(existing, cfg.pf_anchor, str(anchor_file))
        if wired == existing:
            return  # already hooked
        # Validate the would-be ruleset before writing it.
        tmp = self._pf_conf.with_suffix(self._pf_conf.suffix + ".torando.new")
        tmp.write_text(wired, encoding="utf-8")
        check = self._run(["pfctl", "-n", "-f", str(tmp)])
        if check.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise FirewallError(
                f"refusing to modify {self._pf_conf}: the anchor hook would not parse "
                f"({check.stderr.strip()}). Add these two lines to the filter section "
                f'by hand instead:\n  anchor "{cfg.pf_anchor}"\n'
                f'  load anchor "{cfg.pf_anchor}" from "{anchor_file}"'
            )
        bak = self._pf_conf.with_suffix(self._pf_conf.suffix + ".torando.bak")
        if self._pf_conf.exists() and not bak.exists():
            bak.write_bytes(self._pf_conf.read_bytes())
        tmp.replace(self._pf_conf)

    def remove(self, cfg: Config) -> None:
        # Flush the in-kernel anchor (killswitch down now) AND overwrite the
        # anchor file with an inert ruleset, so a later `pfctl -f pf.conf` reload
        # or a reboot — which re-runs the `load anchor` line still in pf.conf —
        # re-loads nothing instead of silently re-arming the killswitch.
        anchor_file = self._anchor_file(cfg)
        try:
            anchor_file.parent.mkdir(parents=True, exist_ok=True)
            anchor_file.write_text("# torando-gui: inactive\n", encoding="utf-8")
        except OSError:
            pass
        self._run(["pfctl", "-a", cfg.pf_anchor, "-F", "all"])
        if self._macos:
            self._set_socks_proxy(cfg, enable=False)

    def _anchor_referenced(self, cfg: Config) -> bool:
        """True only if the ACTIVE main ruleset references our anchor. An anchor
        that is loaded but not referenced is never evaluated (fail-open), so the
        status must not report a killswitch in that case."""
        main = self._run(["pfctl", "-s", "rules"])
        if main.returncode != 0:
            return False
        return f'anchor "{cfg.pf_anchor}"' in (main.stdout or "")

    def status(self, cfg: Config) -> dict[str, object]:
        expected = anchor_rule_count(cfg, self._tor_user(cfg))
        info = self._run(["pfctl", "-s", "info"])
        enabled = info.returncode == 0 and "Status: Enabled" in (info.stdout or "")
        referenced = enabled and self._anchor_referenced(cfg)
        shown = self._run(["pfctl", "-a", cfg.pf_anchor, "-sr"])
        loaded = [ln for ln in (shown.stdout or "").splitlines() if ln.strip()]
        present = len(loaded) if shown.returncode == 0 else 0
        # The killswitch only counts if pf is enabled, the anchor is actually
        # referenced by the active ruleset, and its block rule is loaded.
        killswitch = referenced and any("block" in ln for ln in loaded)
        return {
            "rules_total": expected,
            "rules_present": present,
            "active": referenced and present >= expected,
            "killswitch": killswitch,
        }

    # --- macOS system SOCKS proxy (networksetup) -----------------------------
    def _network_services(self) -> list[str]:
        res = self._run(["networksetup", "-listallnetworkservices"])
        if res.returncode != 0:
            return []
        out = []
        for line in (res.stdout or "").splitlines()[1:]:  # skip the header line
            name = line.strip()
            if name and not name.startswith("*"):  # '*' marks a disabled service
                out.append(name)
        return out

    def _set_socks_proxy(self, cfg: Config, *, enable: bool) -> None:
        host = cfg.host_socks()
        port = str(cfg.socks_port)
        for svc in self._network_services():
            if enable:
                self._run(["networksetup", "-setsocksfirewallproxy", svc, host, port])
                self._run(["networksetup", "-setsocksfirewallproxystate", svc, "on"])
            else:
                self._run(["networksetup", "-setsocksfirewallproxystate", svc, "off"])
