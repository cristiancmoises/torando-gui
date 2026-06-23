# Torando Control — Threat Model

This document states what Torando Control protects, what it does not, and the
assumptions behind those claims. It is written for someone deciding whether the
tool fits a given threat. Read the non-goals before relying on it.

## What it is

Torando Control is a local web GUI and root daemon that automates the upstream
`torando` transparent-proxy setup: it forces the egress traffic of one chosen
local UID through Tor's `TransPort`/`DNSPort`, drops everything else from that
UID (a killswitch), pins `/etc/resolv.conf` to `127.0.0.1`, and manages a
marker-delimited block in `/etc/tor/torrc`. The GUI is served only on loopback.

It is functionally equivalent to running the upstream `torando.sh`/`toroff.sh`
iptables rules by hand, plus torrc/resolv.conf management and a status view.

## Assets

- The user's network-level egress (destination IPs, DNS queries) for the
  torified UID.
- Local control of the daemon (it can rewrite firewall rules and `torrc`).

## Trust assumptions

- The kernel, `tor`, `iptables`/netfilter, and the Python runtime are intact
  and not backdoored.
- Root on the host is trusted. The daemon *is* root-equivalent by necessity.
- The loopback interface is not shared with untrusted local users on a
  multi-user box (see non-goals).
- Tor itself provides the anonymity properties; this tool only routes traffic
  into it.

## What it protects against

1. **Accidental clearnet egress for the chosen UID.** The final `DROP` rule
   means that if Tor is down or the redirect is removed, that UID's traffic is
   dropped, not sent in the clear. This is the killswitch. Loopback
   (`127.0.0.0/8`) is explicitly accepted *before* the drop, so the killswitch
   never blocks local IPC (including the GUI's own connection to the daemon) —
   loopback never leaves the host, so this does not weaken the guarantee.
2. **Local DNS leakage.** UDP/53 from the UID is redirected to Tor's `DNSPort`
   and `resolv.conf` is pinned to `127.0.0.1` (optionally made immutable with
   `chattr +i`), so name resolution does not bypass Tor. The pin is written
   **world-readable (0644)** and the client's real resolver is captured first,
   so disconnect always restores working DNS; a crash/kill/reboot is recovered
   on next daemon start, and `torando-guid --restore-dns` is a manual escape
   hatch — DNS is never left stranded.
3. **Browser/page-based attacks on the control surface.** The local API
   requires a per-session token injected into the page by the server; no CORS
   headers are ever sent (a foreign origin's JS cannot read the token or use
   the API); POSTs additionally require a same-origin `Origin`/`Referer`; the
   `Host` header is allowlisted to defeat DNS-rebinding; a strict CSP is set.
4. **Command injection via the target user.** The upstream script interpolated
   a username into a shell command. Here the UID is validated against the
   passwd database and every `iptables` invocation is an `exec` argv with no
   shell, so a crafted username cannot inject commands.
5. **Half-applied firewall state.** Rules are checked with `-C` before adding
   and rolled back if any rule in the set fails, so the table is never left
   partially built. A connect that fails *after* `/etc/resolv.conf` was pinned
   to `127.0.0.1` also rolls that pin back, so a failed connect never leaves the
   host's DNS pointing at a local resolver the killswitch never armed.

## What it does NOT protect against (non-goals)

- **It is not Tor Browser and does not provide Tor Browser's anonymity set.**
  Transparent torification routes packets, but applications keep their normal
  fingerprints (User-Agent, fonts, screen size, language, plugins, WebRTC,
  `navigator` surface). Two users of this tool do not look alike the way two
  Tor Browser users do. For web anonymity, use Tor Browser; this tool is for
  routing arbitrary application traffic, not for blending into a crowd.
- **A compromised root or kernel.** Anything with root can remove the rules,
  read the traffic before it is encrypted, or replace the daemon. The daemon
  cannot defend the host against the privilege it itself holds.
- **Tor's own limits.** Global passive adversaries, traffic-correlation /
  end-to-end timing attacks, and malicious or hostile exit nodes are out of
  scope — they are properties of Tor and the network, not of this tool. Traffic
  to a non-onion destination is readable by the exit relay; use end-to-end
  encryption (TLS) regardless.
- **Application-layer deanonymization.** Logging into a named account, leaking
  identifiers in request bodies, or running a browser without anti-fingerprint
  hardening will deanonymize you no matter how the packets are routed.
- **Other local users on a multi-user host.** The control surface is bound to
  loopback and token-gated against *browsers*, but the token file under
  `/run/torando-gui` is readable by its group; a local user in that group, or
  any local user able to read the served page, can drive the API. Treat the
  host as single-user, or restrict the runtime directory.
- **IPv6 and non-UDP/53 DNS by default.** The reproduced upstream ruleset
  operates on the IPv4 `OUTPUT` path and redirects UDP/53. Hosts with active
  IPv6 egress, DNS-over-TLS/HTTPS to a fixed resolver, or QUIC may route around
  the rules. Disabling IPv6 for the torified UID, or extending the ruleset, is
  the operator's responsibility and is not done automatically in this release.
- **Traffic of other UIDs.** Only the selected UID is torified. Everything else
  on the system egresses normally.
- **Persistence across `torsocks`-unaware setuid/forking.** Processes that
  change UID away from the torified one will not be covered.

## Known weak points tracked for later work

- The systemd unit runs as full root. A capability bounding set
  (`CAP_NET_ADMIN` + `CAP_LINUX_IMMUTABLE`) with `tor` reload delegated through
  a narrow interface would reduce blast radius; it is not yet in place because
  the daemon also writes `/etc/tor` and calls `systemctl`.
- No IPv6 killswitch is installed automatically (see above).
- The exit-verification check trusts `check.torproject.org`; if that endpoint
  is unreachable the UI reports "unknown" rather than guessing — it never
  fabricates a verdict, but it also cannot verify offline.

## Verifying the claims yourself

- Inspect the applied rules: `iptables -t nat -S OUTPUT` and
  `iptables -S OUTPUT`.
- Confirm the killswitch: with the rules applied and `tor` stopped, traffic
  from the torified UID should fail rather than reach the network.
- Confirm DNS pinning: `cat /etc/resolv.conf` and `lsattr /etc/resolv.conf`.
- Confirm the exit: the GUI's exit card queries `check.torproject.org/api/ip`
  through Tor's SOCKS port and shows the reported IP and `IsTor` verdict.
