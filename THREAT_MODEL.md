# Threat model

What Torando Control protects, what it doesn't, and the assumptions behind both.
Read the non-goals before trusting it with anything.

## What it is

A loopback web GUI plus a root/Administrator daemon that route a user's egress
through Tor with a fail-closed killswitch. The mechanism is platform-specific:

- **Linux** — a per-UID *transparent* proxy: iptables REDIRECT of the UID's TCP
  and UDP/53 to Tor's TransPort/DNSPort, a `DROP` killswitch for everything else,
  and (new in 1.2.0) an **ip6tables IPv6 killswitch** that drops the UID's v6
  egress. This is the original upstream `torando` behaviour, hardened.
- **macOS / FreeBSD / OpenBSD** — a per-UID `pf` killswitch (`block out ...
  user <uid>`, loopback and Tor's account exempt) hooked into `pf.conf`, plus a
  system SOCKS proxy (macOS `networksetup`) or `torsocks`/per-app SOCKS (BSD).
- **Windows** — a *machine-wide* model: the Windows Firewall set to block
  outbound (whitelisting `tor.exe` and loopback) plus the WinINET system SOCKS
  proxy. There is no per-process redirect without a kernel driver, which this
  stdlib-only tool deliberately avoids.

On every platform it pins DNS to `127.0.0.1` (`resolv.conf`+immutable flag,
`networksetup`, or `netsh`) and, where it manages Tor, keeps a marker-delimited
block in the `torrc`. The GUI is served only on loopback.

## Trust assumptions

- The kernel, `tor`, netfilter and the Python runtime are intact.
- Root is trusted. The daemon is root-equivalent by necessity.
- The host is single-user, or its loopback isn't shared with untrusted local
  users (see non-goals).
- Tor provides the anonymity; this tool only routes traffic into it.

## What it protects against

**Accidental clearnet egress.** The final `DROP` means that if Tor is down or
the redirect is gone, the UID's traffic is dropped, not sent in the clear.
Loopback (`127.0.0.0/8`) is accepted before the drop so local IPC and the GUI's
own connection keep working; loopback never leaves the host, so this doesn't
weaken anything.

**DNS leakage.** UDP/53 from the UID goes to Tor's DNSPort and `resolv.conf` is
pinned to `127.0.0.1` (optionally made immutable with `chattr +i`). The pin is
written world-readable (0644) and the real resolver is captured first, so
disconnect always restores working DNS. A crash or reboot is recovered on the
next daemon start, and `torando-guid --restore-dns` is a manual escape hatch.

**Attacks on the control surface.** The local API needs a per-session token
injected into the page. No CORS headers are ever sent, so a foreign origin's JS
can't read the token or call the API. POSTs also require a same-origin
Origin/Referer, the Host header is allowlisted against DNS-rebinding, and a
strict CSP is set.

**Command injection via the target user.** The upstream script interpolated a
username into a shell command. Here the UID is validated against passwd and every
`iptables` call is an argv with no shell.

**Half-applied firewall state.** Each rule is `-C`-checked before being added and
the whole set is rolled back if any rule fails, so the table is never half-built.
A connect that fails after `resolv.conf` was pinned also rolls the pin back.

## What it does NOT protect against

**It is not Tor Browser.** Transparent torification routes packets, but
applications keep their normal fingerprints (User-Agent, fonts, screen size,
language, WebRTC). Two users of this tool don't blend together the way two Tor
Browser users do. For web anonymity, use Tor Browser.

**A compromised root or kernel.** Anything with root can remove the rules, read
traffic before encryption, or replace the daemon.

**Tor's own limits.** Global passive adversaries, traffic correlation, and
hostile exit nodes are out of scope; they belong to Tor and the network. Traffic
to a non-onion destination is readable at the exit, so use TLS regardless.

**Application-layer deanonymization.** Logging into a named account or leaking
identifiers in requests deanonymizes you no matter how packets are routed.

**Other local users.** The control surface is loopback-only and token-gated
against browsers, but the token file under `/run/torando-gui` is group-readable.
A local user who can read it, or read the served page, can drive the API. Treat
the host as single-user, or lock down the runtime directory.

**Non-UDP/53 DNS, and QUIC.** DoT/DoH to a fixed resolver bypasses the DNS pin
(the traffic is still dropped by the killswitch unless it can reach Tor). On
Linux, UDP other than DNS — including QUIC/HTTP3 on UDP/443 — is caught by the
final `DROP`; on macOS/BSD the pf killswitch blocks the UID's non-torified
TCP/UDP; on Windows the machine-wide block covers it. It is dropped, not leaked.

**IPv6 is blocked, not torified.** Since 1.2.0 the killswitch covers IPv6:
Linux drops the UID's v6 egress with `ip6tables`, and the pf/Windows backends
block v6 too. So v6 no longer *leaks*, but v6 destinations are simply
unreachable for the routed user (Tor's v4 DNSPort still resolves AAAA records).
If the kernel can carry IPv6 but `ip6tables` is unavailable, Linux **refuses to
connect** rather than arm a killswitch with an open v6 path. `pf`'s `user` token
only matches TCP/UDP, so ICMP/ICMPv6 for the user is not blocked on macOS/BSD.

**Other UIDs.** On Linux/macOS/BSD only the selected UID is routed; everything
else egresses normally. Windows is machine-wide by necessity: the whole machine
is routed, so there is no per-user scoping there.

## Known weak points

- The systemd unit runs as full root. A `CAP_NET_ADMIN` + `CAP_LINUX_IMMUTABLE`
  bounding set would shrink the blast radius, but the daemon also writes
  `/etc/tor` and calls `systemctl`, so it isn't in place yet.
- **The macOS/BSD/Windows backends are beta.** The Linux transparent proxy is the
  battle-tested path; the others were designed against vendor documentation but
  each user should confirm on their host that the exit card shows Tor and that a
  non-cooperating app is blocked with Tor stopped. Their killswitch is
  authoritative (fail-closed), but the *routing into Tor* depends on apps
  honouring the system SOCKS proxy.
- **pf.conf editing (macOS/BSD).** The daemon hooks its killswitch anchor into
  the main `pf.conf` with a marker block, validating the result with `pfctl -n`
  before writing and backing the file up first; `status` reports the killswitch
  as armed only when pf is enabled *and* the active ruleset actually references
  the anchor. One caveat it cannot detect: pf stops at the first matching
  `quick` rule, so a pre-existing `pass out quick …` earlier in your `pf.conf`
  would be matched before the anchor and defeat the block. If your ruleset uses
  quick-style pass rules, place the `anchor "torando-gui"` reference ahead of
  them, and confirm with the exit card that traffic is actually routed.
- **Windows is machine-wide** and honours the WinINET SOCKS proxy, which resolves
  DNS locally (SOCKS4-style); the killswitch blocks port-53 egress and DNS is
  pinned to Tor's DNSPort to compensate, but apps that bypass WinINET (Firefox
  with its own proxy off, raw-socket tools) are blocked, not routed.
- The exit check trusts `check.torproject.org`. If it's unreachable the UI
  reports "unknown" rather than guessing; it never fabricates a verdict.

## Checking the claims yourself

```sh
iptables -t nat -S OUTPUT      # the REDIRECT + loopback RETURN rules
iptables -S OUTPUT             # the ACCEPTs and the final DROP
cat /etc/resolv.conf           # nameserver 127.0.0.1 while connected
lsattr /etc/resolv.conf        # the immutable bit while connected
```
With the rules applied and `tor` stopped, traffic from the torified UID should
fail rather than reach the network. The GUI's exit card queries
`check.torproject.org/api/ip` through Tor's SOCKS port and shows the exit IP and
`IsTor` verdict.
