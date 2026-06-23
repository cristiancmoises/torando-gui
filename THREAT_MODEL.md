# Threat model

What Torando Control protects, what it doesn't, and the assumptions behind both.
Read the non-goals before trusting it with anything.

## What it is

A loopback web GUI plus a root daemon that automate the upstream `torando`
transparent-proxy setup. It forces one local UID's egress through Tor's
TransPort and DNSPort, drops everything else from that UID (the killswitch),
pins `/etc/resolv.conf` to `127.0.0.1`, and manages a marker-delimited block in
`/etc/tor/torrc`. The GUI is served only on loopback.

It does the same thing as running the upstream `torando.sh`/`toroff.sh` rules by
hand, with torrc/resolv.conf management and a status view on top.

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

**IPv6 and non-UDP/53 DNS.** The ruleset is IPv4 and redirects UDP/53. Active
IPv6 egress, DoT/DoH to a fixed resolver, or QUIC can route around it. Disabling
IPv6 for the torified UID is the operator's job; it isn't automatic yet.

**Other UIDs.** Only the selected UID is torified; everything else egresses
normally.

## Known weak points

- The systemd unit runs as full root. A `CAP_NET_ADMIN` + `CAP_LINUX_IMMUTABLE`
  bounding set would shrink the blast radius, but the daemon also writes
  `/etc/tor` and calls `systemctl`, so it isn't in place yet.
- No automatic IPv6 killswitch (see above). This is the top roadmap item.
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
