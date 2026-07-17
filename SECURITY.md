# Security policy

Torando Control routes a user's traffic through Tor and installs a killswitch,
so treat vulnerabilities seriously.

## Reporting

Don't open a public issue for a security bug. Email it privately to
**cristian@securityops.co**.

Include the version (`torando-guid --version`), your OS and packaging format
(deb/rpm/Arch/Guix/AppImage, macOS `.app`/Homebrew, the FreeBSD/OpenBSD tarball,
or the Windows zip), what you found, and a way to reproduce it. If you want
encryption, say so in a first plaintext mail and we'll exchange a key.

You'll get an acknowledgement within a few days. Once there's a fix it ships
across the official repo and mirrors (Forgejo, GitHub, Codeberg) with an
advisory, and you get credit unless you'd rather not.

## In scope

- Bypasses of the killswitch or DNS pinning that let the torified traffic leave
  in the clear (IPv4 **or** IPv6) in a setup the tool claims to protect, on any
  supported platform.
- A firewall/DNS/proxy teardown that fails to restore the prior state — e.g. a
  disconnect that leaves the host without DNS, or (on Windows) blocking outbound
  with the Tor allow-rule already deleted.
- Auth, CSRF or Host-header bypasses of the loopback control surface.
- Command injection, path traversal, or privilege issues in the daemon
  (including the `pf.conf`/`netsh`/`networksetup` command construction).
- Crashes or unsafe state from malformed input (a crafted GeoIP DB, `torrc`, or
  control-port reply).

## Out of scope

These are documented design boundaries, not bugs (see
[THREAT_MODEL.md](THREAT_MODEL.md)):

- On macOS/BSD/Windows, apps that ignore the system SOCKS proxy are *blocked* by
  the killswitch, not transparently routed — that is by design (only Linux does
  a per-process transparent redirect). A blocked app is fail-closed, not a leak.
- ICMP/ICMPv6 for the torified user on macOS/BSD (pf's `user` token only tags
  TCP/UDP).
- Fingerprinting and anonymity-set properties; this isn't Tor Browser.
- A compromised root/Administrator or kernel, other local users on a shared
  host, and Tor's own threat model (global passive adversary, traffic
  correlation, hostile exits).

## Supported versions

The latest released minor version gets security fixes. Older versions don't.
