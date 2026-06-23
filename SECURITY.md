# Security policy

Torando Control routes a user's traffic through Tor and installs a killswitch,
so treat vulnerabilities seriously.

## Reporting

Don't open a public issue for a security bug. Email it privately to
**cristian@securityops.co**.

Include the version (`torando-guid --version`), your distro and packaging format
(deb/rpm/Arch/Guix/AppImage), what you found, and a way to reproduce it. If you
want encryption, say so in a first plaintext mail and we'll exchange a key.

You'll get an acknowledgement within a few days. Once there's a fix it ships
across the official repo and mirrors (Forgejo, GitHub, Codeberg) with an
advisory, and you get credit unless you'd rather not.

## In scope

- Bypasses of the killswitch or DNS pinning that let the torified UID's traffic
  leave in the clear in a setup the tool claims to protect.
- Auth, CSRF or Host-header bypasses of the loopback control surface.
- Command injection, path traversal, or privilege issues in the daemon.
- Crashes or unsafe state from malformed input (a crafted GeoIP DB, `torrc`, or
  control-port reply).

## Out of scope

These are documented design boundaries, not bugs (see
[THREAT_MODEL.md](THREAT_MODEL.md)):

- IPv6 egress isn't filtered yet (IPv4-only ruleset).
- Fingerprinting and anonymity-set properties; this isn't Tor Browser.
- A compromised root or kernel, other local users on a shared host, and Tor's
  own threat model (global passive adversary, traffic correlation, hostile
  exits).

## Supported versions

The latest released minor version gets security fixes. Older versions don't.
