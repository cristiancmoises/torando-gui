# Security Policy

Torando Control is a privacy/security tool: it routes a Linux user's egress
through Tor and installs a killswitch. Please treat vulnerabilities accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it
privately, by email, to:

- **cristian@securityops.co** (maintainer)

Include: affected version (`torando-guid --version`), distro and packaging
format (deb/rpm/Arch/Guix/AppImage), a description, and a reproduction or proof
of concept. If you need encryption, say so in a first plaintext mail and a key
will be exchanged.

You will get an acknowledgement within a few days. Once a fix is ready it will
be released across all mirrors (Codeberg, GitHub, Forgejo) with a coordinated
advisory; credit is given unless you prefer otherwise.

## Scope

In scope (please report):

- Bypasses of the killswitch or DNS pinning that let the torified UID's traffic
  egress in the clear in a configuration the tool claims to protect.
- Auth/CSRF/host-header bypasses of the loopback control surface.
- Command injection, path traversal, or privilege issues in the root daemon.
- Crashes or unsafe state from malformed input (e.g. a crafted GeoIP DB,
  `torrc`, or control-port reply).

Out of scope — these are **documented design boundaries**, not bugs (see
[THREAT_MODEL.md](THREAT_MODEL.md)):

- **IPv6 egress is not filtered** (IPv4-only ruleset); no automatic IPv6
  killswitch yet.
- Anonymity-set / fingerprinting properties — this is not Tor Browser.
- A compromised root account or kernel; other local users on a multi-user host;
  Tor's own threat model (global passive adversary, traffic correlation,
  malicious exits).

## Supported versions

The latest released minor version receives security fixes. Older versions are
not maintained.
