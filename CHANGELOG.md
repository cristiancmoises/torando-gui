# Changelog

All notable changes to **Torando Control** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-06-23

A correctness, robustness and packaging pass. No behaviour changes for a
successful connect; the fixes harden the failure paths and the Guix packaging.

### Fixed
- **Failed connect no longer degrades host DNS.** `connect()` pins
  `/etc/resolv.conf` to `127.0.0.1` before installing the netfilter rules. If
  rule application then failed, the pin (often `chattr +i` immutable) was left
  in place with the killswitch never armed — breaking name resolution
  system-wide. A failed connect now rolls the `resolv.conf` pin back.
- **Durable atomic writes.** `config.save` and the `torrc`/`resolv.conf` writers
  now `fsync` the file and its parent directory before/after `os.replace`, so a
  crash mid-write can no longer publish a truncated or empty
  `/etc/resolv.conf` or config.
- **Corrupt GeoIP database can no longer crash the daemon.** A truncated or
  malicious `.mmdb` made the decoder raise `IndexError`/`struct.error`/
  `RecursionError`; these are now translated to "no location", honouring the
  reader's documented never-crash contract.
- **`torrc` keeps exactly one managed block.** `merge_torrc` now collapses any
  stale duplicate managed blocks instead of leaving older directives active.
- **`resolv.conf` backup is refreshed.** The pre-lock backup is removed after a
  successful restore, so the next connect captures the resolver that is live
  then (e.g. after a DHCP change) rather than replaying a stale snapshot.

### Changed / Hardened
- **Tor control auth advertises only what it implements.** The control client
  performs plain `COOKIE` authentication; the unimplemented `SAFECOOKIE`
  (`AUTHCHALLENGE`) branch was removed. Tor's default `CookieAuthentication`
  advertises `COOKIE` alongside `SAFECOOKIE`, so loopback cookie auth is
  unaffected.
- **`?token=` is GET-only.** The query-string token shortcut exists for the
  `EventSource` (`GET /api/events`) stream; it can no longer satisfy a `POST`,
  keeping CSRF defence bound to the `X-Torando-Token` header.
- **`HEAD` requests never open the SSE stream** or return a body, per HTTP
  semantics.
- **Launcher surfaces `systemctl` errors.** A failed `systemctl start` (e.g. a
  polkit denial) now reports its stderr instead of a generic "not reachable".

### Packaging
- **GNU Guix System (Shepherd) service.** Guix supervises daemons with the GNU
  Shepherd, not systemd, so the bundled systemd unit is inert there. Added a
  native `torando-gui-service-type` — standalone in
  `packaging/torando-gui-shepherd.scm`, and in the securityops channel as
  `(securityops services torando)` — that runs `torando-guid` as root via the
  Shepherd (`herd start torando-gui`). The systemd unit remains for systemd
  hosts.
- **Self-contained Guix package.** `packaging/guix.scm` now rewrites both shims
  to call the store `python3` and prepends the store paths of the tools the
  root daemon shells out to (`iptables`, `chattr` via `e2fsprogs`, `tor`); the
  installed systemd unit points at the store binary instead of `/usr/bin`. The
  source `local-file` excludes `dist/`, `.git/` and build caches. Added as
  `torando-gui` to the **securityops** Guix channel.
- **`e2fsprogs` (`chattr`) declared as a dependency** in the deb, rpm, Arch and
  Guix definitions (the daemon sets the `resolv.conf` immutable bit).
- Project/home-page URLs point at the public **Codeberg** repository, with
  GitHub and the self-hosted Forgejo listed as mirrors.

### Notes
- The `dist/` binaries shipped alongside this tree are the **1.0.0** release
  downloads. Rebuild 1.0.1 packages with `make all` on a host that has
  `dpkg-deb`/`rpmbuild`/`appimagetool`; the Guix package builds 1.0.1 from
  source directly.
- **IPv6 egress is still not filtered** (the ruleset is IPv4-only) and the
  killswitch does not cover IPv6 — a deliberate, documented limitation tracked
  in [THREAT_MODEL.md](THREAT_MODEL.md). Disable IPv6 for the torified UID, or
  extend the ruleset, until a v6 killswitch ships.

## [1.0.0] — 2026-06-19

Initial release.

### Added
- Loopback web GUI + root daemon that reproduces the upstream `torando`
  five-rule per-UID transparent torification and killswitch, builds every
  `iptables` call as an `exec` argv (no shell), and validates the target UID
  against the passwd database.
- Marker-delimited `/etc/tor/torrc` management and `/etc/resolv.conf` pinning
  (optionally immutable), both backed up first and written atomically.
- Live status: Tor bootstrap, circuit count, DNS-leak and exit verification
  (through Tor's SOCKS port), offline GeoIP/city resolution from Tor's own
  GeoIP and an optional GeoLite2-City `.mmdb`.
- Hardened loopback HTTP surface: per-session token (constant-time compare),
  no CORS, Host-header allowlist, same-origin POST check, strict CSP.
- Packaging for Debian, Fedora/RHEL, Arch, GNU Guix, AppImage and a portable
  `.tar.zst`; systemd unit, polkit policy, desktop entry and icons.
- [THREAT_MODEL.md](THREAT_MODEL.md) and a unit-test suite covering the engine,
  SOCKS framing, exit-check invariants, config, `torrc`/`resolv` editing and the
  server's access controls.

[1.0.1]: https://codeberg.org/cristiancmoises/torando-gui/releases/tag/v1.0.1
[1.0.0]: https://codeberg.org/cristiancmoises/torando-gui/releases/tag/v1.0.0
