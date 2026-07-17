# Changelog

All notable changes to **Torando Control** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-07-16

Cross-platform. Torando Control now runs on macOS, FreeBSD, OpenBSD and Windows
alongside Linux, and the long-standing IPv6 leak is closed. Every backend is
fail-closed: traffic that can't reach Tor is dropped, never sent in the clear.

### Added — IPv6 killswitch (Linux)
- **The killswitch now covers IPv6.** A new `ip6tables` ruleset (allow the UID's
  loopback, `DROP` everything else) is armed whenever the kernel can carry IPv6.
  IPv6 is blocked rather than torified — Tor's IPv4 DNSPort already resolves AAAA
  records, so there is no v6 anonymity to gain, only a leak to close. This was
  the #1 documented gap in the threat model. Kernel-generated neighbour
  discovery has no socket owner, so a per-UID `--uid-owner` drop never touches
  it. Toggle with `ipv6_killswitch` (default on).
- **Fail-closed on a missing tool.** If the kernel has IPv6 but `ip6tables` is
  unavailable, `connect()` now *refuses* rather than arm a killswitch with an
  open v6 path. Set `ipv6_killswitch=false` to accept the risk.

### Added — macOS, FreeBSD, OpenBSD (pf)
- **A `pf` firewall backend.** A per-UID killswitch anchor (`block out ...
  user <uid>`, loopback and Tor's `_tor` account exempt) is loaded with `pfctl`
  and hooked into the main `pf.conf` through a marker-delimited block —
  **validated with `pfctl -n` before writing**, so a broken hook is never
  loaded (fail-safe). macOS additionally sets the **system SOCKS proxy** via
  `networksetup`; the BSDs route through `torsocks`/per-app SOCKS. DNS is pinned
  with `networksetup` (macOS) or `resolv.conf` + `chflags schg` (BSD).
- **A macOS `.app` bundle** (unsigned, shell-script executable — builds on
  Linux), a LaunchDaemon, an install/uninstall script, and a **Homebrew formula**.
- **rc.d services** for FreeBSD (`service torando-gui`) and OpenBSD
  (`rcctl … torando_gui`), with install scripts and release tarballs.

### Added — Windows
- **A machine-wide killswitch + system proxy.** Windows has no driverless
  per-process redirect, so the honest model: the Windows Firewall is set to
  block outbound on every profile (the prior policy is captured and restored on
  disconnect; only our own named rules are added — never `netsh advfirewall
  reset`), `tor.exe` and loopback are whitelisted, and the WinINET system SOCKS
  proxy is pointed at Tor. Interface DNS is pinned with `netsh`. Admin detection
  is stdlib-only (`ctypes`/`shell32`).
- **A Windows release**: `.cmd` launchers, an `install.ps1` that registers the
  daemon as a boot-time Scheduled Task (SYSTEM), and `uninstall.ps1`.

### Changed
- **Platform-aware everywhere.** New `platform`, `firewall`, `pf`, `winfw` and
  `dns` modules; per-OS default paths (`/etc`, Homebrew prefix, `/usr/local`,
  `%ProgramData%`); per-OS Tor service control (systemd/`service`/`rcctl`/`brew
  services`/Scheduled Task). The proven Linux behaviour is byte-for-byte
  unchanged. `pwd` is imported defensively so the daemon loads on Windows.
- The backend firewall/DNS interface is now `cfg`-based, so each platform reads
  exactly the context it needs.

### Packaging / CI / Docs
- `make windows macos freebsd openbsd`, a GitHub **release workflow** that builds
  every artifact on a tag, and CI jobs on `windows-latest` and `macos-latest`
  (the iptables/`resolv.conf` tests skip themselves off Linux).
- README gets a platform-support matrix and per-OS install; USAGE and
  THREAT_MODEL document the honest per-platform semantics and the IPv6 killswitch.

### Tests
- New suites for the IPv6 ruleset, the pf/Windows/DNS backends (all pure command
  generation, exercised on Linux via fake runners), platform detection, per-OS
  paths, and the fail-closed IPv6 composition. 144 tests, green on Linux.

## [1.1.0] — 2026-06-23

A native desktop app, and the fixes for the bugs that could break connectivity.

### Fixed — critical
- **Killswitch no longer drops the torified user's loopback.** The ruleset now
  exempts `127.0.0.0/8` (a `RETURN` in nat and an `-o lo` `ACCEPT` before the
  `DROP`). Previously, the moment you connected, the killswitch dropped the
  user's loopback — cutting the GUI off from its own daemon and breaking every
  local service. The ruleset grew from 5 to 7 rules.
- **resolv.conf is written world-readable (0644).** The atomic writer used
  `mkstemp` (0600) and `os.replace` kept it, silently making `/etc/resolv.conf`
  root-only — so DNS broke for your normal user *even after disconnect*, forcing
  a manual edit. Now always `0644`.
- **DNS is never left stranded.** connect() pins `resolv.conf` **last** (after
  the redirect is live) and rolls back rules + DNS on any failure; disconnect
  restores the real resolver first and unconditionally; the daemon
  **auto-recovers** an orphaned pin on startup (crash/kill/reboot); and
  `torando-guid --restore-dns` is a one-shot manual escape hatch. The captured
  resolver is refreshed each connect (tracks DHCP changes).
- **A bad/unreadable `config.json` no longer crashes the daemon** (e.g.
  `PermissionError`) — it falls back to safe defaults.
- **Routing fields are locked while connected.** Changing `target_uid` /
  `trans_port` / `dns_port` mid-session would orphan the active killswitch; the
  app now refuses until you disconnect.

### Added — native desktop app
- **`torando-gui` opens a real application window** (GTK4 + WebKitGTK via
  PyGObject), like the Mullvad desktop shell — its own window, icon and taskbar
  entry, no browser chrome. If the GTK stack is absent it falls back to the
  browser (`torando-gui --browser` forces it). The window is unprivileged and
  talks to the daemon over loopback only. New module `torando_gui/desktop.py`.
- GTK4/WebKitGTK/PyGObject declared as **optional** deps (deb `Recommends`, rpm
  `Recommends`, Arch `optdepends`, `pip install torando-gui[gui]`).

### Docs
- Rewrote the docs and added screenshots to the README. [docs/USAGE.md](docs/USAGE.md)
  covers running, recovery and configuration; THREAT_MODEL and README were
  updated for the new ruleset and the DNS handling.

### Tests
- New/updated regression tests for the 7-rule set and loopback ordering, the
  0644 resolv mode, connect/disconnect/recovery invariants, the routing-field
  lock, and config robustness. (Server tests require loopback HTTP, unavailable
  in some sandboxes; the rest run anywhere.)

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
  Shepherd (`herd start torando-gui`). It auto-seeds `/etc/torando-gui/config.json`
  on first activation (`seed-config` field; `manage_torrc=false`, `dns_port=5353`
  by default) so it works out of the box alongside `tor-service-type`. The
  systemd unit remains for systemd hosts.
- **Self-contained Guix package.** `packaging/guix.scm` now rewrites both shims
  to call the store `python3` and prepends the store paths of the tools the
  root daemon shells out to (`iptables`, `chattr` via `e2fsprogs`, `tor`); the
  installed systemd unit points at the store binary instead of `/usr/bin`. The
  source `local-file` excludes `dist/`, `.git/` and build caches. Added as
  `torando-gui` to the **securityops** Guix channel.
- **`e2fsprogs` (`chattr`) declared as a dependency** in the deb, rpm, Arch and
  Guix definitions (the daemon sets the `resolv.conf` immutable bit).
- Self-hosted **Forgejo** is the official repository; GitHub and Codeberg are
  mirrors. Home-page URLs point at the public GitHub mirror.

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

[1.2.0]: https://github.com/cristiancmoises/torando-gui/releases/tag/v1.2.0
[1.1.0]: https://github.com/cristiancmoises/torando-gui/releases/tag/v1.1.0
[1.0.1]: https://github.com/cristiancmoises/torando-gui/releases/tag/v1.0.1
[1.0.0]: https://github.com/cristiancmoises/torando-gui/releases/tag/v1.0.0
