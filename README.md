# Torando Control

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![Python ≥ 3.11](https://img.shields.io/badge/python-%E2%89%A5%203.11-blue.svg)](pyproject.toml)
[![No third-party deps](https://img.shields.io/badge/dependencies-stdlib%20only-success.svg)](pyproject.toml)

A **native desktop app** (GTK4 + WebKitGTK — like the Mullvad VPN app's shell,
not a browser tab) that routes one Linux user's egress through Tor as a
transparent proxy, with a killswitch. It automates the upstream
[`torando`](https://github.com/cristiancmoises/torando) iptables setup
(`torando.sh`/`toroff.sh`) and the `torrc`/`resolv.conf` edits its README
describes, and adds live status, DNS-leak and exit checks, and safe rule
management. (No GTK stack installed? The launcher falls back to your browser —
same UI.)

Read [THREAT_MODEL.md](THREAT_MODEL.md) first. In particular: this is **not**
Tor Browser and does not provide Tor Browser's anonymity set — it routes
packets, it does not anonymize application fingerprints.

**Docs:** [Usage](docs/USAGE.md) · [Security architecture](docs/SECURITY.md) ·
[Performance](docs/PERFORMANCE.md) · [Threat model](THREAT_MODEL.md) ·
[Changelog](CHANGELOG.md)

> **Architecture.** A small **root daemon** (`torando-guid`, pure stdlib) does
> all privileged work and serves a loopback API; an **unprivileged GUI**
> (`torando-gui`) talks to it over `127.0.0.1` only. The GUI has no privileges.

> **Repositories.** Canonical on **Codeberg**, mirrored to GitHub and a
> self-hosted Forgejo:
> [codeberg.org/cristiancmoises/torando-gui](https://codeberg.org/cristiancmoises/torando-gui)
> · [github.com/cristiancmoises/torando-gui](https://github.com/cristiancmoises/torando-gui)
> · [git.securityops.co/cristiancmoises/torando-gui](https://git.securityops.co/cristiancmoises/torando-gui).
> See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## How it works

The daemon installs a per-UID transparent-proxy + killswitch ruleset (loopback
is exempt so the GUI and local services keep working — see
[docs/SECURITY.md](docs/SECURITY.md)):

1. `nat/OUTPUT` — to `127.0.0.0/8` → `RETURN` (never torify loopback)
2. `nat/OUTPUT` — TCP from the UID → `REDIRECT` to Tor `TransPort` (9040)
3. `nat/OUTPUT` — UDP/53 from the UID → `REDIRECT` to Tor `DNSPort`
4. `filter/OUTPUT` — output on `lo` → `ACCEPT` (loopback stays local)
5. `filter/OUTPUT` — TCP to `TransPort` → `ACCEPT`
6. `filter/OUTPUT` — UDP to `DNSPort` → `ACCEPT`
7. `filter/OUTPUT` — anything else from the UID → `DROP` (the killswitch)

It also writes a marker-delimited block into `/etc/tor/torrc`
(`VirtualAddrNetwork`, `AutomapHostsOnResolve`, `TransPort`, `DNSPort`,
`SocksPort`, optionally `ControlPort`, `ExitNodes`, bridges) and pins
`/etc/resolv.conf` to `nameserver 127.0.0.1`, backing up the originals first.

Unlike the upstream shell script, the target user is validated against the
passwd database and every `iptables` call is an `exec` argv with no shell, so a
crafted username cannot inject commands.

The GUI is served only on `127.0.0.1:8088`. The API is gated by a per-session
token injected into the page, an allowlisted `Host` header (anti DNS-rebinding),
a same-origin check on POSTs, and a strict CSP. No CORS headers are ever sent.

## Requirements

- Linux with `tor`, `iptables` (legacy or nft-backed), and `systemd`.
- Python ≥ 3.11 (standard library only — no third-party Python dependencies).
- Root for the daemon (it edits netfilter, `torrc`, `resolv.conf`).

## Install

Download the release assets from the [Codeberg releases
page](https://codeberg.org/cristiancmoises/torando-gui/releases) (or a mirror).

### Debian / Ubuntu
```sh
sudo apt install ./torando-gui_1.0.1_all.deb
sudo systemctl enable --now torando-gui.service
torando-gui            # opens the UI in your browser
```

### Fedora / RHEL
```sh
sudo dnf install ./torando-gui-1.0.1-1.noarch.rpm
sudo systemctl enable --now torando-gui.service
torando-gui
```

### Arch
```sh
makepkg -si            # from the packaging/ directory (uses PKGBUILD)
sudo systemctl enable --now torando-gui.service
torando-gui
```

### GNU Guix
Build and install the package straight from the checkout:
```sh
guix package -f packaging/guix.scm
```
The Guix build is **self-contained**: both shims are rewritten to call the
store `python3` and prepend the store paths of `iptables`, `chattr`
(`e2fsprogs`) and `tor` — nothing extra is needed on the profile's `PATH`.

It is also published in the **securityops** channel; with that channel on your
load path you can simply:
```sh
guix install torando-gui
# or, without pulling, from a local channel checkout:
guix install -L /path/to/securityops-channel torando-gui
```

#### Run as a service on Guix System (GNU Shepherd)
Guix System supervises daemons with the **GNU Shepherd, not systemd** — so the
`torando-gui.service` systemd unit shipped in this package is inert on Guix. The
**securityops** channel provides a native service type,
`torando-gui-service-type` in `(securityops services torando)`. Add it to your
`operating-system`:
```scheme
(use-modules (securityops services torando))

(operating-system
  ;; …
  (services
   (cons* (service torando-gui-service-type)   ; runs torando-guid on 127.0.0.1:8088
          (service tor-service-type)           ; Tor itself (Shepherd-managed)
          %desktop-services)))                 ; or %base-services + a network service
```
`guix system reconfigure`, then `herd start torando-gui` (it also runs at boot).
The daemon runs as root under Shepherd and logs to `/var/log/torando-gui.log`;
run the `torando-gui` launcher to open the UI. Config fields: `host`, `port`,
`package`, `config-file`, `seed-config`, `extra-options`.

> On Guix System `/etc/tor/torrc` is a read-only store symlink owned by
> `tor-service-type`, so the service **auto-seeds `/etc/torando-gui/config.json`**
> on first activation (only if absent, so GUI changes persist) with
> `"manage_torrc": false` and `"dns_port": 5353` — matching a typical
> `tor-service-type`, so it works out of the box with no manual toggling.
> Override via the `seed-config` field (a JSON string, or `#f`). The netfilter
> rules, DNS pinning, killswitch and status work normally; Tor service control
> from the GUI uses `systemctl` and is a no-op on Guix (use `herd`).

The `packaging/systemd/torando-gui.service` unit is for **systemd** hosts
(Debian/Fedora/Arch, or `guix package` on a systemd distro).

### AppImage (no system install)
```sh
chmod +x Torando_Control-x86_64.AppImage
./Torando_Control-x86_64.AppImage
```
The AppImage uses `pkexec` to start the root daemon and needs a system
`python3` ≥ 3.11 (the app is pure-stdlib and is not bundled with a Python
runtime). It does not install a systemd unit; the daemon runs for the session.

### Portable tarball
A relocatable `DESTDIR`-style tree with an `install.sh`/`uninstall.sh`, produced
by `make tarball` (`packaging/build-tarball.sh`):
```sh
tar --zstd -xf torando-gui-1.0.1.tar.zst
cd torando-gui-1.0.1 && sudo ./install.sh
```
(The `*-src.tar.gz` published next to it is the source snapshot, not the
installable tree.)

## Usage

1. Start the service (`systemctl start torando-gui.service`) or run
   `torando-gui`, which will start it for you via polkit on a desktop session.
2. In the UI, pick the user whose traffic should go through Tor.
3. Press the onion. The dial tracks Tor's bootstrap; once routed, the exit card
   shows the Tor exit IP and the DNS card confirms resolution is pinned.
4. "New identity" requests a fresh circuit (`NEWNYM`).
5. Press the onion again to disconnect; rules are removed and `resolv.conf` is
   restored from backup.

Settings (gear icon) expose the Tor ports, exit-country pin, control port,
`resolv.conf` locking, and bridge lines.

### Run the daemon directly (debugging)
```sh
sudo torando-guid --host 127.0.0.1 --port 8088
# UI preview with no privileges and no Tor:
torando-guid --mock --open
```

## Build from source

```sh
make test           # ruff check + ruff format --check + pytest
make deb            # -> dist/torando-gui_1.0.1_all.deb           (needs dpkg-deb)
make rpm            # -> dist/torando-gui-1.0.1-1.noarch.rpm      (needs rpmbuild)
make appimage       # -> dist/Torando_Control-x86_64.AppImage     (needs appimagetool)
make tarball        # -> dist/torando-gui-1.0.1.tar.zst           (needs zstd)
make all            # every format whose tooling is present on this host
```

## Layout

- `backend/torando_gui/` — daemon, engine, Tor control client, SOCKS/exit
  check, torrc/resolv management, server, launcher.
- `backend/torando_gui/webroot/` — the single-page UI (no build step, no remote
  assets).
- `tests/` — unit tests for the engine, SOCKS framing, exit-check invariants,
  config, torrc/resolv editing, and the server's access controls.
- `packaging/` — systemd unit, polkit policy, desktop entry, icon, and the
  per-format build scripts (`guix.scm` for the Guix package;
  `torando-gui-shepherd.scm` for the Guix System Shepherd service).
- `THREAT_MODEL.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` — project
  docs; CI for GitHub and Forgejo/Codeberg lives in `.github/` and `.forgejo/`.

## License

AGPL-3.0-only. See [LICENSE](LICENSE). Upstream `torando` is GPL-3.0; this is an
independent GUI that drives the same iptables behavior.
