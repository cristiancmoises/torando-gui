# Torando Control

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![stdlib only](https://img.shields.io/badge/dependencies-stdlib%20only-success.svg)](pyproject.toml)

Routes one Linux user's traffic through Tor as a transparent proxy, with a
killswitch so nothing leaks if Tor goes down. Desktop app on top of a small root
daemon. It does the same job as the [`torando`](https://github.com/cristiancmoises/torando)
shell scripts (iptables redirect to Tor's TransPort/DNSPort, `torrc` and
`resolv.conf` edits), but adds a UI, live status and exit checks, transactional
rule changes, and DNS that always restores itself.

<p align="center">
  <img src="docs/screenshots/connected.png" alt="Connected" width="280">
  &nbsp;
  <img src="docs/screenshots/disconnected.png" alt="Disconnected" width="280">
  &nbsp;
  <img src="docs/screenshots/settings.png" alt="Settings" width="280">
</p>

This is not Tor Browser. It routes packets; it does not hide application
fingerprints. Read [THREAT_MODEL.md](THREAT_MODEL.md) before you rely on it.

Docs: [Usage](docs/USAGE.md) · [Threat model](THREAT_MODEL.md) ·
[Changelog](CHANGELOG.md) · [Security policy](SECURITY.md)

## How it works

There are two pieces. `torando-guid` is the root daemon: it programs netfilter,
edits `torrc` and `resolv.conf`, talks to Tor's control port, and serves a UI on
`127.0.0.1:8088`. `torando-gui` is the front end: a GTK4/WebKitGTK desktop
window (it falls back to your browser if that stack isn't installed). The front
end has no privileges and only talks to the daemon over loopback.

When you connect, the daemon installs a per-UID ruleset. Loopback is exempt, so
the UI keeps reaching its own daemon and local services keep working:

1. `nat/OUTPUT` — UID to `127.0.0.0/8` → `RETURN` (never touch loopback)
2. `nat/OUTPUT` — UID, TCP → `REDIRECT` to Tor's `TransPort`
3. `nat/OUTPUT` — UID, UDP/53 → `REDIRECT` to Tor's `DNSPort`
4. `filter/OUTPUT` — UID, out on `lo` → `ACCEPT`
5. `filter/OUTPUT` — UID, TCP to `TransPort` → `ACCEPT`
6. `filter/OUTPUT` — UID, UDP to `DNSPort` → `ACCEPT`
7. `filter/OUTPUT` — UID, everything else → `DROP` (the killswitch)

It also writes a marker-delimited block into `/etc/tor/torrc` and pins
`/etc/resolv.conf` to `nameserver 127.0.0.1`, keeping a backup of the originals.

The target user is resolved to a numeric UID against the passwd database, and
every `iptables` call is run as an argv with no shell, so a crafted username
can't inject commands. The UI is loopback-only and gated by a per-session token,
a Host-header allowlist, a same-origin check on POSTs, and a strict CSP. No CORS
headers are sent.

## Requirements

- Linux with `tor` and `iptables` (legacy or nft-backed).
- Python 3.11+ (standard library only).
- Root for the daemon.
- For the native window: GTK4, WebKitGTK and PyGObject. Without them the app
  opens in your browser instead.

## Install

Grab the release assets from the [releases page](https://github.com/cristiancmoises/torando-gui/releases).

### Debian / Ubuntu
```sh
sudo apt install ./torando-gui_1.1.0_all.deb
sudo systemctl enable --now torando-gui.service
torando-gui
```

### Fedora / RHEL
```sh
sudo dnf install ./torando-gui-1.1.0-1.noarch.rpm
sudo systemctl enable --now torando-gui.service
torando-gui
```

### Arch
```sh
makepkg -si          # from packaging/, uses PKGBUILD
sudo systemctl enable --now torando-gui.service
torando-gui
```

### GNU Guix
```sh
guix package -f packaging/guix.scm
```
The Guix build is self-contained: the launchers are rewritten to call the store
`python3` and find `iptables`, `chattr` (`e2fsprogs`) and `tor` in the store, so
nothing extra is needed on `PATH`. It is also in the **securityops** channel:
```sh
guix install torando-gui
# or from a local checkout, without pulling:
guix install -L /path/to/securityops-channel torando-gui
```

On Guix System, daemons run under the GNU Shepherd, not systemd, so the bundled
`torando-gui.service` unit does nothing there. The securityops channel ships a
service type instead:
```scheme
(use-modules (securityops services torando))

(operating-system
  (services
   (cons* (service torando-gui-service-type)
          (service tor-service-type)
          %desktop-services)))
```
Run `guix system reconfigure`, then `herd start torando-gui`. The service
auto-seeds `/etc/torando-gui/config.json` with `manage_torrc` off and
`dns_port` 5353, because on Guix `tor-service-type` owns the read-only
`/etc/tor/torrc` and listens on DNSPort 5353. See [docs/USAGE.md](docs/USAGE.md)
for the per-platform notes.

### AppImage
```sh
chmod +x Torando_Control-x86_64.AppImage
./Torando_Control-x86_64.AppImage
```
Uses `pkexec` to start the root daemon and needs a system `python3` 3.11+. It
doesn't install a systemd unit; the daemon runs for the session.

## Usage

1. Start the service (`systemctl start torando-gui.service`) or run
   `torando-gui`, which starts it for you over polkit on a desktop session.
2. Pick the user whose traffic should go through Tor.
3. Press Connect. The status tracks Tor's bootstrap; once routed it shows the
   exit IP, country and city, and confirms DNS is pinned.
4. New identity requests a fresh circuit.
5. Press Disconnect to remove the rules and restore your real `resolv.conf`.

The gear opens settings: Tor ports, exit country, control port, `resolv.conf`
pinning, and bridge lines.

Run the daemon directly for debugging:
```sh
sudo torando-guid --host 127.0.0.1 --port 8088
torando-guid --mock --open      # UI preview, no privileges, no Tor
```
If DNS ever gets stuck pinned to `127.0.0.1`, `sudo torando-guid --restore-dns`
clears the lock and restores your resolver. See
[docs/USAGE.md](docs/USAGE.md#recovery).

## Build from source

```sh
make test            # ruff + pytest
make deb             # dist/torando-gui_1.1.0_all.deb       (needs dpkg-deb)
make rpm             # dist/torando-gui-1.1.0-1.noarch.rpm  (needs rpmbuild)
make appimage        # dist/Torando_Control-x86_64.AppImage (needs appimagetool)
make tarball         # dist/torando-gui-1.1.0.tar.zst       (needs zstd)
make all             # every format whose tooling is present
```

## Layout

- `backend/torando_gui/` — daemon, engine, Tor control client, exit check,
  torrc/resolv management, server, launcher, desktop window.
- `backend/torando_gui/webroot/` — the UI (no build step, no remote assets).
- `tests/` — engine, SOCKS framing, exit-check, config, torrc/resolv, server.
- `packaging/` — systemd unit, polkit policy, desktop entry, icon, per-format
  build scripts, `guix.scm`, and the Guix System Shepherd service.

## Repositories

Official: **Forgejo** (`git.securityops.co/cristiancmoises/torando-gui`).
Mirrors: [GitHub](https://github.com/cristiancmoises/torando-gui) and
[Codeberg](https://codeberg.org/berkeley/torando-gui). Contribute on whichever
you like; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues
privately per [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-only, see [LICENSE](LICENSE). The upstream `torando` scripts are
GPL-3.0; this is an independent reimplementation with a GUI.
