# Torando Control — Usage Guide

Torando Control routes **one chosen Linux user's** entire network egress through
Tor as a transparent proxy, with a killswitch (everything that can't go through
Tor is dropped, never sent in the clear). It is split in two:

- **`torando-guid`** — the root daemon. It programs netfilter, manages
  `resolv.conf`, talks to Tor's control port, and serves the control UI on
  `127.0.0.1:8088`.
- **`torando-gui`** — the unprivileged front end. By default it opens a
  **native desktop window** (GTK4 + WebKitGTK); if that stack isn't installed
  it falls back to your browser. It has no privileges — it only talks to the
  daemon over loopback.

> Read [THREAT_MODEL.md](../THREAT_MODEL.md) first. This is **not** Tor Browser:
> it routes packets, it does not anonymize application fingerprints.

---

## Quick start

1. **Start the daemon** (once, as root / via your init system):
   - systemd: `sudo systemctl enable --now torando-gui.service`
   - Guix System (Shepherd): it's started by `torando-gui-service-type`
     (`sudo herd start torando-gui` if needed)
2. **Open the app:** run `torando-gui` (native window, or browser fallback).
3. **Pick the user** whose traffic should go through Tor (the dropdown lists
   real login accounts).
4. **Press the onion** to connect. The dial tracks Tor's bootstrap; once routed,
   the exit card shows the Tor exit IP and the DNS card confirms DNS is pinned.
5. **New identity** requests a fresh circuit (`NEWNYM`).
6. **Press the onion again** to disconnect — rules are removed and your real
   `resolv.conf` is restored automatically.

The session is gated by a per-request token the daemon injects into the page;
you never copy/paste it.

---

## If something goes wrong (recovery)

The daemon is built so a failure or crash can **never strand you without DNS**:

- **A failed connect rolls everything back** — rules removed, `resolv.conf`
  restored. Your internet is exactly as it was before you pressed connect.
- **A crash/kill/reboot while connected** is detected on the next daemon start,
  which un-pins `resolv.conf` if you're no longer actually routing.
- **Manual escape hatch** — if DNS is ever stuck pinned to `127.0.0.1`:
  ```sh
  sudo torando-guid --restore-dns
  ```
  This clears the immutable bit and restores your captured resolver, then exits.
  As a last resort you can always:
  ```sh
  sudo chattr -i /etc/resolv.conf
  sudo cp /etc/resolv.conf.torando.bak /etc/resolv.conf   # if present
  ```

> The historical bug where the tool left `/etc/resolv.conf` root-only-readable
> (mode 0600) — silently breaking DNS for your normal user even after restore —
> is fixed: the file is always written `0644`.

---

## CLI reference (`torando-guid`)

```
torando-guid [--host H] [--port P] [--config FILE]
             [--mock] [--open] [--no-token-file] [--restore-dns]
```

| Flag | Meaning |
|---|---|
| `--host` | Bind address (must be loopback; non-loopback is refused unless `--mock`). |
| `--port` | Bind port (default 8088). |
| `--config` | Path to `config.json` (default `/etc/torando-gui/config.json`). |
| `--mock` | UI-preview backend: no root, no Tor, believable fake state. Great for screenshots/dev. |
| `--open` | Open the UI in a browser on start. |
| `--no-token-file` | Don't write the session token to `/run`. |
| `--restore-dns` | Emergency: clear the `resolv.conf` lock, restore the real resolver, exit. |

`torando-gui [--browser]` — the GUI; `--browser` forces the browser path.

Preview the UI with no privileges:
```sh
torando-guid --mock --open
```

---

## Configuration

Settings persist to `/etc/torando-gui/config.json` (written `0644`, no secrets).
Edit them in the app's **Settings** (gear icon) or by hand:

| Key | Default | Notes |
|---|---|---|
| `host` / `port` | `127.0.0.1` / `8088` | The control surface. Loopback only. |
| `trans_port` | `9040` | Tor `TransPort`. Must match your Tor config. |
| `dns_port` | `53` | Tor `DNSPort`. **Set to match your Tor** (e.g. `5353`). |
| `socks_port` | `9050` | Tor `SocksPort` (used for exit verification). |
| `control_port` | `9051` | Tor `ControlPort` (bootstrap/NEWNYM; cookie auth). |
| `target_uid` | `null` | The UID to torify. Set via the app. |
| `manage_torrc` | `true` | Write a managed block into `/etc/tor/torrc`. **Turn off** where Tor's config is managed elsewhere (e.g. Guix). |
| `lock_resolv` | `true` | Pin + (immutable) `resolv.conf` to `127.0.0.1`. |
| `exit_country` | `null` | ISO code (e.g. `de`) to pin the exit country. |
| `use_bridges` / `bridges` | `false` / `[]` | Optional bridge lines. |

> **Routing fields can't be changed while connected.** `target_uid`,
> `trans_port` and `dns_port` define the live killswitch rules — the app refuses
> to change them until you disconnect, so the old rules can't be orphaned.

### Matching your Tor instance
Torando does not run Tor; it routes into an existing Tor. Make sure Tor actually
listens on the ports above. A common mismatch: a system Tor with
`DNSPort 5353` while Torando defaults `dns_port` to `53` — set `dns_port` to
`5353` (the Guix service seeds this for you).

---

## Verifying it works

```sh
iptables -t nat -S OUTPUT      # the REDIRECT + loopback RETURN rules
iptables -S OUTPUT             # the ACCEPTs + the final DROP (killswitch)
cat /etc/resolv.conf           # nameserver 127.0.0.1 while connected
lsattr /etc/resolv.conf        # the 'i' (immutable) flag while connected
```
In the app, the **exit card** queries `check.torproject.org/api/ip` *through*
Tor's SOCKS port and shows the exit IP + `IsTor` verdict. It never fabricates a
verdict: if the check can't be done it shows "unknown".

---

## Platform notes

- **Debian/Ubuntu, Fedora/RHEL, Arch:** the systemd unit + polkit rule let an
  active local session start/stop the service without a password.
- **Guix System:** use the Shepherd service (`torando-gui-service-type`). Tor's
  `/etc/tor/torrc` is a read-only store symlink owned by `tor-service-type`, so
  `manage_torrc` is seeded **off** and `dns_port` to `5353`. Manage Tor with
  `herd`, not the GUI's start/stop (which uses `systemctl`).
- **Native window deps:** GTK4 + WebKitGTK + PyGObject. Without them you still
  get the full UI in a browser.
