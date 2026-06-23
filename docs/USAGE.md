# Usage

Torando Control routes one Linux user's entire network egress through Tor, with
a killswitch: anything that can't go through Tor is dropped, never sent in the
clear. It's two programs:

- `torando-guid`, the root daemon. It programs netfilter, manages `resolv.conf`,
  talks to Tor's control port, and serves the UI on `127.0.0.1:8088`.
- `torando-gui`, the front end. By default it opens a GTK4/WebKitGTK desktop
  window; without that stack it falls back to your browser. It has no
  privileges and only talks to the daemon over loopback.

Read [THREAT_MODEL.md](../THREAT_MODEL.md) first. This is not Tor Browser: it
routes packets, it does not anonymize application fingerprints.

## Quick start

1. Start the daemon (once, as root via your init system):
   - systemd: `sudo systemctl enable --now torando-gui.service`
   - Guix System: it's started by `torando-gui-service-type`
     (`sudo herd start torando-gui` if needed)
2. Run `torando-gui` to open the app.
3. Pick the user whose traffic should go through Tor (the menu lists real login
   accounts).
4. Press Connect. The status tracks Tor's bootstrap; once routed it shows the
   exit IP and confirms DNS is pinned.
5. New identity requests a fresh circuit.
6. Press Disconnect to remove the rules and restore your real `resolv.conf`.

The session is gated by a per-request token the daemon injects into the page;
you never copy or paste it.

## Recovery

The daemon is built so a failure or crash can't leave you without DNS:

- A failed connect rolls everything back. Rules removed, `resolv.conf` restored.
  Your internet is exactly as it was before.
- A crash, kill or reboot while connected is caught on the next daemon start,
  which un-pins `resolv.conf` if you're no longer routing.
- If DNS is ever stuck pinned to `127.0.0.1`:
  ```sh
  sudo torando-guid --restore-dns
  ```
  This clears the immutable bit, restores your captured resolver, and exits. As
  a last resort:
  ```sh
  sudo chattr -i /etc/resolv.conf
  sudo cp /etc/resolv.conf.torando.bak /etc/resolv.conf   # if present
  ```

`resolv.conf` is always written 0644. (An earlier version left it 0600, which
broke DNS for the normal user even after a restore; that's fixed.)

## CLI

```
torando-guid [--host H] [--port P] [--config FILE]
             [--mock] [--open] [--no-token-file] [--restore-dns]
```

| Flag | Meaning |
|---|---|
| `--host` | Bind address; must be loopback unless `--mock`. |
| `--port` | Bind port (default 8088). |
| `--config` | Path to `config.json` (default `/etc/torando-gui/config.json`). |
| `--mock` | UI-preview backend: no root, no Tor, believable fake state. |
| `--open` | Open the UI in a browser on start. |
| `--no-token-file` | Don't write the session token to `/run`. |
| `--restore-dns` | Clear the `resolv.conf` lock, restore the resolver, exit. |

`torando-gui [--browser]` is the front end; `--browser` forces the browser path.

Preview the UI with no privileges:
```sh
torando-guid --mock --open
```

## Configuration

Settings live in `/etc/torando-gui/config.json` (0644, no secrets). Edit them in
the app's settings or by hand:

| Key | Default | Notes |
|---|---|---|
| `host` / `port` | `127.0.0.1` / `8088` | Control surface, loopback only. |
| `trans_port` | `9040` | Tor TransPort. Must match your Tor. |
| `dns_port` | `53` | Tor DNSPort. Set to match your Tor (often `5353`). |
| `socks_port` | `9050` | Tor SocksPort (used for exit verification). |
| `control_port` | `9051` | Tor ControlPort (bootstrap/NEWNYM, cookie auth). |
| `target_uid` | `null` | UID to torify. Set in the app. |
| `manage_torrc` | `true` | Write a managed block into `torrc`. Turn off where Tor is configured elsewhere (e.g. Guix). |
| `lock_resolv` | `true` | Pin (and make immutable) `resolv.conf`. |
| `exit_country` | `null` | ISO code (e.g. `de`) to pin the exit country. |
| `use_bridges` / `bridges` | `false` / `[]` | Optional bridge lines. |

`target_uid`, `trans_port` and `dns_port` define the live rules, so the app
refuses to change them while connected. Disconnect first.

Torando doesn't run Tor; it routes into an existing Tor, so Tor has to be
listening on the ports above. A common mismatch is a system Tor with
`DNSPort 5353` while `dns_port` is the default `53`; set `dns_port` to `5353`
(the Guix service seeds this for you).

## Verifying

```sh
iptables -t nat -S OUTPUT      # REDIRECT + loopback RETURN
iptables -S OUTPUT             # the ACCEPTs and the final DROP
cat /etc/resolv.conf           # nameserver 127.0.0.1 while connected
lsattr /etc/resolv.conf        # the immutable bit while connected
```
The exit card queries `check.torproject.org/api/ip` through Tor's SOCKS port and
shows the exit IP and `IsTor` verdict. If it can't run the check it shows
"unknown" rather than guessing.

## Platform notes

- Debian/Ubuntu, Fedora/RHEL, Arch: the systemd unit plus polkit rule let an
  active local session start and stop the service without a password.
- Guix System: use the Shepherd service. Tor's `/etc/tor/torrc` is a read-only
  store symlink owned by `tor-service-type`, so `manage_torrc` is seeded off and
  `dns_port` to 5353. Manage Tor with `herd`, not the GUI's start/stop.
- Native window: needs GTK4, WebKitGTK and PyGObject. Without them you still get
  the full UI in a browser.
