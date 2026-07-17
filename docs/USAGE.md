# Usage

Torando Control routes a user's network egress through Tor with a killswitch:
anything that can't go through Tor is dropped, never sent in the clear. On Linux
it's a per-user *transparent* proxy; on macOS, the BSDs and Windows it sets the
system SOCKS proxy and blocks everything that tries to bypass it (see
[Platform notes](#platform-notes)). It's two programs:

- `torando-guid`, the root/Administrator daemon. It programs the firewall
  (iptables/ip6tables, `pf`, or Windows Firewall), manages DNS, talks to Tor's
  control port, and serves the UI on `127.0.0.1:8088`.
- `torando-gui`, the front end. On Linux it opens a GTK4/WebKitGTK desktop
  window; without that stack (and by default elsewhere) it falls back to your
  browser. It has no privileges and only talks to the daemon over loopback.

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

The daemon is built so a failure or crash can't strand you without DNS, on any
platform:

- A failed connect rolls everything back — rules removed, DNS restored — so your
  network is exactly as it was before.
- A crash, kill or reboot while connected is caught on the next daemon start,
  which un-pins DNS if you're no longer routing.
- The captured prior state (resolver, firewall policy, system proxy) is snapshot
  **once** and never overwritten by the tool's own pin, so a reconnect can't
  lose your real configuration.

The one-shot escape hatch is the same everywhere — it restores DNS and exits:
```sh
sudo torando-guid --restore-dns          # Linux/macOS/BSD
```
```powershell
torando-guid --restore-dns               # Windows (elevated)
```

Per-platform last resort, if `--restore-dns` can't run:

- **Linux / BSD** — clear the lock and put back the backup:
  ```sh
  sudo chattr -i /etc/resolv.conf                          # Linux
  sudo chflags noschg /etc/resolv.conf                     # BSD
  sudo cp /etc/resolv.conf.torando.bak /etc/resolv.conf    # if present
  ```
  `resolv.conf` is always written 0644 (an earlier version left it 0600, which
  broke DNS for the normal user; fixed).
- **macOS** — DNS is set per service, not in `resolv.conf`:
  ```sh
  networksetup -listallnetworkservices
  sudo networksetup -setdnsservers "Wi-Fi" Empty           # back to DHCP
  ```
- **Windows** — return DNS to DHCP and re-allow outbound (the daemon does this
  itself; only needed if it can't run):
  ```powershell
  netsh interface ipv4 set dnsservers name="Wi-Fi" source=dhcp
  netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
  ```
  Or just run the bundled `uninstall.ps1`, which performs the full teardown.

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
| `trans_port` | `9040` | Tor TransPort (Linux transparent redirect). Must match your Tor. |
| `dns_port` | `53` | Tor DNSPort. Set to match your Tor (often `5353`). |
| `socks_port` | `9050` | Tor SocksPort (exit verification; the system proxy on macOS/Windows). |
| `control_port` | `9051` | Tor ControlPort (bootstrap/NEWNYM, cookie auth). |
| `target_uid` | `null` | UID to torify. Set in the app. Ignored on Windows (machine-wide). |
| `manage_torrc` | `true` | Write a managed block into `torrc`. Turn off where Tor is configured elsewhere (Guix, Homebrew, the Expert Bundle). |
| `lock_resolv` | `true` | Pin (and make immutable) DNS. |
| `ipv6_killswitch` | `true` | Block the UID's IPv6 egress (Linux ip6tables / pf `inet6`). Leave on unless you have no IPv6. |
| `exit_country` | `null` | ISO code (e.g. `de`) to pin the exit country. |
| `use_bridges` / `bridges` | `false` / `[]` | Optional bridge lines. |
| `tor_user` | `null` | Account Tor runs as, for the pf exemption (defaults to `_tor` on macOS/BSD). |
| `tor_path` | `null` | Path to `tor.exe` the Windows firewall whitelists (required on Windows). |
| `pf_anchor` | `torando-gui` | Name of the pf anchor the daemon owns (macOS/BSD). |
| `allow_lan` / `allow_dhcp` | `false` / `true` | Windows: also permit the local subnet / DHCP under the killswitch. |

`target_uid`, `trans_port` and `dns_port` define the live rules, so the app
refuses to change them while connected. Disconnect first.

Torando doesn't run Tor; it routes into an existing Tor, so Tor has to be
listening on the ports above. A common mismatch is a system Tor with
`DNSPort 5353` while `dns_port` is the default `53`; set `dns_port` to `5353`
(the Guix service seeds this for you).

## Verifying

The exit card in the app queries `check.torproject.org/api/ip` through Tor's
SOCKS port and shows the exit IP and `IsTor` verdict (or "unknown" rather than
guessing). To confirm the rules yourself:

**Linux**
```sh
iptables  -t nat -S OUTPUT     # REDIRECT + loopback RETURN
iptables  -S OUTPUT            # the ACCEPTs and the final DROP
ip6tables -S OUTPUT            # the IPv6 killswitch (loopback ACCEPT + DROP)
cat /etc/resolv.conf           # nameserver 127.0.0.1 while connected
lsattr /etc/resolv.conf        # the immutable bit while connected
```

**macOS / FreeBSD / OpenBSD**
```sh
pfctl -s info                          # Status: Enabled
pfctl -a torando-gui -sr                # the loopback pass + block-out rules
pfctl -s rules | grep torando-gui       # confirms the anchor is REFERENCED
scutil --dns | grep nameserver          # 127.0.0.1 (macOS)
networksetup -getsocksfirewallproxy Wi-Fi   # macOS: Enabled Yes, 127.0.0.1 9050
```

**Windows** (elevated)
```powershell
netsh advfirewall show allprofiles | findstr "Policy"   # ...,BlockOutbound
netsh advfirewall firewall show rule name=TorandoGUI-Tor-Out
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
netsh interface ipv4 show dnsservers                     # 127.0.0.1 while pinned
```

The strongest test on any platform: stop Tor while connected and confirm the
torified traffic **fails** rather than reaching the network — that is the
killswitch doing its job.

## Platform notes

The killswitch is fail-closed everywhere; the routing mechanism differs because
the OS primitives do. On Linux only, apps need no configuration. Elsewhere,
configure apps to use the system SOCKS proxy at `127.0.0.1:9050` (most browsers
and many tools do this automatically once the system proxy is set) — anything
that ignores it is blocked, not leaked.

### Linux
- Debian/Ubuntu, Fedora/RHEL, Arch: the systemd unit plus polkit rule let an
  active local session start and stop the service without a password.
- The IPv6 killswitch needs `ip6tables`. If the kernel has IPv6 but `ip6tables`
  is missing, connect refuses (rather than leave v6 open) — install it, or set
  `ipv6_killswitch=false`.
- Guix System: use the Shepherd service. Tor's `/etc/tor/torrc` is a read-only
  store symlink owned by `tor-service-type`, so `manage_torrc` is seeded off and
  `dns_port` to 5353. Manage Tor with `herd`, not the GUI's start/stop.
- Native window: needs GTK4, WebKitGTK and PyGObject. Without them you still get
  the full UI in a browser.

### macOS
- Install Tor with Homebrew (`brew install tor && brew services start tor`). The
  daemon leaves `torrc` alone by default (`manage_torrc=false`); set your
  `SocksPort`/`DNSPort` in the brew `torrc`.
- Connect sets the **system SOCKS proxy** (`networksetup -setsocksfirewallproxy`)
  on every active network service and loads a per-UID `pf` killswitch anchor,
  hooked into `/etc/pf.conf` via a validated marker block. DNS is pinned with
  `networksetup -setdnsservers 127.0.0.1` (not `/etc/resolv.conf`, which macOS
  ignores). Disconnect restores the captured proxy/DNS.
- The `.app` is unsigned; first launch needs Right-click → Open, or
  `xattr -dr com.apple.quarantine "/Applications/Torando Control.app"`.
- pf's `user` match only tags TCP/UDP, so ICMP for the user is not blocked — a
  documented limitation.

### FreeBSD / OpenBSD
- Install the `tor` package; it runs as `_tor`. Enable pf
  (`sysrc pf_enable=YES && service pf start` on FreeBSD).
- Connect loads a per-UID `pf` killswitch anchor and pins DNS in
  `/etc/resolv.conf` with `chflags schg`. Route apps through Tor with `torsocks`
  or per-app SOCKS at `127.0.0.1:9050` (there is no system-wide SOCKS setting on
  the BSDs).
- The rc.d service is `torando-gui` (FreeBSD) / `torando_gui` (OpenBSD).

### Windows
- The killswitch is **machine-wide** — there is no driverless per-process
  redirect on Windows, so there is no "target user". Connect flips the Windows
  Firewall to block outbound on every profile (capturing the prior policy first),
  whitelists `tor.exe` (from `tor_path`) and loopback, points the WinINET system
  proxy at Tor, and pins interface DNS with `netsh`. Disconnect restores all of
  it and deletes only the rules it added — it never runs `netsh advfirewall
  reset`.
- **All-in-one:** the `-windows.zip` bundles its own embedded Python and Tor, so
  there is nothing to install first. `install.ps1` copies the bundle to
  `Program Files`, writes a `torrc` (no `TransPort` — Windows has no transparent
  proxy), and registers two boot-time Scheduled Tasks as SYSTEM: `TorandoGUI-Tor`
  (the bundled Tor) and `TorandoGUI-Daemon` (the root daemon). `manage_torrc` is
  seeded off because the bundled Tor owns its `torrc`; set exit country / bridges
  by editing `%ProgramData%\torando-gui\torrc` and restarting the `TorandoGUI-Tor`
  task. Tor ships frequent security updates — refresh the bundled copy by
  installing a newer release (see `BUNDLED.txt`).

## Troubleshooting

- **The exit card says "unknown".** Tor isn't reachable on the SOCKS port, or the
  check host is blocked. Confirm Tor is running and `socks_port` matches your
  `torrc`.
- **Connect fails with a DNSPort/TransPort mismatch.** The daemon routes into an
  *existing* Tor, so its ports must match. The classic case is a system Tor on
  `DNSPort 5353` while `dns_port` is `53` — set `dns_port` to `5353`.
- **Linux: "refusing to connect… ip6tables is unavailable".** Your kernel has
  IPv6 but `ip6tables` isn't installed, so the v6 killswitch can't be armed. Install
  it (usually the `iptables`/`iptables-nft` package), or set `ipv6_killswitch=false`
  to accept an unfiltered IPv6 path.
- **macOS/BSD: connected but traffic still isn't through Tor.** The killswitch
  blocks non-Tor egress, but routing *into* Tor needs the SOCKS proxy. On macOS
  confirm `networksetup -getsocksfirewallproxy` shows it enabled; on the BSDs use
  `torsocks`. Also verify the anchor is actually evaluated
  (`pfctl -s rules | grep torando-gui`) — if your `pf.conf` has an earlier
  `pass … quick` rule, move the `anchor "torando-gui"` reference ahead of it.
- **macOS: "app is damaged / cannot be opened".** Gatekeeper quarantine on the
  unsigned app. `xattr -dr com.apple.quarantine "/Applications/Torando Control.app"`,
  or approve it in System Settings → Privacy & Security.
- **Windows: everything is blocked, including Tor.** `tor_path` must point at a
  real `tor.exe` so the firewall can whitelist it. If a disconnect was interrupted,
  run `uninstall.ps1` (or `torando-guid --restore-dns`) to restore the policy.
- **DNS is stuck on 127.0.0.1 after a crash.** Run `torando-guid --restore-dns`,
  or see [Recovery](#recovery) for the per-platform manual steps.
