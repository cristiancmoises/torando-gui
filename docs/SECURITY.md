# Torando Control — Security Architecture

This is the technical security documentation: how Torando Control is built to be
safe, the exact controls, and where the boundaries are. For the *threat model*
(assets, what is/ isn't in scope) read [THREAT_MODEL.md](../THREAT_MODEL.md);
for **vulnerability reporting** read the top-level [SECURITY.md](../SECURITY.md).

## Trust split: root daemon vs. unprivileged GUI

| Component | Privilege | Surface |
|---|---|---|
| `torando-guid` | **root** (needs `CAP_NET_ADMIN` for netfilter, `CAP_LINUX_IMMUTABLE` for `chattr`, writes `/etc/{tor,resolv.conf}`) | a loopback HTTP API + the embedded UI |
| `torando-gui` (native window / browser) | **the desktop user**, no privileges | talks to the daemon over `127.0.0.1` only |

The GUI never has privileges; it cannot touch netfilter or files. Everything
privileged lives in the small, pure-stdlib daemon, which is the only thing to
audit for privilege escalation.

## The netfilter ruleset (per UID)

Applied in order; loopback is exempt so local IPC and the GUI keep working:

```
1. nat/OUTPUT     -m owner --uid-owner U -d 127.0.0.0/8 -j RETURN
2. nat/OUTPUT     -m owner --uid-owner U -p tcp        -j REDIRECT --to-ports <TransPort>
3. nat/OUTPUT     -m owner --uid-owner U -p udp --dport 53 -j REDIRECT --to-ports <DNSPort>
4. filter/OUTPUT  -m owner --uid-owner U -o lo          -j ACCEPT
5. filter/OUTPUT  -m owner --uid-owner U -p tcp --dport <TransPort> -j ACCEPT
6. filter/OUTPUT  -m owner --uid-owner U -p udp --dport <DNSPort>   -j ACCEPT
7. filter/OUTPUT  -m owner --uid-owner U                -j DROP        # killswitch
```

- **Fail-closed:** rule 7 drops anything from the UID not explicitly torified.
  If Tor is down or the redirect is removed, traffic is dropped — never sent in
  the clear.
- **Loopback exemption (rules 1, 4)** is a security-neutral correctness fix:
  `127.0.0.0/8` never leaves the host, and Tor's TransPort/DNSPort live on
  loopback. Without it the killswitch DROP'd the UID's own loopback, which broke
  the GUI↔daemon channel and every local service.
- **Apply is transactional:** each rule is `-C`-checked before `-A`, and on any
  failure every rule added in that pass is rolled back, so the table is never
  left half-built.
- **No shell, ever:** every `iptables` call is an `exec` argv. The only
  user-controlled value (the target user) is resolved to a validated numeric
  UID against the passwd database *before* it reaches any command — closing the
  command-injection class the upstream `torando.sh` text substitution had.

## DNS handling and the resolv.conf safety contract

DNS is the single most dangerous thing this tool touches — a mistake here takes
the whole host offline. The contract:

- The pin (`nameserver 127.0.0.1`) is written **atomically and durably**
  (temp file → `fsync` → `os.replace` → `fsync` dir) and **world-readable
  (0644)**. A root-only (0600) resolv.conf silently breaks DNS for every
  non-root user — this was a real bug and is now regression-tested.
- The client's **real resolver is captured first** (refreshed each connect, so
  it tracks DHCP changes) and restored verbatim on disconnect.
- `resolv.conf` is pinned **last**, only after the firewall redirect is live, so
  a failed connect never touches it.
- Recovery is layered: failed connect → rollback; crash/reboot → startup
  auto-recovery if not actually routing; manual → `torando-guid --restore-dns`.
- A bad/unreadable/corrupt `config.json` never crashes the daemon — it falls
  back to safe defaults rather than dying mid-session.

The immutable bit (`chattr +i`) stops NetworkManager/dhcpcd from un-pinning DNS
mid-session (a leak), at the cost of needing the recovery paths above; it is
best-effort and its failure is reported, not fatal.

## The loopback control surface

A root-equivalent HTTP API on localhost is defended against *other local
software and browser tabs* (not other root):

- **Bind 127.0.0.1 only** — the daemon refuses any non-loopback bind.
- **Per-session token** in `X-Torando-Token`, compared with
  `hmac.compare_digest` (constant time). Injected into the page by the daemon;
  never stored client-side beyond the page.
- **No CORS — ever.** No `Access-Control-Allow-Origin` is sent, so a foreign
  origin's JS cannot read the token or API responses.
- **Host-header allowlist** defeats DNS-rebinding.
- **Origin/Referer check on POSTs**, and the `?token=` query shortcut (needed
  for `EventSource`) is **accepted only on GET** — so CSRF defence stays
  header-bound for mutating calls.
- **Strict CSP** (`default-src 'none'`; `script/style/connect-src 'self'`),
  plus `COOP`/`CORP`/`X-Frame-Options: DENY`/`Referrer-Policy: no-referrer`.
- Request bodies are capped (1 MiB); tokens are redacted from logs.
- The embedded WebKit view loads only the loopback origin, with developer-extras
  and back/forward gestures disabled.

## Tor control protocol

`torctl` speaks the control protocol on loopback. It does **plain `COOKIE`
authentication** (reads the cookie file Tor advertises); the `SAFECOOKIE`
`AUTHCHALLENGE` handshake is intentionally not implemented (Tor's default
advertises `COOKIE` alongside it). A `SAFECOOKIE`-only control port falls
through to a clear error rather than a silent insecure path. All control failures
degrade to "unknown" in the UI — never a fabricated "secured" verdict.

## Parser hardening

The from-scratch parsers (`socks`, `mmdb`, `geoip`, `netcheck`) are written to
never crash on hostile/corrupt input: a malformed GeoIP `.mmdb` (truncated,
cyclic pointers) is caught and reported as "no location" rather than raising;
the exit check uses a real TLS context (cert + hostname verification) through the
SOCKS tunnel and caps the response.

## Known boundaries (see THREAT_MODEL.md)

- **IPv6 is not filtered** (IPv4-only ruleset) — disable IPv6 for the torified
  UID until a v6 killswitch ships. This is the top roadmap item.
- Not an anonymity-set tool (not Tor Browser).
- A compromised root/kernel, other local users in the runtime-dir group, and
  Tor's own threat model (global passive adversary, traffic correlation,
  malicious exits) are out of scope.
- The systemd unit runs as full root; a `CAP_NET_ADMIN`+`CAP_LINUX_IMMUTABLE`
  bounding set is tracked for a later release.
