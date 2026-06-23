# Torando Control — Performance

Torando Control is a control plane, not a data plane: once the netfilter rules
are in place, **all packet forwarding happens in the kernel and through Tor** —
the daemon is not in the data path and adds no per-packet overhead. Your
throughput and latency are Tor's, not Torando's.

## What actually costs anything

| Operation | Cost | Notes |
|---|---|---|
| Connect | a handful of `iptables` execs + one atomic `resolv.conf` write + (opt.) `chattr` | sub-second; each rule is `-C`-checked then `-A`'d |
| Disconnect | symmetric `iptables -D` + restore `resolv.conf` | sub-second |
| Steady state (routing) | **zero daemon involvement** | kernel + Tor only |
| Status poll / SSE | one Tor control round-trip + a few rule `-C` checks every ~2 s | loopback only |
| Exit verification | one HTTPS request **through Tor** | seconds (Tor latency); on demand |

## Daemon footprint

- **Pure Python standard library, no third-party runtime deps.** No async
  framework, no ORM, no template engine.
- `ThreadingHTTPServer` with `daemon_threads`: one thread per request, plus one
  long-lived thread per open `EventSource` (the UI keeps a single SSE stream).
- Memory: a small ring buffer of recent log lines (capacity 500) and the
  gzipped+fingerprinted static assets, built **once at startup**. Idle RSS is a
  few MiB of CPython.
- The status loop wakes about every 2 seconds while a client is connected and is
  idle otherwise; there is no busy-polling.

## Static asset serving

Static files (`app.js`, `app.css`, `worldmap.js`, icons) are read, **gzipped at
level 9, and BLAKE2b-fingerprinted once at startup**, then served with an
immutable `Cache-Control` and a strong `ETag` (so reloads are `304`s).
Compression and hashing never happen per request. The token-injected `index`
is the only dynamic document and is never cached.

## GeoIP lookups

- Country resolution uses Tor's own ASCII `geoip` ranges, loaded once and
  **binary-searched** (`bisect`) — O(log n) per lookup, fully offline.
- Optional city/lat-lon resolution reads a GeoLite2 `.mmdb` with a dependency-
  free reader that walks the binary search tree directly (no full parse, no
  third-party C extension). The DB is opened lazily on first use and cached.

## The native GUI

The desktop window is a thin GTK4 + WebKitGTK shell around the same loopback UI
(the Mullvad-style "web UI in a native shell" model). WebKit's renderer is the
heaviest part of the *client* (tens of MiB), but it is unprivileged and entirely
separate from the daemon. If the GTK stack isn't present the launcher uses your
browser, which has no extra cost.

## Scaling notes / tuning

- This is a **single-user, single-host** tool. There is no multi-client or
  multi-tenant path to scale.
- The 1 MiB request-body cap and the ~2 s status cadence are the only tunables
  that affect load; neither matters for one local user.
- Throughput tuning belongs to **Tor** (bridges, `NumEntryGuards`, exit
  selection), not to Torando — Torando only points traffic at it.

## Measuring

```sh
# daemon resident memory
ps -o rss= -C torando-guid

# rule application latency (rules go in/out in well under a second)
time sudo torando-guid --restore-dns   # exercises the file/chattr path only

# steady-state: the daemon is idle; confirm with
top -p "$(pgrep -f torando_gui)"
```
