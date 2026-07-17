# Contributing

Torando Control is a small, stdlib-only Python project. Before changing anything
in the netfilter, DNS or control-surface code, read
[THREAT_MODEL.md](THREAT_MODEL.md).

## Where to send changes

The repo is mirrored across three forges; use whichever you prefer:

- Forgejo (official): <https://git.securityops.co/cristiancmoises/torando-gui>
- GitHub: <https://github.com/cristiancmoises/torando-gui>
- Codeberg: <https://codeberg.org/berkeley/torando-gui>

Don't open a public issue for a security bug; see [SECURITY.md](SECURITY.md).

## Setup

No third-party runtime dependencies. For the dev tools:

```sh
python3 -m pip install --user ruff pytest   # or: guix shell python python-pytest python-ruff
```

Run the UI with no privileges and no Tor:

```sh
make mock            # backend/ python3 -m torando_gui --mock --open
```

## Tests and lint

`make test` is what CI runs:

```sh
make lint            # ruff check .
make fmt             # ruff format .
make test            # ruff check + ruff format --check + pytest
```

Keep the code stdlib-only. Add or update tests under `tests/` for any behaviour
change. Match the existing style: argv-only subprocess calls (never a shell
string), atomic and durable writes for system files, and fail closed (never
report "secured" unless it's verified).

The firewall/DNS backends are split by platform: `engine.py` (Linux
iptables/ip6tables), `pf.py` (macOS/BSD), `winfw.py` (Windows) and `dns.py`
(per-OS DNS pinning), selected by `platform.py` and composed in `firewall.py`.
All of them build their commands as pure, side-effect-free functions that take a
`runner` seam, so the whole cross-platform surface is unit-tested on Linux with
fake runners — add tests the same way rather than gating them on the host OS.
Guard POSIX-only imports (`pwd`) so the daemon still imports on Windows.

## Commits

Write focused commits and sign them off to certify the
[DCO](https://developercertificate.org/):

```sh
git commit -s -m "engine: ..."
```

## Packaging

Build scripts live in `packaging/`, driven by the `Makefile`:

- Linux: `make deb rpm tarball appimage` (needs `dpkg-deb`/`rpmbuild`/`zstd`/
  `appimagetool`), plus `packaging/guix.scm` and the securityops channel.
- Cross-platform: `make windows macos freebsd openbsd` stage each platform's
  bundle (pure-Python payload + launchers + install scripts) into `dist/`; they
  build on Linux and only need `zip`/`tar`.

If you change the installed file layout, update **every** definition (deb, rpm,
PKGBUILD, guix.scm, the securityops channel, AppRun, tarball, and the
`packaging/{windows,macos,freebsd,openbsd}` install scripts) so they stay in
sync. Version strings live in `pyproject.toml`, `backend/torando_gui/__init__.py`,
`packaging/_common.sh`, the spec/PKGBUILD/guix.scm, and the macOS `Info.plist`.
Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which builds and
attaches every artifact.

## License

By contributing you agree your work is licensed under AGPL-3.0-only. New files
need the SPDX header:

```
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) <year> <you>
```
