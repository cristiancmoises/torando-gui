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

## Commits

Write focused commits and sign them off to certify the
[DCO](https://developercertificate.org/):

```sh
git commit -s -m "engine: ..."
```

## Packaging

Build scripts live in `packaging/`, driven by the `Makefile` (`make deb rpm
tarball appimage`). The Guix definition is `packaging/guix.scm`, and the package
is also in the securityops channel. If you change the installed file layout,
update every packaging definition (deb, rpm, PKGBUILD, guix.scm, AppRun, tarball)
so they stay in sync.

## License

By contributing you agree your work is licensed under AGPL-3.0-only. New files
need the SPDX header:

```
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) <year> <you>
```
