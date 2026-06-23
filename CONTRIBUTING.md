# Contributing to Torando Control

Thanks for your interest. Torando Control is a small, dependency-free
(stdlib-only) Python project with a strong emphasis on correctness and a clear
threat model. Please read [THREAT_MODEL.md](THREAT_MODEL.md) before proposing
changes to the netfilter, DNS or control-surface behaviour.

## Where to send changes

The repository is mirrored across three forges; contribute on whichever you
prefer:

- **Codeberg** (canonical): <https://codeberg.org/cristiancmoises/torando-gui>
- **GitHub**: <https://github.com/cristiancmoises/torando-gui>
- **Forgejo** (self-hosted): <https://git.securityops.co/cristiancmoises/torando-gui>

Security issues: **do not** open a public issue — see [SECURITY.md](SECURITY.md).

## Development setup

No third-party runtime dependencies. For the dev tooling:

```sh
python3 -m pip install --user ruff pytest      # or: guix shell python python-pytest python-ruff
```

Run the UI with no privileges and no Tor (mock backend):

```sh
make mock            # cd backend && python3 -m torando_gui --mock --open
```

## Tests, lint and format

`make test` is the gate CI runs:

```sh
make lint            # ruff check .
make fmt             # ruff format .
make test            # ruff check + ruff format --check + pytest tests/ -q
```

- Keep the code **stdlib-only** — no new runtime dependencies.
- Add or update tests under `tests/` for any behaviour change; the suite must
  pass and `ruff` must be clean (config in `pyproject.toml`, line length 100).
- Match the existing style: argv-only subprocess calls (never a shell string),
  atomic + durable writes for any system file, and fail **closed** (never
  fabricate a "secured" verdict).

## Commits and DCO

Write focused commits with a clear message. Sign off your commits to certify
the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "engine: ..."
```

## Packaging

Per-format build scripts live in `packaging/` and are driven by the `Makefile`
(`make deb rpm tarball appimage`, or `make all`). The Guix definition is
`packaging/guix.scm` (and the package is published in the **securityops**
channel). If you change the installed file layout, update **every** packaging
definition (deb, rpm, PKGBUILD, guix.scm, AppRun, the portable tarball) so they
stay in sync.

## License

By contributing you agree your work is licensed under **AGPL-3.0-only**, the
project's license. New files must carry the SPDX header:

```
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) <year> <you>
```
