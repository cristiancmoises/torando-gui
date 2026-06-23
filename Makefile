# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
.POSIX:
.PHONY: help test lint fmt run mock map deb rpm tarball appimage all clean

PY = python3

help:
	@echo "targets:"
	@echo "  test      ruff check + ruff format --check + pytest"
	@echo "  lint      ruff check"
	@echo "  fmt       ruff format"
	@echo "  mock      run the daemon in mock mode (no root, no Tor) and open the UI"
	@echo "  deb rpm tarball appimage   build that package into dist/"
	@echo "  all       build every package whose tooling is present"
	@echo "  clean     remove build/ and dist/"

test: lint
	$(PY) -m ruff format --check .
	$(PY) -m pytest tests/ -q

lint:
	$(PY) -m ruff check .

fmt:
	$(PY) -m ruff format .

mock:
	cd backend && $(PY) -m torando_gui --mock --open

map:
	$(PY) packaging/geo/gen_worldmap.py

deb:
	sh packaging/build-deb.sh

rpm:
	sh packaging/build-rpm.sh

tarball:
	sh packaging/build-tarball.sh

appimage:
	sh packaging/build-appimage.sh

all:
	@sh packaging/build-deb.sh || echo "deb: skipped/failed"
	@sh packaging/build-tarball.sh || echo "tarball: skipped/failed"
	@sh packaging/build-rpm.sh || echo "rpm: skipped/failed (needs rpmbuild)"
	@sh packaging/build-appimage.sh || echo "appimage: skipped/failed (needs appimagetool)"
	@echo "--- dist/ ---"; ls -1 dist/ 2>/dev/null || true

clean:
	rm -rf build dist
