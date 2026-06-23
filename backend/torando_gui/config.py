# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Configuration model and persistence for the Torando Control daemon.

All paths are overridable so the test-suite never touches real system files.
The on-disk format is JSON; unknown keys are ignored on load (forward-compat)
and never written back, so a newer daemon cannot be downgraded by an old file.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

# --- system locations (FHS) -------------------------------------------------
CONFIG_DIR = Path("/etc/torando-gui")
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNTIME_DIR = Path("/run/torando-gui")
TOKEN_FILE = RUNTIME_DIR / "token"

DEFAULT_TORRC = Path("/etc/tor/torrc")
DEFAULT_RESOLV = Path("/etc/resolv.conf")

# Markers delimiting the block this daemon owns inside torrc. Anything outside
# the markers is never touched.
TORRC_BEGIN = "# >>> torando-gui managed block (do not edit by hand) >>>"
TORRC_END = "# <<< torando-gui managed block <<<"


def _fsync_dir(directory: Path) -> None:
    """Best-effort fsync of a directory so a rename is durable across a crash."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass  # some filesystems (e.g. tmpfs) cannot fsync a directory
    finally:
        os.close(fd)


def atomic_write_text(path: Path, content: str) -> None:
    """Write *content* to *path* atomically and durably.

    Temp file in the same directory, ``fsync`` the data, then ``os.replace``
    (an atomic rename), then ``fsync`` the parent directory.  Without the
    fsyncs a crash between the write and the metadata flush can publish a
    zero-length or truncated file — fatal when the target is
    ``/etc/resolv.conf`` or the daemon's config.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        tmp = None  # ownership transferred; do not unlink in finally
        _fsync_dir(path.parent)
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)


@dataclass
class Config:
    """Runtime configuration. Every field has a safe default."""

    # local web/control surface
    host: str = "127.0.0.1"
    port: int = 8088

    # tor ports — defaults mirror the upstream torando torrc exactly
    trans_port: int = 9040
    dns_port: int = 53
    socks_port: int = 9050
    control_port: int = 9051

    # which local user's egress is forced through Tor (None until chosen)
    target_uid: int | None = None

    # behaviour toggles
    manage_torrc: bool = True
    enable_control_port: bool = True
    lock_resolv: bool = True
    use_bridges: bool = False
    exit_country: str | None = None  # ISO code without braces, e.g. "de"
    bridges: list[str] = field(default_factory=list)

    # external checks / system paths
    check_url: str = "https://check.torproject.org/api/ip"
    torrc_path: str = str(DEFAULT_TORRC)
    resolv_path: str = str(DEFAULT_RESOLV)

    def sanitized(self) -> dict[str, Any]:
        """Config as sent to the browser; nothing secret lives here today."""
        return asdict(self)

    def host_socks(self) -> str:
        """Host to reach Tor's SocksPort on. Always loopback by design."""
        return "127.0.0.1"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def load(path: Path = CONFIG_FILE) -> Config:
    """Load config, returning defaults if the file is absent or empty."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError):
        return Config()
    raw = raw.strip()
    if not raw:
        return Config()
    return Config.from_dict(json.loads(raw))


def save(cfg: Config, path: Path = CONFIG_FILE) -> None:
    """Persist config atomically and durably (see :func:`atomic_write_text`)."""
    payload = json.dumps(asdict(cfg), indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, payload)
