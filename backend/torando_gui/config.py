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

from . import platform as _plat


def default_paths(platform_id: str | None = None) -> dict[str, Path]:
    """Per-OS install/runtime locations.

    Linux keeps its exact FHS layout (``/etc/torando-gui``, ``/run``,
    ``/etc/tor/torrc``) so nothing about the proven path changes. The other
    platforms follow their own conventions: Homebrew's prefix on macOS,
    ``/usr/local/etc`` on FreeBSD, ``C:\\ProgramData`` on Windows.
    """
    p = platform_id or _plat.CURRENT
    if p == _plat.WINDOWS:
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "torando-gui"
        return {
            "config_dir": base,
            "runtime_dir": base / "run",
            "torrc": base / "torrc",
            "resolv": base / "resolv.conf",  # unused on Windows (netsh drives DNS)
        }
    if p == _plat.MACOS:
        # Apple Silicon Homebrew lives under /opt/homebrew; Intel under /usr/local.
        # Detect the prefix itself (not tor's etc dir, which may not exist until
        # `brew install tor` runs) so the torrc path is right from first launch.
        brew = Path("/opt/homebrew") if Path("/opt/homebrew").is_dir() else Path("/usr/local")
        return {
            "config_dir": Path("/etc/torando-gui"),
            "runtime_dir": Path("/var/run/torando-gui"),
            "torrc": brew / "etc/tor/torrc",
            "resolv": Path("/etc/resolv.conf"),  # a stub on macOS; networksetup drives DNS
        }
    if p == _plat.FREEBSD:
        return {
            "config_dir": Path("/usr/local/etc/torando-gui"),
            "runtime_dir": Path("/var/run/torando-gui"),
            "torrc": Path("/usr/local/etc/tor/torrc"),
            "resolv": Path("/etc/resolv.conf"),
        }
    if p in (_plat.OPENBSD, _plat.NETBSD):
        return {
            "config_dir": Path("/etc/torando-gui"),
            "runtime_dir": Path("/var/run/torando-gui"),
            "torrc": Path("/etc/tor/torrc"),
            "resolv": Path("/etc/resolv.conf"),
        }
    # Linux (and unknown): the original FHS layout, unchanged.
    return {
        "config_dir": Path("/etc/torando-gui"),
        "runtime_dir": Path("/run/torando-gui"),
        "torrc": Path("/etc/tor/torrc"),
        "resolv": Path("/etc/resolv.conf"),
    }


_PATHS = default_paths()

# --- system locations (platform-aware; Linux keeps the FHS layout) ----------
CONFIG_DIR = _PATHS["config_dir"]
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNTIME_DIR = _PATHS["runtime_dir"]
TOKEN_FILE = RUNTIME_DIR / "token"

DEFAULT_TORRC = _PATHS["torrc"]
DEFAULT_RESOLV = _PATHS["resolv"]

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


def atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    """Write *content* to *path* atomically, durably, and with a sane mode.

    Temp file in the same directory, ``fsync`` the data, then ``os.replace``
    (an atomic rename), then ``fsync`` the parent directory.  Without the
    fsyncs a crash between the write and the metadata flush can publish a
    zero-length or truncated file — fatal when the target is
    ``/etc/resolv.conf`` or the daemon's config.

    ``tempfile.mkstemp`` creates the temp file 0600 and ``os.replace`` keeps
    that mode, which silently makes ``/etc/resolv.conf`` (and torrc)
    root-only-readable — breaking DNS for every non-root user until they
    ``chmod`` it back by hand.  So the file is always chmod'd to *mode* (0644
    by default: the conventional, world-readable mode for these files) before
    the rename, regardless of any broken mode a previous write may have left.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)  # mkstemp made it 0600; force the intended mode
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

    # IPv6 killswitch (Linux ip6tables / pf inet6). When the kernel can carry
    # IPv6 an un-firewalled v6 path is a leak, so this drops the torified UID's
    # IPv6 egress. Default on; turn off only if you have no IPv6 at all.
    ipv6_killswitch: bool = True

    # cross-platform firewall knobs (ignored on platforms that don't use them)
    #   tor_user   — the account Tor runs as (pf exemption); None = platform default
    #   tor_path   — path to the tor executable (Windows firewall allow-rule)
    #   pf_anchor  — name of the pf anchor this daemon owns (macOS/BSD)
    #   allow_lan  — permit LAN/loopback-subnet egress under the killswitch (Windows)
    #   allow_dhcp — permit DHCP so the box can still get a lease (Windows)
    tor_user: str | None = None
    tor_path: str | None = None
    pf_anchor: str = "torando-gui"
    allow_lan: bool = False
    allow_dhcp: bool = True

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
    """Load config, returning safe defaults if the file is absent, empty,
    unreadable, or malformed.

    The daemon must never fail to start because of a bad config file: a missing
    file, a permission error, a directory in the way, or invalid JSON all fall
    back to built-in defaults rather than crashing (which, mid-session, could
    leave the firewall/DNS in a half-applied state with no way to recover via
    the UI).
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        # FileNotFoundError, IsADirectoryError, PermissionError, … — all safe
        # to treat as "no usable config; use defaults".
        return Config()
    raw = raw.strip()
    if not raw:
        return Config()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return Config()
    if not isinstance(data, dict):
        return Config()
    return Config.from_dict(data)


def save(cfg: Config, path: Path = CONFIG_FILE) -> None:
    """Persist config atomically and durably (see :func:`atomic_write_text`)."""
    payload = json.dumps(asdict(cfg), indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, payload)
