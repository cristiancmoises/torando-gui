# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Safe editing of /etc/tor/torrc and /etc/resolv.conf.

torrc edits are confined to a marker-delimited block; text outside the markers
is preserved verbatim. resolv.conf is replaced wholesale (its whole point here
is to force ``nameserver 127.0.0.1``) but the previous contents are backed up
first. Every write is atomic: temp file in the same directory, then os.replace.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from .config import TORRC_BEGIN, TORRC_END, Config, atomic_write_text

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


def render_torrc_block(cfg: Config) -> str:
    """Render the managed torrc block from config. Deterministic."""
    lines = [
        TORRC_BEGIN,
        "VirtualAddrNetwork 10.192.0.0/10",
        "AutomapHostsOnResolve 1",
        f"TransPort {cfg.trans_port}",
        f"DNSPort {cfg.dns_port}",
        f"SocksPort {cfg.socks_port}",
    ]
    if cfg.enable_control_port:
        lines += [f"ControlPort {cfg.control_port}", "CookieAuthentication 1"]
    if cfg.exit_country:
        code = cfg.exit_country.strip().lower()
        lines += [f"ExitNodes {{{code}}}", "StrictNodes 1"]
    if cfg.use_bridges:
        lines.append("UseBridges 1")
        lines += [f"Bridge {b.strip()}" for b in cfg.bridges if b.strip()]
    lines.append(TORRC_END)
    return "\n".join(lines) + "\n"


def merge_torrc(existing: str, block: str) -> str:
    """Insert or replace the managed block inside *existing* torrc text."""
    begin = existing.find(TORRC_BEGIN)
    if begin == -1:
        base = existing if existing.endswith("\n") or not existing else existing + "\n"
        joiner = "" if not existing else "\n"
        return base + joiner + block
    end = existing.find(TORRC_END, begin)
    if end == -1:  # truncated/corrupt block: replace to end of file
        return existing[:begin] + block
    end += len(TORRC_END)
    tail = existing[end:]
    if tail.startswith("\n"):
        tail = tail[1:]
    # Defend against a torrc that somehow carries more than one managed block
    # (e.g. a hand-edit or an interrupted older write): collapse them all into
    # the single fresh block, so stale duplicate directives never stay active.
    tail = _strip_managed_blocks(tail)
    return existing[:begin] + block + tail


def _strip_managed_blocks(text: str) -> str:
    """Remove every complete BEGIN..END managed span (and its trailing newline)."""
    while True:
        b = text.find(TORRC_BEGIN)
        if b == -1:
            return text
        e = text.find(TORRC_END, b)
        if e == -1:  # dangling BEGIN: drop from it to end of file
            return text[:b]
        e += len(TORRC_END)
        if text[e : e + 1] == "\n":
            e += 1
        text = text[:b] + text[e:]


def _backup_once(path: Path) -> None:
    bak = path.with_suffix(path.suffix + ".torando.bak")
    if path.exists() and not bak.exists():
        bak.write_bytes(path.read_bytes())


def apply_torrc(cfg: Config, path: Path | None = None) -> Path:
    target = path or Path(cfg.torrc_path)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    _backup_once(target)
    atomic_write_text(target, merge_torrc(existing, render_torrc_block(cfg)))
    return target


PINNED_RESOLV = "nameserver 127.0.0.1\n"

# Immutability command builders. Linux uses chattr's ext-attr immutable bit;
# the BSDs (and macOS) use chflags with the system-immutable flag. These make
# the pin survive dhclient/resolvconf/resolvd trying to rewrite resolv.conf.
CHATTR_SET = lambda p: ["chattr", "+i", p]  # noqa: E731
CHATTR_CLEAR = lambda p: ["chattr", "-i", p]  # noqa: E731
CHFLAGS_SET = lambda p: ["chflags", "schg", p]  # noqa: E731
CHFLAGS_CLEAR = lambda p: ["chflags", "noschg", p]  # noqa: E731


def _backup_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".torando.bak")


def _is_only_our_pin(text: str) -> bool:
    """True if *text* holds only our loopback pin (no real upstream resolver)."""
    meaningful = [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    return meaningful == ["nameserver 127.0.0.1"]


def _capture_resolver(path: Path) -> None:
    """Snapshot the current *real* resolver as the restore point.

    Refreshed on every lock so a later disconnect restores the latest client
    DNS (e.g. after a DHCP lease change), but never snapshots our own pin over a
    good backup.
    """
    if not path.exists():
        return
    current = path.read_bytes()
    if _is_only_our_pin(current.decode("utf-8", "replace")):
        return
    _backup_path(path).write_bytes(current)


def resolv_is_pinned(cfg: Config, path: Path | None = None) -> bool:
    """True if resolv.conf currently holds only our 127.0.0.1 pin."""
    target = path or Path(cfg.resolv_path)
    try:
        return _is_only_our_pin(target.read_text(encoding="utf-8"))
    except OSError:
        return False


def lock_resolv(
    cfg: Config,
    path: Path | None = None,
    runner: Runner | None = None,
    immutable: bool = True,
    set_immutable: Callable[[str], list[str]] = CHATTR_SET,
    clear_immutable: Callable[[str], list[str]] = CHATTR_CLEAR,
) -> dict[str, object]:
    """Pin resolv.conf at 127.0.0.1 (mode 0644) and optionally make it immutable.

    Captures the current real resolver first so :func:`restore_resolv` can put
    it back. The pin is written world-readable on purpose — a root-only
    resolv.conf breaks DNS for every non-root user. The immutability command is
    injectable so the BSDs use ``chflags schg`` where Linux uses ``chattr +i``.
    """
    run = runner or _default_runner
    target = path or Path(cfg.resolv_path)
    _capture_resolver(target)
    run(clear_immutable(str(target)))  # clear any prior lock so we can write
    atomic_write_text(target, PINNED_RESOLV, mode=0o644)
    locked = False
    note = ""
    if immutable:
        res = run(set_immutable(str(target)))
        locked = res.returncode == 0
        if not locked:
            note = (res.stderr or "immutable flag unavailable").strip()
    return {"path": str(target), "immutable": locked, "note": note}


def restore_resolv(
    cfg: Config,
    path: Path | None = None,
    runner: Runner | None = None,
    clear_immutable: Callable[[str], list[str]] = CHATTR_CLEAR,
) -> dict[str, object]:
    """Undo :func:`lock_resolv`: clear the immutable bit, put the client's real
    resolver back (mode 0644), and drop the backup.

    This is what the GUI's *disconnect* calls, what ``--restore-dns`` calls, and
    what the daemon runs at startup when it finds an orphaned pin — so a crash,
    a kill, or a reboot can never strand the host without DNS.
    """
    run = runner or _default_runner
    target = path or Path(cfg.resolv_path)
    run(clear_immutable(str(target)))  # always make it writable again first
    bak = _backup_path(target)
    restored = False
    note = ""
    if bak.exists():
        try:
            atomic_write_text(target, bak.read_text(encoding="utf-8"), mode=0o644)
            bak.unlink()
            restored = True
        except OSError as exc:
            note = f"restore failed: {exc}"
    elif resolv_is_pinned(cfg, target):
        note = "no backup found; resolv.conf left mutable with the loopback pin"
    return {"path": str(target), "restored": restored, "note": note}


# Backwards-compatible name used by the app/backend layer.
unlock_resolv = restore_resolv
