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
        if text[e:e + 1] == "\n":
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


def lock_resolv(
    cfg: Config,
    path: Path | None = None,
    runner: Runner | None = None,
    immutable: bool = True,
) -> dict[str, object]:
    """Point resolv.conf at 127.0.0.1 and optionally set the immutable bit."""
    run = runner or _default_runner
    target = path or Path(cfg.resolv_path)
    _backup_once(target)
    run(["chattr", "-i", str(target)])  # clear any prior lock so we can write
    atomic_write_text(target, "nameserver 127.0.0.1\n")
    locked = False
    note = ""
    if immutable:
        res = run(["chattr", "+i", str(target)])
        locked = res.returncode == 0
        if not locked:
            note = (res.stderr or "chattr +i unavailable").strip()
    return {"path": str(target), "immutable": locked, "note": note}


def unlock_resolv(
    cfg: Config,
    path: Path | None = None,
    runner: Runner | None = None,
) -> dict[str, object]:
    """Clear the immutable bit and restore the pre-lock resolv.conf if present."""
    run = runner or _default_runner
    target = path or Path(cfg.resolv_path)
    run(["chattr", "-i", str(target)])
    bak = target.with_suffix(target.suffix + ".torando.bak")
    restored = False
    if bak.exists():
        atomic_write_text(target, bak.read_text(encoding="utf-8"))
        # Drop the backup once restored so the next connect captures the
        # resolver that is live *then* (it may have changed via DHCP) rather
        # than replaying a stale snapshot from an earlier session.
        bak.unlink()
        restored = True
    return {"path": str(target), "restored": restored}
