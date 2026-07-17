# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Daemon entrypoint: ``python -m torando_gui`` / ``torando-guid``."""

from __future__ import annotations

import argparse
import os
import secrets
import signal
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__, config
from . import platform as _plat
from .app import App, MockBackend, SystemBackend
from .server import make_server


def _ensure_windows_log() -> None:
    """On Windows, guarantee a log file even if this was launched directly with
    ``pythonw -m torando_gui`` (no console → sys.stderr is None) rather than via
    the bundle's boot/daemon.py. Belt-and-braces so diagnostics always exist."""
    if not _plat.is_windows():
        return
    if sys.stderr is not None and getattr(sys.stderr, "name", "").endswith("daemon.log"):
        return  # boot/daemon.py already redirected us to the log
    base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    for d in (os.path.join(base, "torando-gui", "logs"), os.environ.get("TEMP", "."), "."):
        try:
            os.makedirs(d, exist_ok=True)
            fh = open(  # noqa: SIM115 — kept open for the process lifetime (it IS stdio)
                os.path.join(d, "daemon.log"), "a", buffering=1, encoding="utf-8", errors="replace"
            )
            sys.stdout = fh
            sys.stderr = fh
            return
        except OSError:
            continue


def _new_token(runtime_dir: Path, write_file: bool) -> str:
    token = secrets.token_urlsafe(32)
    if write_file:
        try:
            runtime_dir.mkdir(parents=True, exist_ok=True)
            tf = runtime_dir / "token"
            tf.write_text(token + "\n", encoding="utf-8")
            os.chmod(tf, 0o600)
        except OSError as exc:
            print(f"warning: could not write token file: {exc}", file=sys.stderr)
    return token


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="torando-guid", description="Torando Control daemon")
    p.add_argument("--host", default=None, help="bind address (default from config: 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="bind port (default from config: 8088)")
    p.add_argument("--config", default=str(config.CONFIG_FILE), help="path to config.json")
    p.add_argument("--mock", action="store_true", help="UI preview backend; no root, no Tor")
    p.add_argument("--open", action="store_true", help="open the GUI in a browser on start")
    p.add_argument("--no-token-file", action="store_true", help="do not write the token to /run")
    p.add_argument(
        "--restore-dns",
        action="store_true",
        help="emergency: clear the resolv.conf lock and restore the real resolver, then exit",
    )
    p.add_argument(
        "--disconnect",
        action="store_true",
        help="full teardown: remove firewall rules, restore the system proxy and DNS, then exit",
    )
    p.add_argument("--version", action="version", version=f"torando-gui {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    _ensure_windows_log()
    args = build_parser().parse_args(argv)
    cfg_path = Path(args.config)
    cfg = config.load(cfg_path)
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port

    # Emergency DNS recovery: undo a DNS pin/lock and exit. Needs root but no
    # Tor and no server — the escape hatch when a session left DNS down. Uses
    # the platform pinner (resolv.conf on Linux/BSD, networksetup on macOS,
    # netsh on Windows).
    if args.restore_dns:
        from . import dns as dnsmod

        res = dnsmod.make_dns().restore(cfg)
        print(f"DNS restore: {res}", file=sys.stderr)
        return 0 if res.get("restored") or not res.get("note") else 1

    # Full teardown: remove the firewall rules, restore the captured system proxy
    # (Windows) and DNS, then exit. This is what uninstall runs so removal never
    # leaves the browser pointed at a now-dead SOCKS proxy.
    if args.disconnect:
        backend = SystemBackend(cfg.host_socks(), cfg.control_port)
        app = App(cfg, backend, "", mock=False, config_path=cfg_path)
        try:
            app.disconnect()
            print("disconnected: rules removed, proxy/DNS restored", file=sys.stderr)
            return 0
        except Exception as exc:  # noqa: BLE001 — teardown must not crash uninstall
            print(f"disconnect error: {exc}", file=sys.stderr)
            return 1

    if cfg.host != "127.0.0.1" and not args.mock:
        print(
            "refusing to bind a non-loopback address; this daemon is root-equivalent",
            file=sys.stderr,
        )
        return 2

    token = _new_token(config.RUNTIME_DIR, write_file=not args.no_token_file and not args.mock)
    backend = MockBackend() if args.mock else SystemBackend(cfg.host_socks(), cfg.control_port)
    app = App(cfg, backend, token, mock=args.mock, config_path=cfg_path)

    # If a previous session crashed/was killed while connected, resolv.conf may
    # still be pinned even though we are no longer routing. Restore it on start
    # so the host is never stranded without DNS.
    if not args.mock:
        app.recover_orphaned_dns()

    httpd = make_server(app, cfg.host, cfg.port)
    url = f"http://{cfg.host}:{cfg.port}/"
    banner = "MOCK MODE — no privileges, no Tor" if args.mock else "live"
    app.log.emit("info", f"torando-gui {__version__} listening on {url} ({banner})")
    print(f"torando-gui {__version__} on {url}  [{banner}]", file=sys.stderr)
    if not args.mock:
        print(f"token: {token}", file=sys.stderr)

    stop = threading.Event()

    def _shutdown(*_a: object) -> None:
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
