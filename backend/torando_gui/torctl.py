# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""A small Tor control-protocol client (control-spec.txt).

Talks plaintext to Tor's ControlPort on localhost. Supports cookie auth and
null auth. Used for bootstrap progress, "new identity" (SIGNAL NEWNYM) and a
compact circuit summary. Everything degrades gracefully: if the control port
is closed, callers get ``None``/empty results and the UI hides those panels.
"""

from __future__ import annotations

import contextlib
import re
import socket
from dataclasses import dataclass

_PROGRESS = re.compile(r"PROGRESS=(\d+)")
_TAG = re.compile(r"TAG=(\S+)")
_SUMMARY = re.compile(r'SUMMARY="([^"]*)"')


class ControlError(RuntimeError):
    pass


@dataclass
class Bootstrap:
    progress: int
    tag: str
    summary: str


class TorControl:
    def __init__(self, host: str = "127.0.0.1", port: int = 9051, timeout: float = 4.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = bytearray()

    # --- connection lifecycle ------------------------------------------
    def __enter__(self) -> TorControl:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def connect(self) -> None:
        self._sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        self._sock.settimeout(self._timeout)
        self._authenticate()

    def close(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._send("QUIT")
            self._sock.close()
            self._sock = None

    def is_available(self) -> bool:
        try:
            self.connect()
        except (OSError, ControlError):
            return False
        else:
            self.close()
            return True

    # --- raw protocol --------------------------------------------------
    def _send(self, line: str) -> None:
        assert self._sock is not None
        self._sock.sendall(line.encode("ascii") + b"\r\n")

    def _read_line(self) -> str:
        assert self._sock is not None
        while b"\r\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ControlError("control connection closed")
            self._buf += chunk
        idx = self._buf.index(b"\r\n")
        line = self._buf[:idx].decode("ascii", "replace")
        del self._buf[: idx + 2]
        return line

    def _read_reply(self) -> list[str]:
        """Collect one reply, returning its payload lines. Raises on non-2xx."""
        lines: list[str] = []
        while True:
            line = self._read_line()
            if len(line) < 4:
                raise ControlError(f"malformed control line: {line!r}")
            code, sep, rest = line[:3], line[3], line[4:]
            if code[0] != "2":
                raise ControlError(f"{code}: {rest}")
            if sep == "+":  # multi-line data follows, terminated by "."
                lines.append(rest)
                while True:
                    data = self._read_line()
                    if data == ".":
                        break
                    lines.append(data)
                continue
            lines.append(rest)
            if sep == " ":  # final line of this reply
                return lines

    def command(self, line: str) -> list[str]:
        self._send(line)
        return self._read_reply()

    # --- auth ----------------------------------------------------------
    def _authenticate(self) -> None:
        info = self.command("PROTOCOLINFO 1")
        methods: list[str] = []
        cookie_path: str | None = None
        for ln in info:
            if ln.startswith("AUTH METHODS="):
                head = ln[len("AUTH METHODS=") :]
                methods = head.split(" ", 1)[0].split(",")
                m = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', ln)
                if m:
                    cookie_path = m.group(1).encode().decode("unicode_escape")
        # Plain COOKIE auth only. The SAFECOOKIE AUTHCHALLENGE handshake is not
        # implemented; Tor's default CookieAuthentication advertises COOKIE
        # alongside SAFECOOKIE, so loopback cookie auth still works. (A
        # SAFECOOKIE-only ControlPort would fall through to the error below.)
        if "COOKIE" in methods and cookie_path:
            with open(cookie_path, "rb") as fh:
                cookie = fh.read()
            self.command(f"AUTHENTICATE {cookie.hex()}")
        elif "NULL" in methods or not methods:
            self.command("AUTHENTICATE")
        else:
            raise ControlError(f"unsupported auth methods: {methods}")

    # --- high level ----------------------------------------------------
    def bootstrap(self) -> Bootstrap | None:
        try:
            reply = self.command("GETINFO status/bootstrap-phase")
        except ControlError:
            return None
        text = "\n".join(reply)
        prog = _PROGRESS.search(text)
        tag = _TAG.search(text)
        summ = _SUMMARY.search(text)
        if not prog:
            return None
        return Bootstrap(
            int(prog.group(1)),
            tag.group(1) if tag else "",
            summ.group(1) if summ else "",
        )

    def new_identity(self) -> None:
        self.command("SIGNAL NEWNYM")

    def circuit_count(self) -> int:
        try:
            reply = self.command("GETINFO circuit-status")
        except ControlError:
            return 0
        return sum(1 for ln in reply if " BUILT " in f" {ln} ")
