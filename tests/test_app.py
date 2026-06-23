# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""App orchestration tests, focused on failure-path safety: a connect() that
fails after resolv.conf was pinned must roll the pin back, so a failed connect
never leaves the host's DNS pointing at a dead local resolver."""

from __future__ import annotations

import pytest
from torando_gui.app import App, MockBackend
from torando_gui.config import Config


class FlakyBackend(MockBackend):
    """MockBackend whose apply_rules fails, with lock/unlock call accounting."""

    def __init__(self) -> None:
        super().__init__()
        self.locked = False
        self.unlocked = False

    def lock_resolv(self, cfg: Config) -> dict[str, object]:
        self.locked = True
        return super().lock_resolv(cfg)

    def unlock_resolv(self, cfg: Config) -> dict[str, object]:
        self.unlocked = True
        return super().unlock_resolv(cfg)

    def apply_rules(self, uid: int, trans: int, dns: int) -> None:
        raise RuntimeError("simulated iptables failure")


def _app(backend, tmp_path) -> App:
    return App(
        Config(target_uid=1000),
        backend,
        "tok",
        mock=True,
        config_path=tmp_path / "config.json",
    )


def test_connect_rolls_back_resolv_on_rule_failure(tmp_path):
    backend = FlakyBackend()
    app = _app(backend, tmp_path)
    with pytest.raises(RuntimeError, match="simulated iptables failure"):
        app.connect()
    assert backend.locked is True
    assert backend.unlocked is True  # the pin was rolled back


def test_connect_happy_path_does_not_unlock(tmp_path):
    backend = MockBackend()
    app = App(
        Config(target_uid=1000),
        backend,
        "tok",
        mock=True,
        config_path=tmp_path / "config.json",
    )
    st = app.connect()
    assert st["active"] is True
    assert st["rules"]["killswitch"] is True
