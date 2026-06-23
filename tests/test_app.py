# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""App orchestration tests, focused on failure-path and recovery safety.

The contract these lock down — the difference between "usable" and "lost my
internet and had to hand-edit resolv.conf":

  * connect() pins resolv.conf LAST (after the firewall redirect is live) and
    rolls EVERYTHING back on any failure, so a failed connect never leaves the
    host pinned or half-routed.
  * disconnect() restores DNS first and unconditionally.
  * recover_orphaned_dns() un-pins DNS at startup if a previous session died
    while connected (rules gone, pin left behind).
"""

from __future__ import annotations

import pytest
from torando_gui.app import App, MockBackend
from torando_gui.config import Config


class StatefulBackend(MockBackend):
    """MockBackend that models resolv pin + rule state with call accounting."""

    def __init__(self, *, fail_rules: bool = False, fail_lock: bool = False) -> None:
        super().__init__()
        self.pinned = False
        self.rules = False
        self.unlock_calls = 0
        self._fail_rules = fail_rules
        self._fail_lock = fail_lock

    def apply_rules(self, uid: int, trans: int, dns: int) -> None:
        if self._fail_rules:
            raise RuntimeError("simulated iptables failure")
        self.rules = True
        super().apply_rules(uid, trans, dns)

    def remove_rules(self, uid: int, trans: int, dns: int) -> None:
        self.rules = False
        super().remove_rules(uid, trans, dns)

    def lock_resolv(self, cfg: Config) -> dict[str, object]:
        if self._fail_lock:
            raise RuntimeError("simulated chattr failure")
        self.pinned = True
        return super().lock_resolv(cfg)

    def unlock_resolv(self, cfg: Config) -> dict[str, object]:
        self.unlock_calls += 1
        self.pinned = False
        return super().unlock_resolv(cfg)

    def resolv_is_pinned(self, cfg: Config) -> bool:
        return self.pinned

    def rules_status(self, uid: int, trans: int, dns: int) -> dict[str, object]:
        st = super().rules_status(uid, trans, dns)
        st["killswitch"] = self.rules
        st["active"] = self.rules
        return st


def _app(backend, tmp_path) -> App:
    return App(
        Config(target_uid=1000), backend, "tok", mock=True, config_path=tmp_path / "config.json"
    )


def test_connect_happy_path_pins_and_routes(tmp_path):
    backend = StatefulBackend()
    st = _app(backend, tmp_path).connect()
    assert backend.rules is True
    assert backend.pinned is True
    assert st["rules"]["killswitch"] is True


def test_failed_rules_leaves_no_pin_no_rules(tmp_path):
    # apply_rules runs BEFORE lock_resolv now, so a rule failure must leave DNS
    # untouched (never pinned) and no rules behind.
    backend = StatefulBackend(fail_rules=True)
    with pytest.raises(RuntimeError, match="iptables"):
        _app(backend, tmp_path).connect()
    assert backend.pinned is False  # DNS never pinned -> internet intact
    assert backend.rules is False


def test_failed_lock_rolls_back_rules(tmp_path):
    # If pinning DNS fails (e.g. chattr), the rules that were already applied
    # must be rolled back so the killswitch isn't left armed without DNS.
    backend = StatefulBackend(fail_lock=True)
    with pytest.raises(RuntimeError, match="chattr"):
        _app(backend, tmp_path).connect()
    assert backend.pinned is False
    assert backend.rules is False  # rolled back


def test_disconnect_always_restores_dns(tmp_path):
    backend = StatefulBackend()
    app = _app(backend, tmp_path)
    app.connect()
    app.disconnect()
    assert backend.pinned is False
    assert backend.rules is False
    assert backend.unlock_calls >= 1


def test_recover_orphaned_dns_unpins_when_not_routing(tmp_path):
    # Simulate a crashed session: pin present, but no rules (killswitch gone).
    backend = StatefulBackend()
    backend.pinned = True
    backend.rules = False
    app = _app(backend, tmp_path)
    app.recover_orphaned_dns()
    assert backend.pinned is False  # DNS rescued
    assert backend.unlock_calls == 1


def test_recover_leaves_pin_when_genuinely_routing(tmp_path):
    # Pin present AND rules present -> genuinely connected; must NOT un-pin.
    backend = StatefulBackend()
    backend.pinned = True
    backend.rules = True
    app = _app(backend, tmp_path)
    app.recover_orphaned_dns()
    assert backend.pinned is True
    assert backend.unlock_calls == 0


def test_update_config_blocks_routing_field_change_while_connected(tmp_path):
    backend = StatefulBackend()
    app = _app(backend, tmp_path)
    app.connect()  # now routing
    with pytest.raises(RuntimeError, match="disconnect before changing"):
        app.update_config({"trans_port": 9999})
    # a non-routing field is fine while connected
    st = app.update_config({"exit_country": "de"})
    assert st["config"]["exit_country"] == "de"


def test_update_config_allows_routing_change_when_disconnected(tmp_path):
    backend = StatefulBackend()
    app = _app(backend, tmp_path)
    st = app.update_config({"target_uid": 0})  # root: a uid that always exists
    assert st["config"]["target_uid"] == 0
