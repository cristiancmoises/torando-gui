# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Config model + persistence tests."""

from __future__ import annotations

from torando_gui.config import Config, load, save


def test_defaults_mirror_upstream_torando_ports():
    c = Config()
    assert (c.trans_port, c.dns_port, c.socks_port, c.control_port) == (9040, 53, 9050, 9051)
    assert c.host == "127.0.0.1"
    assert c.target_uid is None
    assert c.host_socks() == "127.0.0.1"


def test_roundtrip_save_load(tmp_path):
    p = tmp_path / "config.json"
    c = Config(port=9999, target_uid=1000, exit_country="de", bridges=["obfs4 1.2.3.4:1 ABC"])
    save(c, p)
    back = load(p)
    assert back == c


def test_from_dict_drops_unknown_keys():
    c = Config.from_dict({"port": 1234, "totally_unknown": "x", "target_uid": 1001})
    assert c.port == 1234
    assert c.target_uid == 1001
    assert not hasattr(c, "totally_unknown")


def test_load_missing_file_returns_defaults(tmp_path):
    assert load(tmp_path / "nope.json") == Config()


def test_load_empty_file_returns_defaults(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("   \n")
    assert load(p) == Config()


def test_save_is_atomic_no_temp_left(tmp_path):
    p = tmp_path / "config.json"
    save(Config(), p)
    leftovers = [x.name for x in tmp_path.iterdir() if x.name != "config.json"]
    assert leftovers == []
    assert p.read_text().endswith("\n")


def test_sanitized_is_json_safe():
    import json

    json.dumps(Config().sanitized())  # must not raise
