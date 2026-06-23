# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Native desktop application window (GTK4 + WebKitGTK).

This is the "full app, not a website" front end: a real application window —
its own title bar, icon, taskbar entry and process — that embeds the daemon's
control UI, the same way the Mullvad VPN desktop app embeds its web UI in a
native shell. There is no address bar and no browser chrome.

The window has no privileges of its own. It talks to the root daemon
(``torando-guid``) only over the loopback HTTP API on 127.0.0.1, exactly like
the browser path — the daemon injects the per-session token into the page.

If GTK4/WebKitGTK/PyGObject aren't installed, :func:`run` degrades gracefully
to opening the UI in the user's browser (``launcher.open_in_browser``), so the
tool is always usable.
"""

from __future__ import annotations

import html
import sys

from .launcher import _url, ensure_daemon

APP_ID = "co.securityops.torando-gui"
TITLE = "Torando Control"


def _error_html(url: str, hint: str) -> str:
    """A small dark error page shown in-window when the daemon isn't reachable."""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
  html,body{{height:100%;margin:0;background:#11141a;color:#e6e9ef;
    font:15px/1.5 system-ui,sans-serif;display:flex;align-items:center;
    justify-content:center}}
  .card{{max-width:30rem;padding:2rem;text-align:center}}
  h1{{font-size:1.15rem;margin:0 0 .75rem}}
  code{{background:#1b1f29;padding:.15rem .4rem;border-radius:.3rem;
    color:#9ecbff;white-space:pre-wrap}}
  .muted{{color:#9aa3b2;font-size:.92rem;margin-top:1rem}}
</style></head><body><div class="card">
  <h1>Torando Control daemon is not reachable</h1>
  <p>The GUI could not reach the backend at <code>{html.escape(url)}</code>.</p>
  <p><code>{html.escape(hint)}</code></p>
  <p class="muted">This window will connect automatically once the daemon is up
  — use the reload button.</p>
</div></body></html>"""


def run(argv: list[str] | None = None) -> int:
    """Show the native window. Returns a process exit code.

    Falls back to the browser launcher if the GTK stack is unavailable.
    """
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("WebKit", "6.0")
        from gi.repository import Gio, Gtk, WebKit
    except Exception as exc:  # noqa: BLE001 — ANY toolkit problem must fall back
        # ImportError (no PyGObject), ValueError (typelib version absent),
        # AttributeError (a shadowing `gi`), etc. — never crash; use the browser.
        sys.stderr.write(
            f"native GUI unavailable ({exc}); opening in your browser instead.\n"
        )
        from .launcher import open_in_browser

        return open_in_browser(argv)

    url = _url()
    reachable, hint = ensure_daemon()

    app = Gtk.Application(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def on_activate(application: "Gtk.Application") -> None:
        win = Gtk.ApplicationWindow(application=application)
        win.set_title(TITLE)
        win.set_default_size(1024, 768)
        win.set_icon_name("torando-gui")

        web = WebKit.WebView()
        settings = web.get_settings()
        # Lock the embedded view down: it only ever loads our loopback origin.
        settings.set_property("enable-developer-extras", False)
        settings.set_property("enable-back-forward-navigation-gestures", False)

        header = Gtk.HeaderBar()
        reload_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        reload_btn.set_tooltip_text("Reload")
        reload_btn.connect("clicked", lambda _b: web.load_uri(url))
        header.pack_start(reload_btn)
        win.set_titlebar(header)

        if reachable:
            web.load_uri(url)
        else:
            web.load_html(_error_html(url, hint), url)
        win.set_child(web)
        win.present()

    app.connect("activate", on_activate)
    # Don't hand our CLI args to GTK (it would reject unknown options).
    return app.run([sys.argv[0]])


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
