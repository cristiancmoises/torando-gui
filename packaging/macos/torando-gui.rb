# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Homebrew formula for Torando Control. Ship this in a tap
# (e.g. cristiancmoises/tap) so users can:
#
#   brew tap cristiancmoises/tap
#   brew install torando-gui
#   sudo brew services start tor
#   torando-gui
#
# Replace the url/sha256 with the tagged release archive when cutting a release:
#   sha256sum torando-gui-1.3.4.tar.gz
class TorandoGui < Formula
  desc "Route a user's egress through Tor (system SOCKS proxy + pf killswitch)"
  homepage "https://github.com/cristiancmoises/torando-gui"
  url "https://github.com/cristiancmoises/torando-gui/archive/refs/tags/v1.3.4.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "AGPL-3.0-only"

  depends_on "python@3.12"
  depends_on "tor" => :recommended

  def install
    # Pure-stdlib package: install the tree under libexec and shim the CLIs.
    libexec.install "backend/torando_gui"
    py = Formula["python@3.12"].opt_bin/"python3.12"
    %w[torando-gui torando-guid].each do |name|
      mod = name == "torando-gui" ? "torando_gui.launcher" : "torando_gui"
      (bin/name).write <<~SH
        #!/bin/sh
        export PYTHONPATH="#{libexec}${PYTHONPATH:+:$PYTHONPATH}"
        exec "#{py}" -m #{mod} "$@"
      SH
      chmod 0755, bin/name
    end
  end

  def caveats
    <<~EOS
      The root daemon (torando-guid) must run as root to drive pf, the system
      SOCKS proxy and DNS. Start it with:
        sudo torando-guid
      or install the LaunchDaemon from the release's packaging/macos/.
      Tor must be running: brew services start tor
    EOS
  end

  test do
    assert_match "1.3.4", shell_output("#{bin}/torando-guid --version")
  end
end
