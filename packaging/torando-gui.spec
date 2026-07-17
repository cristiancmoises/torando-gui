# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
Name:           torando-gui
Version:        1.3.0
Release:        1%{?dist}
Summary:        Route a user's egress through Tor (transparent proxy + killswitch)

License:        AGPL-3.0-only
URL:            https://github.com/cristiancmoises/torando-gui
BuildArch:      noarch

Requires:       python3 >= 3.11
Requires:       tor
Requires:       iptables
Requires:       e2fsprogs
Requires:       polkit
# Native desktop GUI (GTK4 + WebKitGTK). Optional: without them the launcher
# falls back to opening the UI in the browser.
Recommends:     python3-gobject
Recommends:     gtk4
Recommends:     webkitgtk6.0
Suggests:       python3-pillow

%description
Loopback web GUI that forces one local user's traffic through Tor's
TransPort/DNSPort and drops everything else from that user (a killswitch).
Automates the upstream torando iptables rules plus torrc and resolv.conf
management, and shows live bootstrap, DNS-leak and exit status.

%prep
# Sources are staged by build-rpm.sh into %{_sourcedir}/stage; nothing to do.

%build
# Pure Python; no compilation.

%install
rm -rf %{buildroot}
cp -a %{_sourcedir}/stage/. %{buildroot}/
install -d %{buildroot}%{_licensedir}/%{name}
install -m 0644 %{_sourcedir}/LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/THREAT_MODEL.md
%{_prefix}/lib/torando-gui/
%{_bindir}/torando-gui
%{_bindir}/torando-guid
%{_prefix}/lib/systemd/system/torando-gui.service
%{_datadir}/polkit-1/actions/co.securityops.torando-gui.policy
%{_datadir}/polkit-1/rules.d/49-torando-gui.rules
%{_datadir}/applications/torando-gui.desktop
%{_datadir}/icons/hicolor/*/apps/torando-gui.png

%post
%systemd_post torando-gui.service

%preun
%systemd_preun torando-gui.service

%postun
%systemd_postun_with_restart torando-gui.service

%changelog
* Mon Jun 23 2026 Cristian Cezar Moisés <cristian@securityops.co> - 1.0.1-1
- Robustness/correctness pass: durable atomic writes (fsync), failed-connect
  rolls back the resolv.conf pin, corrupt GeoIP DB never crashes, torrc keeps a
  single managed block, plain-COOKIE Tor control auth, HEAD/SSE and query-token
  hardening. Declare e2fsprogs (chattr) as a dependency.
* Fri Jun 19 2026 Cristian Cezar Moisés <cristian@securityops.co> - 1.0.0-1
- Initial release.
