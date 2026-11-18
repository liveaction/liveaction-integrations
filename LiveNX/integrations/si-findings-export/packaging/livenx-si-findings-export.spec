Name:           livenx-si-findings-export
Version:        %{?pkg_version}%{!?pkg_version:1.1.0}
Release:        1%{?dist}
Summary:        Export LiveNX Security Insight findings to a JSON Lines file
License:        Proprietary
BuildArch:      noarch
Requires:       python3
Requires:       systemd
Requires(pre):  shadow-utils

# No Source: tags; build_rpm.sh puts the files in %%{_sourcedir}.
%description
Runs a systemd service that continuously reads LiveNX Security Insight
findings (the si_findings table) through the LiveNX REST API and appends them
to a JSON Lines file under /data. It runs on any RHEL 8 compatible host that
reaches LiveNX on port 443, or on the LiveNX server itself.

Everything is installed under /var, /etc and /data.

%prep

%build

%install
install -d -m 0755 %{buildroot}/var/lib/%{name}
install -d -m 0755 %{buildroot}/etc/%{name}
install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0755 %{_sourcedir}/si_findings_export.py %{buildroot}/var/lib/%{name}/si_findings_export.py
install -m 0600 %{_sourcedir}/si-findings-export.env %{buildroot}/etc/%{name}/si-findings-export.env
install -m 0644 %{_sourcedir}/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%pre
if ! getent passwd si-findings-export >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin si-findings-export
fi

%post
install -d -o si-findings-export -g si-findings-export -m 0755 /data/si-findings-export
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable %{name}.service >/dev/null 2>&1 || :
    # Exits immediately (and stays stopped) until SI_LIVENX_HOST is set.
    systemctl restart %{name}.service || :
fi

%preun
# $1 is 0 on erase and 1 on upgrade; only stop the service when removing.
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now %{name}.service >/dev/null 2>&1 || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
# The service account, the export position and the exported findings in
# /data/si-findings-export are left for the operator to remove.

%files
%attr(0755,root,root) /var/lib/%{name}/si_findings_export.py
%dir /var/lib/%{name}
%dir /etc/%{name}
%config(noreplace) %attr(0600,root,root) /etc/%{name}/si-findings-export.env
%{_unitdir}/%{name}.service

%changelog
* Wed Nov 18 2026 LiveAction Integrations <noreply@liveaction.com> - 1.1.0-1
- Initial RPM for RHEL 8; same payload as the Debian package
- Log in with SI_API_USERNAME / SI_API_PASSWORD when the API token is not accepted
