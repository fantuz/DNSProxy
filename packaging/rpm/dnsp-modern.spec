Name:           dnsp-modern
Version:        %{dnsp_version}
Release:        1%{?dist}
Summary:        DNS-over-HTTPS forwarding resolver
License:        MIT
URL:            https://github.com/fantuz/DNSProxy
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl
BuildRequires:  pkgconfig(libcurl)
BuildRequires:  python3
BuildRequires:  redhat-rpm-config
BuildRequires:  systemd-rpm-macros
Requires:       ca-certificates
Requires:       python3
%{?systemd_ordering}

%description
Event-driven DNS-over-HTTPS forwarder with UDP and TCP listeners, EDNS
validation and Prometheus metrics. The systemd service is opt-in.

%prep
%autosetup

%build
%set_build_flags
%make_build -f modern.mk

%install
install -Dpm 0755 dnsp-modern %{buildroot}%{_bindir}/dnsp-modern
install -Dpm 0644 packaging/systemd/dnsp-modern.service %{buildroot}%{_unitdir}/dnsp-modern.service

install -Dpm 0755 packaging/linux/dnsp-configure-dns %{buildroot}%{_sbindir}/dnsp-configure-dns
install -Dpm 0644 packaging/systemd/dnsp-modern-dns-recovery.service %{buildroot}%{_unitdir}/dnsp-modern-dns-recovery.service
install -Dpm 0644 packaging/systemd/dnsp-modern-dns-recovery.timer %{buildroot}%{_unitdir}/dnsp-modern-dns-recovery.timer

%check
%make_build -f modern.mk modern-check

# Skip the preset macro so initial enablement stays with the operator.
# The distro's systemd unit-file triggers handle daemon reloads.
%preun
if [ "$1" -eq 0 ] && [ -f /var/lib/dnsp-modern-integration/state.json ]; then
    echo 'Restore DNS with dnsp-configure-dns restore before removing dnsp-modern.' >&2
    exit 1
fi
%systemd_preun dnsp-modern.service dnsp-modern-dns-recovery.timer

%postun
%systemd_postun_with_restart dnsp-modern.service

%files
%license LICENSE
%doc packaging/README-packaging.md packaging/systemd/port-53.conf
%{_bindir}/dnsp-modern
%{_unitdir}/dnsp-modern.service
%{_sbindir}/dnsp-configure-dns
%{_unitdir}/dnsp-modern-dns-recovery.service
%{_unitdir}/dnsp-modern-dns-recovery.timer
