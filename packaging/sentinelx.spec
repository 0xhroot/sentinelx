Name:           sentinelx
Version:        1.0.0
Release:        1%{?dist}
Summary:        Enterprise Linux Runtime Integrity & Rootkit Detection Platform

License:        GPLv3+
URL:            https://github.com/sentinelx/sentinelx
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  cargo
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel

%description
SentinelX is an enterprise-grade Linux runtime integrity monitoring and
rootkit detection platform. It provides real-time kernel-level telemetry
via eBPF, fanotify, netlink, and audit sockets, with 7 detection engines,
automated response capabilities, and fleet management for multi-host
deployments.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked

%check
cargo test --workspace --locked

%install
install -Dm755 target/release/sentinelx-backend %{buildroot}/usr/bin/sentinelx-backend
install -Dm755 target/release/sentinelx-cli %{buildroot}/usr/bin/sentinelx-cli
install -Dm644 packaging/sentinelx.service %{buildroot}/usr/lib/systemd/system/sentinelx.service
install -Dm644 packaging/sentinelx.conf %{buildroot}/etc/sentinelx/sentinelx.toml
install -dm755 %{buildroot}/var/lib/sentinelx

%files
%license LICENSE
%doc README.md CHANGELOG.md
/usr/bin/sentinelx-backend
/usr/bin/sentinelx-cli
%dir /etc/sentinelx
%config(noreplace) /etc/sentinelx/sentinelx.toml
%dir /var/lib/sentinelx
/usr/lib/systemd/system/sentinelx.service

%post
%systemd_post sentinelx.service

%preun
%systemd_preun sentinelx.service

%postun
%systemd_postun_with_restart sentinelx.service
