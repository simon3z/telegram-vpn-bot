%bcond_without check

Name:           telegram-vpn-bot
Version:        0.3.0
# Release: computed by rpm-build.sh (--define release N = commits since
# the last tag + 1); defaults to 1 when release is not defined.
Release:        %{?release}%{!?release:1}%{?dist}
Summary:        Telegram bot that manages WireGuard VPN peers (port knocking)
# Cumulative SPDX expression (project AND union of all vendored crate
# licenses); verified by rpm-build.sh (license_expression) against the
# Cargo.toml license fields of the vendored crates.
License:        MIT AND Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-1-Clause AND BSD-2-Clause AND BSD-3-Clause AND ISC AND LGPL-2.1-or-later AND MIT/Apache-2.0 AND Unicode-3.0 AND Unlicense
URL:            https://github.com/simon3z/telegram-vpn-bot
# Source0: git archive of the project
# Source1: vendored dependencies (cargo vendor) + .cargo/config
Source0:        %{name}-%{version}.tar.xz
Source1:        %{name}-%{version}-vendor.tar.xz

ExclusiveArch:  %{rust_arches}

Requires:       systemd

BuildRequires:  rust
# cargo-rpm-macros provides the %%cargo_* macros and the cargo_vendor
# fileattr hook: the cargo-vendor.txt installed under %%{_defaultlicensedir}
# becomes Provides: bundled(crate(<name>)) = <version> per vendored crate.
BuildRequires:  cargo-rpm-macros
# native-tls (reqwest's TLS backend) links against the system OpenSSL;
# boringtun's C code is compiled with cc-rs using the standard build flags.
BuildRequires:  openssl-devel

%description
%{summary}.

%prep
# -a 1: extract the vendor tarball (Source1) on top of Source0
%autosetup -a 1
# %%cargo_prep writes .cargo/config.toml (offline mode, vendored
# sources, [profile.rpm]). Offline resolution is driven by the
# Cargo.lock shipped in Source0; it must match the vendored set, and
# both come from the repo's tracked Cargo.lock.
%cargo_prep -v vendor

# System user and group for the daemon, defined declaratively so rpm
# (>= 4.19) creates them from this file during installation.
cat > telegram-vpn-bot-sysusers.conf <<'EOF'
g tgvpnbot -
u tgvpnbot - - /var/lib/tgvpnbot /usr/sbin/nologin
EOF

%build
# %%cargo_build: cargo build --profile rpm -Z avoid-dev-deps + smp flags;
# offline mode comes from the .cargo/config.toml that %%cargo_prep wrote.
%cargo_build
# Write cargo-vendor.txt (one "name vX.Y.Z" line per crate); %%install
# ships it to the license dir where the cargo_vendor fileattr hook reads
# it to emit the bundled(crate(<name>) = <version>) provides.
%cargo_vendor_manifest

%install
# %%cargo_install: cargo install --profile rpm --no-track --path .
export PATH="%{buildroot}%{_bindir}:$PATH"
%cargo_install
# Ship the example config where the unit file expects it (/etc/tgvpnbot).
install -Dm 0644 config/config.toml.example \
    %{buildroot}/etc/tgvpnbot/config.toml
install -Dm 0644 config/telegram-vpn-bot.service \
    %{buildroot}/usr/lib/systemd/system/telegram-vpn-bot.service
# rpm's sysusers handler creates the user but not its home directory
# (useradd without -m), so package it for the unit's WorkingDirectory.
install -d %{buildroot}/var/lib/tgvpnbot
# Ship the sysusers config defining the tgvpnbot user and group; rpm
# creates them from this file during installation, so the unit's
# User=/Group= and WorkingDirectory exist before the service can start.
install -Dm 0644 telegram-vpn-bot-sysusers.conf \
    %{buildroot}%{_sysusersdir}/%{name}.conf
# Ship the vendor manifest and the bundled crates' license files to the
# package license dir; the cargo_vendor fileattr hook only emits its
# provides when cargo-vendor.txt lives under %%{_defaultlicensedir}.
# Crate-name prefixes avoid basename clashes (LICENSE is not unique).
mkdir -p %{buildroot}%{_defaultlicensedir}/%{name}
install -m 0644 cargo-vendor.txt \
    "%{buildroot}%{_defaultlicensedir}/%{name}/"
for crate in vendor/*/; do
    c=$(basename "$crate")
    ls "$crate" | grep -iE '^(licen|copying)' | while read -r f; do
        install -m 0644 "$crate$f" \
            "%{buildroot}%{_defaultlicensedir}/%{name}/${c}-$f"
    done
done

%check
%if %{with check}
# Single binary crate (no lib target); test the bin target with the
# rpm profile, as ci.sh does with --release --all-targets.
%{__cargo} test %{__cargo_common_opts} --profile rpm --bins --no-fail-fast
%endif

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun %{name}.service

%files
%license LICENSE
%license %{_defaultlicensedir}/%{name}/*
%doc README.md
%{_bindir}/telegram-vpn-bot
%config(noreplace) /etc/tgvpnbot/config.toml
/usr/lib/systemd/system/telegram-vpn-bot.service
%dir /var/lib/tgvpnbot
%{_sysusersdir}/%{name}.conf

%changelog
* Tue Oct 13 2026 Federico Simoncelli <federico.simoncelli@gmail.com> - 0.3.0-%{?release}%{!?release:1}
- Updated to upstream 0.3.0

* Sat Oct 10 2026 Federico Simoncelli <federico.simoncelli@gmail.com> - 0.2.0-%{?release}%{!?release:1}
- Initial package release
