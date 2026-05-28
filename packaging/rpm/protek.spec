# Protek RPM spec — phase 71.
#
# Build with rpmbuild + a source tarball:
#   ./packaging/build.sh rpm     (see packaging/build.sh)
#
# Or manually:
#   git archive --format=tar.gz --prefix=protek-2.1.0/ HEAD > ~/rpmbuild/SOURCES/protek-2.1.0.tar.gz
#   rpmbuild -ba packaging/rpm/protek.spec
#
# Resulting RPM lands in ~/rpmbuild/RPMS/noarch/protek-2.1.0-1.*.noarch.rpm

%global appname     protek
%global appshare    %{_datadir}/protek
%global apphome     %{_localstatedir}/lib/protek
%global appconf     %{_sysconfdir}/protek
%global applogs     %{_localstatedir}/log/protek
%global appvenv     %{_libdir}/protek/venv

# Disable strip + build-id mangling on a pure-Python package.
%global __os_install_post %{nil}
%global debug_package %{nil}

Name:           protek
Version:        2.1.0
Release:        1%{?dist}
Summary:        CrowdSec → MikroTik bouncer with a NOC-style dashboard

License:        MIT
URL:            https://github.com/syedhashmi/Protek
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  systemd-rpm-macros
BuildRequires:  python3 >= 3.12

Requires:       python3 >= 3.12
Requires:       python3-virtualenv
Requires:       nginx
Requires:       sqlite
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Protek is a self-hosted CrowdSec bouncer that mirrors decisions from
one or more LAPI sources into a MikroTik RouterOS address-list, plus
a tactical-dark NOC dashboard for visibility (decisions, alerts,
scenarios, geo map, federation, multi-bouncer, intelligence layer).

Supports additional bouncer kinds (iptables/ipset, Cloudflare Rules
Lists, pfSense, OPNsense) and federation across multiple CrowdSec
instances. Off-box backups to S3-compatible storage. OIDC SSO. SLO
sustained-breach alerts. Automated DR drill. Disk + Litestream
observability watchdog.

%prep
%setup -q

%build
# Pure-Python — nothing to compile at build time. The venv is
# materialized at install time in %post so the deps are locked to the
# host's Python ABI rather than the build host's.

%install
rm -rf %{buildroot}

# Code dir
install -d -m 0755 %{buildroot}%{appshare}
cp -a *.py bouncers templates static scripts docs requirements.txt \
    %{buildroot}%{appshare}/
cp -a .env.example %{buildroot}%{appshare}/env.example

# Empty mutable state dirs (owned by protek:protek post-install)
install -d -m 0750 %{buildroot}%{apphome}
install -d -m 0750 %{buildroot}%{applogs}
install -d -m 0750 %{buildroot}%{appconf}

# systemd unit
install -D -m 0644 packaging/debian/protek.service \
    %{buildroot}%{_unitdir}/protek.service

%files
%license LICENSE
%doc README.md ROADMAP.md CONTEXT.md SKILL.md docs/DOCKER.md docs/grafana
%{appshare}
%{_unitdir}/protek.service
%attr(0750, protek, protek) %dir %{apphome}
%attr(0750, protek, protek) %dir %{applogs}
%attr(0750, root, protek)   %dir %{appconf}

%pre
# Idempotent user creation — matches the .deb postinst shape.
getent group protek >/dev/null || groupadd -r protek
getent passwd protek >/dev/null || \
    useradd -r -g protek -d %{apphome} -s /sbin/nologin \
            -c "Protek bouncer service" protek
exit 0

%post
# Build the venv once. Same logic as the .deb postinst — installer
# tracks the venv at %{appvenv} so upgrades skip rebuild unless missing.
if [ ! -f %{appvenv}/bin/python ]; then
    mkdir -p %{_libdir}/protek
    python3 -m venv %{appvenv}
    %{appvenv}/bin/pip install --no-cache-dir -U pip setuptools wheel
    %{appvenv}/bin/pip install --no-cache-dir -r %{appshare}/requirements.txt
fi

# Seed /etc/protek/.env from the example if missing.
if [ ! -f %{appconf}/.env ] && [ -f %{appshare}/env.example ]; then
    cp %{appshare}/env.example %{appconf}/.env
    chown root:protek %{appconf}/.env
    chmod 0640 %{appconf}/.env
    echo "*** %{appconf}/.env created from template — run setup_admin BEFORE START:"
    echo "***   sudo -u protek %{appvenv}/bin/python %{appshare}/scripts/setup_admin.py --username admin"
fi

%systemd_post protek.service
echo "*** Run 'systemctl start protek' once %{appconf}/.env is configured."

%preun
%systemd_preun protek.service

%postun
%systemd_postun_with_restart protek.service

%changelog
* Thu May 28 2026 Syed Hashmi <syed@syedhashmi.trade> - 2.1.0-1
- Arc 14 operator UX (phases 81-86)
- Arc 15 production-grade ops (phases 87-93)
- Arc 16 deploy + fleet ops (phases 94-98)
- Phase 33 Grafana board pack
- IPv6 + dry_run fixes

* Thu May 21 2026 Syed Hashmi <syed@syedhashmi.trade> - 2.0.0-1
- Initial 2.0 release — arcs 1-13 feature set
