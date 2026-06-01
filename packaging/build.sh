#!/usr/bin/env bash
# packaging/build.sh — build Protek as .deb (default) or .rpm.
#
# Usage:
#   ./packaging/build.sh         # → ../protek_2.1.0-1_all.deb
#   ./packaging/build.sh deb     # same as above
#   ./packaging/build.sh rpm     # → ~/rpmbuild/RPMS/noarch/protek-2.1.0-1.*.noarch.rpm
#
# Build dependencies:
#   Debian/Ubuntu: build-essential debhelper dh-python python3-all
#                  python3-setuptools devscripts
#   Fedora/RHEL:   rpm-build rpmdevtools systemd-rpm-macros python3 git
#
# Neither path bundles the venv — both ship code + requirements.txt
# and let the postinst/postscriptlet build the venv on install. This
# keeps the package noarch and avoids ABI lock-in to the build host's
# Python.

set -e
cd "$(dirname "$0")/.."

kind="${1:-deb}"

case "$kind" in

  deb)
    if [ ! -d packaging/debian ]; then
      echo "packaging/debian/ missing — are you in the repo root?" >&2
      exit 1
    fi
    if ! command -v dpkg-buildpackage >/dev/null; then
      echo "dpkg-buildpackage not found — install with:" >&2
      echo "  sudo apt install -y build-essential debhelper dh-python python3-all python3-setuptools devscripts" >&2
      exit 1
    fi
    # dh expects debian/ at the repo root. The symlink target is relative
    # to the symlink's own location (the repo root), so `packaging/debian`
    # — not `../packaging/debian` (which would resolve to /var/www/packaging
    # one directory up). Trap removes it on exit even if the build errors.
    ln -sfn packaging/debian debian
    trap 'rm -f debian' EXIT
    chmod +x packaging/debian/postinst packaging/debian/prerm packaging/debian/rules
    dpkg-buildpackage -us -uc -b
    echo
    echo "Built: $(ls -1 ../protek_*.deb 2>/dev/null | head -1)"
    echo "Test in a fresh container:"
    echo "   docker run -it --rm -v \"\$(pwd)/..\":/work debian:12 \\"
    echo "       bash -c 'apt update && apt install -y /work/protek_*.deb'"
    ;;

  rpm)
    if ! command -v rpmbuild >/dev/null; then
      echo "rpmbuild not found — install with:" >&2
      echo "  sudo dnf install -y rpm-build rpmdevtools systemd-rpm-macros" >&2
      exit 1
    fi
    if [ ! -f packaging/rpm/protek.spec ]; then
      echo "packaging/rpm/protek.spec missing" >&2
      exit 1
    fi

    # Extract version from the spec to keep .deb and .rpm aligned.
    version="$(awk '/^Version:/ {print $2; exit}' packaging/rpm/protek.spec)"
    if [ -z "$version" ]; then
      echo "couldn't parse Version: from spec file" >&2
      exit 1
    fi

    # rpmbuild tree
    rpmdev-setuptree 2>/dev/null || mkdir -p "$HOME/rpmbuild"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}

    # Source tarball — git archive guarantees we package only tracked files.
    tarball="$HOME/rpmbuild/SOURCES/protek-${version}.tar.gz"
    git archive --format=tar.gz --prefix="protek-${version}/" \
                -o "$tarball" HEAD
    echo "Source: $tarball"

    cp packaging/rpm/protek.spec "$HOME/rpmbuild/SPECS/"
    rpmbuild -ba "$HOME/rpmbuild/SPECS/protek.spec"
    echo
    echo "Built:"
    ls -1 "$HOME/rpmbuild/RPMS/noarch/protek-${version}-1."*.rpm
    ;;

  *)
    echo "Usage: $0 [deb|rpm]" >&2
    exit 2
    ;;
esac
