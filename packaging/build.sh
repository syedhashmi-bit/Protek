#!/bin/sh
# Build a .deb of Protek 2.0.
# Run on Debian 12+ or Ubuntu 22.04+ with build-essentials + dh-python installed:
#   sudo apt install -y build-essential debhelper dh-python python3-all python3-setuptools devscripts
#
# Usage (from repo root):
#   ./packaging/build.sh
# Output:
#   ../protek_2.0.0-1_all.deb
set -e
cd "$(dirname "$0")/.."

if [ ! -d packaging/debian ]; then
    echo "packaging/debian/ missing — are you in the repo root?"
    exit 1
fi

# dh expects debian/ at the repo root
ln -sfn ../packaging/debian debian
chmod +x packaging/debian/postinst packaging/debian/prerm packaging/debian/rules

dpkg-buildpackage -us -uc -b
rm -f debian

echo
echo "Built: $(ls -1 ../protek_*.deb 2>/dev/null | head -1)"
echo "Test in a fresh container:"
echo "   docker run -it --rm -v \"\$(pwd)/..\":/work debian:12 \\"
echo "       bash -c 'apt update && apt install -y /work/protek_*.deb'"
