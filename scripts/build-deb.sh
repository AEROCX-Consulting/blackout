#!/bin/sh
# Maakt een .deb voor Debian, Ubuntu en Raspberry Pi OS.
#
#   scripts/build-deb.sh <arch: arm64|amd64> <pad naar binary> <versie> [uitvoermap]
#
# Uitvoer: <uitvoermap>/aerocx-blackout_<arch>.deb (vaste naam, zie design/CONTRACT.md §6).
set -eu

ARCH="${1:?arch ontbreekt (arm64 of amd64)}"
BIN="${2:?pad naar de binary ontbreekt}"
VERSION="${3:?versie ontbreekt}"
OUT="${4:-dist}"
MAINTAINER="${DEB_MAINTAINER:-AEROCX <noreply@aerocx.be>}"

case "$ARCH" in arm64 | amd64) ;; *)
	echo "onbekende arch: $ARCH" >&2
	exit 1
	;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$ROOT/packaging"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
D="$WORK/aerocx-blackout"

install -d -m 755 "$D/DEBIAN" "$D/usr/bin" "$D/usr/lib/systemd/user" "$D/usr/share/applications" \
	"$D/usr/share/icons/hicolor/256x256/apps" "$D/usr/share/icons/hicolor/1024x1024/apps" \
	"$D/usr/share/pixmaps" "$D/usr/share/doc/aerocx-blackout"
install -m 755 "$BIN" "$D/usr/bin/aerocx-blackout"
install -m 644 "$PKG/linux/aerocx-blackout.service" "$D/usr/lib/systemd/user/aerocx-blackout.service"
install -m 644 "$PKG/linux/aerocx-blackout.desktop" "$D/usr/share/applications/aerocx-blackout.desktop"
install -m 644 "$PKG/icon-256.png" "$D/usr/share/icons/hicolor/256x256/apps/aerocx-blackout.png"
install -m 644 "$PKG/icon.png" "$D/usr/share/icons/hicolor/1024x1024/apps/aerocx-blackout.png"
install -m 644 "$PKG/icon-256.png" "$D/usr/share/pixmaps/aerocx-blackout.png"
install -m 644 "$ROOT/LICENSE" "$D/usr/share/doc/aerocx-blackout/copyright"
install -m 755 "$PKG/linux/postinst" "$D/DEBIAN/postinst"

# Debian-versie: "1.2.0-dev.5" zou als upstream + revisie gelezen worden; maak er 1.2.0~dev.5 van.
DEB_VERSION="$(printf '%s' "$VERSION" | sed 's/-/~/g')"
SIZE="$(du -sk "$D/usr" | cut -f1)"
sed -e "s|@VERSION@|$DEB_VERSION|" -e "s|@ARCH@|$ARCH|" -e "s|@MAINTAINER@|$MAINTAINER|" -e "s|@SIZE@|$SIZE|" \
	"$PKG/linux/control.in" >"$D/DEBIAN/control"

mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz --build "$D" "$OUT/aerocx-blackout_$ARCH.deb"
echo "gemaakt: $OUT/aerocx-blackout_$ARCH.deb"
