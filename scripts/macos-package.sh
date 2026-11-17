#!/bin/bash
# Bouwt alles voor de Mac (draait op een macOS-runner van GitHub Actions):
#   dist/aerocx-blackout-mac-universal   ruwe universele binary (arm64 + x86_64)
#   dist/AEROCX-Blackout-mac.pkg          installatieprogramma (één klik, LaunchAgent, opent de browser)
#   dist/AEROCX-Blackout-mac.dmg          schijfkopie om de app naar Apps te slepen
#   dist/AEROCX-Blackout-mac.zip          draagbare map zonder installatieprogramma
#
# Gebruik (vanuit de hoofdmap van de repo):  VERSION=1.2.0 scripts/macos-package.sh
#
# Ondertekenen en notariseren gebeurt alleen als deze omgevingsvariabelen gezet zijn
# (GitHub-geheimen); anders wordt alles ad hoc ondertekend en gaat het gewoon verder:
#   APPLE_CERT_P12_BASE64, APPLE_CERT_PASSWORD           Developer ID Application (.p12, base64)
#   APPLE_INSTALLER_CERT_P12_BASE64                      Developer ID Installer (.p12, base64, zelfde wachtwoord)
#   APPLE_TEAM_ID, APPLE_ID, APPLE_APP_PASSWORD          notariseren met notarytool
set -euo pipefail

VERSION="${VERSION:-0.0.0-dev}"
BUILD_NUM="${VERSION%%-*}"            # CFBundleVersion: alleen cijfers en punten
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_NAME="AEROCX Blackout"
BUNDLE_ID="be.aerocx.blackout"
DIST="$ROOT/dist"
WORK="$ROOT/build/mac"
APP="$WORK/$APP_NAME.app"
LDFLAGS="-s -w -X main.version=$VERSION"

export CGO_ENABLED=0 GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

rm -rf "$WORK"
mkdir -p "$WORK" "$DIST"

echo "== Binaries bouwen ($VERSION)"
for arch in arm64 amd64; do
	GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$WORK/aerocx-blackout-$arch" .
	(cd packaging/macos/launcher && GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$WORK/launcher-$arch" .)
done
lipo -create -output "$WORK/aerocx-blackout" "$WORK/aerocx-blackout-arm64" "$WORK/aerocx-blackout-amd64"
lipo -create -output "$WORK/launcher" "$WORK/launcher-arm64" "$WORK/launcher-amd64"
lipo -info "$WORK/aerocx-blackout"

echo "== Icoon (.icns)"
ICONSET="$WORK/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
	sips -z $s $s packaging/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
	d=$((s * 2))
	sips -z $d $d packaging/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$WORK/AppIcon.icns"

echo "== App-bundel"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@BUILD@/$BUILD_NUM/g" packaging/macos/Info.plist >"$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist"
printf 'APPL????' >"$APP/Contents/PkgInfo"
cp "$WORK/launcher" "$APP/Contents/MacOS/$APP_NAME"
cp "$WORK/aerocx-blackout" "$APP/Contents/MacOS/aerocx-blackout"
cp "$WORK/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
chmod 755 "$APP/Contents/MacOS/"*

# ---------- ondertekenen (optioneel) ----------
SIGN_APP=""
SIGN_PKG=""
KEYCHAIN=""
cleanup() {
	if [ -n "$KEYCHAIN" ]; then security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true; fi
	rm -f "$WORK"/*.p12
}
trap cleanup EXIT

if [ -n "${APPLE_CERT_P12_BASE64:-}" ] && [ -n "${APPLE_CERT_PASSWORD:-}" ]; then
	echo "== Sleutelhanger met certificaten"
	KEYCHAIN="${RUNNER_TEMP:-$WORK}/blackout-signing.keychain-db"
	KC_PASS="$(uuidgen)"
	security create-keychain -p "$KC_PASS" "$KEYCHAIN"
	security set-keychain-settings -lut 21600 "$KEYCHAIN"
	security unlock-keychain -p "$KC_PASS" "$KEYCHAIN"
	printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode >"$WORK/app.p12"
	security import "$WORK/app.p12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/productsign
	if [ -n "${APPLE_INSTALLER_CERT_P12_BASE64:-}" ]; then
		printf '%s' "$APPLE_INSTALLER_CERT_P12_BASE64" | base64 --decode >"$WORK/installer.p12"
		security import "$WORK/installer.p12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/productbuild -T /usr/bin/productsign
	fi
	security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KC_PASS" "$KEYCHAIN" >/dev/null
	# shellcheck disable=SC2046
	security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
	SIGN_APP="$(security find-identity -v -p codesigning "$KEYCHAIN" | grep 'Developer ID Application' | head -1 | sed -E 's/.*"(.*)".*/\1/' || true)"
	SIGN_PKG="$(security find-identity -v "$KEYCHAIN" | grep 'Developer ID Installer' | head -1 | sed -E 's/.*"(.*)".*/\1/' || true)"
	echo "Ondertekenen app: ${SIGN_APP:-niet gevonden}"
	echo "Ondertekenen pkg: ${SIGN_PKG:-niet gevonden}"
else
	echo "== Geen Apple-certificaat: ad hoc ondertekenen (de Mac toont dan een waarschuwing)"
fi

sign() { # sign <pad...>
	if [ -n "$SIGN_APP" ]; then
		codesign --force --timestamp --options runtime --sign "$SIGN_APP" "$@"
	else
		codesign --force --sign - "$@"
	fi
}

echo "== App ondertekenen"
sign "$APP/Contents/MacOS/aerocx-blackout"
sign "$APP/Contents/MacOS/$APP_NAME"
sign --identifier "$BUNDLE_ID" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
cp "$APP/Contents/MacOS/aerocx-blackout" "$DIST/aerocx-blackout-mac-universal"

NOTARIZE=""
if [ -n "$SIGN_APP" ] && [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
	NOTARIZE=1
fi
notarize() { # notarize <bestand> [staple]
	[ -n "$NOTARIZE" ] || return 0
	echo "== Notariseren: $(basename "$1")"
	xcrun notarytool submit "$1" --apple-id "$APPLE_ID" --password "$APPLE_APP_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait --timeout 30m
	if [ "${2:-}" = staple ]; then xcrun stapler staple "$1"; fi
}

# ---------- .pkg ----------
echo "== Installatieprogramma (.pkg)"
PKGROOT="$WORK/pkgroot"
mkdir -p "$PKGROOT/Applications"
ditto "$APP" "$PKGROOT/Applications/$APP_NAME.app"
pkgbuild --analyze --root "$PKGROOT" "$WORK/component.plist"
# Nooit "verhuizen" naar een andere kopie van de app (bv. in Downloads): altijd /Applications.
plutil -replace 0.BundleIsRelocatable -bool NO "$WORK/component.plist"
plutil -replace 0.BundleOverwriteAction -string upgrade "$WORK/component.plist"
pkgbuild --root "$PKGROOT" --component-plist "$WORK/component.plist" \
	--scripts packaging/macos/scripts --identifier "$BUNDLE_ID.pkg" --version "$BUILD_NUM" \
	--install-location / "$WORK/AEROCX-Blackout-app.pkg"
sed "s/@VERSION@/$BUILD_NUM/g" packaging/macos/distribution.xml >"$WORK/distribution.xml"
PB_ARGS=(--distribution "$WORK/distribution.xml" --resources packaging/macos/resources --package-path "$WORK")
if [ -n "$SIGN_PKG" ]; then PB_ARGS+=(--sign "$SIGN_PKG" --timestamp); fi
productbuild "${PB_ARGS[@]}" "$DIST/AEROCX-Blackout-mac.pkg"
if [ -n "$SIGN_PKG" ]; then notarize "$DIST/AEROCX-Blackout-mac.pkg" staple; fi

# ---------- .dmg ----------
echo "== Schijfkopie (.dmg)"
DMGSRC="$WORK/dmg"
mkdir -p "$DMGSRC"
ditto "$APP" "$DMGSRC/$APP_NAME.app"
ln -s /Applications "$DMGSRC/Applications"
rm -f "$DIST/AEROCX-Blackout-mac.dmg"
hdiutil create -volname "$APP_NAME" -srcfolder "$DMGSRC" -fs HFS+ -format UDZO -ov "$DIST/AEROCX-Blackout-mac.dmg"
if [ -n "$SIGN_APP" ]; then
	codesign --force --timestamp --sign "$SIGN_APP" "$DIST/AEROCX-Blackout-mac.dmg"
	notarize "$DIST/AEROCX-Blackout-mac.dmg" staple
fi

# ---------- draagbare zip ----------
echo "== Draagbare zip"
PORT="$WORK/zip/$APP_NAME"
mkdir -p "$PORT"
cp "$APP/Contents/MacOS/aerocx-blackout" "$PORT/aerocx-blackout"
cp "packaging/portable/mac/Start AEROCX Blackout.command" "$PORT/"
cp packaging/portable/mac/LEESMIJ.txt "$PORT/"
chmod 755 "$PORT/aerocx-blackout" "$PORT/Start AEROCX Blackout.command"
rm -f "$DIST/AEROCX-Blackout-mac.zip"
ditto -c -k --keepParent "$PORT" "$DIST/AEROCX-Blackout-mac.zip"
# Notariseren van de zip (niet te nieten, de Mac controleert online).
notarize "$DIST/AEROCX-Blackout-mac.zip"

echo "== Klaar"
ls -la "$DIST"
