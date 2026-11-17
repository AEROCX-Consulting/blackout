#!/bin/sh
# AEROCX Blackout installeren op Linux of een Raspberry Pi, in één regel:
#
#   curl -fsSL https://blackout.aerocx.be/install.sh | sh
#
# Verwijderen (je gegevens blijven bewaard):
#
#   curl -fsSL https://blackout.aerocx.be/install.sh | sh -s -- --remove
#
# Wat het doet: de juiste versie (arm64 of amd64) downloaden en controleren (SHA-256),
# in ~/.local/bin zetten, als achtergronddienst voor jouw gebruiker laten starten (systemd),
# ook zonder aanmelden op een Pi zonder scherm, en het adres + de pincode tonen.
# Geen root nodig. Voer het uit als de gewone gebruiker (bv. "pi"), niet met sudo.
#
# Een nieuwe versie installeren: voer dezelfde regel opnieuw uit. Er is geen automatische update.
#
# Alles staat in één functie die pas op de laatste regel wordt aangeroepen. Komt dit script maar
# half binnen (verbinding verbroken), dan gebeurt er dus niets.

blackout_install() {
	set -eu

	BASE_URL="${BLACKOUT_BASE_URL:-https://github.com/AEROCX-Consulting/blackout/releases/latest/download}"
	SITE_URL="https://blackout.aerocx.be"
	NAME="aerocx-blackout"
	BIN_DIR="${BLACKOUT_BIN_DIR:-$HOME/.local/bin}"
	BIN="$BIN_DIR/$NAME"
	UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
	UNIT="$UNIT_DIR/$NAME.service"
	DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$NAME"
	PORT=8474

	say() { printf '%s\n' "$*"; }
	fail() {
		printf '\nFout: %s\n' "$*" >&2
		exit 1
	}
	have() { command -v "$1" >/dev/null 2>&1; }

	download() { # download <url> <bestand>
		if have curl; then
			curl -fsSL --retry 3 -o "$2" "$1"
		elif have wget; then
			wget -q -O "$2" "$1"
		else
			fail "curl of wget is nodig. Installeer eerst: sudo apt install curl"
		fi
	}

	sha256_of() { # sha256_of <bestand> -> controlegetal (kleine letters) of niets
		if have sha256sum; then
			sha256sum "$1" | awk '{print tolower($1)}'
		elif have shasum; then
			shasum -a 256 "$1" | awk '{print tolower($1)}'
		elif have openssl; then
			openssl dgst -sha256 -r "$1" | awk '{print tolower($1)}'
		fi
	}

	ping_app() {
		if have curl; then
			curl -fsS -m 2 "http://127.0.0.1:$PORT/api/ping" 2>/dev/null | grep -q aerocx-blackout
		elif have wget; then
			wget -q -T 2 -O - "http://127.0.0.1:$PORT/api/ping" 2>/dev/null | grep -q aerocx-blackout
		else
			return 1
		fi
	}

	stop_app() {
		if have systemctl; then
			systemctl --user stop "$NAME.service" >/dev/null 2>&1 || true
		fi
		if have curl; then
			curl -fsS -m 3 -X POST "http://127.0.0.1:$PORT/api/quit" >/dev/null 2>&1 || true
		elif have wget; then
			wget -q -T 3 -O /dev/null --post-data= "http://127.0.0.1:$PORT/api/quit" >/dev/null 2>&1 || true
		fi
		sleep 1
		if have pkill; then pkill -u "$(id -u)" -x "$NAME" >/dev/null 2>&1 || true; fi
	}

	systemd_user_ok() {
		have systemctl && systemctl --user show-environment >/dev/null 2>&1
	}

	# Een pad veilig in een systemd-regel zetten: tussen aanhalingstekens, met %, $, \ en " ontsnapt.
	unit_quote() {
		printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g' -e 's/\$/$$/g')"
	}

	# Dezelfde unit als de app zelf schrijft bij "automatisch starten aan" (autostart_linux.go)
	# en als het .deb-pakket meelevert (packaging/linux/aerocx-blackout.service), alleen het pad verschilt.
	write_unit() {
		mkdir -p "$UNIT_DIR"
		cat >"$UNIT" <<EOF
[Unit]
Description=AEROCX Blackout (noodcommunicatie)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$(unit_quote "$BIN") -background
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
	}

	remove() {
		say "AEROCX Blackout verwijderen..."
		if systemd_user_ok; then
			systemctl --user disable --now "$NAME.service" >/dev/null 2>&1 || true
		fi
		stop_app
		rm -f "$UNIT" "$BIN"
		if systemd_user_ok; then systemctl --user daemon-reload >/dev/null 2>&1 || true; fi
		say "Klaar. De app is verwijderd."
		say "Je gegevens en sleutels staan nog in $DATA_DIR"
		say "Wil je die ook weg: rm -rf \"$DATA_DIR\"  (dat kan niet ongedaan gemaakt worden)"
		exit 0
	}

	# ---------- controles ----------
	case "${1:-}" in
		--remove | --verwijder | remove) REMOVE=1 ;;
		"" | --install) REMOVE="" ;;
		-h | --help)
			say "Gebruik: install.sh            installeren of bijwerken"
			say "         install.sh --remove   verwijderen (gegevens blijven bewaard)"
			exit 0
			;;
		*) fail "onbekende optie: $1 (gebruik --remove om te verwijderen)" ;;
	esac

	[ "$(uname -s)" = "Linux" ] || fail "dit script is voor Linux en Raspberry Pi. Voor Mac en Windows: $SITE_URL/"

	if [ "$(id -u)" -eq 0 ]; then
		fail "start dit script niet met sudo of als root, maar als je gewone gebruiker (bv. pi).
Het vraagt zelf om sudo waar dat nodig is."
	fi

	if [ -n "$REMOVE" ]; then remove; fi

	case "$(uname -m)" in
		aarch64 | arm64) ARCH=arm64 ;;
		x86_64 | amd64) ARCH=amd64 ;;
		armv6l | armv7l | armhf)
			fail "dit is een 32-bit systeem. AEROCX Blackout heeft een 64-bit systeem nodig.
Op een Raspberry Pi (3, 4, 5 of Zero 2 W): installeer Raspberry Pi OS (64-bit) met Raspberry Pi Imager."
			;;
		*) fail "dit type processor wordt niet ondersteund: $(uname -m)" ;;
	esac

	say ""
	say "AEROCX Blackout installeren ($ARCH)..."

	# ---------- downloaden en controleren ----------
	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' EXIT
	FILE="$NAME-linux-$ARCH"
	say "  downloaden..."
	download "$BASE_URL/$FILE" "$TMP/$FILE" || fail "downloaden lukte niet. Is er internet?"

	# Zonder geslaagde controle wordt er niets geïnstalleerd.
	download "$BASE_URL/SHA256SUMS.txt" "$TMP/SHA256SUMS.txt" 2>/dev/null ||
		fail "de controlegetallen (SHA256SUMS.txt) konden niet gedownload worden. Zonder controle installeren we niets. Probeer het later opnieuw."
	WANT="$(tr -d '\r' <"$TMP/SHA256SUMS.txt" | awk -v f="$FILE" '$2 == f || $2 == "*" f {print tolower($1); exit}')"
	case "$WANT" in
		"" | *[!0-9a-f]*)
			fail "in SHA256SUMS.txt staat geen geldig controlegetal voor $FILE. Zonder controle installeren we niets. Probeer het later opnieuw."
			;;
	esac
	[ "${#WANT}" -eq 64 ] ||
		fail "in SHA256SUMS.txt staat geen geldig controlegetal voor $FILE. Zonder controle installeren we niets. Probeer het later opnieuw."
	GOT="$(sha256_of "$TMP/$FILE" || true)"
	[ -n "$GOT" ] ||
		fail "het controlegetal kon niet berekend worden (sha256sum ontbreekt). Installeer eerst: sudo apt install coreutils"
	[ "$WANT" = "$GOT" ] ||
		fail "het gedownloade bestand klopt niet (SHA-256). Er is niets geïnstalleerd. Probeer het later opnieuw."
	say "  controle in orde (SHA-256)"

	# ---------- plaatsen ----------
	stop_app
	mkdir -p "$BIN_DIR"
	chmod 755 "$TMP/$FILE"
	mv -f "$TMP/$FILE" "$BIN"
	say "  geplaatst in $BIN"

	# ---------- automatisch starten ----------
	STARTED=""
	if systemd_user_ok; then
		write_unit
		systemctl --user daemon-reload
		systemctl --user enable "$NAME.service" >/dev/null 2>&1 || true
		systemctl --user restart "$NAME.service" && STARTED=1
		say "  start voortaan vanzelf (systemd, gebruikersdienst)"

		# Ook starten zonder dat iemand aanmeldt (Raspberry Pi zonder scherm).
		if have loginctl; then
			if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)" = "yes" ]; then
				:
			elif loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
				say "  start ook zonder aan te melden"
			elif have sudo && sudo -n loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
				say "  start ook zonder aan te melden"
			else
				say "  Tip: wil je dat de app ook start zonder aan te melden (Pi zonder scherm)? Typ dan:"
				say "       sudo loginctl enable-linger $(id -un)"
			fi
		fi
	else
		say "  (geen systemd voor gebruikers gevonden: de app start nu, maar niet vanzelf na een herstart)"
		nohup "$BIN" -background >/dev/null 2>&1 &
		STARTED=1
	fi

	# ---------- wachten tot hij antwoordt ----------
	i=0
	while [ $i -lt 30 ]; do
		ping_app && break
		sleep 1
		i=$((i + 1))
	done

	IP=""
	if have hostname; then IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
	if [ -z "$IP" ] && have ip; then
		IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
	fi
	PIN=""
	if [ -f "$DATA_DIR/blackout.json" ]; then
		PIN="$(sed -n 's/.*"pin": *"\([0-9]*\)".*/\1/p' "$DATA_DIR/blackout.json" | head -1)"
	fi

	say ""
	if ping_app; then
		say "Klaar. AEROCX Blackout draait."
	else
		if [ -n "$STARTED" ]; then
			say "De app is gestart, maar antwoordt nog niet. Wacht even en open dan het adres hieronder."
		fi
		if systemd_user_ok; then
			say "Lukt het niet? Bekijk wat er misging met: journalctl --user -u $NAME -n 50"
		else
			say "Lukt het niet? Start de app dan zelf om de meldingen te zien: $BIN"
		fi
	fi
	say ""
	say "  Op deze computer:         http://localhost:$PORT"
	if [ -n "$IP" ]; then
		say "  Vanaf een ander toestel:  http://$IP:$PORT"
	fi
	if [ -n "$PIN" ]; then
		say "  Pincode:                  $PIN"
	else
		say "  De pincode zie je in de app op deze computer (Instellingen), of met:"
		say "    grep '\"pin\"' \"$DATA_DIR/blackout.json\""
	fi
	say ""
	say "Op een ander toestel (computer, iPad, telefoon) op dezelfde wifi: open het adres en typ de pincode."
	say "Let op: die verbinding is gewone HTTP, niet versleuteld. Wie op hetzelfde wifi-netwerk meekijkt,"
	say "kan de pincode en je berichten zien. Gebruik het dus alleen op je eigen, beveiligde wifi."
	case ":$PATH:" in
		*":$BIN_DIR:"*) ;;
		*) say "(Tip: $BIN_DIR staat nog niet in je PATH. Na opnieuw aanmelden meestal wel.)" ;;
	esac
	say "Nieuwe versie: voer dezelfde installatieregel opnieuw uit (er is geen automatische update)."
	say "Verwijderen: curl -fsSL $SITE_URL/install.sh | sh -s -- --remove"
}

blackout_install "$@"
