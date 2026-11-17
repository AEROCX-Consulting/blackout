#!/bin/sh
# AEROCX Blackout installeren op een Mac, zonder installatieprogramma, in één regel (app Terminal):
#
#   curl -fsSL https://blackout.aerocx.be/install-mac.sh | sh
#
# Verwijderen (je gegevens blijven bewaard):
#
#   curl -fsSL https://blackout.aerocx.be/install-mac.sh | sh -s -- --remove
#
# Wat het doet: de app downloaden en controleren (SHA-256), in ~/Applications/AEROCX Blackout zetten,
# automatisch laten starten bij aanmelden (LaunchAgent) en je browser openen. Geen wachtwoord nodig.
#
# Een nieuwe versie installeren: voer dezelfde regel opnieuw uit. Er is geen automatische update.
#
# Alles staat in één functie die pas op de laatste regel wordt aangeroepen. Komt dit script maar
# half binnen (verbinding verbroken), dan gebeurt er dus niets.

blackout_install_mac() {
	set -eu

	BASE_URL="${BLACKOUT_BASE_URL:-https://github.com/AEROCX-Consulting/blackout/releases/latest/download}"
	FILE="aerocx-blackout-mac-universal"
	DIR="$HOME/Applications/AEROCX Blackout"
	BIN="$DIR/aerocx-blackout"
	LABEL="be.aerocx.blackout"
	PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
	DATA_DIR="$HOME/Library/Application Support/AEROCX Blackout"
	URL="http://localhost:8474"
	UID_NOW="$(id -u)"

	say() { printf '%s\n' "$*"; }
	fail() {
		printf '\nFout: %s\n' "$*" >&2
		exit 1
	}

	ping_app() { curl -fsS -m 2 http://127.0.0.1:8474/api/ping 2>/dev/null | grep -q aerocx-blackout; }

	stop_app() {
		launchctl bootout "gui/$UID_NOW/$LABEL" >/dev/null 2>&1 || true
		curl -fsS -m 3 -X POST http://127.0.0.1:8474/api/quit >/dev/null 2>&1 || true
		sleep 1
		pkill -u "$UID_NOW" -x aerocx-blackout >/dev/null 2>&1 || true
	}

	[ "$(uname -s)" = "Darwin" ] || fail "dit script is voor de Mac. Andere systemen: https://blackout.aerocx.be/"
	[ "$UID_NOW" -ne 0 ] || fail "start dit script niet met sudo, maar gewoon in de app Terminal."

	case "${1:-}" in
		--remove | --verwijder | remove)
			say "AEROCX Blackout verwijderen..."
			stop_app
			rm -f "$PLIST"
			rm -rf "$DIR"
			say "Klaar. De app is verwijderd."
			say "Je gegevens en sleutels staan nog in: $DATA_DIR"
			say "Wil je die ook weg, sleep die map dan naar de prullenmand."
			exit 0
			;;
		"" | --install) ;;
		-h | --help)
			say "Gebruik: install-mac.sh            installeren of bijwerken"
			say "         install-mac.sh --remove   verwijderen (gegevens blijven bewaard)"
			exit 0
			;;
		*) fail "onbekende optie: $1 (gebruik --remove om te verwijderen)" ;;
	esac

	say ""
	say "AEROCX Blackout installeren..."

	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' EXIT
	say "  downloaden..."
	curl -fsSL --retry 3 -o "$TMP/$FILE" "$BASE_URL/$FILE" || fail "downloaden lukte niet. Is er internet?"

	# Zonder geslaagde controle wordt er niets geïnstalleerd.
	curl -fsSL --retry 3 -o "$TMP/SHA256SUMS.txt" "$BASE_URL/SHA256SUMS.txt" 2>/dev/null ||
		fail "de controlegetallen (SHA256SUMS.txt) konden niet gedownload worden. Zonder controle installeren we niets. Probeer het later opnieuw."
	WANT="$(tr -d '\r' <"$TMP/SHA256SUMS.txt" | awk -v f="$FILE" '$2 == f || $2 == "*" f {print tolower($1); exit}')"
	case "$WANT" in
		"" | *[!0-9a-f]*)
			fail "in SHA256SUMS.txt staat geen geldig controlegetal voor $FILE. Zonder controle installeren we niets. Probeer het later opnieuw."
			;;
	esac
	[ "${#WANT}" -eq 64 ] ||
		fail "in SHA256SUMS.txt staat geen geldig controlegetal voor $FILE. Zonder controle installeren we niets. Probeer het later opnieuw."
	GOT="$(shasum -a 256 "$TMP/$FILE" 2>/dev/null | awk '{print tolower($1)}' || true)"
	[ -n "$GOT" ] || fail "het controlegetal kon niet berekend worden (shasum werkt niet). Er is niets geïnstalleerd."
	[ "$WANT" = "$GOT" ] ||
		fail "het gedownloade bestand klopt niet (SHA-256). Er is niets geïnstalleerd. Probeer het later opnieuw."
	say "  controle in orde (SHA-256)"

	stop_app
	mkdir -p "$DIR"
	chmod 755 "$TMP/$FILE"
	mv -f "$TMP/$FILE" "$BIN"
	xattr -d com.apple.quarantine "$BIN" >/dev/null 2>&1 || true

	# Een snelkoppeling om de app later zelf te openen.
	cat >"$DIR/Open AEROCX Blackout.command" <<EOF
#!/bin/sh
nohup "$BIN" -open >/dev/null 2>&1 &
echo "AEROCX Blackout opent in je browser. Je mag dit venster sluiten."
EOF
	chmod 755 "$DIR/Open AEROCX Blackout.command"
	say "  geplaatst in $DIR"

	# Automatisch starten bij aanmelden.
	mkdir -p "$HOME/Library/LaunchAgents"
	cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN</string>
		<string>-background</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
EOF
	if launchctl bootstrap "gui/$UID_NOW" "$PLIST" >/dev/null 2>&1; then
		say "  start voortaan vanzelf als je je aanmeldt"
	else
		say "  (automatisch starten wordt actief na de volgende keer aanmelden)"
		nohup "$BIN" -background >/dev/null 2>&1 &
	fi

	i=0
	while [ $i -lt 40 ]; do
		ping_app && break
		sleep 0.5
		i=$((i + 1))
	done

	say ""
	if ping_app; then
		say "Klaar. AEROCX Blackout draait en opent nu in je browser: $URL"
		open "$URL" >/dev/null 2>&1 || true
	else
		say "De app is gestart, maar antwoordt nog niet. Open zo meteen zelf: $URL"
	fi
	say ""
	say "Vraagt je Mac om verbindingen of apparaten in je lokale netwerk toe te staan? Klik op Sta toe."
	say "Later opnieuw openen: dubbelklik op 'Open AEROCX Blackout' in de map Apps > AEROCX Blackout"
	say "in je thuismap, of open $URL in je browser."
	say "Op je iPad of telefoon gaat de verbinding met deze Mac over gewone HTTP, niet versleuteld:"
	say "gebruik dat alleen op je eigen, beveiligde wifi."
	say "Nieuwe versie: voer dezelfde installatieregel opnieuw uit (er is geen automatische update)."
	say "Verwijderen: curl -fsSL https://blackout.aerocx.be/install-mac.sh | sh -s -- --remove"
}

blackout_install_mac "$@"
