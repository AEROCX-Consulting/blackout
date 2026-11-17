#!/bin/sh
# Dubbelklik op dit bestand om AEROCX Blackout te starten (versie zonder installatieprogramma).
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/aerocx-blackout"

echo ""
echo "AEROCX Blackout wordt gestart..."

# De Mac zet een "uit het internet"-markering op gedownloade bestanden.
# Die halen we weg, anders weigert de Mac het programma te starten.
xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true
chmod +x "$BIN" 2>/dev/null || true

if [ ! -x "$BIN" ]; then
	echo "Het programma 'aerocx-blackout' staat niet naast dit bestand. Pak de zip opnieuw uit."
	exit 1
fi

# Starten, los van dit venster. Draait de app al, dan opent alleen je browser.
nohup "$BIN" -open >/dev/null 2>&1 &

sleep 2
echo ""
echo "De app opent in je browser: http://localhost:8474"
echo ""
printf "Wil je dat AEROCX Blackout voortaan vanzelf start als je je aanmeldt? (j/n) "
read -r ANTWOORD
case "$ANTWOORD" in
	j | J | ja | Ja | JA | y | Y)
		if "$BIN" -autostart=on; then
			echo "Goed. De app start voortaan vanzelf."
			echo "Let op: verplaats deze map daarna niet meer. Doe je dat toch, dubbelklik dan opnieuw op dit bestand."
		else
			echo "Dat lukte niet. Je kunt het ook later aanzetten in de app, bij Instellingen."
		fi
		;;
	*)
		echo "Goed. Je start de app voortaan zelf met een dubbelklik op dit bestand."
		;;
esac
echo ""
echo "Je mag dit venster nu sluiten. De app blijft draaien."
