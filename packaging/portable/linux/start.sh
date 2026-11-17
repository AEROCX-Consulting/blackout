#!/bin/sh
# Start AEROCX Blackout (versie zonder installatie). Gebruik: ./start.sh
# Met een scherm opent je browser vanzelf. Zonder scherm (Raspberry Pi): zie het adres hieronder.
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/aerocx-blackout"
chmod +x "$BIN" 2>/dev/null || true

if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
	nohup "$BIN" -open >/dev/null 2>&1 &
else
	nohup "$BIN" -background >/dev/null 2>&1 &
fi
sleep 2

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "AEROCX Blackout draait."
echo "  Op deze computer:          http://localhost:8474"
if [ -n "$IP" ]; then
	echo "  Vanaf een ander toestel:   http://$IP:8474  (typ daar de pincode)"
fi
echo ""
echo "De pincode zie je in de app op deze computer (Instellingen), of met:"
echo "  grep '\"pin\"' ~/.local/share/aerocx-blackout/blackout.json"
echo ""
echo "Automatisch starten bij aanmelden: $BIN -autostart=on"
echo "Stoppen:                          curl -X POST http://127.0.0.1:8474/api/quit"
