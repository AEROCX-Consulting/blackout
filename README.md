# AEROCX Blackout

Berichten sturen naar je eigen mensen, ook als het gewone internet wegvalt. Rechtstreeks van computer naar computer, over Starlink, je eigen wifi of een LoRa-radio (Meshtastic). Versleuteld, zonder server en zonder account.

## Downloaden

**[blackout.aerocx.be](https://blackout.aerocx.be/)**: de pagina herkent je computer en geeft je het juiste bestand, met drie korte stappen.

Alle bestanden en eerdere versies staan bij de [releases](https://github.com/AEROCX-Consulting/blackout/releases/latest).

| Systeem | Gewoon installeren | Zonder installatieprogramma |
|---|---|---|
| Mac (Apple-chip en Intel, macOS 11+) | [AEROCX-Blackout-mac.pkg](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-mac.pkg) of [.dmg](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-mac.dmg) | [zip](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-mac.zip) |
| Windows 10 en 11 | [AEROCX-Blackout-Setup.exe](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-Setup.exe) | [zip](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-windows.zip) |
| Raspberry Pi (64-bit) | zie hieronder, of [.deb](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/aerocx-blackout_arm64.deb) | [zip](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-linux-arm64.zip) |
| Linux (pc, 64-bit) | [.deb](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/aerocx-blackout_amd64.deb) | [zip](https://github.com/AEROCX-Consulting/blackout/releases/latest/download/AEROCX-Blackout-linux-amd64.zip) |

Of in één regel:

```sh
# Raspberry Pi en Linux (Terminal, als gewone gebruiker)
curl -fsSL https://blackout.aerocx.be/install.sh | sh

# Mac (app Terminal)
curl -fsSL https://blackout.aerocx.be/install-mac.sh | sh
```

```powershell
# Windows (rechtsklik op Start > Terminal)
irm https://blackout.aerocx.be/install.ps1 | iex
```

Een nieuwe versie installeren: voer dezelfde regel opnieuw uit. Er is geen automatische update.

Verwijderen: dezelfde regel met `sh -s -- --remove` in plaats van `sh`, of op Windows
`& ([scriptblock]::Create((irm https://blackout.aerocx.be/install.ps1))) -Remove`.
Je gegevens en sleutels blijven daarbij bewaard.

De installatieregels installeren alleen als het gedownloade programma klopt met het controlegetal in `SHA256SUMS.txt` van dezelfde release; anders stoppen ze zonder iets te installeren.

iPhone, iPad en Android hebben geen eigen app: ze verbinden via de browser met een computer of Raspberry Pi thuis waarop AEROCX Blackout draait.

## Hoe het werkt

1. Elke computer met AEROCX Blackout is een eigen knooppunt; er is geen centrale server en geen account.
2. Je voegt contacten één keer toe met een korte code of QR-code, en jullie wisselen zo elkaars sleutels uit. Computers met de app op dezelfde wifi zien elkaar vanzelf, maar alleen als verzoek: pas als je dat verzoek toelaat, wordt het een contact.
3. Tussen de computers (de stations) is alles versleuteld. Berichten gaan rechtstreeks naar de ontvanger: over Starlink (IPv6), over je eigen wifi, of via een contact dat ze doorgeeft zonder ze te kunnen lezen.
4. Valt ook dat weg, dan gaan ze over een Meshtastic-radio (LoRa, 868 MHz), zuinig en binnen de Europese zendregels.
5. Het scherm is een webpagina op `http://localhost:8474`; je iPad of telefoon op dezelfde wifi gebruikt die met een pincode (zie de beperkingen hieronder).
6. Locatie delen staat standaard uit. Zet je het aan, dan gaat je locatie alleen versleuteld naar je contacten.

## Bouwen vanuit de broncode

Nodig: Go 1.24.

```sh
GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=1.2.0" -o aerocx-blackout .
./aerocx-blackout -open
```

Voor een ander systeem: zet `GOOS`/`GOARCH` (darwin/arm64, darwin/amd64, windows/amd64, linux/arm64, linux/amd64). Op Windows bouw je met `-ldflags "-H windowsgui ..."` zodat er geen zwart venster openblijft.

Handige vlaggen: `-open` (browser openen), `-background` (zonder venster, log in de gegevensmap), `-autostart=on|off` (automatisch starten bij aanmelden).

Testen: `go vet ./... && go test ./...`

De installatiebestanden worden gemaakt door GitHub Actions (`.github/workflows/release.yml`) bij een tag `v*`. Lokaal kun je een `.deb` maken met `scripts/build-deb.sh arm64 <binary> 1.2.0`; de Mac-bestanden met `scripts/macos-package.sh` (alleen op een Mac). Het icoon maak je opnieuw met `python3 scripts/make-icon.py`.

## Eerlijke beperkingen

- **Starlink blijft SpaceX nodig hebben.** De app maakt je onafhankelijk van alle andere internetdiensten, maar niet van het netwerk van Starlink zelf. Valt dat weg, dan werkt het alleen nog over wifi in de buurt en over de radio.
- **Radio is traag en kort.** LoRa haalt een paar kilometer in de bebouwing, meer met een goede antenne hoog buiten. Lange berichten gaan in stukken; foto's gaan niet over de radio.
- **iPad en telefoon gebruiken gewone HTTP.** Tussen je iPad of telefoon en de computer met de app is de verbinding niet versleuteld. Wie op hetzelfde wifi-netwerk meekijkt, kan de pincode en je berichten zien. Gebruik dit alleen op je eigen, beveiligde wifi. Tussen de computers onderling is alles wel versleuteld.
- **Iedereen die op de computer zelf werkt, kan de app bedienen.** Op `localhost` vraagt de app geen pincode. Op een computer met meerdere gebruikers kan dus elke lokale gebruiker jouw app openen en berichten lezen en sturen.
- **Beide kanten moeten elkaar eerst toevoegen**, zolang alles nog werkt. Een Starlink-router laat alleen verkeer binnen waar je zelf eerst naartoe stuurde.
- **Geen automatische updates.** Een nieuwe versie installeer je door de installatieregel (of het installatiebestand) opnieuw uit te voeren.
- **Niet (altijd) ondertekend.** Zolang er geen Apple- en Microsoft-certificaat is, waarschuwen Mac en Windows de eerste keer. De downloadpagina legt uit hoe je toch opent.
- **Windows:** de radio werkt daar alleen via wifi (IP-adres van de radio), niet via USB.
- **Raspberry Pi:** alleen 64-bit (Raspberry Pi OS 64-bit, Pi 3/4/5/Zero 2 W).
- **Telefoon en iPad** zijn geen eigen knooppunt; de computer of Pi thuis moet aan blijven.
- Geen garantie: dit is een hulpmiddel voor noodcommunicatie, geen vervanging van 112 of officiële waarschuwingen.

## Licentie

MIT, zie [LICENSE](LICENSE). Copyright (c) 2026 AEROCX Consulting Group CommV.
