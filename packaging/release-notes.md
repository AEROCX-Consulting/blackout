## AEROCX Blackout 1.2.1

Berichten sturen naar je eigen mensen zolang er een wifi-netwerk is: op hetzelfde wifi-netwerk ook zonder internet, tussen huizen over gewoon internet (Starlink of je gewone provider), en over een LoRa-radio als alles wegvalt. Rechtstreeks van computer naar computer, tussen de computers versleuteld, zonder server en zonder account.

**Downloaden en installeren:** ga naar **https://blackout.aerocx.be/**. De pagina kiest zelf het juiste bestand voor je computer.

### Nieuw in 1.2.1
- **Werkt ook op gewone wifi en gewoon internet**, niet alleen over Starlink: ook met Proximus, Telenet, Orange of een 4G/5G-hotspot.
- **Zoekt zelf je publieke adres op** (bij Google en Cloudflare; uit te zetten in Instellingen) en **zet zelf een poort open op je router** als die dat toelaat. Lukt dat niet, dan gaan berichten via een contact dat jullie allebei kunnen bereiken.
- **Duidelijkere verbindingsstatus** in de app: "via internet" in plaats van "via Starlink".

### Nieuw in 1.2
- Installeren met één klik op Mac, Windows en Raspberry Pi; de app start vanzelf als je je aanmeldt.
- Groepen met rollen, kortere code en QR-code, uitnodigingen voor één keer.
- SOS-knop met voorrang, ook meteen over de radio.
- Locatie delen (standaard uit), foto's, versleutelde back-up.
- Brug tussen internet en radio: een contact met een radio zendt het voor je uit.
- OSINT: waarschuwingen en nieuws op één plek. Beheer van toestellen, contacten en pincode.

### Welk bestand heb ik nodig?
| Systeem | Gewoon installeren | Zonder installatieprogramma |
|---|---|---|
| Mac (Apple-chip en Intel) | `AEROCX-Blackout-mac.pkg` (of `.dmg`) | `AEROCX-Blackout-mac.zip` of `install-mac.sh` |
| Windows 10 en 11 | `AEROCX-Blackout-Setup.exe` | `AEROCX-Blackout-windows.zip` of `install.ps1` |
| Raspberry Pi (64-bit) | `install.sh` of `aerocx-blackout_arm64.deb` | `AEROCX-Blackout-linux-arm64.zip` |
| Linux (pc) | `aerocx-blackout_amd64.deb` of `install.sh` | `AEROCX-Blackout-linux-amd64.zip` |

De losse programma's (`aerocx-blackout-…`) zijn voor wie zelf wil inrichten. `SHA256SUMS.txt` bevat de controlegetallen van alle bestanden; de installatieregels installeren niets als die controle niet lukt.

Een nieuwe versie installeren: voer de installatieregel of het installatiebestand opnieuw uit. Er is geen automatische update.

### Eerlijk om te weten
- Zolang de app niet bij Apple en Microsoft geregistreerd is, toont je computer de eerste keer een waarschuwing. Op de downloadpagina staat stap voor stap hoe je toch opent.
- Tussen huizen heb je internet nodig: met Starlink het netwerk van SpaceX, anders je eigen provider. Valt dat weg, dan werkt het nog op hetzelfde wifi-netwerk, en neemt de radio (Meshtastic, LoRa) het over voor wie er een heeft.
- Op gewoon internet zonder IPv6 kan het zijn dat twee huizen elkaar niet rechtstreeks vinden (strenge router of 4G-provider). Dan gaan berichten via een contact dat beide kunnen bereiken, of via de radio.
- Je code bevat ook het internetadres van je station. Deel hem alleen met mensen die je vertrouwt.
- Sluit je de app af, dan gaat de poort op je router weer dicht. Stopt de app onverwacht, dan sluit je router hem meestal na een uur vanzelf. Uitzetten kan in Instellingen → Verbinding.
- Om je publieke adres te vinden vraagt de app dat op bij Google en Cloudflare (STUN); dat kun je uitzetten in Instellingen.
- Je iPad of telefoon praat met je computer over gewone HTTP, niet versleuteld. Wie op hetzelfde wifi-netwerk meekijkt, kan de pincode en je berichten zien: gebruik dit alleen op je eigen, beveiligde wifi. Tussen de computers onderling is alles wel versleuteld.
- Op de computer zelf vraagt de app geen pincode. Heeft je computer meerdere gebruikers, dan kan elke gebruiker van die computer de app bedienen.
- Computers met de app op dezelfde wifi zien elkaar vanzelf, maar alleen als verzoek. Pas als jij het toelaat, worden het contacten.
- Je gegevens en sleutels blijven op je eigen computer. Maak een back-up in de app.
