## AEROCX Blackout 1.2

Berichten sturen naar je eigen mensen, ook als het gewone internet wegvalt. Rechtstreeks van computer naar computer, over Starlink, je eigen wifi of een LoRa-radio. Tussen de computers versleuteld, zonder server en zonder account.

**Downloaden en installeren:** ga naar **https://blackout.aerocx.be/**. De pagina kiest zelf het juiste bestand voor je computer.

### Nieuw in 1.2
- **Installeren met één klik** op Mac, Windows en Raspberry Pi. De app start vanzelf als je je aanmeldt en opent in je browser.
- **Groepen** met een eigenaar, leden en rollen (beheerder, lid, lezer).
- **Kortere code en QR-code** om contacten toe te voegen, en **uitnodigingen** die je één keer kunt gebruiken.
- **SOS-knop**: gaat met voorrang naar al je contacten, ook meteen over de radio. Je ziet wie het gezien heeft.
- **Locatie delen** (vast adres of GPS van de radio): staat standaard uit en gaat alleen versleuteld naar je contacten.
- **Foto's** sturen (via Starlink en wifi) en een **versleutelde back-up**.
- **Brug Starlink en radio**: kan je iemand niet rechtstreeks bereiken, dan zendt een contact met een radio het voor je uit.
- **OSINT**: waarschuwingen van Meteoalarm, GDACS, aardbevingen, nieuws en berichten die je radio opvangt, op één plek.
- **Beheer**: toestellen (iPad, telefoon) beheren, contacten blokkeren, nieuwe pincode, beheerlogboek.

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
- De Starlink-schotel heeft nog altijd het netwerk van SpaceX nodig. Valt Starlink weg, dan neemt de radio (Meshtastic, LoRa) het over voor wie er een heeft.
- Je iPad of telefoon praat met je computer over gewone HTTP, niet versleuteld. Wie op hetzelfde wifi-netwerk meekijkt, kan de pincode en je berichten zien: gebruik dit alleen op je eigen, beveiligde wifi. Tussen de computers onderling is alles wel versleuteld.
- Op de computer zelf vraagt de app geen pincode. Heeft je computer meerdere gebruikers, dan kan elke gebruiker van die computer de app bedienen.
- Computers met de app op dezelfde wifi zien elkaar vanzelf, maar alleen als verzoek. Pas als jij het toelaat, worden het contacten.
- Je gegevens en sleutels blijven op je eigen computer. Maak een back-up in de app.
