package main

// Berichten over LoRa (Meshtastic, poort PRIVATE_APP).
// Elke LoRa-payload is max 233 bytes. Formaat (alle velden binair):
//
//   'A' 'X' 1 type  van[8]
//   type 'M' (1-op-1) / 'G' (Iedereen) / 'S' (SOS aan iedereen):
//        naar[8] bericht-ID[8] deel[1] aantal[1] nonce[12] versleuteld deel + tag[16]
//   type 'P' (groep): zoals 'M', maar de versleutelde inhoud begint met het groeps-ID[8]
//   type 'm' / 'g' / 's' / 'p' (vanaf v1.2): zoals 'M'/'G'/'S'/'P', met na aantal[1] nog tijd[4]
//        (verzendtijdstip, seconden; meegetekend als kop). Ouder dan 8 dagen of > 10 min in de toekomst
//        = geweigerd; elk bericht-ID wordt één keer verwerkt (bewaarde gezien-lijst). v1.1-contacten
//        krijgen en sturen de hoofdletters (zonder tijd).
//   type 'K' (bevestiging):             naar[8] bericht-ID[8] nonce[12] tag[16]
//   type 'B' (baken, "ik ben bereikbaar"): tijd[4] volgnummer[4] handtekening[64] (84 bytes).
//        Geen positie meer (het baken is niet versleuteld). Ouder dan 15 min of al gezien = genegeerd.
//        Oude bakens (80 bytes v1.1, 88 bytes met positie) worden nog herkend, maar de positie niet gebruikt.
//
// Versleuteling: dezelfde AES-256-GCM-sleutel per contact als over IP; de kop is meegetekend (AAD).
// De Meshtastic-radio's zelf zorgen voor het doorgeven van hop tot hop (mesh).
// Frames kunnen ook via een brug (IP-pakket 'L', zie bridge.go) reizen.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log"
	"strings"
	"time"
)

const (
	loraChunk   = 175 // 233 - 58 bytes kop/nonce/tag
	loraMaxFrag = 4
	photoNote   = " [foto niet verstuurd via radio]"
)

type fragBuf struct {
	parts   [][]byte
	got     int
	created int64
	ch      string
}

func (n *Node) id8(id string) []byte {
	raw, err := b64.DecodeString(id)
	if err != nil || len(raw) < 8 {
		return make([]byte, 8)
	}
	return raw[:8]
}

func (n *Node) contactBy8(p []byte) *Contact {
	for _, c := range n.st.Contacts {
		if bytes.Equal(n.id8(c.ID), p) {
			return c
		}
	}
	return nil
}

func (n *Node) loraHead(t byte) []byte {
	h := make([]byte, 0, mtMaxPayload)
	h = append(h, 'A', 'X', 1, t)
	return append(h, n.id8(n.myID)...)
}

func loraBackoff(tries int) int64 {
	steps := []int64{0, 90, 180, 360, 720, 1800}
	if tries < len(steps) {
		return steps[tries]
	}
	return 1800
}

// frameDest geeft "naar[8]" van een frame (nil voor een baken of iets onbekends).
func frameDest(f []byte) []byte {
	if len(f) < 20 || f[0] != 'A' || f[1] != 'X' || f[2] != 1 {
		return nil
	}
	switch f[3] {
	case 'M', 'G', 'S', 'P', 'K', 'm', 'g', 's', 'p':
		return f[12:20]
	}
	return nil
}

// loraHeadLen: lengte van de (meegetekende) kop van een berichtframe.
func loraHeadLen(f []byte) int {
	if len(f) > 3 && f[3] >= 'a' && f[3] <= 'z' {
		return 34
	}
	return 30
}

const beaconMaxAge = 15 * 60 // s

// loraFrames bouwt alle LoRa-frames van een eigen bericht voor één ontvanger.
func (n *Node) loraFrames(c *Contact, m *Message) [][]byte {
	a, err := n.aead(c)
	if err != nil {
		return nil
	}
	mid, err := hex.DecodeString(m.ID)
	if err != nil || len(mid) != 8 {
		return nil
	}
	old := c.PeerVer == "1.1"
	t := byte('M')
	var prefix []byte
	switch {
	case m.Sos && !old:
		t = 'S'
	case m.Conv == "alle":
		t = 'G'
	case strings.HasPrefix(m.Conv, "g:") && !old:
		gid, err := hex.DecodeString(m.Conv[2:])
		if err != nil || len(gid) != 8 {
			return nil
		}
		t = 'P'
		prefix = gid
	}
	body := []byte(m.Body)
	if m.Img != "" {
		body = append(body, photoNote...)
	}
	chunk := loraChunk - len(prefix)
	if !old { // nieuw formaat: kleine letter + verzendtijdstip in de kop
		t += 'a' - 'A'
		chunk -= 4
	}
	cnt := (len(body) + chunk - 1) / chunk
	if cnt == 0 {
		cnt = 1
	}
	if cnt > loraMaxFrag {
		cnt = loraMaxFrag
		body = []byte(truncBytes(string(body), loraMaxFrag*chunk))
	}
	var out [][]byte
	for i := 0; i < cnt; i++ {
		end := (i + 1) * chunk
		if end > len(body) {
			end = len(body)
		}
		part := append(append([]byte{}, prefix...), body[i*chunk:end]...)
		h := n.loraHead(t)
		h = append(h, n.id8(c.ID)...)
		h = append(h, mid...)
		h = append(h, byte(i), byte(cnt))
		if !old {
			h = binary.BigEndian.AppendUint32(h, uint32(sendClockMs()/1000))
		}
		nonce := make([]byte, 12)
		rand.Read(nonce)
		f := append(append([]byte{}, h...), nonce...)
		out = append(out, a.Seal(f, nonce, part, h))
	}
	return out
}

// loraSendMsg zet alle delen van een eigen bericht voor één ontvanger in de radiowachtrij.
func (n *Node) loraSendMsg(c *Contact, m *Message) {
	prio := 1
	if m.Sos {
		prio = 0
	}
	for i, f := range n.loraFrames(c, m) {
		n.radio.Enqueue(m.ID+"|"+c.ID+"|"+string(rune('0'+i)), f, prio)
	}
}

func (n *Node) loraAckFrame(c *Contact, mid []byte) []byte {
	a, err := n.aead(c)
	if err != nil {
		return nil
	}
	h := n.loraHead('K')
	h = append(h, n.id8(c.ID)...)
	h = append(h, mid...)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(append([]byte{}, h...), nonce...)
	return a.Seal(out, nonce, nil, h)
}

// loraSendAck bevestigt over de eigen radio en, als het via een brug kwam, ook via die brug.
func (n *Node) loraSendAck(c *Contact, msgID string, bridge *Contact) {
	mid, err := hex.DecodeString(msgID)
	if err != nil || len(mid) != 8 {
		return
	}
	key := c.ID + "|" + msgID
	t := now()
	if t-n.loraAcked[key] < 30 {
		return
	}
	n.loraAcked[key] = t
	f := n.loraAckFrame(c, mid)
	if f == nil {
		return
	}
	if n.radio.Ready() {
		n.radio.Enqueue("ack|"+key, f, 0)
	}
	if bridge != nil {
		n.sendL(bridge, f)
	}
}

// loraBeacon: "ik ben bereikbaar" (ondertekend, niet versleuteld, dus zonder positie).
func (n *Node) loraBeacon() {
	h := n.loraHead('B')
	h = binary.BigEndian.AppendUint32(h, uint32(sendClockMs()/1000))
	n.beaconSeq++
	h = binary.BigEndian.AppendUint32(h, n.beaconSeq)
	sig := ed25519.Sign(n.edPriv, append([]byte("aerocx-blackout-beacon|"), h...))
	n.radio.Drop("beacon")
	n.radio.Enqueue("beacon", append(h, sig...), 2)
}

// onLoRa verwerkt een LoRa-payload die de eigen radio hoorde.
func (n *Node) onLoRa(p []byte, from uint32, rssi int32, snr float32) {
	if len(p) < 12 || p[0] != 'A' || p[1] != 'X' || p[2] != 1 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if bytes.Equal(p[4:12], n.id8(n.myID)) {
		return
	}
	n.bridgeFromRadio(p)
	n.loraFrame(p, rssi, snr, nil)
}

// loraFrame (onder slot) verwerkt één frame; bridge != nil als het via een brug (IP) binnenkwam.
func (n *Node) loraFrame(p []byte, rssi int32, snr float32, bridge *Contact) {
	if len(p) < 12 || p[0] != 'A' || p[1] != 'X' || p[2] != 1 {
		return
	}
	c := n.contactBy8(p[4:12])
	if c == nil || c.Blocked {
		return
	}
	via := "radio"
	if bridge != nil {
		via = "bridge"
	}
	seen := func() {
		if bridge != nil {
			c.BridgeSeen = now()
			c.BridgeVia = bridge.ID
		} else {
			c.RadioSeen = now()
			c.RadioRSSI = rssi
			c.RadioSNR = snr
		}
		n.dirty = true
	}
	my8 := n.id8(n.myID)
	switch p[3] {
	case 'B':
		if len(p) != 4+8+4+64 && len(p) != 4+8+4+4+64 && len(p) != 4+8+4+8+64 {
			return
		}
		pub, err := b64.DecodeString(c.ID)
		if err != nil {
			return
		}
		hl := len(p) - 64
		if !ed25519.Verify(pub, append([]byte("aerocx-blackout-beacon|"), p[:hl]...), p[hl:]) {
			return
		}
		ts := int64(binary.BigEndian.Uint32(p[12:16]))
		if d := now() - ts; d > beaconMaxAge || d < -tsMaxFuture/1000 {
			return // te oud (opnieuw uitgezonden?) of klok ver verschoven
		}
		var seq uint32
		if hl == 20 {
			seq = binary.BigEndian.Uint32(p[16:20])
		}
		key := uint64(ts)<<32 | uint64(seq)
		if key <= n.beaconLast[c.ID] {
			return // al gezien: geen "gehoord via radio" op basis van een herhaald baken
		}
		n.beaconLast[c.ID] = key
		seen()
	case 'K':
		if len(p) != 28+12+16 || !bytes.Equal(p[12:20], my8) {
			return
		}
		a, err := n.aead(c)
		if err != nil {
			return
		}
		if _, err := a.Open(nil, p[28:40], p[40:], p[:28]); err != nil {
			return
		}
		seen()
		n.markAcked(c, hex.EncodeToString(p[20:28]), via)
	case 'M', 'G', 'S', 'P', 'm', 'g', 's', 'p':
		hl := loraHeadLen(p)
		if len(p) < hl+12+16 || !bytes.Equal(p[12:20], my8) {
			return
		}
		idx, cnt := int(p[28]), int(p[29])
		if cnt < 1 || cnt > loraMaxFrag || idx >= cnt {
			return
		}
		a, err := n.aead(c)
		if err != nil {
			return
		}
		part, err := a.Open(nil, p[hl:hl+12], p[hl+12:], p[:hl])
		if err != nil {
			return
		}
		kind := p[3]
		heard := true // mag dit frame "gehoord via radio" zetten?
		if kind >= 'a' {
			kind -= 'a' - 'A'
			ts := int64(binary.BigEndian.Uint32(p[30:34]))
			if ok, _, _ := checkTS(ts*1000, time.Now().UnixMilli()); !ok {
				return // te oud of te ver in de toekomst
			}
			if !c.SendsTS {
				c.SendsTS = true
			}
			if d := now() - ts; d > beaconMaxAge || d < -beaconMaxAge {
				heard = false // oud (opnieuw uitgezonden) frame: wel verwerken, niet als "gehoord" tellen
			}
		} else if c.SendsTS {
			return // dit contact stuurt frames met tijd: dit is een oud, opnieuw afgespeeld frame
		}
		msgID := hex.EncodeToString(p[20:28])
		key := c.ID + "|" + msgID
		if kind == p[3] && n.isSeen(key) {
			heard = false // v1.1-frame van een al ontvangen bericht: kan een herhaling zijn
		}
		if heard {
			seen()
		}
		ch := "dm"
		switch kind {
		case 'G', 'S':
			ch = "alle"
		case 'P':
			if len(part) < 8 {
				return
			}
			ch = "g:" + hex.EncodeToString(part[:8])
			part = part[8:]
		}
		if n.isSeen(key) { // al ontvangen: bevestiging ging verloren, stuur opnieuw
			n.loraSendAck(c, msgID, bridge)
			return
		}
		fb := n.frags[key]
		if fb == nil && len(n.frags) >= maxFrags {
			return // te veel berichten tegelijk in opbouw
		}
		if fb == nil || len(fb.parts) != cnt {
			fb = &fragBuf{parts: make([][]byte, cnt), created: now(), ch: ch}
			n.frags[key] = fb
		}
		if fb.parts[idx] == nil {
			fb.parts[idx] = part
			fb.got++
		}
		if fb.got < cnt {
			return
		}
		delete(n.frags, key)
		body := string(bytes.Join(fb.parts, nil))
		if !n.deliverMsg(c, inMsg{ID: msgID, Ch: ch, Body: body, Sos: kind == 'S', Via: via}) {
			return
		}
		n.loraSendAck(c, msgID, bridge)
		// ook over IP bevestigen, voor het geval die weg intussen werkt
		n.sendTo(c, n.sealJSON(c, wire{T: "ack", ID: msgID}))
		log.Printf("radio: bericht van %s via %s (rssi %d, snr %.1f)", c.Name, via, rssi, snr)
	}
}

// loraCleanup (onder slot, elke 2 s) ruimt verlopen hulptabellen op; eens per minuut ook de rest.
func (n *Node) loraCleanup() {
	t := now()
	if t-n.mapClean >= 60 {
		n.mapClean = t
		n.cleanMaps(t)
	}
	for k, f := range n.frags {
		if t-f.created > 1800 {
			delete(n.frags, k)
		}
	}
	for k, v := range n.loraAcked {
		if t-v > 3600 {
			delete(n.loraAcked, k)
		}
	}
	for k, v := range n.brSeen {
		if t-v > 600 {
			delete(n.brSeen, k)
		}
	}
	for id, m := range n.radioHeard {
		for b, ts := range m {
			if t-ts > 3600 {
				delete(m, b)
			}
		}
		if len(m) == 0 {
			delete(n.radioHeard, id)
		}
	}
}
