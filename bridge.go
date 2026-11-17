package main

// Brug Starlink <-> radio.
// Pings melden of een knooppunt een radio heeft ("radio"), of het als brug wil werken ("bridge")
// en welke contacten het via de radio hoort ("rh"). Kan ik iemand niet via IP of mijn eigen radio
// bereiken, maar hoort een brug hem wel, dan stuur ik de (voor de ontvanger versleutelde) LoRa-frames
// in een IP-pakket 'L' naar die brug; de brug zendt ze uit. Omgekeerd: hoort een brug een frame voor
// een contact dat via IP online is, dan stuurt hij het in een 'L'-pakket door.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

const bridgePerMin = 30 // frames per minuut per contact

func (n *Node) sendL(b *Contact, frame []byte) {
	if b == nil || len(frame) == 0 || len(frame) > mtMaxPayload {
		return
	}
	n.sendTo(b, n.seal('L', b, frame))
}

func (n *Node) bridgeRate(id string) bool {
	key := id + "|" + strconv.FormatInt(now()/60, 10)
	n.brCount[key]++
	if len(n.brCount) > 500 {
		n.brCount = map[string]int{key: n.brCount[key]}
	}
	return n.brCount[key] <= bridgePerMin
}

// pickBridge: een contact dat online is via IP, als brug werkt en c recent via de radio hoorde.
func (n *Node) pickBridge(c *Contact) *Contact {
	t := now()
	var best *Contact
	var bestT int64
	for bid, ts := range n.radioHeard[c.ID] {
		b := n.st.Contacts[bid]
		if b == nil || b.ID == c.ID || !b.PeerBridge || !n.ipOnline(b) || t-ts > 1200 {
			continue
		}
		if ts > bestT {
			best, bestT = b, ts
		}
	}
	return best
}

// onBridgeFrame (onder slot): een 'L'-pakket van contact b.
func (n *Node) onBridgeFrame(b *Contact, f []byte) {
	if len(f) < 12 || f[0] != 'A' || f[1] != 'X' || f[2] != 1 {
		return
	}
	dest := frameDest(f)
	if dest != nil && bytes.Equal(dest, n.id8(n.myID)) {
		// voor mij: een brug hoorde dit op de radio
		n.loraFrame(f, 0, 0, b)
		return
	}
	// verzoek om uit te zenden
	if !n.st.Bridge || !n.radio.Ready() {
		return
	}
	if !n.can(b, "bridge") {
		n.event("brug", fmt.Sprintf("Brugverzoek van %s geweigerd (geen recht)", b.Name))
		return
	}
	if !bytes.Equal(f[4:12], n.id8(b.ID)) || !n.bridgeRate(b.ID) {
		return
	}
	h := sha256.Sum256(f)
	key := hex.EncodeToString(h[:8])
	if _, ok := n.brSeen[key]; ok {
		return
	}
	n.brSeen[key] = now()
	prio := 1
	if f[3] == 'K' || f[3] == 'S' || f[3] == 's' {
		prio = 0
	}
	n.radio.Enqueue("L|"+key, f, prio)
	if t := n.contactBy8(dest); t != nil {
		n.event("brug", fmt.Sprintf("Frame van %s voor %s uitgezonden via de radio", b.Name, t.Name))
	} else {
		n.event("brug", fmt.Sprintf("Frame van %s uitgezonden via de radio", b.Name))
	}
}

// bridgeFromRadio (onder slot): een frame dat mijn radio hoorde, doorsturen naar een contact dat via IP online is.
func (n *Node) bridgeFromRadio(f []byte) {
	if !n.st.Bridge {
		return
	}
	dest := frameDest(f)
	if dest == nil || bytes.Equal(dest, n.id8(n.myID)) || bytes.Equal(dest, f[4:12]) {
		return
	}
	t := n.contactBy8(dest)
	if t == nil || !n.ipOnline(t) || !n.can(t, "bridge") {
		return
	}
	if from := n.contactBy8(f[4:12]); from != nil && from.Blocked {
		return
	}
	h := sha256.Sum256(f)
	key := hex.EncodeToString(h[:8])
	if _, ok := n.brSeen[key]; ok {
		return
	}
	n.brSeen[key] = now()
	if !n.bridgeRate(t.ID) {
		return
	}
	n.sendL(t, f)
}
