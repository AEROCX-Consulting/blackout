package main

import (
	"strconv"
	"strings"
)

const (
	maxFrags  = 200 // radioberichten in opbouw
	maxBlobIn = 32  // foto's die tegelijk binnenkomen
)

// cleanMaps (onder slot): hulptabellen begrenzen, zodat ze niet onbeperkt groeien.
func (n *Node) cleanMaps(t int64) {
	// doorgeefteller per minuut: alleen de huidige minuut is nodig
	cur := "|" + strconv.FormatInt(t/60, 10)
	for k := range n.relayCnt {
		if !strings.HasSuffix(k, cur) {
			delete(n.relayCnt, k)
		}
	}
	// pogingen per bericht|ontvanger: weg als er al lang niets meer geprobeerd is
	// (bevestigd, verwijderd of ouder dan 7 dagen); de grootste wachttijd is 30 min.
	for k, v := range n.lastTry {
		if t-v > 3600 {
			delete(n.lastTry, k)
		}
	}
	for k, v := range n.loraLast {
		if t-v > 2*3600 {
			delete(n.loraLast, k)
			delete(n.loraTries, k)
		}
	}
	for k := range n.loraTries {
		if _, ok := n.loraLast[k]; !ok {
			delete(n.loraTries, k)
		}
	}
	for k, v := range n.brLast {
		if t-v > 2*3600 {
			delete(n.brLast, k)
			delete(n.brTries, k)
		}
	}
	for k := range n.brTries {
		if _, ok := n.brLast[k]; !ok {
			delete(n.brTries, k)
		}
	}
	for k, v := range n.lastPing {
		if n.st.Contacts[k] == nil || t-v > 3600 {
			delete(n.lastPing, k)
		}
	}
	for k := range n.reach {
		if n.st.Contacts[k] == nil {
			delete(n.reach, k)
		}
	}
	for k := range n.beaconLast {
		if n.st.Contacts[k] == nil {
			delete(n.beaconLast, k)
		}
	}
	// groepsbevestigingen in delen: alleen voor de huidige versie van een eigen groep
	for k := range n.grpParts {
		p := strings.Split(k, "|")
		g := n.st.Groups[p[0]]
		if len(p) != 3 || g == nil || p[2] != strconv.FormatInt(g.Ver, 10) {
			delete(n.grpParts, k)
		}
	}
	n.pruneSeen()
}
