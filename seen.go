package main

// Tegen het opnieuw afspelen (replay) van opgevangen pakketten: de gezien-lijst.
//
// Berichten, SOS en groepskaarten worden één keer verwerkt: de gezien-lijst (sleutel -> vervaltijd,
// 9 dagen) blijft bewaard over herstarts heen (<datamap>/seen.json, max. 20 000, oudste eruit).
// Of een pakket vers is (opstart-ID + hoogwatermerk, zonder klokvergelijking) staat in clock.go.
// Peers van v1.1 sturen geen ts: hun pakketten worden aanvaard, maar alleen via de gezien-lijst, en
// voegen geen nieuwe adressen toe.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	seenKeep = 60 * 86400 // s (berichten, SOS, groepskaarten)
	seenMax  = 20000
)

type seenFile struct {
	V    int              `json:"v"`
	Seen map[string]int64 `json:"seen"`
}

func (n *Node) seenPath() string { return filepath.Join(n.dir, "seen.json") }

// loadSeen leest de bewaarde gezien-lijst (bij het starten).
func (n *Node) loadSeen() {
	raw, err := os.ReadFile(n.seenPath())
	if err != nil {
		return
	}
	var f seenFile
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	t := now()
	for k, exp := range f.Seen {
		if exp > t && len(k) < 200 {
			n.seenMsg[k] = exp
		}
	}
	n.pruneSeen()
}

// isSeen (onder slot)
func (n *Node) isSeen(key string) bool {
	exp, ok := n.seenMsg[key]
	return ok && exp > now()
}

// markSeenKey (onder slot)
func (n *Node) markSeenKey(key string) {
	n.seenMsg[key] = now() + seenKeep
	n.seenDirty = true
	if len(n.seenMsg) > seenMax {
		n.pruneSeen()
	}
}

// pruneSeen (onder slot): verlopen sleutels weg; daarna zo nodig de oudste tot 90 % van het maximum.
func (n *Node) pruneSeen() {
	t := now()
	for k, exp := range n.seenMsg {
		if exp <= t {
			delete(n.seenMsg, k)
		}
	}
	if len(n.seenMsg) <= seenMax {
		return
	}
	type kv struct {
		k   string
		exp int64
	}
	all := make([]kv, 0, len(n.seenMsg))
	for k, exp := range n.seenMsg {
		all = append(all, kv{k, exp})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].exp < all[j].exp })
	for _, x := range all[:len(all)-seenMax*9/10] {
		delete(n.seenMsg, x.k)
	}
	n.seenDirty = true
}

// saveSeen schrijft de gezien-lijst weg (hooguit om de 10 s, of meteen met force).
func (n *Node) saveSeen(force bool) {
	n.mu.Lock()
	if !n.seenDirty || (!force && time.Since(n.seenSaved) < 10*time.Second) {
		n.mu.Unlock()
		return
	}
	cp := make(map[string]int64, len(n.seenMsg))
	for k, v := range n.seenMsg {
		cp[k] = v
	}
	n.seenDirty = false
	n.seenSaved = time.Now()
	n.mu.Unlock()
	raw, err := json.Marshal(seenFile{V: 1, Seen: cp})
	if err != nil {
		return
	}
	tmp := n.seenPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("gezien-lijst bewaren mislukt: %v", err)
		return
	}
	os.Rename(tmp, n.seenPath())
}
