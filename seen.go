package main

// Tegen het opnieuw afspelen (replay) van opgevangen pakketten.
//
// Elk versleuteld IP-pakket (JSON) draagt het verzendtijdstip "ts" in milliseconden. Pakketten ouder dan
// 8 dagen of meer dan 10 minuten in de toekomst worden geweigerd. Berichten, SOS en groepskaarten
// worden één keer verwerkt: de gezien-lijst (sleutel -> vervaltijd, 9 dagen) blijft bewaard over
// herstarts heen (<datamap>/seen.json, max. 20 000, oudste eruit).
// Peers van v1.1 sturen geen ts: hun pakketten worden aanvaard, maar alleen via de gezien-lijst, en
// voegen geen nieuwe adressen toe.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"
)

// sendSkew verschuift het verzendtijdstip (alleen voor tests: oude pakketten maken).
var sendSkew atomic.Int64

// sendClockMs: verzendtijdstip in ms voor pakketten en radioframes.
func sendClockMs() int64 { return time.Now().UnixMilli() + sendSkew.Load() }

const (
	tsMaxAge    = 8 * 86400 * 1000 // ms
	tsMaxFuture = 10 * 60 * 1000   // ms
	tsFresh     = 2 * 60 * 1000    // ms: alleen een vers pakket mag een adres toevoegen
	seenKeep    = 9 * 86400        // s
	seenMax     = 20000
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

// checkTS beoordeelt het tijdstip uit een pakket.
// ok=false: te oud of te ver in de toekomst (weigeren). legacy: geen ts (v1.1).
// fresh: binnen 2 minuten van nu (alleen dan mag een adres toegevoegd worden).
func checkTS(ts int64, nowMs int64) (ok, fresh, legacy bool) {
	if ts == 0 {
		return true, false, true
	}
	if ts < 1e11 { // seconden (ouder formaat): omzetten
		ts *= 1000
	}
	if nowMs-ts > tsMaxAge || ts-nowMs > tsMaxFuture {
		return false, false, false
	}
	d := nowMs - ts
	if d < 0 {
		d = -d
	}
	return true, d <= tsFresh, false
}
