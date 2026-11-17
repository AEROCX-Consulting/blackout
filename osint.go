package main

// OSINT-motor. Eigendom van de agent "osint"; dit is de vaste interface die de backend gebruikt.
// De backend maakt bij het starten: n.osint = newOSINT(dataDir) en roept n.osint.Start() aan,
// koppelt GET/POST /api/osint aan n.osint.ServeHTTP (na de pincodecontrole),
// en roept vanuit radio.go MeshText/MeshNode aan, en SetLocation wanneer de eigen positie wijzigt.
//
// Alle methoden zijn veilig om tegelijk vanuit verschillende goroutines aan te roepen.
// Bronnen en ophalen: osint_sources.go. Parsers: osint_parse.go.

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	osMaxItems   = 300
	osMaxAge     = 7 * 24 * time.Hour
	osMaxWords   = 50
	osMaxWordLen = 30
	osMaxFeeds   = 20
	osMaxSeen    = 5000
	osUserAgent  = "AEROCX-Blackout/1.2"
)

var osDefaultWords = []string{"stroom", "noodplan", "evacuatie", "BE-Alert", "storing"}

// osItem is één melding. Base is de ernst van de bron zelf; Sev is de getoonde ernst
// (minstens 2 als er een trefwoord in staat).
type osItem struct {
	ID     string   `json:"id"`
	Src    string   `json:"src"`
	Sev    int      `json:"sev"`
	Base   int      `json:"base"`
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Area   string   `json:"area"`
	TS     int64    `json:"ts"`
	Link   string   `json:"link"`
	Read   bool     `json:"read"`
	Hidden bool     `json:"hidden"`
	Hit    []string `json:"hit"`
}

// osItemOut is de vorm in GET /api/osint (zie CONTRACT §4).
type osItemOut struct {
	ID    string   `json:"id"`
	Src   string   `json:"src"`
	Sev   int      `json:"sev"`
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Area  string   `json:"area"`
	TS    int64    `json:"ts"`
	Link  string   `json:"link"`
	Read  bool     `json:"read"`
	Hit   []string `json:"hit"`
}

// osSource is een bron. Kind bepaalt hoe er opgehaald wordt.
type osSource struct {
	ID      string
	Kind    string // mesh | adsb | meteoalarm | gdacs | emsc | rss
	Name    string
	Tag     string
	Desc    string
	Icon    string
	Offline bool
	Custom  bool
	URL     string

	On      bool
	Active  bool
	Status  string
	LastOk  int64
	LastErr string

	everOk  bool
	okRun   time.Time // laatste geslaagde ophaling in deze run (niet bewaard)
	running bool
	nextAt  time.Time
	every   time.Duration
	retry   time.Duration
}

type osSourceOut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Desc    string `json:"desc"`
	Icon    string `json:"icon"`
	Offline bool   `json:"offline"`
	On      bool   `json:"on"`
	Active  bool   `json:"active"`
	Status  string `json:"status"`
	LastOk  int64  `json:"lastOk"`
	LastErr string `json:"lastErr"`
	Custom  bool   `json:"custom"`
	URL     string `json:"url,omitempty"`
}

// osCand is een kandidaat-melding uit een bron, nog niet opgeslagen.
type osCand struct {
	Key      string        // stabiele sleutel binnen de bron (voor ontdubbelen)
	DedupFor time.Duration // 0 = nooit opnieuw; anders pas opnieuw na deze tijd
	Sev      int
	Title    string
	Body     string
	Area     string
	Link     string
	TS       int64 // ms; 0 = nu
}

type OSINT struct {
	mu    sync.Mutex
	dir   string
	items []*osItem
	byID  map[string]*osItem
	seen  map[string]int64
	words []string
	srcs  map[string]*osSource
	order []string

	lat, lon float64
	hasPos   bool

	// instelbaar voor tests
	now         func() time.Time
	client      *http.Client
	localClient *http.Client
	urlMeteo    string
	urlGDACS    string
	urlEMSC     string
	adsbURLs    []string

	startOnce sync.Once
	stopOnce  sync.Once
	started   bool
	done      chan struct{}
	inflight  sync.WaitGroup
	stop      chan struct{}
	wake      chan struct{}

	saveMu   sync.Mutex
	gen      uint64
	savedGen uint64
}

func newOSINT(dataDir string) *OSINT {
	o := &OSINT{
		dir:         dataDir,
		byID:        map[string]*osItem{},
		seen:        map[string]int64{},
		words:       append([]string(nil), osDefaultWords...),
		srcs:        map[string]*osSource{},
		now:         time.Now,
		client:      osNewClient(true, 10*time.Second),
		localClient: osNewClient(false, 3*time.Second),
		urlMeteo:    osURLMeteo,
		urlGDACS:    osURLGDACS,
		urlEMSC:     osURLEMSC,
		adsbURLs:    append([]string(nil), osADSBURLs...),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		wake:        make(chan struct{}, 1),
	}
	for _, s := range osBuiltinSources() {
		o.addSourceLocked(s)
	}
	o.load()
	return o
}

func (o *OSINT) addSourceLocked(s *osSource) {
	if _, ok := o.srcs[s.ID]; !ok {
		o.order = append(o.order, s.ID)
	}
	if s.Status == "" {
		s.Status = osStatusWaiting(s)
	}
	o.srcs[s.ID] = s
}

func osStatusWaiting(s *osSource) string {
	if !s.On {
		return "uit"
	}
	switch s.Kind {
	case "mesh":
		return "nog niets gehoord via de radio"
	case "adsb":
		return "zoekt ontvanger"
	}
	return "wacht op eerste ophaling"
}

func (o *OSINT) nowMs() int64 { return o.now().UnixMilli() }

// Start begint de achtergrondlussen van alle bronnen. Meermaals aanroepen mag.
func (o *OSINT) Start() {
	o.startOnce.Do(func() {
		o.mu.Lock()
		o.started = true
		o.mu.Unlock()
		go func() {
			defer close(o.done)
			o.loop()
		}()
	})
}

// close stopt de achtergrondlus en wacht op lopende ophalingen (voor tests).
func (o *OSINT) close() {
	o.stopOnce.Do(func() { close(o.stop) })
	o.mu.Lock()
	started := o.started
	o.mu.Unlock()
	if started {
		<-o.done
	}
	o.inflight.Wait()
}

func (o *OSINT) kick() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// MeshText: een openbaar Meshtastic-tekstbericht (portnum 1) dat de radio hoorde.
func (o *OSINT) MeshText(fromNode uint32, name, text string, rssi int32, snr float32, ch uint32) {
	text = strings.TrimSpace(osClean(text))
	if text == "" {
		return
	}
	node := fmt.Sprintf("!%08x", fromNode)
	who := strings.TrimSpace(osClean(name))
	label := node
	if who != "" {
		label = who + " (" + node + ")"
	}
	title := "“" + osTrunc(text, 100) + "”"
	var sig []string
	if rssi != 0 {
		sig = append(sig, "signaal "+osNum(float64(rssi), 0)+" dBm")
	}
	if snr != 0 {
		sig = append(sig, "SNR "+osNum(float64(snr), 1)+" dB")
	}
	if ch != 0 {
		sig = append(sig, fmt.Sprintf("kanaal %d", ch))
	}
	body := ""
	if len([]rune(text)) > 100 {
		body = text + "\n\n"
	}
	body += "Bericht op het openbare mesh-kanaal van node " + label + "."
	if len(sig) > 0 {
		body += " " + osCap(strings.Join(sig, ", ")) + "."
	}
	area := who
	if area == "" {
		area = node
	}
	c := osCand{Key: node + "|" + osHash(text), DedupFor: 30 * time.Minute, Sev: 1,
		Title: title, Body: body, Area: area}
	o.meshIngest(c)
}

// MeshNode: een nieuw gehoorde Meshtastic-node.
func (o *OSINT) MeshNode(num uint32, name string) {
	node := fmt.Sprintf("!%08x", num)
	who := strings.TrimSpace(osClean(name))
	if who == "" {
		who = node
	}
	c := osCand{Key: "node|" + node, Sev: 1,
		Title: "Nieuwe node gehoord: " + osTrunc(who, 60),
		Body:  "Meshtastic-node " + node + " is voor het eerst gehoord via je radio. Hij kan openbare berichten doorgeven.",
		Area:  who}
	o.meshIngest(c)
}

func (o *OSINT) meshIngest(c osCand) {
	o.mu.Lock()
	s := o.srcs["mesh"]
	if s == nil || !s.On {
		o.mu.Unlock()
		return
	}
	now := o.nowMs()
	s.LastOk, s.everOk, s.Active, s.LastErr = now, true, true, ""
	s.Status = "actief · laatst gehoord " + o.now().Local().Format("15:04")
	o.ingestLocked(s, c, false)
	data, gen := o.snapshotLocked()
	o.mu.Unlock()
	o.persist(data, gen)
}

// SetLocation: eigen positie (voor afstandsfilters: aardbevingen, vliegtuigen).
func (o *OSINT) SetLocation(lat, lon float64, ok bool) {
	if ok && (lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0)) {
		ok = false
	}
	o.mu.Lock()
	moved := ok != o.hasPos || (ok && osDistKm(o.lat, o.lon, lat, lon) > 5)
	o.lat, o.lon, o.hasPos = lat, lon, ok
	if moved {
		// afstandsfilters opnieuw toepassen bij de volgende ronde
		for _, id := range []string{"emsc", "gdacs"} {
			if s := o.srcs[id]; s != nil && !s.running {
				s.nextAt = time.Time{}
			}
		}
	}
	o.mu.Unlock()
	if moved {
		o.kick()
	}
}

func (o *OSINT) position() (lat, lon float64, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lat, o.lon, o.hasPos
}

// visibleLocked: niet verborgen en de bron staat aan.
func (o *OSINT) visibleLocked(it *osItem) bool {
	if it.Hidden {
		return false
	}
	s := o.srcs[it.Src]
	return s != nil && s.On
}

// Counts: ongelezen en belangrijke (ernst 3) ongelezen items, voor /api/state.
func (o *OSINT) Counts() (unread, important int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, it := range o.items {
		if !o.visibleLocked(it) || it.Read {
			continue
		}
		unread++
		if it.Sev >= 3 {
			important++
		}
	}
	return
}

// Item geeft titel+tekst van een item (om het als bericht te delen).
// title = "<Tag>: <titel>", body = tekst + (gebied op een nieuwe regel).
func (o *OSINT) Item(id string) (title, body string, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	it := o.byID[id]
	if it == nil {
		return "", "", false
	}
	tag := it.Src
	if s := o.srcs[it.Src]; s != nil {
		tag = s.Tag
	}
	title = tag + ": " + it.Title
	body = it.Body
	if it.Area != "" {
		if body != "" {
			body += "\n"
		}
		body += it.Area
	}
	return title, body, true
}

// ---------- opslag van items ----------

func osHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// ingestLocked voegt een kandidaat toe als hij nieuw is. Geeft true als er iets bijkwam.
func (o *OSINT) ingestLocked(s *osSource, c osCand, markRead bool) bool {
	now := o.nowMs()
	ts := c.TS
	if ts <= 0 || ts > now {
		ts = now
	}
	if now-ts > osMaxAge.Milliseconds() {
		return false
	}
	key := s.ID + "|" + c.Key
	if last, ok := o.seen[key]; ok {
		if c.DedupFor == 0 || now-last < c.DedupFor.Milliseconds() {
			return false
		}
	}
	o.seen[key] = now
	idSrc := key
	if c.DedupFor > 0 {
		idSrc = fmt.Sprintf("%s|%d", key, now)
	}
	id := "o" + osHash(idSrc)[:12]
	if o.byID[id] != nil {
		return false
	}
	sev := c.Sev
	if sev < 1 {
		sev = 1
	}
	if sev > 3 {
		sev = 3
	}
	it := &osItem{ID: id, Src: s.ID, Base: sev, Sev: sev, Title: c.Title, Body: c.Body,
		Area: c.Area, TS: ts, Link: osSafeLink(c.Link), Hit: []string{}}
	o.applyWordsLocked(it)
	it.Read = markRead && len(it.Hit) == 0
	o.items = append(o.items, it)
	o.byID[id] = it
	o.pruneLocked()
	return true
}

func (o *OSINT) applyWordsLocked(it *osItem) {
	text := strings.ToLower(it.Title + " " + it.Body + " " + it.Area)
	hit := []string{}
	for _, w := range o.words {
		if w != "" && strings.Contains(text, strings.ToLower(w)) {
			hit = append(hit, w)
		}
	}
	it.Hit = hit
	it.Sev = it.Base
	if len(hit) > 0 && it.Sev < 2 {
		it.Sev = 2
	}
}

// pruneLocked: weg met alles ouder dan 7 dagen; daarna max 300 items, waarbij eerst
// verborgen, dan gewone (ernst 1, geen trefwoord) en pas daarna de rest wegvalt (oudste eerst).
func (o *OSINT) pruneLocked() {
	now := o.nowMs()
	cut := now - osMaxAge.Milliseconds()
	keep := o.items[:0]
	for _, it := range o.items {
		if it.TS >= cut {
			keep = append(keep, it)
		} else {
			delete(o.byID, it.ID)
		}
	}
	o.items = keep
	if over := len(o.items) - osMaxItems; over > 0 {
		rank := func(it *osItem) int {
			switch {
			case it.Hidden:
				return 0
			case it.Sev <= 1 && len(it.Hit) == 0:
				return 1
			}
			return 2
		}
		idx := make([]*osItem, len(o.items))
		copy(idx, o.items)
		sort.SliceStable(idx, func(a, b int) bool {
			ra, rb := rank(idx[a]), rank(idx[b])
			if ra != rb {
				return ra < rb
			}
			return idx[a].TS < idx[b].TS
		})
		drop := map[string]bool{}
		for _, it := range idx[:over] {
			drop[it.ID] = true
			delete(o.byID, it.ID)
		}
		keep := o.items[:0]
		for _, it := range o.items {
			if !drop[it.ID] {
				keep = append(keep, it)
			}
		}
		o.items = keep
	}
	if len(o.seen) > osMaxSeen {
		o.pruneSeenLocked()
	}
}

// pruneSeenLocked vergeet ontdubbelsleutels ouder dan 8 dagen en houdt er max osMaxSeen.
func (o *OSINT) pruneSeenLocked() {
	scut := o.nowMs() - (osMaxAge + 24*time.Hour).Milliseconds()
	for k, t := range o.seen {
		if t < scut {
			delete(o.seen, k)
		}
	}
	if len(o.seen) <= osMaxSeen {
		return
	}
	type kv struct {
		k string
		t int64
	}
	all := make([]kv, 0, len(o.seen))
	for k, t := range o.seen {
		all = append(all, kv{k, t})
	}
	sort.Slice(all, func(a, b int) bool { return all[a].t < all[b].t })
	for _, e := range all[:len(all)-osMaxSeen] {
		delete(o.seen, e.k)
	}
}

// ---------- bewaren (atomisch) ----------

type osFileSource struct {
	On      bool   `json:"on"`
	LastOk  int64  `json:"lastOk,omitempty"`
	LastErr string `json:"lastErr,omitempty"`
}

type osFileFeed struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Name string `json:"name"`
}

type osFile struct {
	V       int                     `json:"v"`
	Items   []*osItem               `json:"items"`
	Words   []string                `json:"words"`
	Sources map[string]osFileSource `json:"sources"`
	Feeds   []osFileFeed            `json:"feeds"`
	Seen    map[string]int64        `json:"seen"`
}

func (o *OSINT) path() string { return filepath.Join(o.dir, "osint.json") }

func (o *OSINT) load() {
	if o.dir == "" {
		return
	}
	b, err := os.ReadFile(o.path())
	if err != nil {
		return
	}
	var f osFile
	if err := json.Unmarshal(b, &f); err != nil {
		_ = os.WriteFile(o.path()+".kapot", b, 0o600)
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, fd := range f.Feeds {
		if osValidFeedURL(fd.URL) != nil || o.srcs[fd.ID] != nil {
			continue
		}
		o.addSourceLocked(osCustomSource(fd.URL, fd.Name))
	}
	for id, fs := range f.Sources {
		if s := o.srcs[id]; s != nil {
			s.On, s.LastOk, s.LastErr = fs.On, fs.LastOk, fs.LastErr
			s.everOk = fs.LastOk > 0
			s.Status = osStatusWaiting(s)
		}
	}
	if f.Words != nil {
		o.words = f.Words
	}
	if f.Seen != nil {
		o.seen = f.Seen
	}
	for _, it := range f.Items {
		if it == nil || it.ID == "" || o.byID[it.ID] != nil || o.srcs[it.Src] == nil {
			continue
		}
		if it.Base == 0 {
			it.Base = it.Sev
		}
		o.applyWordsLocked(it)
		o.items = append(o.items, it)
		o.byID[it.ID] = it
	}
	o.pruneLocked()
}

// snapshotLocked maakt de bestandsinhoud; persist schrijft hem buiten het slot weg.
func (o *OSINT) snapshotLocked() ([]byte, uint64) {
	f := osFile{V: 1, Items: o.items, Words: o.words, Sources: map[string]osFileSource{}, Seen: o.seen, Feeds: []osFileFeed{}}
	if f.Items == nil {
		f.Items = []*osItem{}
	}
	for _, id := range o.order {
		s := o.srcs[id]
		f.Sources[id] = osFileSource{On: s.On, LastOk: s.LastOk, LastErr: s.LastErr}
		if s.Custom {
			f.Feeds = append(f.Feeds, osFileFeed{ID: s.ID, URL: s.URL, Name: s.Name})
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, 0
	}
	o.gen++
	return b, o.gen
}

func (o *OSINT) persist(data []byte, gen uint64) {
	if o.dir == "" || data == nil {
		return
	}
	o.saveMu.Lock()
	defer o.saveMu.Unlock()
	if gen <= o.savedGen {
		return
	}
	if err := osWriteAtomic(o.path(), data); err == nil {
		o.savedGen = gen
	}
}

func osWriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".osint-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ---------- HTTP ----------

type osReq struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Word   string `json:"word"`
	On     *bool  `json:"on"`
	URL    string `json:"url"`
}

func (o *OSINT) stateLocked() map[string]any {
	items := []osItemOut{}
	for i := len(o.items) - 1; i >= 0; i-- { // achterstevoren: bij gelijke tijd het laatst binnengekomen eerst
		it := o.items[i]
		if !o.visibleLocked(it) {
			continue
		}
		hit := it.Hit
		if hit == nil {
			hit = []string{}
		}
		items = append(items, osItemOut{ID: it.ID, Src: it.Src, Sev: it.Sev, Title: it.Title, Body: it.Body,
			Area: it.Area, TS: it.TS, Link: osSafeLink(it.Link), Read: it.Read, Hit: hit})
	}
	sort.SliceStable(items, func(a, b int) bool { return items[a].TS > items[b].TS })
	srcs := []osSourceOut{}
	for _, id := range o.order {
		s := o.srcs[id]
		out := osSourceOut{ID: s.ID, Name: s.Name, Tag: s.Tag, Desc: s.Desc, Icon: s.Icon, Offline: s.Offline,
			On: s.On, Active: s.On && s.Active, Status: s.Status, LastOk: s.LastOk, LastErr: s.LastErr, Custom: s.Custom}
		if s.Custom || s.Kind == "rss" {
			out.URL = s.URL
		}
		if !s.On {
			out.Status = "uit"
		}
		srcs = append(srcs, out)
	}
	words := append([]string{}, o.words...)
	return map[string]any{"items": items, "sources": srcs, "words": words}
}

func osJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ServeHTTP behandelt GET en POST /api/osint (zie design/CONTRACT.md §4).
// POST-acties: read{id} | readall | hide{id} | word-add{word} | word-del{word} |
// source{id,on} | feed-add{url} | feed-del{id of url}. Antwoord = dezelfde vorm als GET (+ ok:true).
func (o *OSINT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		o.mu.Lock()
		st := o.stateLocked()
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(st)
		return
	case http.MethodPost:
	default:
		osJSONErr(w, http.StatusMethodNotAllowed, "Alleen GET en POST zijn toegestaan.")
		return
	}
	var q osReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&q); err != nil {
		osJSONErr(w, http.StatusBadRequest, "Het verzoek is geen geldige JSON.")
		return
	}
	st, kick, errMsg := o.apply(q)
	if errMsg != "" {
		osJSONErr(w, http.StatusBadRequest, errMsg)
		return
	}
	if kick {
		o.kick()
	}
	st["ok"] = true
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(st)
}

func (o *OSINT) apply(q osReq) (state map[string]any, kick bool, errMsg string) {
	o.mu.Lock()
	changed := false
	defer func() {
		var data []byte
		var gen uint64
		if changed && errMsg == "" {
			data, gen = o.snapshotLocked()
		}
		if errMsg == "" {
			state = o.stateLocked()
		}
		o.mu.Unlock()
		if data != nil {
			o.persist(data, gen)
		}
	}()
	switch q.Action {
	case "read", "hide":
		it := o.byID[strings.TrimSpace(q.ID)]
		if it == nil {
			return nil, false, "Deze melding bestaat niet (meer)."
		}
		it.Read = true
		if q.Action == "hide" {
			it.Hidden = true
		}
		changed = true
	case "readall":
		for _, it := range o.items {
			if o.visibleLocked(it) && !it.Read {
				it.Read = true
				changed = true
			}
		}
	case "word-add":
		wd := strings.Join(strings.Fields(osClean(q.Word)), " ")
		if wd == "" {
			return nil, false, "Geef een trefwoord in."
		}
		if len([]rune(wd)) > osMaxWordLen {
			return nil, false, fmt.Sprintf("Een trefwoord mag hoogstens %d tekens lang zijn.", osMaxWordLen)
		}
		for _, x := range o.words {
			if strings.EqualFold(x, wd) {
				return nil, false, "Dit trefwoord staat er al in."
			}
		}
		if len(o.words) >= osMaxWords {
			return nil, false, fmt.Sprintf("Je kan hoogstens %d trefwoorden hebben.", osMaxWords)
		}
		o.words = append(o.words, wd)
		o.rewordLocked()
		changed = true
	case "word-del":
		wd := strings.TrimSpace(q.Word)
		found := false
		for i, x := range o.words {
			if strings.EqualFold(x, wd) {
				o.words = append(o.words[:i:i], o.words[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return nil, false, "Dit trefwoord staat niet in de lijst."
		}
		o.rewordLocked()
		changed = true
	case "source":
		s := o.srcs[strings.TrimSpace(q.ID)]
		if s == nil {
			return nil, false, "Onbekende bron."
		}
		if q.On == nil {
			return nil, false, "Zeg of de bron aan of uit moet (on: true of false)."
		}
		if s.On != *q.On {
			s.On = *q.On
			s.Active = false
			s.Status = osStatusWaiting(s)
			s.nextAt = time.Time{}
			changed = true
			kick = s.On
		}
	case "feed-add":
		u := strings.TrimSpace(q.URL)
		if err := osValidFeedURL(u); err != nil {
			return nil, false, err.Error()
		}
		ns := osCustomSource(u, "")
		for _, id := range o.order {
			x := o.srcs[id]
			if x.ID == ns.ID || (x.URL != "" && strings.EqualFold(x.URL, u)) {
				return nil, false, "Deze feed staat er al in."
			}
		}
		n := 0
		for _, id := range o.order {
			if o.srcs[id].Custom {
				n++
			}
		}
		if n >= osMaxFeeds {
			return nil, false, fmt.Sprintf("Je kan hoogstens %d eigen feeds toevoegen.", osMaxFeeds)
		}
		o.addSourceLocked(ns)
		changed, kick = true, true
	case "feed-del":
		var s *osSource
		key := strings.TrimSpace(q.ID)
		if key == "" {
			key = strings.TrimSpace(q.URL)
		}
		for _, id := range o.order {
			x := o.srcs[id]
			if x.ID == key || (x.URL != "" && strings.EqualFold(x.URL, key)) {
				s = x
				break
			}
		}
		if s == nil {
			return nil, false, "Deze feed bestaat niet."
		}
		if !s.Custom {
			return nil, false, "Een standaardbron kan je niet verwijderen. Zet hem uit als je hem niet wil."
		}
		delete(o.srcs, s.ID)
		for i, id := range o.order {
			if id == s.ID {
				o.order = append(o.order[:i:i], o.order[i+1:]...)
				break
			}
		}
		keep := o.items[:0]
		for _, it := range o.items {
			if it.Src == s.ID {
				delete(o.byID, it.ID)
			} else {
				keep = append(keep, it)
			}
		}
		o.items = keep
		prefix := s.ID + "|"
		for k := range o.seen {
			if strings.HasPrefix(k, prefix) {
				delete(o.seen, k)
			}
		}
		changed = true
	case "":
		return nil, false, "Geef een actie op."
	default:
		return nil, false, "Onbekende actie: " + q.Action + "."
	}
	return nil, kick, ""
}

func (o *OSINT) rewordLocked() {
	for _, it := range o.items {
		o.applyWordsLocked(it)
	}
}

// InternetSeen: is een internetbron (niet mesh/adsb) binnen `within` gelukt?
// Dient als bewijs dat dit station internet heeft, ook zonder contacten en met STUN uit.
func (o *OSINT) InternetSeen(within time.Duration) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	// Alleen ophalingen van deze run tellen, gemeten met de monotone klok: een herstart
	// of een verkeerd gezette klok (Pi zonder RTC) mag geen "internet werkt" tonen.
	now := o.now()
	for _, s := range o.srcs {
		if s != nil && s.On && !s.Offline && !s.okRun.IsZero() && now.Sub(s.okRun) >= 0 && now.Sub(s.okRun) <= within {
			return true
		}
	}
	return false
}
