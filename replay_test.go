package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func countBody(n *Node, body string) int {
	k := 0
	for _, m := range n.st.Messages {
		if m.Body == body {
			k++
		}
	}
	return k
}

func sealed(a *Node, c *Contact, w wire) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sealJSON(c, w)
}

func msgPkt(a *Node, c *Contact, id, body string) []byte {
	return sealed(a, c, wire{T: "msg", ID: id, Ch: "dm", Body: body})
}

func pingPkt(a *Node, c *Contact) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sealJSON(c, a.pingWire("ping"))
}

// legacyPkt: zoals een v1.1-peer: zonder ts.
func legacyPkt(a *Node, c *Contact, w wire) []byte {
	j, _ := json.Marshal(w)
	return a.seal('E', c, j)
}

// restart: het station opnieuw laden uit zijn map (nieuwe opstart-ID).
func restart(t *testing.T, n *Node) *Node {
	t.Helper()
	n.mu.Lock()
	n.dirty = true
	n.mu.Unlock()
	n.save()
	n.saveSeen(true)
	n2, err := loadNode(n.dir, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	return n2
}

const peerAddr = "[2001:db8:10::1]:47474"

func TestReplayIPMessages(t *testing.T) {
	defer sendSkew.Store(0)
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	know(b, a, "Anna")

	p := msgPkt(a, ab, "a000000000000001", "eerste")
	b.handle(p, udp(peerAddr), false)
	b.handle(p, udp(peerAddr), false) // opnieuw afgespeeld
	if countBody(b, "eerste") != 1 {
		t.Fatalf("bericht %d keer bewaard", countBody(b, "eerste"))
	}
	if !b.st.Contacts[a.myID].SendsTS {
		t.Error("contact niet gemarkeerd als ts-stuurder")
	}

	// de gezien-lijst blijft bewaard over een herstart, ook als het bericht zelf al opgeruimd is
	b.mu.Lock()
	b.st.Messages = nil
	b.mu.Unlock()
	b2 := restart(t, b)
	b2.handle(p, udp(peerAddr), false)
	if countBody(b2, "eerste") != 0 {
		t.Fatal("na herstart opnieuw afgespeeld bericht aanvaard")
	}
	b2.mu.Lock()
	if !b2.isSeen(a.myID+"|a000000000000001") || b2.seenMsg[a.myID+"|a000000000000001"] < now()+8*86400 {
		t.Error("vervaltijd gezien-lijst niet ~9 dagen")
	}
	b2.mu.Unlock()

	// een bericht dat volgens de klok van de afzender 10 dagen oud is, uit dezelfde opstart:
	// geweigerd, ook als het niet (meer) in de gezien-lijst staat
	c, d := bareNode(t, "Carla"), bareNode(t, "Dirk")
	cd := know(c, d, "Dirk")
	know(d, c, "Carla")
	sendSkew.Store(-10 * 86400 * 1000)
	old := msgPkt(c, cd, "c000000000000010", "tien dagen oud")
	sendSkew.Store(0)
	d.handle(pingPkt(c, cd), udp(peerAddr), false)
	d.handle(old, udp(peerAddr), false)
	if countBody(d, "tien dagen oud") != 0 {
		t.Fatal("10 dagen oud bericht aanvaard")
	}
}

// Klokverschil tussen stations mag de communicatie niet breken.
func TestClockSkewDoesNotBreak(t *testing.T) {
	defer sendSkew.Store(0)
	for _, tc := range []struct {
		name string
		skew time.Duration // klok van de zender t.o.v. de ontvanger
	}{
		{"ontvanger 6 u achter", 6 * time.Hour},
		{"zender 6 u achter", -6 * time.Hour},
		{"zender 2 u voor", 2 * time.Hour},
		{"zender 30 dagen achter", -30 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
			ab := know(a, b, "Bert")
			ba := know(b, a, "Anna")
			sendSkew.Store(tc.skew.Milliseconds())
			ping := pingPkt(a, ab)
			msg := msgPkt(a, ab, "d000000000000001", "hallo met scheve klok")
			sos := sealed(a, ab, wire{T: "msg", ID: "d000000000000002", Ch: "alle", Body: "Anna heeft hulp nodig.", Sos: true})
			frame := a.loraFrames(ab, &Message{ID: "d000000000000003", Conv: b.myID, From: "me", Body: "radio met scheve klok", TS: now()})[0]
			sendSkew.Store(0)

			b.handle(ping, udp(peerAddr), false)
			if !b.ipOnline(ba) {
				t.Fatal("niet online")
			}
			if _, ok := ba.Observed[udp(peerAddr).String()]; !ok {
				t.Fatal("adres niet geleerd")
			}
			off, ok := recentSkew(ba, 60)
			if !ok || off < tc.skew.Milliseconds()-5000 || off > tc.skew.Milliseconds()+5000 {
				t.Errorf("klokverschil %d ms, verwacht ~%d", off, tc.skew.Milliseconds())
			}
			b.handle(msg, udp(peerAddr), false)
			b.handle(sos, udp(peerAddr), false)
			b.loraFrame(frame, -90, 5, nil)
			if countBody(b, "hallo met scheve klok") != 1 || len(b.st.IncomingSos) != 1 || countBody(b, "radio met scheve klok") != 1 {
				t.Fatalf("bericht %d, SOS %d, radio %d", countBody(b, "hallo met scheve klok"), len(b.st.IncomingSos), countBody(b, "radio met scheve klok"))
			}
			// bevestiging terug (de ontvanger heeft de gewone klok)
			a.st.Messages = append(a.st.Messages, &Message{ID: "d000000000000001", Conv: b.myID, From: "me", Body: "x", TS: now(), Recips: map[string]bool{b.myID: false}})
			a.handle(sealed(b, ba, wire{T: "ack", ID: "d000000000000001"}), udp("[2001:db8:20::1]:47474"), false)
			if !a.st.Messages[len(a.st.Messages)-1].Recips[b.myID] {
				t.Fatal("bevestiging niet verwerkt")
			}
			// state toont het verschil vanaf 5 min
			st := b.stateJSON(httptestLocal(), nil, 0, 0)
			raw, _ := json.Marshal(st["contacts"])
			var cs []map[string]any
			json.Unmarshal(raw, &cs)
			if cs[0]["clockSkew"] == nil {
				t.Error("clockSkew ontbreekt in state")
			}
			if st["clockSkew"] == nil {
				t.Error("eigen klokverschil ontbreekt in state")
			}
		})
	}
}

func TestPeerRestartWithOldClock(t *testing.T) {
	defer sendSkew.Store(0)
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")
	b.mu.Lock()
	b.dirty = true
	b.mu.Unlock()
	oldPing := pingPkt(a, ab)
	oldMsg := msgPkt(a, ab, "e000000000000001", "voor de herstart")
	oldSos := sealed(a, ab, wire{T: "msg", ID: "e000000000000002", Ch: "alle", Body: "Anna heeft hulp nodig.", Sos: true})
	b.handle(oldPing, udp(peerAddr), false)
	b.handle(oldMsg, udp(peerAddr), false)
	b.handle(oldSos, udp(peerAddr), false)
	if countBody(b, "voor de herstart") != 1 || len(b.st.IncomingSos) != 1 {
		t.Fatal("eerste berichten niet aangekomen")
	}
	b.mu.Lock()
	b.st.IncomingSos = nil
	b.mu.Unlock()

	// Anna herstart, met een klok die een dag achterloopt (Pi zonder RTC)
	a.mu.Lock()
	a.dirty = true
	a.mu.Unlock()
	a2 := restart(t, a)
	ab2 := a2.st.Contacts[b.myID]
	sendSkew.Store(-86400 * 1000)
	newPing := pingPkt(a2, ab2)
	newMsg := msgPkt(a2, ab2, "e000000000000003", "na de herstart")
	sendSkew.Store(0)
	ba.LastSeen = 0
	b.handle(newPing, udp("[2001:db8:11::1]:47474"), false)
	if !b.ipOnline(ba) {
		t.Fatal("na herstart met oude klok niet online")
	}
	if _, ok := ba.Observed[udp("[2001:db8:11::1]:47474").String()]; !ok {
		t.Fatal("nieuw adres na herstart niet geleerd")
	}
	b.handle(newMsg, udp("[2001:db8:11::1]:47474"), false)
	if countBody(b, "na de herstart") != 1 {
		t.Fatal("bericht na herstart niet aangekomen")
	}

	// replays van vóór de herstart: ping niet vers, bericht en SOS niet opnieuw — ook na herstart van Bert
	b2 := restart(t, b)
	ba2 := b2.st.Contacts[a.myID]
	ba2.LastSeen = 0
	attacker := udp("[2001:db8:666::6]:40000")
	b2.handle(oldPing, attacker, false)
	b2.handle(newPing, attacker, false)
	if ba2.LastSeen != 0 {
		t.Fatal("afgespeelde ping zette het contact online")
	}
	if _, ok := ba2.Observed[attacker.String()]; ok {
		t.Fatal("afgespeelde ping voegde een adres toe")
	}
	b2.mu.Lock()
	b2.st.Messages = nil
	b2.mu.Unlock()
	b2.handle(oldMsg, attacker, false)
	b2.handle(oldSos, attacker, false)
	b2.handle(newMsg, attacker, false)
	if len(b2.st.Messages) != 0 || len(b2.st.IncomingSos) != 0 {
		t.Fatalf("afgespeeld bericht/SOS aanvaard: %d berichten, %d SOS", len(b2.st.Messages), len(b2.st.IncomingSos))
	}
	// een verse ping van de huidige opstart werkt gewoon
	b2.handle(pingPkt(a2, ab2), udp(peerAddr), false)
	if ba2.LastSeen == 0 {
		t.Fatal("verse ping na alles geweigerd")
	}
}

func TestReplayObservedAddress(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")
	p1 := pingPkt(a, ab)
	b.handle(p1, udp(peerAddr), false)
	if _, ok := ba.Observed[udp(peerAddr).String()]; !ok || ba.LastSeen == 0 {
		t.Fatalf("verse ping: %v", ba.Observed)
	}
	// dezelfde ping opnieuw vanaf een ander adres: geen adres, niet opnieuw "gezien"
	ba.LastSeen = 0
	b.handle(p1, udp("[2001:db8:66::6]:40000"), false)
	if len(ba.Observed) != 1 || ba.LastSeen != 0 {
		t.Fatalf("afgespeelde ping telde mee: %v %d", ba.Observed, ba.LastSeen)
	}
	// v1.1-pakket zonder ts (van een contact dat nooit ts stuurde): wel online, geen nieuw adres
	c, d := bareNode(t, "Carla"), bareNode(t, "Dirk")
	cd := know(c, d, "Dirk")
	dc := know(d, c, "Carla")
	d.handle(legacyPkt(c, cd, wire{T: "ping"}), udp("[2001:db8:77::7]:40000"), false)
	if dc.LastSeen == 0 || len(dc.Observed) != 0 || dc.PeerVer != "1.1" {
		t.Fatalf("v1.1-ping: gezien %d, adressen %v, versie %q", dc.LastSeen, dc.Observed, dc.PeerVer)
	}
	// v1.1-bericht: één keer aanvaard
	lp := legacyPkt(c, cd, wire{T: "msg", ID: "c000000000000001", Ch: "dm", Body: "oud formaat"})
	d.handle(lp, udp(peerAddr), false)
	d.handle(lp, udp(peerAddr), false)
	if countBody(d, "oud formaat") != 1 {
		t.Fatalf("v1.1-bericht %d keer", countBody(d, "oud formaat"))
	}
	// wie ts stuurt, krijgt geen pakketten zonder ts meer aanvaard (oud, afgespeeld)
	b.handle(legacyPkt(a, ab, wire{T: "msg", ID: "a0000000000000ff", Ch: "dm", Body: "afgespeeld zonder ts"}), udp(peerAddr), false)
	if countBody(b, "afgespeeld zonder ts") != 0 {
		t.Fatal("pakket zonder ts aanvaard van een contact dat ts stuurt")
	}
}

func TestReplayGroupCard(t *testing.T) {
	a, b, c := bareNode(t, "Anna"), bareNode(t, "Bert"), bareNode(t, "Carla")
	know(a, b, "Bert")
	know(a, c, "Carla")
	know(b, a, "Anna").Role = "beheerder"
	g, _ := a.groupAction(groupIn{Action: "create", Name: "Buurt", Members: &[]string{b.myID, c.myID}})
	parts := a.groupParts(g, b.myID)
	first := wire{T: "grp", Grp: a.groupWire(g), Cards: parts[0], Part: 0, Parts: len(parts), Ver: g.Ver}
	firstPkt := sealed(a, a.st.Contacts[b.myID], first)
	b.handle(firstPkt, udp(peerAddr), false)
	if b.st.Groups[g.ID] == nil {
		t.Fatal("groep niet aangemaakt")
	}
	// Bert wordt uit de groep gehaald (nieuwe versie zonder hem)
	time.Sleep(1100 * time.Millisecond)
	if _, err := a.groupAction(groupIn{Action: "update", ID: g.ID, Members: &[]string{c.myID}}); err != nil {
		t.Fatal(err)
	}
	kick := wire{T: "grp", Grp: a.groupWire(g), Part: 0, Parts: 1, Ver: g.Ver}
	b.handle(sealed(a, a.st.Contacts[b.myID], kick), udp(peerAddr), false)
	if b.st.Groups[g.ID] != nil {
		t.Fatal("niet uit de groep gehaald")
	}
	// de oude groepskaart opnieuw afgespeeld (ook na herstart): groep komt niet terug
	b.handle(firstPkt, udp(peerAddr), false)
	b2 := restart(t, b)
	b2.handle(firstPkt, udp(peerAddr), false)
	if b.st.Groups[g.ID] != nil || b2.st.Groups[g.ID] != nil {
		t.Fatal("afgespeelde groepskaart zette de groep terug")
	}
	// rechtstreeks: alleen bevestigd
	var rep []wire
	b.onGroupCard(b.st.Contacts[a.myID], &first, func(w wire) { rep = append(rep, w) })
	if len(rep) != 1 || rep[0].T != "grpack" || b.st.Groups[g.ID] != nil {
		t.Fatalf("antwoord: %+v", rep)
	}
}

func TestReplayLoRaFrames(t *testing.T) {
	defer sendSkew.Store(0)
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")
	m := &Message{ID: "b000000000000001", Conv: b.myID, From: "me", Body: "via radio", TS: now()}
	f := a.loraFrames(ab, m)[0]
	if f[3] != 'm' || loraHeadLen(f) != 34 {
		t.Fatalf("frame %c", f[3])
	}
	b.loraFrame(f, -90, 5, nil)
	// bericht opgeruimd, frame opnieuw uitgezonden: niet opnieuw bewaard en niet als "gehoord"
	b.st.Messages = nil
	ba.RadioSeen = 0
	b.loraFrame(f, -90, 5, nil)
	if countBody(b, "via radio") != 0 || ba.RadioSeen != 0 {
		t.Fatal("afgespeeld radioframe opnieuw bewaard of gehoord")
	}
	// nog niets bekend over dit contact (geen eerder tijdstip, geen klokverschil): een frame met een
	// tijd 9 dagen terug wordt niet op tijd geweigerd (de klok kan gewoon achterlopen); de gezien-lijst beslist
	x, y := bareNode(t, "X"), bareNode(t, "Y")
	xy := know(x, y, "Y")
	know(y, x, "X")
	sendSkew.Store(-9 * 86400 * 1000)
	old := x.loraFrames(xy, &Message{ID: "b000000000000002", Conv: y.myID, From: "me", Body: "oud radio", TS: now()})[0]
	sendSkew.Store(0)
	y.loraFrame(old, -90, 5, nil)
	if countBody(y, "oud radio") != 1 {
		t.Fatal("frame van een zender met achterlopende klok geweigerd")
	}
	// met een recent gemeten klokverschil (~0): een frame dat volgens de klok van de afzender
	// 9 dagen oud is, wordt geweigerd
	c, d := bareNode(t, "Carla"), bareNode(t, "Dirk")
	cd := know(c, d, "Dirk")
	know(d, c, "Carla")
	sendSkew.Store(-9 * 86400 * 1000)
	old2 := c.loraFrames(cd, &Message{ID: "b000000000000003", Conv: d.myID, From: "me", Body: "echt oud", TS: now()})[0]
	sendSkew.Store(0)
	c.tsLast.Store(0)
	d.handle(pingPkt(c, cd), udp(peerAddr), false)
	d.loraFrame(old2, -90, 5, nil)
	if countBody(d, "echt oud") != 0 {
		t.Fatal("9 dagen oud frame aanvaard ondanks bekend klokverschil")
	}
	// oud formaat (zonder tijd) van een contact dat tijd meestuurt: geweigerd
	ab.PeerVer = "1.1"
	legacy := a.loraFrames(ab, &Message{ID: "b000000000000004", Conv: b.myID, From: "me", Body: "zonder tijd", TS: now()})[0]
	if legacy[3] != 'M' {
		t.Fatalf("v1.1-frame %c", legacy[3])
	}
	b.loraFrame(legacy, -90, 5, nil)
	if countBody(b, "zonder tijd") != 0 {
		t.Fatal("frame zonder tijd aanvaard van een contact dat tijd meestuurt")
	}
	// van een echt v1.1-contact: aanvaard, één keer
	ba.SendsTS = false
	b.loraFrame(legacy, -90, 5, nil)
	b.loraFrame(legacy, -90, 5, nil)
	if countBody(b, "zonder tijd") != 1 {
		t.Fatalf("v1.1-frame %d keer", countBody(b, "zonder tijd"))
	}
}

func TestPendingNewRateAndGroupCap(t *testing.T) {
	n := bareNode(t, "Anna")
	var last Card
	for i := 0; i < 30; i++ {
		c := strangerCard(t, fmt.Sprint("spam", i))
		last = c
		n.mu.Lock()
		n.onHello(c.E, helloMsg{Card: c}, udp(fmt.Sprintf("[2001:db8:%x::1]:47474", i+1)))
		n.mu.Unlock()
	}
	if len(n.st.Pending) != pendNewPerMin {
		t.Fatalf("%d nieuwe verzoeken in één minuut", len(n.st.Pending))
	}
	if n.st.Pending[last.E] != nil {
		t.Error("nieuw verzoek boven de limiet niet weggegooid")
	}
	// verzoeken uit groepskaarten: eigen maximum, verdringen de andere niet
	for i := 0; i < pendGroupMax+5; i++ {
		c := strangerCard(t, "groep")
		n.mu.Lock()
		n.addPending(c, "groep", "")
		n.mu.Unlock()
	}
	grp := 0
	for _, p := range n.st.Pending {
		if p.Source == "groep" {
			grp++
		}
	}
	if grp != pendGroupMax || len(n.st.Pending) != pendNewPerMin+pendGroupMax {
		t.Fatalf("groep %d, totaal %d", grp, len(n.st.Pending))
	}
}

func httptestLocal() *http.Request {
	r, _ := http.NewRequest("GET", "http://localhost:8474/api/state", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	return r
}

// Opgenomen SOS van 10 dagen oud, later opnieuw afgespeeld, ook als de gezien-lijst het niet meer kent:
// (c) opstart gekend, (d) zender intussen 8x herstart (opstart vergeten), (e) radio, (f) radio en
// contact > 30 min stil, (g) IP, opstart vergeten en contact > 30 min stil. Allemaal geweigerd.
func TestReplayOldSOSAfterSeenListLoss(t *testing.T) {
	defer sendSkew.Store(0)
	a, b := bareNode(t, "A"), bareNode(t, "B")
	ab := know(a, b, "B")
	know(b, a, "A")
	day := int64(86400 * 1000)
	src := udp("[2001:db8:1::5]:47474")
	attacker := udp("[2001:db8:66::6]:47474")
	// 10 dagen geleden: SOS over IP en radio, opgenomen door een aanvaller
	sendSkew.Store(-10 * day)
	recSOS := sealed(a, ab, wire{T: "msg", ID: "ee00000000000001", Ch: "alle", Body: "OUD SOS", Sos: true})
	recFrame := a.loraFrames(ab, &Message{ID: "ee00000000000002", Conv: "alle", From: "me", Body: "OUD RADIO SOS", TS: now(), Sos: true})[0]
	b.handle(recSOS, src, false)
	b.mu.Lock()
	b.loraFrame(recFrame, -90, 5, nil)
	b.mu.Unlock()
	sendSkew.Store(0)
	b.handle(pingPkt(a, ab), src, false) // vandaag: dezelfde opstart pingt nog
	c := b.st.Contacts[a.myID]
	clear := func() {
		b.mu.Lock()
		for k := range b.seenMsg {
			delete(b.seenMsg, k)
		}
		b.st.Messages = nil
		b.st.IncomingSos = nil
		b.mu.Unlock()
	}
	check := func(what, body string) {
		t.Helper()
		if k := countBody(b, body); k != 0 || len(b.st.IncomingSos) != 0 {
			t.Errorf("%s: %d keer aanvaard, %d SOS actief", what, k, len(b.st.IncomingSos))
		}
	}
	clear()
	b.handle(recSOS, attacker, false)
	check("(c) opstart gekend", "OUD SOS")
	for i := 0; i < maxBoots; i++ { // zender herstart 8 keer: de oude opstart wordt vergeten
		a.mu.Lock()
		a.bootID = newBootID()
		a.mu.Unlock()
		b.handle(pingPkt(a, ab), src, false)
		for k, v := range c.Boots {
			if k != a.bootID {
				v.At--
			}
		}
	}
	if len(c.Boots) != maxBoots {
		t.Fatalf("%d opstarten bewaard", len(c.Boots))
	}
	clear()
	b.handle(recSOS, attacker, false)
	check("(d) opstart vergeten", "OUD SOS")
	clear()
	b.mu.Lock()
	b.loraFrame(recFrame, -90, 5, nil)
	b.mu.Unlock()
	check("(e) radio", "OUD RADIO SOS")
	clear()
	b.mu.Lock()
	c.SkewAt -= 1900
	c.RadioOffAt = 0
	b.loraFrame(recFrame, -90, 5, nil)
	b.mu.Unlock()
	check("(f) radio, contact > 30 min stil", "OUD RADIO SOS")
	clear()
	b.handle(recSOS, attacker, false)
	check("(g) IP, opstart vergeten, contact > 30 min stil", "OUD SOS")
	// ook na een herstart van de ontvanger (MaxTS en klokverschil zijn bewaard)
	b2 := restart(t, b)
	b2.mu.Lock()
	for k := range b2.seenMsg {
		delete(b2.seenMsg, k)
	}
	b2.mu.Unlock()
	b2.handle(recSOS, attacker, false)
	b2.mu.Lock()
	b2.loraFrame(recFrame, -90, 5, nil)
	b2.mu.Unlock()
	if len(b2.st.IncomingSos) != 0 || countBody(b2, "OUD SOS") != 0 || countBody(b2, "OUD RADIO SOS") != 0 {
		t.Error("na herstart van de ontvanger: oude SOS aanvaard")
	}
}

// Een Pi die herstart met een klok 1 of 7 dagen terug (< 8 dagen) werkt gewoon, over IP en radio.
func TestPiRestartClockDaysBack(t *testing.T) {
	defer sendSkew.Store(0)
	for _, days := range []int64{1, 7} {
		a, b := bareNode(t, "Pi"), bareNode(t, "B")
		ab := know(a, b, "B")
		ba := know(b, a, "Pi")
		b.handle(pingPkt(a, ab), udp(peerAddr), false)
		b.handle(msgPkt(a, ab, "f000000000000001", "voor"), udp(peerAddr), false)
		a2 := restart(t, a)
		ab2 := a2.st.Contacts[b.myID]
		sendSkew.Store(-days * 86400 * 1000)
		m := msgPkt(a2, ab2, "f000000000000002", "na herstart") // bericht vóór de eerste ping
		sos := sealed(a2, ab2, wire{T: "msg", ID: "f000000000000003", Ch: "alle", Body: "Pi heeft hulp nodig.", Sos: true})
		f := a2.loraFrames(ab2, &Message{ID: "f000000000000004", Conv: b.myID, From: "me", Body: "radio na herstart", TS: now()})[0]
		p := pingPkt(a2, ab2)
		sendSkew.Store(0)
		ba.LastSeen = 0
		b.handle(m, udp(peerAddr), false)
		b.handle(sos, udp(peerAddr), false)
		b.mu.Lock()
		b.loraFrame(f, -90, 5, nil)
		b.mu.Unlock()
		b.handle(p, udp(peerAddr), false)
		if countBody(b, "na herstart") != 1 || len(b.st.IncomingSos) != 1 || countBody(b, "radio na herstart") != 1 || !b.ipOnline(ba) {
			t.Errorf("klok %d dagen terug: bericht %d, SOS %d, radio %d, online %v", days,
				countBody(b, "na herstart"), len(b.st.IncomingSos), countBody(b, "radio na herstart"), b.ipOnline(ba))
		}
	}
}
