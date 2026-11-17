package main

import (
	"encoding/json"
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

func msgPkt(a *Node, c *Contact, id, body string) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sealJSON(c, wire{T: "msg", ID: id, Ch: "dm", Body: body})
}

// legacyPkt: zoals een v1.1-peer: zonder ts.
func legacyPkt(a *Node, c *Contact, w wire) []byte {
	j, _ := json.Marshal(w)
	return a.seal('E', c, j)
}

const peerAddr = "[2001:db8:10::1]:47474"

func TestReplayIPMessages(t *testing.T) {
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

	// te oud (9 dagen) en te ver in de toekomst (11 min): geweigerd; 5 min vooruit: aanvaard
	sendSkew.Store(-9 * 86400 * 1000)
	old := msgPkt(a, ab, "a000000000000002", "oud")
	sendSkew.Store(11 * 60 * 1000)
	fut := msgPkt(a, ab, "a000000000000003", "toekomst")
	sendSkew.Store(5 * 60 * 1000)
	ok := msgPkt(a, ab, "a000000000000004", "bijna nu")
	sendSkew.Store(0)
	for _, x := range [][]byte{old, fut, ok} {
		b.handle(x, udp(peerAddr), false)
	}
	if countBody(b, "oud") != 0 || countBody(b, "toekomst") != 0 || countBody(b, "bijna nu") != 1 {
		t.Fatalf("tijdvenster: oud %d, toekomst %d, bijna nu %d", countBody(b, "oud"), countBody(b, "toekomst"), countBody(b, "bijna nu"))
	}

	// de gezien-lijst blijft bewaard over een herstart, ook als het bericht zelf al opgeruimd is
	b.mu.Lock()
	b.st.Messages = nil
	b.dirty = true
	b.mu.Unlock()
	b.save()
	b.saveSeen(true)
	b2, err := loadNode(b.dir, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	b2.handle(p, udp(peerAddr), false)
	if countBody(b2, "eerste") != 0 {
		t.Fatal("na herstart opnieuw afgespeeld bericht aanvaard")
	}
	b2.mu.Lock()
	if !b2.isSeen(a.myID+"|a000000000000001") || b2.seenMsg[a.myID+"|a000000000000001"] < now()+8*86400 {
		t.Error("vervaltijd gezien-lijst niet ~9 dagen")
	}
	b2.mu.Unlock()
}

func TestReplayObservedAddress(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")
	ping := func() []byte {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.sealJSON(ab, a.pingWire("ping"))
	}
	// oude (5 min) ping vanaf een nieuw adres: geen adres, niet "online"
	sendSkew.Store(-5 * 60 * 1000)
	stale := ping()
	sendSkew.Store(0)
	b.handle(stale, udp("[2001:db8:66::6]:40000"), false)
	if len(ba.Observed) != 0 || ba.LastSeen != 0 {
		t.Fatalf("oude ping telde mee: %v %d", ba.Observed, ba.LastSeen)
	}
	// verse ping: adres toegevoegd
	b.handle(ping(), udp(peerAddr), false)
	if _, ok := ba.Observed[udp(peerAddr).String()]; !ok || ba.LastSeen == 0 {
		t.Fatalf("verse ping: %v", ba.Observed)
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
	ba := b.st.Contacts[a.myID]
	b.onGroupCard(ba, &first, func(wire) {})
	if b.st.Groups[g.ID] == nil {
		t.Fatal("groep niet aangemaakt")
	}
	// Bert wordt uit de groep gehaald (nieuwe versie zonder hem)
	time.Sleep(1100 * time.Millisecond)
	if _, err := a.groupAction(groupIn{Action: "update", ID: g.ID, Members: &[]string{c.myID}}); err != nil {
		t.Fatal(err)
	}
	kick := wire{T: "grp", Grp: a.groupWire(g), Part: 0, Parts: 1, Ver: g.Ver}
	b.onGroupCard(ba, &kick, func(wire) {})
	if b.st.Groups[g.ID] != nil {
		t.Fatal("niet uit de groep gehaald")
	}
	// de oude groepskaart opnieuw afgespeeld: groep komt niet terug, wel bevestigd
	var rep []wire
	b.onGroupCard(ba, &first, func(w wire) { rep = append(rep, w) })
	if b.st.Groups[g.ID] != nil {
		t.Fatal("afgespeelde groepskaart zette de groep terug")
	}
	if len(rep) != 1 || rep[0].T != "grpack" {
		t.Fatalf("antwoord: %+v", rep)
	}
	// en een groepskaart van 9 dagen oud over IP wordt al bij de tijdcontrole geweigerd
	sendSkew.Store(-9 * 86400 * 1000)
	a.mu.Lock()
	old := a.sealJSON(a.st.Contacts[b.myID], wire{T: "grp", Grp: &grpWire{ID: "00000000000000cc", Name: "Oud", Owner: a.myID, Ver: 1, Members: []string{a.myID, b.myID}}, Part: 0, Parts: 1, Ver: 1})
	a.mu.Unlock()
	sendSkew.Store(0)
	b.handle(old, udp(peerAddr), false)
	if b.st.Groups["00000000000000cc"] != nil {
		t.Fatal("oude groepskaart aanvaard")
	}
}

func TestReplayLoRaFrames(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")
	m := &Message{ID: "b000000000000001", Conv: b.myID, From: "me", Body: "via radio", TS: now()}
	f := a.loraFrames(ab, m)[0]
	if f[3] != 'm' || loraHeadLen(f) != 34 {
		t.Fatalf("frame %c", f[3])
	}
	b.loraFrame(f, -90, 5, nil)
	// bericht opgeruimd, frame opnieuw uitgezonden: niet opnieuw bewaard
	b.st.Messages = nil
	b.loraFrame(f, -90, 5, nil)
	if countBody(b, "via radio") != 0 {
		t.Fatal("afgespeeld radioframe opnieuw bewaard")
	}
	// 9 dagen oud: geweigerd
	sendSkew.Store(-9 * 86400 * 1000)
	old := a.loraFrames(ab, &Message{ID: "b000000000000002", Conv: b.myID, From: "me", Body: "oud radio", TS: now()})[0]
	sendSkew.Store(-2 * 3600 * 1000)
	hourOld := a.loraFrames(ab, &Message{ID: "b000000000000003", Conv: b.myID, From: "me", Body: "uur oud", TS: now()})[0]
	sendSkew.Store(0)
	b.loraFrame(old, -90, 5, nil)
	if countBody(b, "oud radio") != 0 {
		t.Fatal("oud radioframe aanvaard")
	}
	// 2 uur oud: wel bewaard (nooit gezien), maar niet als "gehoord via radio"
	ba.RadioSeen = 0
	b.loraFrame(hourOld, -90, 5, nil)
	if countBody(b, "uur oud") != 1 || ba.RadioSeen != 0 {
		t.Fatalf("2 uur oud frame: %d, gehoord %d", countBody(b, "uur oud"), ba.RadioSeen)
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
