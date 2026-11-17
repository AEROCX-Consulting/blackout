package main

import "testing"

// deliverGroup stuurt de groepskaart van de eigenaar "met de hand" naar een lid en geeft de antwoorden.
func deliverGroup(owner, member *Node, g *Group) []wire {
	ownerAtMember := member.st.Contacts[owner.myID]
	parts := owner.groupParts(g, member.myID)
	var replies []wire
	for i, cards := range parts {
		m := wire{T: "grp", Grp: owner.groupWire(g), Cards: cards, Part: i, Parts: len(parts), Ver: g.Ver}
		member.onGroupCard(ownerAtMember, &m, func(w wire) { replies = append(replies, w) })
	}
	return replies
}

func TestGroupCard(t *testing.T) {
	a, b, c := bareNode(t, "Anna"), bareNode(t, "Bert"), bareNode(t, "Carla")
	know(a, b, "Bert")
	know(a, c, "Carla")
	know(b, a, "Anna").Role = "beheerder" // eigenaar is beheerder bij mij: leden worden meteen contact
	know(c, a, "Anna").Role = "beheerder"

	g, err := a.groupAction(groupIn{Action: "create", Name: "Buurt", Members: &[]string{b.myID, c.myID}, Roles: map[string]string{c.myID: "lezer"}})
	if err != nil {
		t.Fatal(err)
	}
	rep := deliverGroup(a, b, g)
	if len(rep) != 1 || rep[0].T != "grpack" || rep[0].Ver != g.Ver {
		t.Fatalf("antwoord: %+v", rep)
	}
	bg := b.st.Groups[g.ID]
	if bg == nil || bg.Name != "Buurt" || !bg.has(c.myID) || bg.role(c.myID) != "lezer" || bg.Owner != a.myID {
		t.Fatalf("groep bij Bert: %+v", bg)
	}
	// Bert kende Carla niet: voorgesteld via de groep
	bc := b.st.Contacts[c.myID]
	if bc == nil || bc.IntroducedBy != "Buurt" || bc.Name != "Carla" {
		t.Fatalf("voorgesteld contact: %+v", bc)
	}
	// eigenaar verwerkt de bevestiging
	ab := a.st.Contacts[b.myID]
	a.onGroupAck(ab, &rep[0])
	if g.Acked[b.myID] != g.Ver {
		t.Fatal("bevestiging niet verwerkt")
	}

	// lezer in de groep: berichten van Carla worden genegeerd (maar wel bevestigd)
	deliverGroup(a, c, g)
	if !b.deliverMsg(bc, inMsg{ID: "00000000000000c1", Ch: "g:" + g.ID, Body: "hallo", Via: "lan"}) {
		t.Fatal("lezer-bericht niet bevestigd")
	}
	for _, m := range b.st.Messages {
		if m.ID == "00000000000000c1" {
			t.Fatal("bericht van lezer bewaard")
		}
	}
	// gewoon lid wel
	ba := b.st.Contacts[a.myID]
	if !b.deliverMsg(ba, inMsg{ID: "00000000000000a1", Ch: "g:" + g.ID, Body: "welkom", Via: "lan"}) || bg.Unread != 1 {
		t.Fatal("groepsbericht niet afgeleverd")
	}
	// onbekende groep: niet bevestigen (wacht op de groepskaart)
	if b.deliverMsg(ba, inMsg{ID: "00000000000000a2", Ch: "g:ffffffffffffffff", Body: "x"}) {
		t.Fatal("bericht voor onbekende groep bevestigd")
	}

	// alleen de eigenaar mag de kaart sturen
	m := wire{T: "grp", Grp: &grpWire{ID: g.ID, Name: "Gekaapt", Owner: c.myID, Ver: g.Ver + 5, Members: []string{c.myID, b.myID}}, Parts: 1}
	b.onGroupCard(bc, &m, func(wire) {})
	if bg.Name != "Buurt" {
		t.Fatal("niet-eigenaar kon groep wijzigen")
	}

	// oudere versie wordt genegeerd
	old := g.Ver
	g.Name = "Nieuw"
	a.groupPublish(g)
	deliverGroup(a, b, g)
	if bg.Name != "Nieuw" || bg.Ver != g.Ver {
		t.Fatal("update niet verwerkt")
	}
	m = wire{T: "grp", Grp: &grpWire{ID: g.ID, Name: "Oud", Owner: a.myID, Ver: old, Members: g.Members}, Parts: 1}
	b.onGroupCard(ba, &m, func(wire) {})
	if bg.Name != "Nieuw" {
		t.Fatal("oude versie overschreef nieuwe")
	}

	// Bert uit de groep halen
	if _, err := a.groupAction(groupIn{Action: "update", ID: g.ID, Members: &[]string{c.myID}}); err != nil {
		t.Fatal(err)
	}
	if !contains(g.Kicked, b.myID) {
		t.Fatal("verwijderd lid moet het nog horen")
	}
	deliverGroup(a, b, g)
	if b.st.Groups[g.ID] != nil {
		t.Fatal("groep niet weg bij verwijderd lid")
	}

	// Carla verlaat de groep
	if _, err := c.groupAction(groupIn{Action: "leave", ID: g.ID}); err != nil {
		t.Fatal(err)
	}
	if c.st.Groups[g.ID].LeftAt == 0 {
		t.Fatal("niet als verlaten gemarkeerd")
	}
	var r []wire
	a.onGroupLeave(a.st.Contacts[c.myID], &wire{ID: g.ID}, func(w wire) { r = append(r, w) })
	if g.has(c.myID) || len(r) != 1 || r[0].T != "grpleft" {
		t.Fatalf("verlaten niet verwerkt: %+v", r)
	}
	c.onGroupLeft(c.st.Contacts[a.myID], &r[0])
	if c.st.Groups[g.ID] != nil || c.st.Left[g.ID] == 0 {
		t.Fatal("groep niet opgeruimd na grpleft")
	}
	// na verlaten: nieuwe kaart -> opnieuw "grpleave", niet opnieuw lid
	r = nil
	deliverGroupTo := wire{T: "grp", Grp: a.groupWire(g), Parts: 1}
	deliverGroupTo.Grp.Members = append(deliverGroupTo.Grp.Members, c.myID)
	c.onGroupCard(c.st.Contacts[a.myID], &deliverGroupTo, func(w wire) { r = append(r, w) })
	if c.st.Groups[g.ID] != nil || len(r) != 1 || r[0].T != "grpleave" {
		t.Fatal("verlaten groep kwam terug")
	}

	// eigenaar heft de groep op
	know(a, b, "Bert")
	g2, _ := a.groupAction(groupIn{Action: "create", Name: "Familie", Members: &[]string{b.myID}})
	deliverGroup(a, b, g2)
	if b.st.Groups[g2.ID] == nil {
		t.Fatal("tweede groep niet aangekomen")
	}
	a.groupAction(groupIn{Action: "delete", ID: g2.ID})
	if g2.visible() {
		t.Fatal("opgeheven groep nog zichtbaar")
	}
	deliverGroup(a, b, g2)
	if b.st.Groups[g2.ID] != nil {
		t.Fatal("opgeheven groep niet weg bij lid")
	}
}

func TestGroupPermsAndBlock(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	know(a, b, "Bert")
	ba := know(b, a, "Anna")
	// Anna is "lezer" bij Bert: lezers mogen geen groepen maken -> uitnodiging genegeerd
	ba.Role = "lezer"
	g, _ := a.groupAction(groupIn{Action: "create", Name: "X", Members: &[]string{b.myID}})
	deliverGroup(a, b, g)
	if b.st.Groups[g.ID] != nil {
		t.Fatal("lezer kon groep maken")
	}
	// lezer: rechtstreekse berichten genegeerd, SOS komt wel door
	if !b.deliverMsg(ba, inMsg{ID: "0000000000000001", Ch: "dm", Body: "hoi"}) {
		t.Fatal("niet bevestigd")
	}
	if !b.deliverMsg(ba, inMsg{ID: "0000000000000002", Ch: "alle", Body: "help", Sos: true}) {
		t.Fatal("SOS niet bevestigd")
	}
	cnt := 0
	for _, m := range b.st.Messages {
		if m.From == a.myID {
			cnt++
			if !m.Sos {
				t.Fatal("gewoon bericht van lezer bewaard")
			}
		}
	}
	if cnt != 1 || len(b.st.IncomingSos) != 1 {
		t.Fatalf("SOS van lezer: %d %d", cnt, len(b.st.IncomingSos))
	}
	// geblokkeerd: niets
	ba.Role = "lid"
	ba.Blocked = true
	if b.deliverMsg(ba, inMsg{ID: "0000000000000003", Ch: "dm", Body: "hoi"}) {
		t.Fatal("geblokkeerd contact afgeleverd")
	}
	if b.can(ba, "send") {
		t.Fatal("geblokkeerd mag sturen")
	}
	// perms aanpassen: lid mag geen "alle" meer
	ba.Blocked = false
	b.st.Perms["lid"]["alle"] = false
	b.deliverMsg(ba, inMsg{ID: "0000000000000004", Ch: "alle", Body: "aan iedereen"})
	for _, m := range b.st.Messages {
		if m.ID == "0000000000000004" {
			t.Fatal("bericht naar Iedereen ondanks recht uit")
		}
	}
}

// Is de eigenaar bij mij geen beheerder, dan worden onbekende leden een verzoek, geen contact.
func TestGroupCardIntroducesAsRequest(t *testing.T) {
	a, b, c := bareNode(t, "Anna"), bareNode(t, "Bert"), bareNode(t, "Carla")
	know(a, b, "Bert")
	know(a, c, "Carla")
	know(b, a, "Anna") // rol: lid
	g, err := a.groupAction(groupIn{Action: "create", Name: "Straat", Members: &[]string{b.myID, c.myID}})
	if err != nil {
		t.Fatal(err)
	}
	rep := deliverGroup(a, b, g)
	if len(rep) != 1 || rep[0].T != "grpack" {
		t.Fatalf("antwoord: %+v", rep)
	}
	if b.st.Groups[g.ID] == nil {
		t.Fatal("groep niet aangemaakt")
	}
	if b.st.Contacts[c.myID] != nil {
		t.Fatal("onbekend lid werd meteen contact")
	}
	p := b.st.Pending[c.myID]
	if p == nil || p.Source != "groep" || p.Note != "voorgesteld via Straat door Anna" {
		t.Fatalf("verzoek: %+v", p)
	}
}

func TestGroupCardLimits(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	_ = ab
	ba := know(b, a, "Anna")
	ba.Role = "beheerder"
	send := func(gw *grpWire, cards []Card) {
		m := wire{T: "grp", Grp: gw, Cards: cards, Part: 0, Parts: 1, Ver: gw.Ver}
		b.onGroupCard(ba, &m, func(wire) {})
	}
	// ongeldig groeps-ID
	for _, id := range []string{"", "abc", "0123456789abcdeg", "0123456789ABCDEF", "0123456789abcdef00", "../../etc/passwd"} {
		send(&grpWire{ID: id, Name: "X", Owner: a.myID, Ver: 1, Members: []string{a.myID, b.myID}}, nil)
		if len(b.st.Groups) != 0 {
			t.Fatalf("groeps-ID %q aanvaard", id)
		}
	}
	// meer dan 50 leden
	mem := []string{a.myID, b.myID}
	for i := 0; i < groupMaxMembers; i++ {
		mem = append(mem, strangerCard(t, "x").E)
	}
	send(&grpWire{ID: "00000000000000aa", Name: "Groot", Owner: a.myID, Ver: 1, Members: mem}, nil)
	if len(b.st.Groups) != 0 {
		t.Fatal("groep met te veel leden aanvaard")
	}
	// lange naam wordt begrensd zonder UTF-8 te breken; rollen alleen voor leden
	long := ""
	for i := 0; i < 30; i++ {
		long += "é"
	}
	send(&grpWire{ID: "00000000000000ab", Name: long, Owner: a.myID, Ver: 1, Members: []string{a.myID, b.myID},
		Roles: map[string]string{"vreemde": "beheerder", b.myID: "lezer"}}, nil)
	g := b.st.Groups["00000000000000ab"]
	if g == nil || len(g.Name) > 40 || g.Roles["vreemde"] != "" || g.Roles[b.myID] != "lezer" {
		t.Fatalf("groep: %+v", g)
	}
	// hooguit 50 groepen per eigenaar
	for i := 0; i < groupMaxPerOwner+5; i++ {
		send(&grpWire{ID: "1000000000" + hex6(i), Name: "G", Owner: a.myID, Ver: 1, Members: []string{a.myID, b.myID}}, nil)
	}
	cnt := 0
	for _, g := range b.st.Groups {
		if g.Owner == a.myID {
			cnt++
		}
	}
	if cnt != groupMaxPerOwner {
		t.Fatalf("%d groepen van één eigenaar", cnt)
	}
	// lokaal: groep maken met te veel leden geweigerd
	var ids []string
	for i := 0; i < groupMaxMembers; i++ {
		x := bareNode(t, "x")
		know(a, x, "x")
		ids = append(ids, x.myID)
	}
	if _, err := a.groupAction(groupIn{Action: "create", Name: "Te groot", Members: &ids}); err == nil {
		t.Fatal("groep met 51 leden gemaakt")
	}
}

func hex6(i int) string {
	const h = "0123456789abcdef"
	b := make([]byte, 6)
	for k := 5; k >= 0; k-- {
		b[k] = h[i%16]
		i /= 16
	}
	return string(b)
}
