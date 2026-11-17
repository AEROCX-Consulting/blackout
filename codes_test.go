package main

import (
	"strings"
	"testing"
)

func TestCardCodes(t *testing.T) {
	a := bareNode(t, "Anna")
	a.myAddrs = []string{"[2a0d:3344:1::5]:47474", "192.168.1.10:47474"}
	card := a.myCard()

	// nieuwe korte code
	code := cardCode(card)
	if !strings.HasPrefix(code, "AXB2:") {
		t.Fatal(code)
	}
	got, err := parseCardText(code)
	if err != nil || got.E != card.E || got.N != "Anna" || len(got.A) != 2 {
		t.Fatalf("v2: %v %+v", err, got)
	}
	// met spaties/regeleinden en tekst ervoor
	if _, err := parseCardText("Mijn code:\n" + code[:20] + "\n " + code[20:]); err != nil {
		t.Fatal(err)
	}
	// oude lange code blijft werken
	got, err = parseCardText(cardText(card))
	if err != nil || got.E != card.E {
		t.Fatalf("v1: %v", err)
	}
	// beschadigd
	if _, err := parseCardText(code[:len(code)-6]); err == nil {
		t.Fatal("afgekapte code aanvaard")
	}
	if _, err := parseCardText("hallo"); err == nil {
		t.Fatal("geen code aanvaard")
	}
	// QR
	if png, err := qrPNG(code, 4); err != nil || len(png) < 100 {
		t.Fatal(err)
	}
}

func TestInviteCode(t *testing.T) {
	a := bareNode(t, "Anna")
	inv, err := a.makeInvite("Carla", "lezer", nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	code := a.inviteCode(inv)
	if !strings.HasPrefix(code, "AXB2I:") {
		t.Fatal(code)
	}
	card, ref, err := parseAnyCode(code)
	if err != nil || ref == nil || ref.ID != inv.ID || card.E != a.myID {
		t.Fatalf("%v %+v", err, ref)
	}
	// parseCardText geeft gewoon de kaart
	if c, err := parseCardText(code); err != nil || c.E != a.myID {
		t.Fatal(err)
	}
	// vervalst ID -> handtekening klopt niet
	raw, _ := b64.DecodeString(strings.TrimPrefix(code, "AXB2I:"))
	raw[len(raw)-64-4-1] ^= 1
	if _, _, err := parseAnyCode("AXB2I:" + b64.EncodeToString(raw)); err == nil {
		t.Fatal("vervalste uitnodiging aanvaard")
	}
	// verlopen
	inv.Exp = now() - 10
	inv.Sig = b64.EncodeToString(signWith(a, inviteSignBytes(inv.ID, inv.Exp)))
	if _, _, err := parseAnyCode(a.inviteCode(inv)); err == nil || !strings.Contains(err.Error(), "verlopen") {
		t.Fatalf("verlopen uitnodiging: %v", err)
	}
}

func TestInviteHandshake(t *testing.T) {
	a := bareNode(t, "Anna")
	c := bareNode(t, "Carla")
	b := bareNode(t, "Bert")
	know(a, b, "Bert")
	g, err := a.groupAction(groupIn{Action: "create", Name: "Buurt", Members: &[]string{b.myID}})
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := a.makeInvite("Carla", "lezer", []string{g.ID}, 7)
	card, ref, err := parseAnyCode(a.inviteCode(inv))
	if err != nil {
		t.Fatal(err)
	}
	// Carla voegt de code toe; haar hello draagt het versleutelde uitnodigings-ID
	ca := &Contact{ID: card.E, Name: "Anna", Card: card, Observed: map[string]int64{}, Role: "lid", Invite: ref.ID}
	c.st.Contacts[card.E] = ca
	hello := c.helloFor(ca)
	var h helloMsg
	if err := jsonUnmarshal(hello[36:], &h); err != nil || h.Inv == "" {
		t.Fatal("geen uitnodiging in hello")
	}
	if !a.tryInvite(h.Card, h.Inv) {
		t.Fatal("uitnodiging niet aanvaard")
	}
	cc := a.st.Contacts[c.myID]
	if cc == nil || cc.Role != "lezer" || cc.Name != "Carla" {
		t.Fatalf("contact: %+v", cc)
	}
	if !g.has(c.myID) || g.role(c.myID) != "lezer" {
		t.Fatal("niet in groep gezet")
	}
	if !inv.Used {
		t.Fatal("niet als gebruikt gemarkeerd")
	}
	// eenmalig
	delete(a.st.Contacts, c.myID)
	if a.tryInvite(h.Card, h.Inv) {
		t.Fatal("uitnodiging twee keer gebruikt")
	}
	// een vreemde kan het ID niet hergebruiken (andere sleutel)
	x := bareNode(t, "Xavier")
	inv2, _ := a.makeInvite("", "lid", nil, 7)
	ca.Invite = inv2.ID
	h2 := helloMsg{}
	jsonUnmarshal(c.helloFor(ca)[36:], &h2)
	if a.tryInvite(x.myCard(), h2.Inv) {
		t.Fatal("uitnodiging met andere sleutel aanvaard")
	}
}
