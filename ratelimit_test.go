package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"testing"
)

// strangerCard: een geldige, ondertekende kaart van een onbekende.
func strangerCard(t *testing.T, name string) Card {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	xk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c := Card{N: name, E: b64.EncodeToString(pub), X: b64.EncodeToString(xk.PublicKey().Bytes()), A: []string{"[2001:db8::1]:47474"}, TS: 1}
	c.S = b64.EncodeToString(ed25519.Sign(priv, c.signBytes()))
	return c
}

func helloRaw(c Card) []byte {
	j, _ := json.Marshal(helloMsg{Card: c})
	return j
}

func udp(s string) *net.UDPAddr { a, _ := net.ResolveUDPAddr("udp", s); return a }

func countPrefix(n *Node, prefix string) int {
	k := 0
	for _, p := range n.st.Pending {
		if p.Prefix == prefix {
			k++
		}
	}
	return k
}

func TestPendingLimitPerSource(t *testing.T) {
	n := bareNode(t, "Anna")
	var cards []Card
	for i := 0; i < 5; i++ {
		c := strangerCard(t, fmt.Sprintf("Vreemde %d", i))
		cards = append(cards, c)
		n.mu.Lock()
		n.onHello(c.E, helloMsg{Card: c}, udp("[2001:db8:5:6::"+fmt.Sprint(i+1)+"]:47474"), false)
		n.st.Pending[c.E].Seen = now() - int64(100-i) // oplopend: de laatste is de nieuwste
		n.mu.Unlock()
	}
	pre := srcPrefix(net.ParseIP("2001:db8:5:6::99"))
	if k := countPrefix(n, pre); k != pendPerSrc {
		t.Fatalf("per /64: %d verzoeken, verwacht %d", k, pendPerSrc)
	}
	if n.st.Pending[cards[4].E] == nil || n.st.Pending[cards[0].E] != nil {
		t.Error("niet de oudste verwijderd")
	}
	// ander /64 telt apart
	c := strangerCard(t, "Ander net")
	n.mu.Lock()
	n.onHello(c.E, helloMsg{Card: c}, udp("[2001:db8:5:7::1]:47474"), false)
	n.mu.Unlock()
	if n.st.Pending[c.E] == nil {
		t.Error("ander /64 geweigerd")
	}
	// IPv4: per adres
	for i := 0; i < 4; i++ {
		c := strangerCard(t, "v4")
		n.mu.Lock()
		n.onHello(c.E, helloMsg{Card: c}, udp("192.168.50.77:47474"), true)
		n.mu.Unlock()
	}
	if k := countPrefix(n, "192.168.50.77"); k != pendPerSrc {
		t.Errorf("per IPv4-adres: %d", k)
	}
}

func TestPendingLimitTotalDropsOldest(t *testing.T) {
	n := bareNode(t, "Anna")
	var first Card
	for i := 0; i < pendMax+10; i++ {
		c := strangerCard(t, fmt.Sprintf("V%d", i))
		if i == 0 {
			first = c
		}
		n.mu.Lock()
		n.onHello(c.E, helloMsg{Card: c}, udp(fmt.Sprintf("[2001:db8:%x::1]:47474", i+1)), false)
		n.st.Pending[c.E].Seen = now() - int64(1000-i)
		n.mu.Unlock()
	}
	if len(n.st.Pending) != pendMax {
		t.Fatalf("%d verzoeken, verwacht %d", len(n.st.Pending), pendMax)
	}
	if n.st.Pending[first.E] != nil {
		t.Error("oudste verzoek niet verwijderd")
	}
}

func TestHelloRateLimited(t *testing.T) {
	l := newRateLim(20, 4)
	ok := 0
	for i := 0; i < 100; i++ {
		if l.allow("pfx") {
			ok++
		}
	}
	if ok != 8 { // burst = 2 x 4
		t.Errorf("per bron: %d doorgelaten", ok)
	}
	l = newRateLim(20, 4)
	ok = 0
	for i := 0; i < 200; i++ {
		if l.allow(fmt.Sprint("p", i)) {
			ok++
		}
	}
	if ok != 40 { // burst = 2 x 20
		t.Errorf("globaal: %d doorgelaten", ok)
	}

	// echte hello's van één /64: na de emmer worden ze niet meer verwerkt (geen handtekening, geen verzoek)
	n := bareNode(t, "Anna")
	for i := 0; i < 30; i++ {
		c := strangerCard(t, "spam")
		n.handleHello(c.E, helloRaw(c), udp("[2001:db8:77:1::5]:47474"), false)
	}
	if len(n.st.Pending) > pendPerSrc {
		t.Errorf("%d verzoeken van één bron", len(n.st.Pending))
	}
	// een ongeldige handtekening geeft geen verzoek
	c := strangerCard(t, "vals")
	c.N = "anders"
	n.handleHello(c.E, helloRaw(c), udp("192.168.50.9:47474"), true)
	if n.st.Pending[c.E] != nil {
		t.Error("vervalste kaart aanvaard")
	}
	// een bekende kaart zonder nieuwe versie kost niets (en verandert niets)
	b := bareNode(t, "Bert")
	know(n, b, "Bert")
	n.handleHello(b.myID, helloRaw(b.myCard()), udp("192.168.50.9:47474"), true)
}
