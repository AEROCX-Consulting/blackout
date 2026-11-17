package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type radioCapture struct {
	mu  sync.Mutex
	got [][]byte
}

func (rc *radioCapture) tx(p []byte) { rc.mu.Lock(); rc.got = append(rc.got, p); rc.mu.Unlock() }

func (rc *radioCapture) wait(t *testing.T, n int) [][]byte {
	t.Helper()
	waitFor(t, "radio-frames", 2*time.Second, func() bool { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.got) >= n })
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := rc.got
	rc.got = nil
	return out
}

func lastMsg(n *Node) *Message {
	if len(n.st.Messages) == 0 {
		return nil
	}
	return n.st.Messages[len(n.st.Messages)-1]
}

func TestLoRaFrames(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	ab := know(a, b, "Bert")
	ba := know(b, a, "Anna")

	// 1-op-1, lang bericht in 3 delen, in omgekeerde volgorde aangekomen
	body := strings.Repeat("Stroom is weg hier. ", 25) // 500 bytes
	m := &Message{ID: "0123456789abcdef", Conv: b.myID, From: "me", Body: body, TS: now()}
	fs := a.loraFrames(ab, m)
	if len(fs) != 3 {
		t.Fatalf("%d delen", len(fs))
	}
	for _, f := range fs {
		if len(f) > mtMaxPayload || f[3] != 'm' {
			t.Fatalf("frame %c %d bytes", f[3], len(f))
		}
	}
	for i := len(fs) - 1; i >= 0; i-- {
		b.loraFrame(fs[i], -90, 5, nil)
	}
	got := lastMsg(b)
	if got == nil || got.Body != body || got.Via != "radio" || got.Conv != a.myID {
		t.Fatalf("bericht: %+v", got)
	}
	if ba.RadioSeen == 0 || ba.RadioRSSI != -90 {
		t.Fatal("radio-gegevens niet bijgewerkt")
	}
	// bevestiging 'K'
	a.st.Messages = append(a.st.Messages, &Message{ID: m.ID, Conv: b.myID, From: "me", Body: body, Recips: map[string]bool{b.myID: false}})
	k := b.loraAckFrame(ba, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	a.loraFrame(k, -80, 3, nil)
	if !lastMsg(a).Recips[b.myID] || lastMsg(a).Via != "radio" {
		t.Fatal("bevestiging niet verwerkt")
	}

	// Iedereen 'G' en SOS 'S'
	for _, tc := range []struct {
		m    *Message
		typ  byte
		conv string
		sos  bool
	}{
		{&Message{ID: "1111111111111111", Conv: "alle", From: "me", Body: "Test aan iedereen"}, 'g', "alle", false},
		{&Message{ID: "2222222222222222", Conv: "alle", From: "me", Body: "Anna heeft hulp nodig.", Sos: true}, 's', "alle", true},
		{&Message{ID: "4444444444444444", Conv: b.myID, From: "me", Body: "kijk", Img: "00112233aabbccdd"}, 'm', a.myID, false},
	} {
		fs := a.loraFrames(ab, tc.m)
		if len(fs) != 1 || fs[0][3] != tc.typ {
			t.Fatalf("type %c", fs[0][3])
		}
		b.loraFrame(fs[0], -90, 5, nil)
		got := lastMsg(b)
		if got.ID != tc.m.ID || got.Conv != tc.conv || got.Sos != tc.sos {
			t.Fatalf("%c: %+v", tc.typ, got)
		}
		if tc.m.Img != "" && !strings.HasSuffix(got.Body, photoNote) {
			t.Fatalf("fotomelding ontbreekt: %q", got.Body)
		}
	}
	if len(b.st.IncomingSos) != 1 {
		t.Fatal("SOS via radio niet als incomingSos")
	}

	// groep 'P': groeps-ID zit in de versleutelde inhoud
	g, _ := a.groupAction(groupIn{Action: "create", Name: "Buurt", Members: &[]string{b.myID}})
	deliverGroup(a, b, g)
	gm := &Message{ID: "3333333333333333", Conv: "g:" + g.ID, From: "me", Body: strings.Repeat("x", 300)}
	fs = a.loraFrames(ab, gm)
	if len(fs) != 2 || fs[0][3] != 'p' {
		t.Fatalf("P-frames: %d", len(fs))
	}
	if strings.Contains(string(fs[0]), g.ID) {
		t.Fatal("groeps-ID onversleuteld")
	}
	for _, f := range fs {
		b.loraFrame(f, -90, 5, nil)
	}
	got = lastMsg(b)
	if got.ID != gm.ID || got.Conv != "g:"+g.ID || got.Body != gm.Body {
		t.Fatalf("groepsbericht: %+v", got)
	}
	// een v1.1-ontvanger krijgt een groepsbericht als gewoon 1-op-1 bericht
	ab.PeerVer = "1.1"
	if fs := a.loraFrames(ab, gm); fs[0][3] != 'M' {
		t.Fatal("geen terugval voor v1.1")
	}
	ab.PeerVer = ""

	// vervalst frame (andere sleutel) wordt genegeerd
	x := bareNode(t, "Xavier")
	xb := know(x, b, "Bert")
	fake := x.loraFrames(xb, &Message{ID: "5555555555555555", Conv: b.myID, Body: "nep"})[0]
	copy(fake[4:12], a.id8(a.myID)) // doet zich voor als Anna
	before := len(b.st.Messages)
	b.loraFrame(fake, 0, 0, nil)
	if len(b.st.Messages) != before {
		t.Fatal("vervalst frame aanvaard")
	}
}

func TestLoRaBeaconNoPositionNoReplay(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	know(a, b, "Bert")
	ba := know(b, a, "Anna")
	rc := &radioCapture{}
	a.radio.testTx = rc.tx
	a.st.Share = true
	a.st.Loc = &Pos{Lat: 10.5, Lon: 20.25}
	a.loraBeacon()
	f := rc.wait(t, 1)[0]
	if len(f) != 84 {
		t.Fatalf("baken %d bytes", len(f))
	}
	b.loraFrame(f, -100, 2, nil)
	if ba.RadioSeen == 0 || ba.Pos != nil {
		t.Fatalf("baken: gezien %d, positie %+v", ba.RadioSeen, ba.Pos)
	}
	// hetzelfde baken opnieuw uitgezonden: niet opnieuw "gehoord"
	ba.RadioSeen = 0
	b.loraFrame(f, -100, 2, nil)
	if ba.RadioSeen != 0 {
		t.Fatal("herhaald baken aanvaard")
	}
	// een volgend baken wel
	a.loraBeacon()
	f2 := rc.wait(t, 1)[0]
	b.loraFrame(f2, -100, 2, nil)
	if ba.RadioSeen == 0 {
		t.Fatal("volgend baken geweigerd")
	}
	// baken van 20 minuten geleden: genegeerd
	sendSkew.Store(-20 * 60 * 1000)
	a.loraBeacon()
	sendSkew.Store(0)
	old := rc.wait(t, 1)[0]
	ba.RadioSeen = 0
	delete(b.beaconLast, a.myID)
	b.loraFrame(old, -100, 2, nil)
	if ba.RadioSeen != 0 {
		t.Fatal("oud baken aanvaard")
	}
	// vervalst baken: handtekening klopt niet
	f3 := append([]byte{}, f2...)
	f3[17] ^= 1
	delete(b.beaconLast, a.myID)
	b.loraFrame(f3, 0, 0, nil)
	if ba.RadioSeen != 0 {
		t.Fatal("vervalst baken aanvaard")
	}
}

// Brug 'L': een brug zendt frames uit voor een contact, met rechten en controle van de afzender.
func TestBridgeFrames(t *testing.T) {
	a, br, c := bareNode(t, "Anna"), bareNode(t, "Brug"), bareNode(t, "Carla")
	ac := know(a, c, "Carla")
	know(a, br, "Brug")
	bra := know(br, a, "Anna")
	know(br, c, "Carla")
	know(c, a, "Anna")
	rc := &radioCapture{}
	br.radio.testTx = rc.tx

	m := &Message{ID: "abcdefabcdefabcd", Conv: c.myID, From: "me", Body: "via de brug"}
	f := a.loraFrames(ac, m)[0]
	br.onBridgeFrame(bra, f)
	out := rc.wait(t, 1)
	c.loraFrame(out[0], -95, 3, nil)
	if got := lastMsg(c); got == nil || got.Body != "via de brug" {
		t.Fatal("niet aangekomen via brug")
	}
	// hetzelfde frame niet twee keer uitzenden
	br.onBridgeFrame(bra, f)
	// frame dat niet van de afzender zelf komt: weigeren
	f2 := c.loraFrames(c.st.Contacts[a.myID], &Message{ID: "abcdefabcdefabce", Conv: a.myID, Body: "x"})[0]
	br.onBridgeFrame(bra, f2) // Anna stuurt een frame van Carla door: niet toegestaan
	// geen recht "bridge" voor de rol van Anna
	bra.Role = "lezer"
	br.st.Perms["lezer"]["bridge"] = false
	br.onBridgeFrame(bra, a.loraFrames(ac, &Message{ID: "abcdefabcdefabcf", Conv: c.myID, Body: "y"})[0])
	bra.Role = "lid"
	// brug uit
	br.st.Bridge = false
	br.onBridgeFrame(bra, a.loraFrames(ac, &Message{ID: "abcdefabcdefabd0", Conv: c.myID, Body: "z"})[0])
	time.Sleep(200 * time.Millisecond)
	rc.mu.Lock()
	n := len(rc.got)
	rc.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d frames ten onrechte uitgezonden", n)
	}

	// 'L' voor mij: verwerken als "bridge"
	br.st.Bridge = true
	cbr := know(c, br, "Brug")
	m3 := &Message{ID: "abcdefabcdefabd1", Conv: c.myID, From: "me", Body: "rechtstreeks via L"}
	c.onBridgeFrame(cbr, a.loraFrames(ac, m3)[0])
	if got := lastMsg(c); got.ID != m3.ID || got.Via != "bridge" {
		t.Fatalf("L voor mij: %+v", got)
	}
}
