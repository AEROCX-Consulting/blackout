package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"net/http/httptest"
	"testing"
	"time"
)

func testJPEG(t *testing.T) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 220, 160))
	r := rand.New(rand.NewSource(1))
	for i := range img.Pix {
		img.Pix[i] = uint8(r.Intn(256))
	}
	img.Set(0, 0, color.Black)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 20*1024 || buf.Len() > maxBlob {
		t.Fatalf("test-JPEG %d bytes", buf.Len())
	}
	return buf.Bytes()
}

func findMsg(ms []map[string]any, body string) map[string]any {
	for _, m := range ms {
		if m["body"] == body {
			return m
		}
	}
	return nil
}

// Drie knooppunten op loopback: toevoegen, groep, groepsbericht, SOS + bevestiging, foto, blokkeren.
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integratietest")
	}
	a := liveNode(t, "Anna", nil)
	b := liveNode(t, "Bert", nil)
	c := liveNode(t, "Carla", nil)
	pair(a, b)
	pair(a, c)
	waitFor(t, "A ziet B en C online", 8*time.Second, func() bool { return a.online(b.myID) && a.online(c.myID) })
	waitFor(t, "B en C zien A online", 8*time.Second, func() bool { return b.online(a.myID) && c.online(a.myID) })

	// state volgt het contract
	s := a.state()
	for _, k := range []string{"version", "now", "me", "contacts", "groups", "pending", "alleUnread", "urls", "local", "pin", "radio", "radioSettings",
		"sos", "incomingSos", "policy", "perms", "devices", "invites", "audit", "log", "osint", "autostart", "backup", "bridge", "sdr"} {
		if _, ok := s[k]; !ok {
			t.Errorf("state mist %q", k)
		}
	}
	ct := s["contacts"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "name", "cardName", "online", "via", "lastSeen", "unread", "radioSeen", "radioRssi", "radioSnr", "pos", "role", "blocked", "introducedBy", "route"} {
		if _, ok := ct[k]; !ok {
			t.Errorf("contact mist %q", k)
		}
	}
	if r := ct["route"].(map[string]any); r["k"] != "lan" && r["k"] != "star" {
		t.Errorf("route: %v", r)
	}

	// groep: B en C kennen elkaar niet en worden voorgesteld. Bij C is A beheerder (meteen contact),
	// bij B gewoon lid (B krijgt C als verzoek en laat hem toe).
	c.post("/api/contact", map[string]any{"action": "role", "id": a.myID, "role": "beheerder"})
	res := a.post("/api/group", map[string]any{"action": "create", "name": "Buurt", "members": []string{b.myID, c.myID}})
	gid := res["id"].(string)
	conv := "g:" + gid
	waitFor(t, "verzoek van C bij B", 5*time.Second, func() bool {
		ok := false
		b.lock(func() {
			p := b.st.Pending[c.myID]
			ok = p != nil && p.Source == "groep" && b.st.Contacts[c.myID] == nil
		})
		return ok
	})
	b.lock(func() {
		if p := b.st.Pending[c.myID]; p.Note != "voorgesteld via Buurt door Anna" {
			t.Errorf("uitleg bij verzoek: %q", p.Note)
		}
	})
	b.post("/api/contact", map[string]any{"action": "accept", "id": c.myID, "name": "Carla"})
	b.lock(func() { b.st.Contacts[c.myID].IntroducedBy = "Buurt" })
	waitFor(t, "groep bij B en C", 5*time.Second, func() bool {
		ok := true
		b.lock(func() { ok = b.st.Groups[gid] != nil && b.st.Contacts[c.myID] != nil })
		c.lock(func() { ok = ok && c.st.Groups[gid] != nil && c.st.Contacts[b.myID] != nil })
		return ok
	})
	b.lock(func() {
		if b.st.Contacts[c.myID].IntroducedBy != "Buurt" {
			t.Errorf("introducedBy: %q", b.st.Contacts[c.myID].IntroducedBy)
		}
	})
	waitFor(t, "B en C zien elkaar", 8*time.Second, func() bool { return b.online(c.myID) && c.online(b.myID) })
	waitFor(t, "eigenaar kreeg bevestigingen", 5*time.Second, func() bool {
		ok := false
		a.lock(func() { g := a.st.Groups[gid]; ok = g.Acked[b.myID] == g.Ver && g.Acked[c.myID] == g.Ver })
		return ok
	})

	// groepsbericht van B
	b.post("/api/send", map[string]any{"conv": conv, "body": "Stroom is weg in onze straat"})
	waitFor(t, "groepsbericht bij A en C", 5*time.Second, func() bool {
		return findMsg(a.messages(conv), "Stroom is weg in onze straat") != nil && findMsg(c.messages(conv), "Stroom is weg in onze straat") != nil
	})
	waitFor(t, "groepsbericht bevestigd", 5*time.Second, func() bool {
		m := findMsg(b.messages(conv), "Stroom is weg in onze straat")
		return m != nil && m["acked"].(float64) == 2 && m["total"].(float64) == 2
	})
	var convs []map[string]any
	a.get("/api/convs", &convs)
	if len(convs) != 4 || convs[0]["id"] != "alle" {
		t.Errorf("convs: %s", dump(convs))
	}

	// SOS van C, bevestiging door A
	c.post("/api/location", map[string]any{"lat": 10.5, "lon": 20.25, "share": true}) // delen staat standaard uit
	sos := c.post("/api/sos", map[string]any{"action": "start"})
	sid := sos["id"].(string)
	waitFor(t, "SOS bij A en B", 5*time.Second, func() bool {
		return len(a.state()["incomingSos"].([]any)) == 1 && len(b.state()["incomingSos"].([]any)) == 1
	})
	in := a.state()["incomingSos"].([]any)[0].(map[string]any)
	if in["id"] != sid || in["from"] != c.myID || in["pos"] == nil {
		t.Errorf("incomingSos: %v", in)
	}
	a.post("/api/sos", map[string]any{"action": "seen", "id": sid})
	if len(a.state()["incomingSos"].([]any)) != 0 {
		t.Error("SOS blijft staan na bevestigen")
	}
	waitFor(t, "bevestiging bij C", 5*time.Second, func() bool {
		s, _ := c.state()["sos"].(map[string]any)
		acks, _ := s["acks"].([]any)
		return len(acks) == 1 && acks[0] == a.myID
	})
	c.post("/api/sos", map[string]any{"action": "stop"})
	waitFor(t, "SOS weg bij B na stoppen", 5*time.Second, func() bool { return len(b.state()["incomingSos"].([]any)) == 0 })
	if c.state()["sos"] != nil {
		t.Error("SOS nog actief")
	}

	// foto van A naar B
	jp := testJPEG(t)
	a.post("/api/send", map[string]any{"conv": b.myID, "body": "Foto van de straat", "img": "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(jp)})
	var img map[string]any
	waitFor(t, "foto bij B", 15*time.Second, func() bool {
		m := findMsg(b.messages(a.myID), "Foto van de straat")
		if m == nil || m["img"] == nil {
			return false
		}
		img = m["img"].(map[string]any)
		return img["status"] == "ok"
	})
	code, got := b.call("GET", "/api/blob/"+img["id"].(string), nil)
	if code != 200 || !bytes.Equal(got, jp) {
		t.Fatalf("blob: %d, %d bytes", code, len(got))
	}
	// te grote of foute foto
	if code, _ := a.call("POST", "/api/send", map[string]any{"conv": b.myID, "img": base64.StdEncoding.EncodeToString([]byte("geen jpeg"))}); code != 400 {
		t.Errorf("foute foto aanvaard: %d", code)
	}

	// blokkeren: B blokkeert A
	b.post("/api/contact", map[string]any{"action": "block", "id": a.myID})
	a.post("/api/send", map[string]any{"conv": b.myID, "body": "Na de blokkade"})
	time.Sleep(2 * time.Second)
	if findMsg(b.messages(a.myID), "Na de blokkade") != nil {
		t.Fatal("bericht van geblokkeerd contact afgeleverd")
	}
	if m := findMsg(a.messages(b.myID), "Na de blokkade"); m == nil || m["acked"].(float64) != 0 {
		t.Fatal("bericht aan blokkeerder bevestigd")
	}
	if code, _ := b.call("POST", "/api/send", map[string]any{"conv": a.myID, "body": "x"}); code != 400 {
		t.Error("sturen naar geblokkeerd contact aanvaard")
	}
	b.post("/api/contact", map[string]any{"action": "unblock", "id": a.myID})
	waitFor(t, "bericht komt alsnog na deblokkeren", 8*time.Second, func() bool { return findMsg(b.messages(a.myID), "Na de blokkade") != nil })

	// pincode: niet-localhost zonder sessie krijgt 401
	req := httptest.NewRequest("GET", "/api/state", nil)
	req.RemoteAddr = "192.168.1.20:5000"
	req.Host = "192.168.1.5:8474"
	rec := httptest.NewRecorder()
	a.mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("zonder pincode: %d", rec.Code)
	}
	// andere website (CSRF) weigeren
	req = httptest.NewRequest("POST", "/api/sos", bytes.NewReader([]byte(`{"action":"start"}`)))
	req.RemoteAddr = "127.0.0.1:5000"
	req.Host = "localhost:8474"
	req.Header.Set("Origin", "https://kwaadaardig.example")
	rec = httptest.NewRecorder()
	a.mux.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("CSRF: %d", rec.Code)
	}
}

// Brug: X ↔(IP)↔ Y ↔(radio)↔ Z. Z is niet via IP bereikbaar.
func TestIntegrationBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("integratietest")
	}
	mk := func(name string) *Node {
		n, err := loadNode(t.TempDir(), nextPort(), 0, true)
		if err != nil {
			t.Fatal(err)
		}
		n.st.Name = name
		n.bumpCard()
		n.pingEvery, n.outboxEvery, n.retryGap, n.loraWait = 300*time.Millisecond, 200*time.Millisecond, 1, 1
		return n
	}
	x, y, z := mk("Xander"), mk("Yves"), mk("Zoë")
	x.dropFrom[short(z.myID)] = true
	z.dropFrom[short(x.myID)] = true
	z.dropFrom[short(y.myID)] = true
	y.dropFrom[short(z.myID)] = true
	y.radio.testTx = func(p []byte) { z.onLoRa(p, 1, -97, 4.5) }
	z.radio.testTx = func(p []byte) { y.onLoRa(p, 2, -101, 2.5) }
	X := &tnode{Node: x, t: t, mux: x.routes()}
	Y := &tnode{Node: y, t: t, mux: y.routes()}
	Z := &tnode{Node: z, t: t, mux: z.routes()}
	for _, n := range []*Node{x, y, z} {
		n.run()
	}
	pair(X, Y)
	pair(Y, Z)
	pair(X, Z)
	Z.lock(func() { z.loraBeacon() })
	waitFor(t, "X en Y online", 8*time.Second, func() bool { return X.online(y.myID) && Y.online(x.myID) })
	waitFor(t, "Y hoort Z via radio", 5*time.Second, func() bool {
		ok := false
		Y.lock(func() { ok = now()-y.st.Contacts[z.myID].RadioSeen < 60 })
		return ok
	})
	waitFor(t, "X weet dat Y brug is voor Z", 5*time.Second, func() bool {
		ok := false
		X.lock(func() { ok = x.pickBridge(x.st.Contacts[z.myID]) != nil })
		return ok
	})
	var route map[string]any
	for _, ci := range X.state()["contacts"].([]any) {
		if cm := ci.(map[string]any); cm["id"] == z.myID {
			route = cm["route"].(map[string]any)
		}
	}
	if route["k"] != "bridge" {
		t.Errorf("route naar Z: %v", route)
	}

	// X -> Z via de brug
	X.post("/api/send", map[string]any{"conv": z.myID, "body": "Hoor je me via de brug?"})
	waitFor(t, "bericht bij Z", 10*time.Second, func() bool { return findMsg(Z.messages(x.myID), "Hoor je me via de brug?") != nil })
	if m := findMsg(Z.messages(x.myID), "Hoor je me via de brug?"); m["via"] != "radio" {
		t.Errorf("via bij Z: %v", m["via"])
	}
	waitFor(t, "bevestiging bij X via brug", 10*time.Second, func() bool {
		m := findMsg(X.messages(z.myID), "Hoor je me via de brug?")
		return m != nil && m["acked"].(float64) == 1
	})
	if m := findMsg(X.messages(z.myID), "Hoor je me via de brug?"); m["via"] != "bridge" {
		t.Errorf("via bij X: %v", m["via"])
	}

	// Z -> X: eigen radio, de brug stuurt het via IP door
	Z.post("/api/send", map[string]any{"conv": x.myID, "body": "Ja, luid en duidelijk"})
	waitFor(t, "antwoord bij X", 10*time.Second, func() bool { return findMsg(X.messages(z.myID), "Ja, luid en duidelijk") != nil })
	if m := findMsg(X.messages(z.myID), "Ja, luid en duidelijk"); m["via"] != "bridge" {
		t.Errorf("via bij X: %v", m["via"])
	}
	waitFor(t, "bevestiging bij Z", 10*time.Second, func() bool {
		m := findMsg(Z.messages(x.myID), "Ja, luid en duidelijk")
		return m != nil && m["acked"].(float64) == 1
	})

	// brug uitzetten: Y zendt niets meer uit voor X
	Y.post("/api/admin", map[string]any{"action": "policy", "bridge": false})
	X.post("/api/send", map[string]any{"conv": z.myID, "body": "Na brug uit"})
	time.Sleep(2500 * time.Millisecond)
	if findMsg(Z.messages(x.myID), "Na brug uit") != nil {
		t.Error("brug werkte terwijl ze uit stond")
	}
}
