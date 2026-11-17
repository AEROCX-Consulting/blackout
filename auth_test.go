package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const lanHost = "192.168.50.10:8474"

type hreq struct {
	method, path string
	body         any
	remote       string
	cookie       string
	origin       string
}

func doReq(h http.Handler, q hreq) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if q.body != nil {
		j, _ := json.Marshal(q.body)
		rd = bytes.NewReader(j)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(q.method, q.path, rd)
	req.RemoteAddr = q.remote
	req.Host = lanHost
	if strings.HasPrefix(q.remote, "127.") {
		req.Host = "localhost:8474"
	}
	if q.origin != "" {
		req.Header.Set("Origin", q.origin)
	} else if q.method == "POST" {
		req.Header.Set("Origin", "http://"+req.Host)
	}
	if q.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "axblackout", Value: q.cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loginAs(t *testing.T, h http.Handler, n *Node, remote string) string {
	t.Helper()
	rec := doReq(h, hreq{method: "POST", path: "/api/login", body: map[string]string{"pin": n.st.Pin}, remote: remote})
	if rec.Code != 200 {
		t.Fatalf("inloggen: %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "axblackout" {
			return c.Value
		}
	}
	t.Fatal("geen cookie")
	return ""
}

func wrongPin(n *Node) string {
	if n.st.Pin == "000000" {
		return "111111"
	}
	return "000000"
}

func TestPrivateSource(t *testing.T) {
	own := []net.IP{net.ParseIP("2001:db8:aa:bb::10"), net.ParseIP("192.168.50.10")}
	cases := map[string]bool{
		"127.0.0.1":          true,
		"::1":                true,
		"10.1.2.3":           true,
		"172.16.9.9":         true,
		"192.168.1.1":        true,
		"100.64.0.1":         true,
		"100.127.255.254":    true,
		"100.128.0.1":        false,
		"169.254.10.10":      true,
		"fe80::1":            true,
		"fd12:3456::1":       true,
		"2001:db8:aa:bb::99": true,  // zelfde /64
		"2001:db8:aa:bc::99": false, // ander /64
		"203.0.113.7":        false,
		"198.51.100.20":      false,
		"::ffff:192.168.1.4": true,
		"::ffff:203.0.113.7": false,
		"2001:db8:ffff::1":   false,
	}
	for s, want := range cases {
		if got := privateSource(net.ParseIP(s), own); got != want {
			t.Errorf("%s: %v, verwacht %v", s, got, want)
		}
	}
	if privateSource(nil, own) {
		t.Error("nil mag niet")
	}
}

func TestRemoteNotPrivateForbidden(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	for _, p := range []string{"/", "/api/ping", "/api/state"} {
		rec := doReq(h, hreq{method: "GET", path: p, remote: "203.0.113.9:4000"})
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "eigen netwerk") {
			t.Errorf("%s vanaf internet: %d %s", p, rec.Code, rec.Body)
		}
	}
	rec := doReq(h, hreq{method: "POST", path: "/api/login", body: map[string]string{"pin": n.st.Pin}, remote: "[2001:db8:9::5]:4000"})
	if rec.Code != 403 {
		t.Errorf("login vanaf vreemd IPv6: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/ping", remote: "192.168.50.20:4000"}); rec.Code != 200 {
		t.Errorf("ping vanaf wifi: %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	for _, p := range []string{"/", "/api/ping", "/assets/logo.svg", "/api/state"} {
		rec := doReq(h, hreq{method: "GET", path: p, remote: "127.0.0.1:5000"})
		hd := rec.Header()
		if hd.Get("X-Frame-Options") != "DENY" || !strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: koppen ontbreken: %v", p, hd)
		}
	}
	for _, p := range []string{"/assets/", "/assets/fonts/"} {
		if rec := doReq(h, hreq{method: "GET", path: p, remote: "127.0.0.1:5000"}); rec.Code != 404 {
			t.Errorf("%s: mapoverzicht %d", p, rec.Code)
		}
	}
}

func TestPinLockout(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	bad := map[string]string{"pin": wrongPin(n)}
	for i := 1; i <= 4; i++ {
		if rec := doReq(h, hreq{method: "POST", path: "/api/login", body: bad, remote: "192.168.50.20:4000"}); rec.Code != 403 {
			t.Fatalf("poging %d: %d", i, rec.Code)
		}
	}
	rec := doReq(h, hreq{method: "POST", path: "/api/login", body: bad, remote: "192.168.50.21:4000"})
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "Te veel foute pogingen, probeer opnieuw over 1 min") {
		t.Fatalf("5e poging: %d %s", rec.Code, rec.Body)
	}
	// ook de juiste pincode wordt nu geweigerd, ook vanaf een ander toestel
	rec = doReq(h, hreq{method: "POST", path: "/api/login", body: map[string]string{"pin": n.st.Pin}, remote: "192.168.50.30:4000"})
	if rec.Code != 429 {
		t.Fatalf("tijdens blokkering: %d", rec.Code)
	}
	n.mu.Lock()
	found := false
	for _, a := range n.st.Audit {
		if strings.Contains(a.X, "verkeerde pincode") && strings.Contains(a.X, "geblokkeerd") {
			found = true
		}
	}
	n.pinLockUntil = time.Now().Add(-time.Second) // blokkering voorbij
	n.mu.Unlock()
	if !found {
		t.Error("geen melding in het beheerlogboek")
	}
	// tweede reeks: blokkering verdubbelt
	for i := 1; i <= 5; i++ {
		rec = doReq(h, hreq{method: "POST", path: "/api/login", body: bad, remote: "192.168.50.20:4000"})
	}
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "over 2 min") {
		t.Fatalf("tweede blokkering: %d %s", rec.Code, rec.Body)
	}
	n.mu.Lock()
	n.pinLockDur = 50 * time.Minute
	n.pinLockUntil = time.Now().Add(-time.Second)
	n.mu.Unlock()
	for i := 1; i <= 5; i++ {
		rec = doReq(h, hreq{method: "POST", path: "/api/login", body: bad, remote: "192.168.50.20:4000"})
	}
	if !strings.Contains(rec.Body.String(), "over 60 min") {
		t.Fatalf("maximum 1 u: %s", rec.Body)
	}
	n.mu.Lock()
	n.pinLockUntil = time.Now().Add(-time.Second)
	n.mu.Unlock()
	loginAs(t, h, n, "192.168.50.20:4000")
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pinFails != 0 || n.pinLockDur != 0 {
		t.Errorf("na goede pincode niet teruggezet: %d %v", n.pinFails, n.pinLockDur)
	}
}

func TestPinLockoutParallel(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	bad := map[string]string{"pin": wrongPin(n)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := doReq(h, hreq{method: "POST", path: "/api/login", body: bad, remote: "192.168.50.20:4000"})
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[403] != pinMaxFails-1 || codes[429] != 40-(pinMaxFails-1) {
		t.Fatalf("parallelle pogingen: %v", codes)
	}
}

func TestLoginOriginAndMethods(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	if rec := doReq(h, hreq{method: "GET", path: "/api/login", remote: "192.168.50.20:4000"}); rec.Code != 405 {
		t.Errorf("GET login: %d", rec.Code)
	}
	rec := doReq(h, hreq{method: "POST", path: "/api/login", body: map[string]string{"pin": n.st.Pin}, remote: "192.168.50.20:4000", origin: "http://evil.example"})
	if rec.Code != 403 {
		t.Errorf("login met vreemde Origin: %d", rec.Code)
	}
	tok := loginAs(t, h, n, "192.168.50.20:4000")
	if rec := doReq(h, hreq{method: "GET", path: "/api/logout", remote: "192.168.50.20:4000", cookie: tok}); rec.Code != 405 {
		t.Errorf("GET logout: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: "192.168.50.20:4000", cookie: tok}); rec.Code != 200 {
		t.Errorf("sessie na GET logout: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "POST", path: "/api/logout", remote: "192.168.50.20:4000", cookie: tok}); rec.Code != 200 {
		t.Errorf("POST logout: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: "192.168.50.20:4000", cookie: tok}); rec.Code != 401 {
		t.Errorf("na logout: %d", rec.Code)
	}
}

func TestSessionExpires(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	tok := loginAs(t, h, n, "192.168.50.20:4000")
	n.mu.Lock()
	n.st.Sessions[tok].Seen = now() - 31*86400
	n.mu.Unlock()
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: "192.168.50.20:4000", cookie: tok}); rec.Code != 401 {
		t.Errorf("verlopen sessie: %d", rec.Code)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.st.Sessions[tok] != nil {
		t.Error("verlopen sessie niet opgeruimd")
	}
}

func TestSensitiveActionsNeedPin(t *testing.T) {
	n := bareNode(t, "Anna")
	h := n.routes()
	const ipad = "192.168.50.20:4000"
	tok := loginAs(t, h, n, ipad)
	other := loginAs(t, h, n, "192.168.50.21:4000")
	calls := []hreq{
		{method: "POST", path: "/api/backup", body: map[string]any{"pass": "een lange wachtzin hier"}},
		{method: "POST", path: "/api/admin", body: map[string]any{"action": "newpin"}},
		{method: "POST", path: "/api/admin", body: map[string]any{"action": "revokeDevice", "id": "x"}},
		{method: "POST", path: "/api/autostart", body: map[string]any{"on": false}},
	}
	for _, c := range calls {
		c.remote, c.cookie = ipad, tok
		if rec := doReq(h, c); rec.Code != 403 || !strings.Contains(rec.Body.String(), "pincode") {
			t.Errorf("%s %v zonder pincode: %d %s", c.path, c.body, rec.Code, rec.Body)
		}
	}
	// verkeerde pincode telt als foute poging
	rec := doReq(h, hreq{method: "POST", path: "/api/admin", body: map[string]any{"action": "newpin", "pin": wrongPin(n)}, remote: ipad, cookie: tok})
	if rec.Code != 403 {
		t.Errorf("newpin met verkeerde pincode: %d", rec.Code)
	}
	n.mu.Lock()
	fails := n.pinFails
	pin := n.st.Pin
	n.mu.Unlock()
	if fails != 1 {
		t.Errorf("foute poging niet geteld: %d", fails)
	}
	// backup met pincode werkt
	rec = doReq(h, hreq{method: "POST", path: "/api/backup", body: map[string]any{"pass": "een lange wachtzin hier", "pin": pin}, remote: ipad, cookie: tok})
	if rec.Code != 200 || !bytes.HasPrefix(rec.Body.Bytes(), []byte(backupMagic)) {
		t.Errorf("backup met pincode: %d", rec.Code)
	}
	// nieuwe pincode: andere toestellen afgemeld, dit toestel blijft
	rec = doReq(h, hreq{method: "POST", path: "/api/admin", body: map[string]any{"action": "newpin", "pin": pin}, remote: ipad, cookie: tok})
	if rec.Code != 200 {
		t.Fatalf("newpin: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: "192.168.50.21:4000", cookie: other}); rec.Code != 401 {
		t.Errorf("ander toestel na newpin: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: ipad, cookie: tok}); rec.Code != 200 {
		t.Errorf("eigen toestel na newpin: %d", rec.Code)
	}
	// op de computer zelf: geen pincode nodig, en newpin meldt alle toestellen af
	rec = doReq(h, hreq{method: "POST", path: "/api/admin", body: map[string]any{"action": "newpin"}, remote: "127.0.0.1:5000"})
	if rec.Code != 200 {
		t.Fatalf("newpin lokaal: %d", rec.Code)
	}
	if rec := doReq(h, hreq{method: "GET", path: "/api/state", remote: ipad, cookie: tok}); rec.Code != 401 {
		t.Errorf("toestel na lokale newpin: %d", rec.Code)
	}
	// quit blijft alleen lokaal
	if rec := doReq(h, hreq{method: "POST", path: "/api/quit", remote: ipad, cookie: tok}); rec.Code != 403 {
		t.Errorf("quit vanaf toestel: %d", rec.Code)
	}
}
