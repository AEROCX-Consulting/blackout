package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- STUN ----------

// RFC 5769 §2.2 en §2.3 (wachtwoord voor MESSAGE-INTEGRITY: "VOkJxbRl1RmTxUk/WvJxBt").
var (
	rfc5769v4 = []byte{0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
		0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
		0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
		0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
		0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96}
	rfc5769v6 = []byte{0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
		0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
		0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
		0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
		0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c}
)

func TestSTUNRFC5769(t *testing.T) {
	id := stunTxOf(rfc5769v4)
	for _, tc := range []struct {
		msg  []byte
		want string
	}{{rfc5769v4, "192.0.2.1:32853"}, {rfc5769v6, "[2001:db8:1234:5678:11:2233:4455:6677]:32853"}} {
		if !isSTUN(tc.msg) {
			t.Fatal("isSTUN false")
		}
		a, err := parseSTUNResponse(tc.msg, id)
		if err != nil || a.String() != tc.want {
			t.Fatalf("got %v %v, want %s", a, err, tc.want)
		}
		// beschadigde FINGERPRINT
		bad := append([]byte{}, tc.msg...)
		bad[len(bad)-1] ^= 1
		if _, err := parseSTUNResponse(bad, id); err != errStunFingerp {
			t.Fatalf("kapotte fingerprint aanvaard: %v", err)
		}
		// andere transactie
		other := id
		other[0] ^= 0xff
		if _, err := parseSTUNResponse(tc.msg, other); err != errStunTx {
			t.Fatalf("vreemde transactie aanvaard: %v", err)
		}
		// afgekapt
		for i := 0; i < len(tc.msg); i++ {
			if _, err := parseSTUNResponse(tc.msg[:i], id); err == nil {
				t.Fatalf("afgekapt op %d aanvaard", i)
			}
		}
	}
	// verzoek: 20 bytes, type 0x0001, lengte 0, cookie
	req := stunRequest(id)
	if len(req) != 20 || binary.BigEndian.Uint16(req) != 1 || binary.BigEndian.Uint32(req[4:]) != stunMagic || !bytes.Equal(req[8:], id[:]) {
		t.Fatalf("verzoek: %x", req)
	}
	// eigen antwoord (voor de nep-server) is leesbaar, met en zonder fingerprint
	for _, f := range []bool{false, true} {
		r := stunResponse(id, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4242}, f)
		if a, err := parseSTUNResponse(r, id); err != nil || a.String() != "203.0.113.9:4242" {
			t.Fatal(a, err)
		}
	}
	// een pakket van een contact is nooit STUN
	n := bareNode(t, "A")
	if isSTUN(append(n.header('E'), make([]byte, 60)...)) {
		t.Fatal("contactpakket als STUN herkend")
	}
}

func FuzzSTUN(f *testing.F) {
	f.Add(rfc5769v4)
	f.Add(rfc5769v6)
	f.Add(stunRequest(stunTxID{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if isSTUN(b) {
			parseSTUNResponse(b, stunTxOf(b))
		}
	})
}

// nepSTUN: antwoordt met een vast "publiek" adres. Telt de verzoeken.
func fakeSTUN(t *testing.T, mapped string) (*net.UDPConn, *atomic.Int32) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ma, _ := net.ResolveUDPAddr("udp", mapped)
	cnt := new(atomic.Int32)
	go func() {
		buf := make([]byte, 1500)
		for {
			nr, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if nr < 20 || binary.BigEndian.Uint16(buf) != stunBindReq {
				continue
			}
			cnt.Add(1)
			c.WriteToUDP(stunResponse(stunTxOf(buf[:nr]), ma, true), from)
		}
	}()
	return c, cnt
}

func TestSTUNClient(t *testing.T) {
	srv, cnt := fakeSTUN(t, "203.0.113.7:40001")
	a := liveNode(t, "Anna", func(n *Node) { n.nw.servers = []string{srv.LocalAddr().String()} })
	a.nw.dish = "127.0.0.1:1" // geen schotel
	a.nw.env.gwPort = 1       // geen router
	a.nw.env.ssdpAddr = "127.0.0.1:1"
	a.netRound()
	s := a.state()
	nw := s["net"].(map[string]any)
	if nw["stun"] != "ok" || nw["internet"] != true || !strings.Contains(dump(nw["publicAddrs"]), "203.0.113.7:40001") {
		t.Fatalf("net: %v (verzoeken %d)", dump(nw), cnt.Load())
	}
	if !strings.Contains(dump(s["me"].(map[string]any)["addrs"]), "203.0.113.7:40001") {
		t.Fatalf("publiek adres niet in de kaart: %v", s["me"])
	}
	// de kaart in de code bevat het publieke adres (ondertekend)
	card, err := parseCardText(a.code())
	if err != nil || !contains(card.A, "203.0.113.7:40001") {
		t.Fatalf("code: %v %v", err, card.A)
	}
	for _, k := range []string{"internet", "ipv6Global", "publicAddrs", "stun", "portmap", "starlink"} {
		if _, ok := nw[k]; !ok {
			t.Errorf("net mist %q", k)
		}
	}
	// uitzetten: geen verzoeken meer, adres weg uit de kaart
	a.post("/api/admin", map[string]any{"action": "policy", "stun": false, "portmap": false})
	before := cnt.Load()
	a.netRound()
	s = a.state()
	nw = s["net"].(map[string]any)
	if nw["stun"] != "uit" || nw["portmap"] != "uit" || cnt.Load() != before || strings.Contains(dump(s["me"]), "203.0.113.7") {
		t.Fatalf("uit: %v %d/%d", dump(nw), cnt.Load(), before)
	}
	if p := s["policy"].(map[string]any); p["stun"] != false || p["portmap"] != false {
		t.Fatalf("policy: %v", p)
	}
}

// Een STUN-antwoord van een ander adres dan de server (of een onbekende transactie) wordt genegeerd,
// en komt nooit bij de verwerking van contactpakketten.
func TestSTUNSpoofIgnored(t *testing.T) {
	srv, _ := fakeSTUN(t, "203.0.113.7:40001")
	a := liveNode(t, "Anna", func(n *Node) { n.nw.servers = []string{srv.LocalAddr().String()} })
	var conn *net.UDPConn
	a.lock(func() {
		for k, c := range a.socks {
			if a.sockInfo[k].IP.Equal(net.IPv4(127, 0, 0, 1)) {
				conn = c
			}
		}
	})
	id := newStunTxID()
	a.nw.mu.Lock()
	a.nw.tx[id] = &stunTx{server: srv.LocalAddr().(*net.UDPAddr), conn: conn}
	a.nw.mu.Unlock()
	spoof, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer spoof.Close()
	spoof.WriteToUDP(stunResponse(id, &net.UDPAddr{IP: net.ParseIP("198.51.100.66"), Port: 1}, true), conn.LocalAddr().(*net.UDPAddr))
	srv.WriteToUDP(stunResponse(newStunTxID(), &net.UDPAddr{IP: net.ParseIP("198.51.100.67"), Port: 1}, true), conn.LocalAddr().(*net.UDPAddr))
	time.Sleep(300 * time.Millisecond)
	a.nw.mu.Lock()
	res := a.nw.tx[id].res
	a.nw.mu.Unlock()
	if res != nil {
		t.Fatalf("vervalst antwoord aanvaard: %v", res)
	}
	srv.WriteToUDP(stunResponse(id, &net.UDPAddr{IP: net.ParseIP("198.51.100.68"), Port: 2}, false), conn.LocalAddr().(*net.UDPAddr))
	waitFor(t, "echt antwoord", 2*time.Second, func() bool {
		a.nw.mu.Lock()
		defer a.nw.mu.Unlock()
		return a.nw.tx[id].res != nil && a.nw.tx[id].res.String() == "198.51.100.68:2"
	})
}

// ---------- NAT-PMP / PCP ----------

type fakeGW struct {
	conn  *net.UDPConn
	mu    sync.Mutex
	pcp   bool // PCP begrijpen (anders: "versie niet ondersteund")
	maps  map[int]uint32
	reqs  int
	nonce [12]byte
}

func newFakeGW(t *testing.T, pcp bool) *fakeGW {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	g := &fakeGW{conn: c, pcp: pcp, maps: map[int]uint32{}}
	go func() {
		buf := make([]byte, 1500)
		for {
			nr, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			b := buf[:nr]
			g.mu.Lock()
			g.reqs++
			switch {
			case b[0] == 2 && g.pcp && nr >= 60:
				r := make([]byte, 60)
				r[0], r[1] = 2, 0x81
				copy(r[4:8], b[4:8])
				copy(r[24:60], b[24:60])
				copy(r[44:60], net.ParseIP("203.0.113.50").To16())
				port := int(binary.BigEndian.Uint16(b[40:]))
				g.maps[port] = binary.BigEndian.Uint32(b[4:])
				copy(g.nonce[:], b[24:36])
				// eerst een antwoord met een verkeerde nonce (moet genegeerd worden)
				w := append([]byte{}, r...)
				w[24] ^= 0xff
				c.WriteToUDP(w, from)
				c.WriteToUDP(r, from)
			case b[0] != 0:
				c.WriteToUDP([]byte{0, 128 + b[1]&0x7f, 0, 1, 0, 0, 0, 0}, from)
			case b[1] == 0:
				c.WriteToUDP([]byte{0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 51}, from)
			case b[1] == 1 && nr >= 12:
				port := int(binary.BigEndian.Uint16(b[4:]))
				life := binary.BigEndian.Uint32(b[8:])
				g.maps[port] = life
				r := make([]byte, 16)
				r[1] = 129
				binary.BigEndian.PutUint16(r[8:], uint16(port))
				if life > 0 {
					binary.BigEndian.PutUint16(r[10:], uint16(port+1))
				}
				binary.BigEndian.PutUint32(r[12:], life)
				c.WriteToUDP(r, from)
			}
			g.mu.Unlock()
		}
	}()
	return g
}

func loopAddrs() []ifAddr {
	_, n8, _ := net.ParseCIDR("127.0.0.0/8")
	return []ifAddr{{IP: net.IPv4(127, 0, 0, 1).To4(), Net: n8, Name: "lo", Loop: true}}
}

func TestPortMapPCPAndNATPMP(t *testing.T) {
	pmTestLoopback = true
	defer func() { pmTestLoopback = false }()
	gw := net.IPv4(127, 0, 0, 1).To4()
	for _, pcp := range []bool{true, false} {
		g := newFakeGW(t, pcp)
		env := pmEnv{gwPort: g.conn.LocalAddr().(*net.UDPAddr).Port, ssdpAddr: "127.0.0.1:1", timeout: 200 * time.Millisecond}
		m, err := tryPortMap(context.Background(), env, loopAddrs(), []net.IP{gw}, 47474, nil)
		if err != nil {
			t.Fatalf("pcp=%v: %v", pcp, err)
		}
		want, method := "203.0.113.50:47474", "pcp"
		if !pcp {
			want, method = "203.0.113.51:47475", "natpmp"
		}
		if m.Method != method || m.Ext.String() != want || m.Lifetime != time.Hour {
			t.Fatalf("pcp=%v: %+v", pcp, m)
		}
		g.mu.Lock()
		if g.maps[47474] != 3600 {
			t.Fatalf("lease: %v", g.maps)
		}
		g.mu.Unlock()
		if err := releasePortMap(context.Background(), env, m); err != nil {
			t.Fatal(err)
		}
		g.mu.Lock()
		if g.maps[47474] != 0 {
			t.Fatalf("niet verwijderd: %v", g.maps)
		}
		g.mu.Unlock()
	}
	// een router die zwijgt: binnen ~2 s opgegeven
	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: gw})
	defer dead.Close()
	t0 := time.Now()
	env := pmEnv{gwPort: dead.LocalAddr().(*net.UDPAddr).Port, ssdpAddr: "127.0.0.1:1", timeout: 100 * time.Millisecond}
	if _, err := tryPortMap(context.Background(), env, loopAddrs(), []net.IP{gw}, 47474, nil); err == nil || time.Since(t0) > 4*time.Second {
		t.Fatalf("zwijgende router: %v na %v", err, time.Since(t0))
	}
}

func TestPortMapParsers(t *testing.T) {
	var nonce [12]byte
	nonce[3] = 7
	// NAT-PMP-router op een PCP-vraag
	if r, err := parsePCPMapResponse([]byte{0, 129, 0, 1, 0, 0, 0, 0}, nonce, 47474); err != nil || !r.OldVer {
		t.Fatal(r, err)
	}
	// privé/CGNAT-adressen zijn niet publiek
	for _, s := range []string{"10.1.2.3", "192.168.1.1", "100.64.0.1", "100.127.255.1", "169.254.1.1", "127.0.0.1", "0.0.0.0", "fd00::1", "fe80::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("%s publiek?", s)
		}
	}
	for _, s := range []string{"81.82.83.84", "100.128.0.1", "2a0d:3344::1"} {
		if !publicIP(net.ParseIP(s)) {
			t.Errorf("%s niet publiek?", s)
		}
	}
}

func FuzzPortMap(f *testing.F) {
	f.Add([]byte{0, 129, 0, 0, 0, 0, 0, 1, 0xb9, 0x72, 0xb9, 0x72, 0, 0, 14, 16})
	f.Add(make([]byte, 60))
	f.Fuzz(func(t *testing.T, b []byte) {
		var nonce [12]byte
		parsePCPMapResponse(b, nonce, 47474)
		parseNATPMPMapResponse(b, 47474)
		parseNATPMPAddrResponse(b)
	})
}

// ---------- UPnP ----------

const igdDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>`

type fakeIGD struct {
	mu    sync.Mutex
	calls []string
	maps  map[string]string
	ext   string
	fail  map[string]int // actie -> UPnP-foutcode (één keer)
	// alleen vaste doorverwijzingen (lease 0)
	permOnly bool
}

func (f *fakeIGD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == "GET" && r.URL.Path == "/desc.xml" {
		io.WriteString(w, igdDesc)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/ctl/IPConn" {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	act := r.Header.Get("SOAPAction")
	args := parseSOAPLeaves(body)
	name := act[strings.Index(act, "#")+1 : len(act)-1]
	f.calls = append(f.calls, name)
	if code := f.fail[name]; code != 0 {
		delete(f.fail, name)
		w.WriteHeader(500)
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>nee</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
		return
	}
	switch name {
	case "GetExternalIPAddress":
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, f.ext)
	case "GetGenericPortMappingEntry":
		var keys []string
		for k := range f.maps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		i, _ := strconv.Atoi(args["NewPortMappingIndex"])
		if i >= len(keys) {
			w.WriteHeader(500)
			io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
			return
		}
		v := f.maps[keys[i]]
		cl, rest, _ := strings.Cut(v, "/")
		host, iport, _ := strings.Cut(cl, ":")
		parts := strings.SplitN(rest, "/", 3)
		fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>%s</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%s</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%s</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`, keys[i], parts[0], iport, host, parts[2], parts[1])
	case "AddPortMapping":
		if f.permOnly && args["NewLeaseDuration"] != "0" {
			w.WriteHeader(500)
			io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
			return
		}
		f.maps[args["NewExternalPort"]] = args["NewInternalClient"] + ":" + args["NewInternalPort"] + "/" + args["NewProtocol"] + "/" + args["NewLeaseDuration"] + "/" + args["NewPortMappingDescription"]
		io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`)
	case "DeletePortMapping":
		delete(f.maps, args["NewExternalPort"])
		io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`)
	}
}

// fakeSSDP antwoordt op M-SEARCH met de gegeven LOCATION.
func fakeSSDP(t *testing.T, loc string) string {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			nr, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !strings.HasPrefix(string(buf[:nr]), "M-SEARCH * HTTP/1.1") || !strings.Contains(string(buf[:nr]), "InternetGatewayDevice") {
				continue
			}
			c.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: "+loc+"\r\n\r\n"), from)
		}
	}()
	return c.LocalAddr().String()
}

func TestUPnP(t *testing.T) {
	pmTestLoopback = true
	defer func() { pmTestLoopback = false }()
	igd := &fakeIGD{maps: map[string]string{}, ext: "81.82.83.84", fail: map[string]int{"AddPortMapping": 718}}
	hs := httptest.NewServer(igd)
	defer hs.Close()
	env := pmEnv{gwPort: 1, ssdpAddr: fakeSSDP(t, hs.URL+"/desc.xml"), timeout: 500 * time.Millisecond}
	m, err := upnpMap(context.Background(), env, loopAddrs(), 47474)
	if err != nil {
		t.Fatal(err)
	}
	igd.mu.Lock()
	if m.Method != "upnp" || m.Ext.IP.String() != "81.82.83.84" || m.Ext.Port == 47474 || len(igd.maps) != 1 {
		t.Fatalf("na conflict (718) een andere externe poort verwacht: %+v %v", m, igd.maps)
	}
	got := igd.maps[fmt.Sprint(m.Ext.Port)]
	igd.mu.Unlock()
	if got != "127.0.0.1:47474/UDP/3600/AEROCX Blackout" {
		t.Fatalf("mapping: %q", got)
	}
	if err := releasePortMap(context.Background(), env, m); err != nil {
		t.Fatal(err)
	}
	igd.mu.Lock()
	if len(igd.maps) != 0 {
		t.Fatalf("niet verwijderd: %v", igd.maps)
	}
	igd.mu.Unlock()

	// alleen vaste leases (725) -> lease 0
	igd.fail["AddPortMapping"] = 725
	m, err = upnpMap(context.Background(), env, loopAddrs(), 47474)
	if err != nil || !strings.HasSuffix(igd.maps["47474"], "/0/AEROCX Blackout") {
		t.Fatalf("725: %v %v", err, igd.maps)
	}
	releasePortMap(context.Background(), env, m)

	// router zonder publiek adres (dubbele NAT): geen doorverwijzing
	igd.ext = "100.72.1.2"
	if _, err := upnpMap(context.Background(), env, loopAddrs(), 47474); err == nil {
		t.Fatal("CGNAT-adres aanvaard")
	}
}

func TestUPnPRejectsForeignLocations(t *testing.T) {
	_, n24, _ := net.ParseCIDR("192.168.1.0/24")
	addrs := []ifAddr{{IP: net.ParseIP("192.168.1.10").To4(), Net: n24, Name: "en0"}}
	for _, loc := range []string{"http://8.8.8.8/desc.xml", "http://192.168.2.1/desc.xml", "https://192.168.1.1/x", "http://router.example/desc.xml",
		"http://user:pw@192.168.1.1/x", "file:///etc/passwd", ""} {
		if _, err := checkLocation(loc, addrs); err == nil {
			t.Errorf("LOCATION %q aanvaard", loc)
		}
	}
	if _, err := checkLocation("http://192.168.1.1:5000/rootDesc.xml", addrs); err != nil {
		t.Fatal(err)
	}
	// control-URL die naar een ander toestel wijst
	loc, _ := checkLocation("http://192.168.1.1:5000/rootDesc.xml", addrs)
	evil := strings.Replace(igdDesc, "/ctl/IPConn", "http://192.168.1.66/ctl", 1)
	if _, _, err := parseIGDDescription([]byte(evil), loc); err == nil {
		t.Fatal("control-URL naar ander toestel aanvaard")
	}
	ctrl, svc, err := parseIGDDescription([]byte(igdDesc), loc)
	if err != nil || ctrl != "http://192.168.1.1:5000/ctl/IPConn" || svc != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatal(ctrl, svc, err)
	}
	bad := strings.Replace(igdDesc, "WANIPConnection:1<", "WANIPConnection:1\"><x a=\"<", 1)
	if _, _, err := parseIGDDescription([]byte(bad), loc); err == nil {
		t.Fatal("vreemd servicetype aanvaard")
	}
}

func FuzzUPnP(f *testing.F) {
	f.Add([]byte(igdDesc), []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/x\r\n\r\n"))
	_, n24, _ := net.ParseCIDR("192.168.1.0/24")
	addrs := []ifAddr{{IP: net.ParseIP("192.168.1.10").To4(), Net: n24, Name: "en0"}}
	loc, _ := checkLocation("http://192.168.1.1/x", addrs)
	f.Fuzz(func(t *testing.T, desc, ssdp []byte) {
		parseIGDDescription(desc, loc)
		parseSOAPLeaves(desc)
		parseSSDPReply(ssdp, addrs)
	})
}

// ---------- gateway ----------

func TestGatewayParsing(t *testing.T) {
	proc := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	if g := parseProcNetRoute(proc); g.String() != "192.168.1.1" {
		t.Fatalf("linux: %v", g)
	}
	mac := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	if g := parseRouteGetDefault(mac); g.String() != "192.168.1.254" {
		t.Fatalf("mac: %v", g)
	}
	win := `===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.0.1    192.168.0.23     55
          0.0.0.0          0.0.0.0      10.0.0.138       10.0.0.12     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
Persistent Routes:
  None
`
	if g := parseRoutePrint(win); g.String() != "10.0.0.138" {
		t.Fatalf("windows: %v", g)
	}
	for _, s := range []string{"", "rommel\n\x00\n", "0.0.0.0 0.0.0.0 On-link 1.2.3.4 5"} {
		if parseRoutePrint(s) != nil || parseRouteGetDefault(s) != nil || parseProcNetRoute(s) != nil {
			t.Fatalf("rommel gaf een gateway: %q", s)
		}
	}
	_, n24, _ := net.ParseCIDR("192.168.5.0/24")
	_, ll, _ := net.ParseCIDR("169.254.0.0/16")
	g := guessGateways([]ifAddr{{IP: net.ParseIP("192.168.5.20").To4(), Net: n24}, {IP: net.ParseIP("169.254.3.3").To4(), Net: ll, LL: true}})
	if len(g) != 1 || g[0].String() != "192.168.5.1" {
		t.Fatalf("gok: %v", g)
	}
}

// ---------- wifi: adressen, link-local, multicast ----------

func TestLinkLocalSending(t *testing.T) {
	// classifyAddr: link-local alleen op een gewone (multicast) interface, niet op een tunnel
	eth := net.Interface{Index: 2, Name: "eth0", Flags: net.FlagUp | net.FlagMulticast | net.FlagBroadcast}
	tun := net.Interface{Index: 9, Name: "utun3", Flags: net.FlagUp | net.FlagMulticast | net.FlagPointToPoint}
	ll := &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}
	if a := classifyAddr(ll, eth, false); a == nil || !a.LL || a.key() != "fe80::1%eth0" || a.udpAddr(1).Zone != "eth0" {
		t.Fatalf("eth0: %+v", a)
	}
	if classifyAddr(ll, tun, false) != nil {
		t.Fatal("link-local op een tunnel")
	}
	ula := &net.IPNet{IP: net.ParseIP("fd12::5"), Mask: net.CIDRMask(64, 128)}
	if a := classifyAddr(ula, eth, false); a == nil || a.LL {
		t.Fatal("ULA (fd00::/8) moet gewoon meedoen")
	}
	// volgorde: publiek IPv6, IPv4, link-local
	list := sortIfAddrs([]ifAddr{{IP: net.ParseIP("fe80::1"), LL: true}, {IP: net.ParseIP("192.168.1.2")}, {IP: net.ParseIP("2a0d::1")}})
	if list[0].IP.String() != "2a0d::1" || !list[2].LL {
		t.Fatalf("volgorde: %v", list)
	}

	// link-local komt nooit in de kaart; een contact met alleen link-local wordt via de multicast-hello
	// geleerd (lanProbe) en dan rechtstreeks gepingd.
	a := liveNode(t, "Anna", nil)
	b := liveNode(t, "Bert", nil)
	pair(a, b)
	waitFor(t, "online", 8*time.Second, func() bool { return a.online(b.myID) })
	var bAddr *net.UDPAddr
	b.lock(func() {
		for k, c := range b.socks {
			if b.sockInfo[k].Loop && b.sockInfo[k].v4() {
				bAddr = c.LocalAddr().(*net.UDPAddr)
			}
		}
	})
	a.lock(func() {
		c := a.st.Contacts[b.myID]
		c.Observed = map[string]int64{}
		c.Card.A = nil
		a.lanProbe(c, bAddr)
		if a.probeLast[c.ID] == 0 {
			t.Error("geen probe")
		}
		last := a.probeLast[c.ID]
		a.lanProbe(c, bAddr) // binnen 10 s: niet opnieuw
		if a.probeLast[c.ID] != last {
			t.Error("probe niet begrensd")
		}
	})
	waitFor(t, "adres geleerd via probe", 5*time.Second, func() bool {
		ok := false
		a.lock(func() { _, ok = a.st.Contacts[b.myID].Observed[bAddr.String()] })
		return ok
	})
}

func TestMcastDedup(t *testing.T) {
	n := bareNode(t, "A")
	p := []byte("NN\x01Hhallo")
	if n.mcastDup(p) || !n.mcastDup(p) || n.mcastDup([]byte("ander")) {
		t.Fatal("dubbele multicast niet herkend")
	}
}

// ---------- Starlink-schotel ----------

func TestStarlinkProbe(t *testing.T) {
	// een h2c-server (zoals de gRPC van de schotel) antwoordt met SETTINGS
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	if !probeStarlink(context.Background(), ln.Addr().String()) {
		t.Fatal("h2c-server niet herkend")
	}
	// een gewone webserver (HTTP/1.1) of een dichte poort is geen schotel
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hs.Close()
	if probeStarlink(context.Background(), strings.TrimPrefix(hs.URL, "http://")) {
		t.Fatal("HTTP/1.1 als schotel herkend")
	}
	if probeStarlink(context.Background(), "127.0.0.1:1") {
		t.Fatal("dichte poort als schotel herkend")
	}
}

// Route-tekst: "via internet", en "via Starlink" alleen als de schotel gevonden is.
func TestRouteTextInternet(t *testing.T) {
	a := liveNode(t, "Anna", nil)
	a.lock(func() {
		c := &Contact{ID: "x", Name: "X", Via: "star", LastSeen: now(), Observed: map[string]int64{}}
		if _, txt := a.route(c, false); txt != "via internet" {
			t.Errorf("tekst: %q", txt)
		}
		a.nw.starlink = true
		if _, txt := a.route(c, false); txt != "via Starlink" {
			t.Errorf("tekst: %q", txt)
		}
		a.nw.starlink = false
	})
}

// ---------- N4-1: "zelfde wifi" alleen op grond van het bronadres ----------

// De multicastsocket (0.0.0.0:47475) ontvangt ook unicast van overal. Een hello van een
// internetadres mag nooit als "zelfde wifi-netwerk" gelden, ook niet met autoLan aan.
func TestLanTrustBySourceAddress(t *testing.T) {
	a := liveNode(t, "Anna", func(n *Node) { n.st.Policy.AutoLan = true })
	_, n24, _ := net.ParseCIDR("10.77.0.0/24")
	a.lock(func() {
		a.sockInfo["10.77.0.5"] = ifAddr{IP: net.ParseIP("10.77.0.5").To4(), Net: n24, Index: 99, Name: "wifitest"}
		a.sockInfo["2a0d:3344:1:2::5"] = ifAddr{IP: net.ParseIP("2a0d:3344:1:2::5"), Net: &net.IPNet{IP: net.ParseIP("2a0d:3344:1:2::"), Mask: net.CIDRMask(128, 128)}, Index: 99, Name: "wifitest"}
	})
	helloPkt := func(c Card) []byte {
		return append(append([]byte{'N', 'N', 1, 'H'}, mustB64(t, c.E)...), helloRaw(c)...)
	}

	// 1. van internet, binnen op de multicastsocket: verzoek "via internet", niet toegelaten
	for _, src := range []string{"203.0.113.9:47474", "192.168.77.9:47474", "[2001:db8:9::1]:47474", "100.64.1.2:47474"} {
		c := strangerCard(t, "Vreemde")
		a.handle(helloPkt(c), udp(src), true)
		a.lock(func() {
			if a.st.Contacts[c.E] != nil {
				t.Fatalf("%s: vanzelf toegelaten als lid", src)
			}
			p := a.st.Pending[c.E]
			if p == nil || p.Source != "internet" || p.Note != "via internet" {
				t.Fatalf("%s: verzoek %+v", src, p)
			}
		})
	}
	// 2. van het eigen subnet / dezelfde /64 / link-local: zelfde wifi (autoLan laat toe)
	for _, src := range []string{"10.77.0.9:47474", "[2a0d:3344:1:2::77]:47474", "169.254.3.4:47474", "[fe80::1234%lo]:47474"} {
		c := strangerCard(t, "Buur")
		a.handle(helloPkt(c), udp(src), true)
		a.lock(func() {
			if a.st.Contacts[c.E] == nil {
				t.Fatalf("%s: niet als zelfde wifi herkend", src)
			}
		})
	}
	// 3. lanProbe: een bekend contact dat zich "meldt" vanaf internet krijgt geen rechtstreekse ping
	b := bareNode(t, "Bert")
	a.lock(func() { know(a.Node, b, "Bert") })
	b.st.Name = "Bert2"
	b.bumpCard()
	a.handle(helloPkt(b.myCard()), udp("203.0.113.10:47474"), true)
	a.lock(func() {
		if a.probeLast[b.myID] != 0 {
			t.Fatal("ping verstuurd naar een internetadres")
		}
		// en de weg wordt nooit "lan" voor een internetadres
		c := a.st.Contacts[b.myID]
		a.markSeen(c, udp("203.0.113.10:47474"), true)
		if c.Via != "star" {
			t.Fatalf("via %q", c.Via)
		}
		a.markSeen(c, udp("10.77.0.10:47474"), true)
		if c.Via != "lan" {
			t.Fatalf("via %q", c.Via)
		}
	})
	b.st.Name = "Bert3"
	b.bumpCard()
	a.handle(helloPkt(b.myCard()), udp("10.77.0.11:47474"), true) // nieuw adres op het eigen netwerk
	a.lock(func() {
		if a.probeLast[b.myID] == 0 {
			t.Fatal("geen ping naar een buur op het eigen netwerk")
		}
	})
}

func mustB64(t *testing.T, s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatal("sleutel", err)
	}
	return b
}

// K4-1c: na stoppen maakt een ronde niets meer (ook geen STUN of doorverwijzing).
func TestNoNetRoundAfterStop(t *testing.T) {
	srv, cnt := fakeSTUN(t, "203.0.113.7:40001")
	a := liveNode(t, "Anna", func(n *Node) { n.nw.servers = []string{srv.LocalAddr().String()} })
	a.releaseNet()
	a.netRound()
	if cnt.Load() != 0 {
		t.Fatalf("%d STUN-verzoeken na stoppen", cnt.Load())
	}
}

// K4-1b: router met alleen vaste doorverwijzingen; een oude doorverwijzing van deze app (na een
// crash) wordt hergebruikt, een dubbele opgeruimd.
func TestUPnPReuseOwnPermanent(t *testing.T) {
	pmTestLoopback = true
	defer func() { pmTestLoopback = false }()
	igd := &fakeIGD{maps: map[string]string{
		"31000": "127.0.0.1:47474/UDP/0/AEROCX Blackout",
		"31001": "127.0.0.1:47474/UDP/0/AEROCX Blackout",
		"8080":  "127.0.0.1:80/TCP/0/iets anders",
	}, ext: "81.82.83.84", fail: map[string]int{}, permOnly: true}
	hs := httptest.NewServer(igd)
	defer hs.Close()
	env := pmEnv{gwPort: 1, ssdpAddr: fakeSSDP(t, hs.URL+"/desc.xml"), timeout: 500 * time.Millisecond}
	m, err := upnpMap(context.Background(), env, loopAddrs(), 47474)
	if err != nil {
		t.Fatal(err)
	}
	igd.mu.Lock()
	defer igd.mu.Unlock()
	if m.Ext.Port != 31000 || !m.Permanent || igd.maps["31001"] != "" || igd.maps["8080"] == "" || len(igd.maps) != 2 {
		t.Fatalf("%+v %v", m, igd.maps)
	}
}
