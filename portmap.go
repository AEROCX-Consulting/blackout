package main

// Zelf een poort openzetten op de thuisrouter, zodat contacten op internet mij rechtstreeks bereiken.
// Volgorde: PCP (RFC 6887) en NAT-PMP (RFC 6886) op UDP 5351 van de gateway, daarna UPnP IGD
// (SSDP + SOAP). Alleen antwoorden van de gateway (PCP/NAT-PMP) of van een privé-adres in het eigen
// subnet (UPnP) worden aanvaard; alles is begrensd in grootte en tijd.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	pmLease     = 3600 // s
	pmPort      = 5351
	pmMaxReply  = 1100
	pcpVersion  = 2
	pcpOpMap    = 1
	natpmpOpMap = 1 // UDP
)

type portMapping struct {
	Method   string // pcp | natpmp | upnp
	Ext      *net.UDPAddr
	Local    net.IP
	Gateway  net.IP
	Lifetime time.Duration
	Got      time.Time
	Port     int // interne poort
	// de router kent alleen vaste doorverwijzingen: open tot de app ze netjes weghaalt
	Permanent bool
	// UPnP
	ctrl, svc string
	// PCP
	nonce [12]byte
}

var errPMNoReply = errors.New("geen antwoord van de router")

// pmExchange: verstuur req naar gw:port vanaf local, met herhaling (250, 500, 1000 ms).
// De socket is "verbonden": het besturingssysteem laat alleen antwoorden van gw:port door.
func pmExchange(ctx context.Context, local, gw net.IP, port int, req []byte, ok func([]byte) bool) ([]byte, error) {
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: local}, &net.UDPAddr{IP: gw, Port: port})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf := make([]byte, pmMaxReply)
	wait := 250 * time.Millisecond
	for try := 0; try < 3; try++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		end := time.Now().Add(wait)
		for {
			conn.SetReadDeadline(end)
			nr, err := conn.Read(buf)
			if err != nil {
				break // time-out (of ICMP "poort dicht"): volgende poging
			}
			if ok(buf[:nr]) {
				return append([]byte{}, buf[:nr]...), nil
			}
		}
		wait *= 2
	}
	return nil, errPMNoReply
}

// ---------- PCP (RFC 6887) ----------

func pcpMapRequest(local net.IP, port, extPort int, lifetime uint32, nonce [12]byte) []byte {
	b := make([]byte, 60)
	b[0] = pcpVersion
	b[1] = pcpOpMap
	binary.BigEndian.PutUint32(b[4:], lifetime)
	copy(b[8:24], local.To16()) // IPv4 als ::ffff:a.b.c.d
	copy(b[24:36], nonce[:])
	b[36] = 17 // UDP
	binary.BigEndian.PutUint16(b[40:], uint16(port))
	binary.BigEndian.PutUint16(b[42:], uint16(extPort))
	copy(b[44:60], net.IPv4zero.To16()) // geen voorkeur voor het externe adres
	return b
}

type pcpResult struct {
	Code     byte
	Lifetime uint32
	Ext      *net.UDPAddr
	OldVer   bool // de router kent alleen NAT-PMP
}

// parsePCPMapResponse controleert versie, opcode, nonce, protocol en poort.
func parsePCPMapResponse(b []byte, nonce [12]byte, port int) (*pcpResult, error) {
	if len(b) >= 2 && b[0] == 0 && b[1]&0x80 != 0 {
		return &pcpResult{OldVer: true}, nil // NAT-PMP-antwoord: "versie niet ondersteund"
	}
	if len(b) < 60 || len(b) > pmMaxReply || len(b)%4 != 0 {
		return nil, errors.New("pcp: verkeerde lengte")
	}
	if b[0] != pcpVersion || b[1] != 0x80|pcpOpMap {
		return nil, errors.New("pcp: geen MAP-antwoord")
	}
	r := &pcpResult{Code: b[3], Lifetime: binary.BigEndian.Uint32(b[4:])}
	if r.Code != 0 {
		return r, fmt.Errorf("pcp: router weigert (code %d)", r.Code)
	}
	var got [12]byte
	copy(got[:], b[24:36])
	if got != nonce || b[36] != 17 || int(binary.BigEndian.Uint16(b[40:])) != port {
		return nil, errors.New("pcp: antwoord hoort niet bij mijn vraag")
	}
	if r.Lifetime == 0 {
		return r, nil // verwijderd
	}
	ext := net.IP(append([]byte{}, b[44:60]...))
	extPort := int(binary.BigEndian.Uint16(b[42:]))
	if ext.To4() == nil || extPort == 0 {
		return nil, errors.New("pcp: geen bruikbaar extern adres")
	}
	r.Ext = &net.UDPAddr{IP: ext.To4(), Port: extPort}
	return r, nil
}

func pcpMap(ctx context.Context, local, gw net.IP, gport, port int, lifetime uint32, nonce [12]byte) (*pcpResult, error) {
	req := pcpMapRequest(local, port, port, lifetime, nonce)
	var res *pcpResult
	var perr error
	_, err := pmExchange(ctx, local, gw, gport, req, func(b []byte) bool {
		r, err := parsePCPMapResponse(b, nonce, port)
		if r == nil && err != nil {
			return false // hoort niet bij ons: verder wachten
		}
		res, perr = r, err
		return true
	})
	if err != nil {
		return nil, err
	}
	return res, perr
}

// ---------- NAT-PMP (RFC 6886) ----------

func natpmpMapRequest(port, extPort int, lifetime uint32) []byte {
	b := make([]byte, 12)
	b[0], b[1] = 0, natpmpOpMap
	binary.BigEndian.PutUint16(b[4:], uint16(port))
	binary.BigEndian.PutUint16(b[6:], uint16(extPort))
	binary.BigEndian.PutUint32(b[8:], lifetime)
	return b
}

// parseNATPMPMapResponse: 16 bytes, versie 0, opcode 129, resultaat 0, onze interne poort.
func parseNATPMPMapResponse(b []byte, port int) (extPort int, lifetime uint32, err error) {
	if len(b) < 16 || b[0] != 0 || b[1] != 128+natpmpOpMap {
		return 0, 0, errors.New("nat-pmp: geen map-antwoord")
	}
	if code := binary.BigEndian.Uint16(b[2:]); code != 0 {
		return 0, 0, fmt.Errorf("nat-pmp: router weigert (code %d)", code)
	}
	if int(binary.BigEndian.Uint16(b[8:])) != port {
		return 0, 0, errors.New("nat-pmp: antwoord voor een andere poort")
	}
	return int(binary.BigEndian.Uint16(b[10:])), binary.BigEndian.Uint32(b[12:]), nil
}

// parseNATPMPAddrResponse: antwoord op "extern adres?" (12 bytes, opcode 128).
func parseNATPMPAddrResponse(b []byte) (net.IP, error) {
	if len(b) < 12 || b[0] != 0 || b[1] != 128 {
		return nil, errors.New("nat-pmp: geen adres-antwoord")
	}
	if code := binary.BigEndian.Uint16(b[2:]); code != 0 {
		return nil, fmt.Errorf("nat-pmp: router weigert (code %d)", code)
	}
	return net.IPv4(b[8], b[9], b[10], b[11]).To4(), nil
}

func natpmpMap(ctx context.Context, local, gw net.IP, gport, port int, lifetime uint32) (*net.UDPAddr, uint32, error) {
	ab, err := pmExchange(ctx, local, gw, gport, []byte{0, 0}, func(b []byte) bool { return len(b) >= 2 && b[0] == 0 && b[1] == 128 })
	if err != nil {
		return nil, 0, err
	}
	ext, err := parseNATPMPAddrResponse(ab)
	if err != nil {
		return nil, 0, err
	}
	mb, err := pmExchange(ctx, local, gw, gport, natpmpMapRequest(port, port, lifetime), func(b []byte) bool {
		return len(b) >= 2 && b[0] == 0 && b[1] == 128+natpmpOpMap
	})
	if err != nil {
		return nil, 0, err
	}
	extPort, life, err := parseNATPMPMapResponse(mb, port)
	if err != nil {
		return nil, 0, err
	}
	if lifetime > 0 && (extPort == 0 || life == 0) {
		return nil, 0, errors.New("nat-pmp: geen poort gekregen")
	}
	return &net.UDPAddr{IP: ext, Port: extPort}, life, nil
}

// publicIPv4: een adres dat op internet bruikbaar is (geen privé, CGNAT, link-local …).
func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10 (CGNAT, ook Starlink)
			return false
		}
		if v4[0] == 0 || v4[0] >= 240 {
			return false
		}
		return true
	}
	return ip.IsGlobalUnicast()
}

// ---------- samen ----------

type pmEnv struct {
	gwPort   int // 5351 (tests: andere poort)
	ssdpAddr string
	timeout  time.Duration
}

// tryPortMap probeert PCP, NAT-PMP en UPnP. gws: mogelijke gateways (eerste = van het systeem).
func tryPortMap(ctx context.Context, env pmEnv, addrs []ifAddr, gws []net.IP, port int, prevNonce *[12]byte) (*portMapping, error) {
	var lastErr error = errors.New("geen router gevonden")
	for _, gw := range gws {
		la := localFor(addrs, gw)
		if la == nil {
			continue
		}
		var nonce [12]byte
		if prevNonce != nil {
			nonce = *prevNonce // vernieuwen: dezelfde nonce (RFC 6887 §11.2)
		} else {
			rand.Read(nonce[:])
		}
		r, err := pcpMap(ctx, la.IP, gw, env.gwPort, port, pmLease, nonce)
		if err == nil && r != nil && r.Ext != nil {
			if !publicIP(r.Ext.IP) {
				lastErr = errors.New("de router heeft zelf geen publiek adres")
				continue
			}
			return &portMapping{Method: "pcp", Ext: r.Ext, Local: la.IP, Gateway: gw, Port: port,
				Lifetime: time.Duration(r.Lifetime) * time.Second, Got: time.Now(), nonce: nonce}, nil
		}
		if err == errPMNoReply {
			lastErr = err
			continue // poort 5351 zwijgt: ook NAT-PMP heeft geen zin
		}
		ext, life, err := natpmpMap(ctx, la.IP, gw, env.gwPort, port, pmLease)
		if err == nil {
			if !publicIP(ext.IP) {
				lastErr = errors.New("de router heeft zelf geen publiek adres")
				continue
			}
			return &portMapping{Method: "natpmp", Ext: ext, Local: la.IP, Gateway: gw, Port: port,
				Lifetime: time.Duration(life) * time.Second, Got: time.Now()}, nil
		}
		lastErr = err
	}
	m, err := upnpMap(ctx, env, addrs, port)
	if err == nil {
		return m, nil
	}
	if lastErr == errPMNoReply || lastErr == nil {
		lastErr = err
	}
	return nil, lastErr
}

// releasePortMap haalt de doorverwijzing weg (bij netjes stoppen of als de instelling uitgaat).
func releasePortMap(ctx context.Context, env pmEnv, m *portMapping) error {
	if m == nil {
		return nil
	}
	switch m.Method {
	case "pcp":
		_, err := pcpMap(ctx, m.Local, m.Gateway, env.gwPort, m.Port, 0, m.nonce)
		return err
	case "natpmp":
		_, err := pmExchange(ctx, m.Local, m.Gateway, env.gwPort, natpmpMapRequest(m.Port, 0, 0), func(b []byte) bool {
			return len(b) >= 2 && b[0] == 0 && b[1] == 128+natpmpOpMap
		})
		return err
	case "upnp":
		_, err := soapCall(ctx, m.ctrl, m.svc, "DeletePortMapping", [][2]string{
			{"NewRemoteHost", ""}, {"NewExternalPort", fmt.Sprint(m.Ext.Port)}, {"NewProtocol", "UDP"}})
		return err
	}
	return nil
}
