package main

// Eigen adressen per interface, en ontdekking op het lokale netwerk (multicast).
//
// Zelfde wifi zonder internet: er is dan vaak geen standaardroute. Lid worden van een multicastgroep
// "op de standaardinterface" mislukt dan (Linux: "no such device"). Daarom: lid worden op ELKE
// geschikte interface apart (IPv4 239.255.47.47 en IPv6 ff02::4747, poort 47475), opnieuw als de
// interfaces wijzigen, en de hello's per interface versturen vanaf de eigen socket op poort 47474
// (dan weet de ontvanger meteen het juiste adres en de juiste poort, ook link-local).

import (
	"context"
	"crypto/sha256"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	mcastGroup6 = "[ff02::4747]:47475"
	maxSocks    = 16
)

// ifAddr is één eigen adres met zijn interface.
type ifAddr struct {
	IP    net.IP
	Net   *net.IPNet
	Index int
	Name  string
	LL    bool // link-local (fe80::/10 of 169.254/16): niet in de kaart, alleen op dit netwerk
	Loop  bool
}

func (a ifAddr) v4() bool { return a.IP.To4() != nil }

// key is de sleutel van de socket: het adres, met de interface erbij voor link-local IPv6.
func (a ifAddr) key() string {
	if a.LL && !a.v4() {
		return a.IP.String() + "%" + a.Name
	}
	return a.IP.String()
}

func (a ifAddr) udpAddr(port int) *net.UDPAddr {
	ua := &net.UDPAddr{IP: a.IP, Port: port}
	if a.LL && !a.v4() {
		ua.Zone = a.Name
	}
	return ua
}

// lanCapable: een interface waarop buren kunnen zitten (wifi, ethernet), geen tunnel.
func lanCapable(f net.Flags) bool {
	return f&net.FlagUp != 0 && f&net.FlagMulticast != 0 && f&net.FlagLoopback == 0 && f&net.FlagPointToPoint == 0
}

// listIfAddrs is een variabele zodat tests een vaste lijst kunnen geven.
var listIfAddrs = func(loopback bool) []ifAddr {
	var out []ifAddr
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if x := classifyAddr(ipn, ifc, loopback); x != nil {
				out = append(out, *x)
			}
		}
	}
	return sortIfAddrs(out)
}

func classifyAddr(ipn *net.IPNet, ifc net.Interface, loopback bool) *ifAddr {
	ip := ipn.IP
	if ip.IsMulticast() || ip.IsUnspecified() {
		return nil
	}
	x := &ifAddr{IP: ip, Net: ipn, Index: ifc.Index, Name: ifc.Name}
	switch {
	case ip.IsLoopback():
		if !loopback {
			return nil
		}
		x.Loop = true
	case ip.IsLinkLocalUnicast():
		if !lanCapable(ifc.Flags) {
			return nil // link-local op tunnels (utun, awdl …) heeft geen zin
		}
		x.LL = true
	case ip.To4() == nil && !ip.IsGlobalUnicast():
		return nil
	}
	return x
}

// sortIfAddrs: publiek IPv6 eerst (Starlink/glasvezel), dan IPv4, link-local als laatste.
func sortIfAddrs(in []ifAddr) []ifAddr {
	rank := func(a ifAddr) int {
		switch {
		case a.LL:
			return 3
		case a.v4():
			return 1
		default:
			return 0
		}
	}
	sort.SliceStable(in, func(i, j int) bool { return rank(in[i]) < rank(in[j]) })
	if len(in) > maxSocks {
		in = in[:maxSocks]
	}
	return in
}

// localIPs: de eigen adressen zonder link-local (voor de webadressen van het scherm).
func localIPs(loopback bool) []net.IP {
	var out []net.IP
	for _, a := range listIfAddrs(loopback) {
		if !a.LL {
			out = append(out, a.IP)
		}
	}
	return out
}

// ---------- multicast ----------

type mcastState struct {
	conn4, conn6 *net.UDPConn
	joined       map[string]string // "4|<index>" -> handtekening van de interface
	failLog      map[string]bool
	dedup        map[[16]byte]time.Time
	last         time.Time
}

func (n *Node) mcPort() int {
	if n.mcastPort != 0 {
		return n.mcastPort
	}
	return 47475
}

func (n *Node) mcGroup4() *net.UDPAddr {
	g, _ := net.ResolveUDPAddr("udp4", mcastGroup)
	g.Port = n.mcPort()
	return g
}

func (n *Node) mcGroup6(zone string) *net.UDPAddr {
	g, _ := net.ResolveUDPAddr("udp6", mcastGroup6)
	g.Port = n.mcPort()
	g.Zone = zone
	return g
}

func (n *Node) mcLog(key, msg string) {
	if n.mc.failLog == nil {
		n.mc.failLog = map[string]bool{}
	}
	if !n.mc.failLog[key] {
		n.mc.failLog[key] = true
		log.Print(msg)
	}
}

// mcastRefresh (onder slot): ontvangstsockets openen en op elke geschikte interface lid worden.
// Een interface die wegviel of een ander adres kreeg, wordt opnieuw aangemeld.
func (n *Node) mcastRefresh(addrs []ifAddr) {
	if n.noLAN {
		return
	}
	if n.mc.joined == nil {
		n.mc.joined = map[string]string{}
	}
	type ifc struct {
		index int
		name  string
		v4    net.IP
		sig4  []string
		has6  bool
	}
	ifs := map[int]*ifc{}
	for _, a := range addrs {
		if a.Loop {
			continue
		}
		x := ifs[a.Index]
		if x == nil {
			x = &ifc{index: a.Index, name: a.Name}
			ifs[a.Index] = x
		}
		if a.v4() {
			if x.v4 == nil || (x.v4.IsLinkLocalUnicast() && !a.LL) {
				x.v4 = a.IP
			}
			x.sig4 = append(x.sig4, a.IP.String())
		} else {
			x.has6 = true
		}
	}
	port := strconv.Itoa(n.mcPort())
	if n.mc.conn4 == nil {
		if c, err := listenReuseUDP("udp4", "0.0.0.0:"+port); err == nil {
			n.mc.conn4 = c
			n.mc.joined = map[string]string{}
			go n.readLoop(c, true)
		} else {
			n.mcLog("l4", "zoeken op het lokale netwerk (IPv4) werkt niet: "+err.Error())
		}
	}
	if n.mc.conn6 == nil {
		if c, err := listenReuseUDP("udp6", "[::]:"+port); err == nil {
			n.mc.conn6 = c
			go n.readLoop(c, true)
		} else {
			n.mcLog("l6", "zoeken op het lokale netwerk (IPv6) werkt niet: "+err.Error())
		}
	}
	g4 := n.mcGroup4().IP
	g6 := n.mcGroup6("").IP
	seen := map[string]bool{}
	for _, x := range ifs {
		if x.v4 != nil && n.mc.conn4 != nil {
			k := "4|" + strconv.Itoa(x.index)
			sig := x.name + "|" + strings.Join(x.sig4, ",")
			seen[k] = true
			if old, ok := n.mc.joined[k]; !ok || old != sig {
				rawSock(n.mc.conn4, func(fd uintptr) error { return sockJoin4(fd, g4, x.v4, false) }) // oude aanmelding weg (fout = niets)
				err := rawSock(n.mc.conn4, func(fd uintptr) error { return sockJoin4(fd, g4, x.v4, true) })
				if err == nil || isAddrInUse(err) {
					n.mc.joined[k] = sig
					log.Printf("zoeken op het lokale netwerk via %s (%s)", x.name, x.v4)
				} else {
					n.mcLog("j"+k+sig, "aanmelden op "+x.name+" (IPv4) mislukt: "+err.Error())
				}
			}
		}
		if x.has6 && n.mc.conn6 != nil {
			k := "6|" + strconv.Itoa(x.index)
			seen[k] = true
			if _, ok := n.mc.joined[k]; !ok {
				err := rawSock(n.mc.conn6, func(fd uintptr) error { return sockJoin6(fd, g6, x.index, true) })
				if err == nil || isAddrInUse(err) {
					n.mc.joined[k] = x.name
				} else {
					n.mcLog("j"+k, "aanmelden op "+x.name+" (IPv6) mislukt: "+err.Error())
				}
			}
		}
	}
	for k := range n.mc.joined {
		if !seen[k] {
			delete(n.mc.joined, k) // interface weg: het besturingssysteem ruimt het lidmaatschap op
		}
	}
}

// rawSock voert f uit op de bestandsdescriptor van de socket.
func rawSock(c *net.UDPConn, f func(fd uintptr) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(fd) }); err != nil {
		return err
	}
	return ferr
}

// mcastHello (onder slot): per interface en per familie één hello naar de groep, vanaf de eigen
// socket op poort 47474 (IPv6: liefst het link-local adres, dat er altijd is).
func (n *Node) mcastHello() {
	if n.noLAN {
		return
	}
	pick := map[string]string{} // "4|idx" / "6|idx" -> socketsleutel
	for k, a := range n.sockInfo {
		if a.Loop || n.socks[k] == nil {
			continue
		}
		fam := "6|"
		if a.v4() {
			fam = "4|"
		}
		pk := fam + strconv.Itoa(a.Index)
		cur, ok := pick[pk]
		if !ok {
			pick[pk] = k
			continue
		}
		ca := n.sockInfo[cur]
		// IPv4: liefst geen link-local; IPv6: liefst link-local
		if (a.v4() && ca.LL && !a.LL) || (!a.v4() && a.LL && !ca.LL) || (a.LL == ca.LL && k < cur) {
			pick[pk] = k
		}
	}
	p := n.helloPkt()
	for pk, k := range pick {
		a := n.sockInfo[k]
		if strings.HasPrefix(pk, "4|") {
			n.socks[k].WriteToUDP(p, n.mcGroup4())
		} else {
			n.socks[k].WriteToUDP(p, n.mcGroup6(a.Name))
		}
	}
}

// mcastDup: hetzelfde multicastpakket binnen 3 s opnieuw (meerdere interfaces op hetzelfde net).
func (n *Node) mcastDup(pkt []byte) bool {
	n.mcMu.Lock()
	defer n.mcMu.Unlock()
	t := time.Now()
	if n.mc.dedup == nil {
		n.mc.dedup = map[[16]byte]time.Time{}
	}
	if t.Sub(n.mc.last) > 5*time.Second || len(n.mc.dedup) > 512 {
		for k, ts := range n.mc.dedup {
			if t.Sub(ts) > 3*time.Second {
				delete(n.mc.dedup, k)
			}
		}
		n.mc.last = t
	}
	h := sha256.Sum256(pkt)
	var k [16]byte
	copy(k[:], h[:16])
	if ts, ok := n.mc.dedup[k]; ok && t.Sub(ts) < 3*time.Second {
		return true
	}
	if len(n.mc.dedup) < 1024 {
		n.mc.dedup[k] = t
	}
	return false
}

// lanProbe (onder slot): een bekend contact meldt zich op het lokale netwerk vanaf een adres dat ik
// nog niet gebruik (bv. link-local zonder router). Stuur daar rechtstreeks een ping heen; zijn
// antwoord voegt het adres toe. Hooguit om de 10 s per contact.
func (n *Node) lanProbe(c *Contact, from *net.UDPAddr) {
	if c == nil || c.Blocked || from == nil {
		return
	}
	a := from.String()
	t := now()
	if ts, ok := c.Observed[a]; ok && t-ts < 60 {
		return
	}
	if n.probeLast == nil {
		n.probeLast = map[string]int64{}
	}
	if t-n.probeLast[c.ID] < 10 {
		return
	}
	n.probeLast[c.ID] = t
	n.writeAll(n.sealJSON(c, n.pingWire("ping")), from)
}

// listenReuseUDP: een UDP-socket die de poort mag delen (meerdere programma's/tests op één toestel).
func listenReuseUDP(network, addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = setReuse(fd) }); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// onLink (onder slot): ligt ip op een van mijn eigen netwerken? Link-local (fe80::/10, 169.254/16),
// dit toestel zelf (loopback), IPv4 in het subnet van een eigen interface, IPv6 in dezelfde /64 als
// een eigen adres (ook fc00::/7). Alleen dit bepaalt "zelfde wifi-netwerk", autoLan en de weg "lan".
func (n *Node) onLink(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return true
	}
	v4 := ip.To4() != nil
	m64 := net.CIDRMask(64, 128)
	for _, a := range n.sockInfo { // alleen adressen met een open socket (refreshAddrs houdt dit bij)
		if a.LL || a.Loop || a.Net == nil || a.v4() != v4 {
			continue
		}
		if v4 {
			if a.Net.Contains(ip) {
				return true
			}
		} else if a.IP.Mask(m64).Equal(ip.Mask(m64)) {
			return true
		}
	}
	return false
}
