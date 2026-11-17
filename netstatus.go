package main

// Bereikbaarheid over gewoon internet: publiek adres (STUN), poort op de router (PCP/NAT-PMP/UPnP),
// Starlink-schotel herkennen, en de status voor /api/state ("net").
// Elke 5 minuten en meteen na een netwerkwijziging.

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	netEvery      = 5 * time.Minute
	starlinkDish  = "192.168.100.1:9200" // gRPC van de schotel (alleen een HTTP/2-handdruk, geen opdracht)
	stunWaitTotal = 2500 * time.Millisecond
)

type stunTx struct {
	server *net.UDPAddr
	conn   *net.UDPConn
	sock   string
	res    *net.UDPAddr
}

type netWatch struct {
	mu       sync.Mutex
	kickC    chan struct{}
	manual   bool // tests: geen automatische rondes
	servers  []string
	env      pmEnv
	tx       map[stunTxID]*stunTx
	stun     string // bezig | ok | mislukt | uit
	stunPub  []string
	stunSym  bool // per server een andere poort: rechtstreeks verbinden lukt dan zelden
	stunAt   time.Time
	pm       *portMapping
	pmStatus string // bezig | upnp | natpmp | pcp | uit | niet ondersteund
	pmKey    string
	pmTried  time.Time
	starlink bool
	dish     string
	running  bool
	closed   bool // na stoppen: geen nieuwe doorverwijzing meer maken
}

func newNetWatch() *netWatch {
	return &netWatch{kickC: make(chan struct{}, 1), servers: defaultStunServers, tx: map[stunTxID]*stunTx{},
		stun: "bezig", pmStatus: "bezig", dish: starlinkDish, env: pmEnv{gwPort: pmPort, ssdpAddr: ssdpAddr}}
}

func (w *netWatch) kick() {
	select {
	case w.kickC <- struct{}{}:
	default:
	}
}

// cardAddrs: publieke adressen voor in mijn kaart (STUN en de poort op de router).
func (w *netWatch) cardAddrs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	if w.pm != nil && w.pm.Ext != nil {
		out = append(out, w.pm.Ext.String())
	}
	for _, a := range w.stunPub {
		if !contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// onSTUN: een STUN-antwoord op een van mijn sockets. Alleen aanvaard als de transactie bestaat,
// het antwoord van dezelfde server komt en op dezelfde socket binnenkomt.
func (w *netWatch) onSTUN(pkt []byte, from *net.UDPAddr, conn *net.UDPConn) {
	id := stunTxOf(pkt)
	w.mu.Lock()
	defer w.mu.Unlock()
	tx := w.tx[id]
	if tx == nil || tx.conn != conn || tx.res != nil || from.Port != tx.server.Port || !from.IP.Equal(tx.server.IP) {
		return
	}
	if a, err := parseSTUNResponse(pkt, id); err == nil {
		tx.res = a
	}
}

func resolveStun(ctx context.Context, servers []string) []*net.UDPAddr {
	var out []*net.UDPAddr
	for _, s := range servers {
		host, ps, err := net.SplitHostPort(s)
		if err != nil {
			host, ps = s, strconv.Itoa(stunDefaultPort)
		}
		port, err := strconv.Atoi(ps)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		var ips []net.IP
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			ias, _ := net.DefaultResolver.LookupIPAddr(c, host)
			cancel()
			for _, ia := range ias {
				ips = append(ips, ia.IP)
			}
		}
		var has4, has6 bool
		for _, ip := range ips {
			if ip.To4() != nil && !has4 {
				has4 = true
				out = append(out, &net.UDPAddr{IP: ip.To4(), Port: port})
			} else if ip.To4() == nil && !has6 {
				has6 = true
				out = append(out, &net.UDPAddr{IP: ip, Port: port})
			}
		}
	}
	return out
}

// stunRound vraagt vanaf elke eigen socket (geen link-local) aan elke server het publieke adres.
// Geeft het aantal antwoorden en de publieke adressen die per socket overeenstemmen.
func (n *Node) stunRound(ctx context.Context) (answers int, pub []string, sym bool) {
	w := n.nw
	w.mu.Lock()
	servers := append([]string{}, w.servers...)
	w.mu.Unlock()
	dsts := resolveStun(ctx, servers)
	if len(dsts) == 0 {
		return 0, nil, false
	}
	type sk struct {
		key  string
		conn *net.UDPConn
		la   *net.UDPAddr
	}
	var socks []sk
	n.mu.Lock()
	for k, c := range n.socks {
		a := n.sockInfo[k]
		if a.LL {
			continue
		}
		socks = append(socks, sk{k, c, c.LocalAddr().(*net.UDPAddr)})
	}
	n.mu.Unlock()
	type out struct {
		id  stunTxID
		pkt []byte
		tx  *stunTx
	}
	var sent []out
	w.mu.Lock()
	for _, s := range socks {
		for _, d := range dsts {
			if (d.IP.To4() != nil) != (s.la.IP.To4() != nil) || d.IP.IsLoopback() != s.la.IP.IsLoopback() {
				continue
			}
			if len(w.tx) >= 64 {
				break
			}
			id := newStunTxID()
			tx := &stunTx{server: d, conn: s.conn, sock: s.key}
			w.tx[id] = tx
			sent = append(sent, out{id, stunRequest(id), tx})
		}
	}
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		for _, o := range sent {
			delete(w.tx, o.id)
		}
		w.mu.Unlock()
	}()
	send := func() {
		for _, o := range sent {
			w.mu.Lock()
			done := o.tx.res != nil
			w.mu.Unlock()
			if !done {
				o.tx.conn.WriteToUDP(o.pkt, o.tx.server)
			}
		}
	}
	send()
	deadline := time.Now().Add(stunWaitTotal)
	resent := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
		w.mu.Lock()
		all := true
		for _, o := range sent {
			if o.tx.res == nil {
				all = false
				break
			}
		}
		w.mu.Unlock()
		if all {
			break
		}
		if !resent && time.Until(deadline) < stunWaitTotal-800*time.Millisecond {
			resent = true
			send()
		}
	}
	w.mu.Lock()
	perSock := map[string]map[string]bool{}
	for _, o := range sent {
		if o.tx.res == nil {
			continue
		}
		answers++
		if perSock[o.tx.sock] == nil {
			perSock[o.tx.sock] = map[string]bool{}
		}
		perSock[o.tx.sock][o.tx.res.String()] = true
	}
	w.mu.Unlock()
	keys := make([]string, 0, len(perSock))
	for k := range perSock {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m := perSock[k]
		if len(m) != 1 {
			sym = true // wisselende poort per bestemming
			continue
		}
		for a := range m {
			ua, err := net.ResolveUDPAddr("udp", a)
			if err == nil && (publicIP(ua.IP) || ua.IP.IsLoopback()) && !contains(pub, a) && len(pub) < 4 {
				pub = append(pub, a)
			}
		}
	}
	return answers, pub, sym
}

// probeStarlink: antwoordt de schotel (192.168.100.1:9200) met een HTTP/2-SETTINGS-frame?
// Alleen de verbindingshanddruk; er wordt niets gevraagd of veranderd.
func probeStarlink(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 700 * time.Millisecond}
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(900 * time.Millisecond))
	pre := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)
	if _, err := c.Write(pre); err != nil {
		return false
	}
	h := make([]byte, 9)
	for got := 0; got < 9; {
		nr, err := c.Read(h[got:])
		if err != nil {
			return false
		}
		got += nr
	}
	ln := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
	return h[3] == 4 && h[4]&1 == 0 && binary.BigEndian.Uint32(h[5:])&0x7fffffff == 0 && ln%6 == 0 && ln <= 16384
}

func (n *Node) netLoop() {
	for {
		n.netRound()
		select {
		case <-n.nw.kickC:
			time.Sleep(2 * time.Second) // netwerk eerst laten stabiliseren
			select {
			case <-n.nw.kickC:
			default:
			}
		case <-time.After(netEvery):
		case <-n.quit:
			return
		}
	}
}

// netRound: één ronde STUN + poort op de router + Starlink. Houdt het globale slot niet vast
// tijdens netwerkverkeer.
func (n *Node) netRound() {
	w := n.nw
	w.mu.Lock()
	if w.running || w.closed {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	n.mu.Lock()
	stunOn, pmOn := !n.st.Policy.StunOff, !n.st.Policy.PortmapOff
	var addrs []ifAddr
	for k, a := range n.sockInfo {
		if n.socks[k] != nil {
			addrs = append(addrs, a)
		}
	}
	port := n.udpPort
	n.mu.Unlock()

	// 1. publiek adres
	var ans int
	var pub []string
	var sym bool
	if stunOn {
		ans, pub, sym = n.stunRound(ctx)
	}
	w.mu.Lock()
	oldStun, oldPub := w.stun, strings.Join(w.stunPub, ",")
	switch {
	case !stunOn:
		w.stun, w.stunPub, w.stunSym = "uit", nil, false
	case ans > 0:
		w.stun, w.stunPub, w.stunSym, w.stunAt = "ok", pub, sym, time.Now()
	default:
		w.stun, w.stunPub, w.stunSym = "mislukt", nil, false
	}
	newStun, newPub := w.stun, strings.Join(w.stunPub, ",")
	w.mu.Unlock()

	// 2. poort op de router
	pmMsg := n.portmapRound(ctx, pmOn, addrs, port)

	// 3. Starlink-schotel
	sl := probeStarlink(ctx, w.dish)
	w.mu.Lock()
	oldSL := w.starlink
	w.starlink = sl
	dish := w.dish
	w.mu.Unlock()

	n.mu.Lock()
	n.applyAddrs()
	if newStun != oldStun || newPub != oldPub {
		switch {
		case newStun == "ok" && newPub != "":
			n.event("netwerk", "Publiek adres gevonden: "+newPub)
		case newStun == "ok" && sym:
			n.event("netwerk", "Internet werkt, maar je router geeft elke keer een andere poort: contacten op internet bereiken je vooral als zij een open poort hebben")
		case newStun == "ok":
			n.event("netwerk", "Internet werkt (publiek adres niet rechtstreeks bruikbaar)")
		case newStun == "mislukt" && oldStun == "ok":
			n.event("netwerk", "Geen antwoord meer van internet")
		}
	}
	if pmMsg != "" {
		n.event("netwerk", pmMsg)
	}
	if sl != oldSL && sl {
		n.event("netwerk", "Starlink-schotel gevonden ("+strings.Split(dish, ":")[0]+")")
	}
	n.mu.Unlock()
}

// portmapRound: poort openzetten, vernieuwen (na de helft van de lease) of weghalen. Geeft een
// logboekregel terug als er iets veranderde.
func (n *Node) portmapRound(ctx context.Context, on bool, addrs []ifAddr, port int) string {
	w := n.nw
	w.mu.Lock()
	cur, env := w.pm, w.env
	w.mu.Unlock()
	if !on {
		if cur != nil {
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			releasePortMap(c, env, cur)
			cancel()
		}
		w.mu.Lock()
		w.pm, w.pmStatus, w.pmKey = nil, "uit", ""
		w.mu.Unlock()
		if cur != nil {
			return "Poort op de router weer gesloten"
		}
		return ""
	}
	var gws []net.IP
	if g := osGateway(); g != nil && g.IsPrivate() {
		gws = append(gws, g)
	}
	if len(gws) == 0 {
		gws = guessGateways(addrs)
		if len(gws) > 3 {
			gws = gws[:3]
		}
	}
	var kp []string
	for _, g := range gws {
		kp = append(kp, g.String())
	}
	for _, a := range addrs {
		if a.v4() && !a.LL && !a.Loop {
			kp = append(kp, a.IP.String())
		}
	}
	sort.Strings(kp)
	key := strings.Join(kp, ",")
	w.mu.Lock()
	fresh := cur != nil && key == w.pmKey && time.Since(cur.Got) < cur.Lifetime/2
	retryLater := cur == nil && key == w.pmKey && w.pmStatus == "niet ondersteund" && time.Since(w.pmTried) < 30*time.Minute
	w.mu.Unlock()
	if fresh || retryLater {
		return ""
	}
	if cur != nil && key != w.pmKey { // ander netwerk: oude doorverwijzing weg
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		releasePortMap(c, env, cur)
		cancel()
		cur = nil
	}
	var prevNonce *[12]byte
	if cur != nil && cur.Method == "pcp" {
		prevNonce = &cur.nonce
	}
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return ""
	}
	m, err := tryPortMap(ctx, env, addrs, gws, port, prevNonce)
	w.mu.Lock()
	if w.closed && m != nil { // intussen gestopt: deze doorverwijzing meteen weer weghalen
		w.mu.Unlock()
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		releasePortMap(c, env, m)
		cancel()
		return ""
	}
	defer w.mu.Unlock()
	w.pmKey, w.pmTried = key, time.Now()
	old := w.pmStatus
	if err != nil {
		w.pm, w.pmStatus = nil, "niet ondersteund"
		if old != w.pmStatus {
			log.Printf("poort op de router openzetten lukt niet: %v", err)
			if cur != nil {
				return "De open poort op de router is verdwenen"
			}
		}
		return ""
	}
	w.pm, w.pmStatus = m, m.Method
	if cur == nil || cur.Ext.String() != m.Ext.String() {
		return fmt.Sprintf("Poort open op de router (%s): contacten op internet bereiken je via %s", pmName(m.Method), m.Ext)
	}
	return ""
}

func pmName(m string) string {
	switch m {
	case "upnp":
		return "UPnP"
	case "natpmp":
		return "NAT-PMP"
	case "pcp":
		return "PCP"
	}
	return m
}

// releaseNet: bij netjes stoppen de poort op de router weer sluiten (max. 2 s).
func (n *Node) releaseNet() {
	w := n.nw
	w.mu.Lock()
	m, env := w.pm, w.env
	w.pm = nil
	w.closed = true // een lopende ronde maakt geen nieuwe doorverwijzing meer
	w.mu.Unlock()
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := releasePortMap(ctx, env, m); err != nil {
		log.Printf("poort op de router sluiten mislukt: %v", err)
	} else {
		log.Printf("poort op de router gesloten")
	}
}

// netJSON (onder slot): de "net"-status voor /api/state.
func (n *Node) netJSON() map[string]any {
	w := n.nw
	ipv6, lan := false, false
	var pub []string
	for k, a := range n.sockInfo {
		if n.socks[k] == nil || a.Loop {
			continue
		}
		if a.LL || a.IP.IsPrivate() {
			lan = true
		}
		if !a.v4() && !a.LL && publicIP(a.IP) {
			ipv6 = true
			if s := net.JoinHostPort(a.IP.String(), strconv.Itoa(n.udpPort)); len(pub) < 6 {
				pub = append(pub, s)
			}
		}
	}
	sort.Strings(pub)
	starOnline := false
	t := now()
	for _, c := range n.st.Contacts {
		if !c.Blocked && c.Via == "star" && t-c.LastSeen < onlineSecs {
			starOnline = true
		}
	}
	osintNet := n.osint != nil && n.osint.InternetSeen(20*time.Minute)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, a := range w.stunPub {
		if !contains(pub, a) {
			pub = append([]string{a}, pub...)
		}
	}
	portOpen := w.pm != nil && w.pm.Ext != nil
	if portOpen && !contains(pub, w.pm.Ext.String()) {
		pub = append([]string{w.pm.Ext.String()}, pub...)
	}
	if pub == nil {
		pub = []string{}
	}
	// Internet is er als we het ergens aan zien: STUN lukte, een open poort, een contact via internet,
	// of een OSINT-internetbron die recent iets ophaalde. Een Starlink-schotel of IPv6-adres alleen
	// is geen bewijs (bij een storing blijven die zichtbaar).
	internet := w.stun == "ok" || portOpen || starOnline || osintNet
	out := map[string]any{
		"internet": internet, "ipv6Global": ipv6, "publicAddrs": pub, "stun": w.stun, "portmap": w.pmStatus,
		"starlink": w.starlink, "lan": lan, "portOpen": portOpen, "changingPort": w.stunSym,
		"portPermanent": portOpen && w.pm.Permanent,
	}
	if !w.stunAt.IsZero() {
		out["stunAt"] = w.stunAt.UnixMilli()
	}
	return out
}

// netIsStarlink (onder slot): voor de teksten "via Starlink" / "via internet".
func (n *Node) netIsStarlink() bool {
	n.nw.mu.Lock()
	defer n.nw.mu.Unlock()
	return n.nw.starlink
}
