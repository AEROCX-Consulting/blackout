package main

// Toegang tot het webscherm vanaf andere toestellen: pincode, blokkering bij raden,
// alleen vanaf privé-netwerken, sessies die verlopen, en beveiligingskoppen.

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	pinMaxFails   = 5
	pinFirstLock  = time.Minute
	pinMaxLock    = time.Hour
	sessionIdle   = 30 * 86400 // seconden: sessie vervalt na 30 dagen niet gebruiken
	cspPolicy     = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	msgNotPrivate = "Dit scherm is alleen bereikbaar vanaf je eigen netwerk (thuis-wifi of op deze computer zelf)."
)

// securityHeaders op elk HTTP-antwoord (tegen clickjacking, MIME-raden en lekken van adressen).
func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", cspPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// privateSource: mag dit adres het webscherm gebruiken? Loopback, RFC1918, CGNAT (100.64/10),
// link-local (v4/v6), ULA (fc00::/7) en globale IPv6 in hetzelfde /64 als een eigen adres.
func privateSource(ip net.IP, own []net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.IsPrivate() || cgnatNet.Contains(v4) || v4.IsLinkLocalUnicast()
	}
	if ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	ip16 := ip.To16()
	for _, o := range own {
		o = o.To16()
		if o != nil && o.To4() == nil && o.IsGlobalUnicast() && string(o[:8]) == string(ip16[:8]) {
			return true
		}
	}
	return false
}

// eigen adressen (voor de /64-vergelijking), 30 s bewaard
var ownIPs struct {
	sync.Mutex
	at  time.Time
	ips []net.IP
}

func ownAddrs() []net.IP {
	ownIPs.Lock()
	defer ownIPs.Unlock()
	if time.Since(ownIPs.at) < 30*time.Second && ownIPs.ips != nil {
		return ownIPs.ips
	}
	var out []net.IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
				out = append(out, ipn.IP.To16())
			}
		}
	}
	if out == nil {
		out = []net.IP{}
	}
	ownIPs.ips, ownIPs.at = out, time.Now()
	return out
}

func allowedSource(r *http.Request) bool {
	ip := reqIP(r)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return privateSource(ip, ownAddrs())
}

func normPin(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), " ", "") }

func lockText(d time.Duration) string {
	m := int((d + time.Minute - 1) / time.Minute)
	if m < 1 {
		m = 1
	}
	return fmt.Sprintf("Te veel foute pogingen, probeer opnieuw over %d min", m)
}

// pinAttempt (onder slot): één poging met de pincode, met een globale teller en oplopende blokkering.
// code: 200 goed, 403 verkeerd, 429 geblokkeerd.
func (n *Node) pinAttempt(pin string, r *http.Request) (int, string) {
	t := time.Now()
	if t.Before(n.pinLockUntil) {
		return 429, lockText(n.pinLockUntil.Sub(t))
	}
	pin = normPin(pin)
	if pin != "" && n.st.Pin != "" && subtle.ConstantTimeCompare([]byte(pin), []byte(n.st.Pin)) == 1 {
		n.pinFails = 0
		n.pinLockDur = 0
		return 200, ""
	}
	n.pinFails++
	who := "onbekend adres"
	if ip := reqIP(r); ip != nil {
		who = ip.String()
	}
	if n.pinFails < pinMaxFails {
		n.event("beheer", fmt.Sprintf("Verkeerde pincode vanaf %s (%d/%d)", who, n.pinFails, pinMaxFails))
		return 403, "Verkeerde pincode"
	}
	n.pinFails = 0
	if n.pinLockDur == 0 {
		n.pinLockDur = pinFirstLock
	} else {
		n.pinLockDur *= 2
		if n.pinLockDur > pinMaxLock {
			n.pinLockDur = pinMaxLock
		}
	}
	n.pinLockUntil = t.Add(n.pinLockDur)
	n.audit(fmt.Sprintf("%d keer een verkeerde pincode (laatst vanaf %s): inloggen %d min geblokkeerd", pinMaxFails, who, int(n.pinLockDur/time.Minute)))
	return 429, lockText(n.pinLockDur)
}

// confirmPin: een gevoelige actie vanaf een ander toestel vraagt de pincode opnieuw (veld "pin").
// Op deze computer zelf (localhost) is dat niet nodig.
func (n *Node) confirmPin(w http.ResponseWriter, r *http.Request, pin string) bool {
	if isLocalReq(r) {
		return true
	}
	if normPin(pin) == "" {
		httpErr(w, 403, "Typ de pincode opnieuw om dit vanaf een ander toestel te doen")
		return false
	}
	n.mu.Lock()
	code, msg := n.pinAttempt(pin, r)
	n.mu.Unlock()
	if code == 200 {
		return true
	}
	if code == 403 {
		time.Sleep(time.Second)
	}
	httpErr(w, code, msg)
	return false
}

// expireSessions (onder slot): sessies die 30 dagen niet gebruikt zijn, vervallen.
func (n *Node) expireSessions() {
	t := now()
	for tok, s := range n.st.Sessions {
		if t-s.Seen > sessionIdle {
			delete(n.st.Sessions, tok)
			n.dirty = true
		}
	}
}
