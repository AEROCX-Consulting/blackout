package main

// Beheer: rollen en rechten, toestellen (sessies), uitnodigingen, beheerlogboek en gebeurtenissenlog.

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var permKeys = []string{"send", "alle", "sos", "groups", "invite", "osint", "bridge"}

func defaultPerms() map[string]map[string]bool {
	mk := func(on ...string) map[string]bool {
		m := map[string]bool{}
		for _, k := range permKeys {
			m[k] = false
		}
		for _, k := range on {
			m[k] = true
		}
		return m
	}
	return map[string]map[string]bool{
		"beheerder": mk(permKeys...),
		"lid":       mk("send", "alle", "sos", "groups", "osint", "bridge"),
		"lezer":     mk("sos", "bridge"),
	}
}

func roleOf(c *Contact) string {
	if c == nil || c.Role == "" {
		return "lid"
	}
	return c.Role
}

// can: mag dit contact (volgens zijn rol bij mij) dit doen? Wordt toegepast op wat binnenkomt.
func (n *Node) can(c *Contact, perm string) bool {
	if c == nil || c.Blocked {
		return false
	}
	r := roleOf(c)
	if r == "beheerder" {
		return true
	}
	p := n.st.Perms[r]
	if p == nil {
		return false
	}
	return p[perm]
}

// ---------- beheerlogboek ----------

type AuditEntry struct {
	T int64  `json:"t"`
	X string `json:"x"`
	S string `json:"s,omitempty"` // ondertekend met mijn sleutel
}

func (n *Node) signAudit(a AuditEntry) AuditEntry {
	if n.edPriv == nil {
		seed, err := b64.DecodeString(n.st.EdSeed)
		if err != nil || len(seed) != 32 {
			return a
		}
		a.S = b64.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(fmt.Sprintf("aerocx-blackout-audit|%d|%s", a.T, a.X))))
		return a
	}
	a.S = b64.EncodeToString(ed25519.Sign(n.edPriv, []byte(fmt.Sprintf("aerocx-blackout-audit|%d|%s", a.T, a.X))))
	return a
}

// audit (onder slot): beheerwijziging bewaren en ook in het gewone logboek zetten.
func (n *Node) audit(x string) {
	n.st.Audit = append(n.st.Audit, n.signAudit(AuditEntry{T: now(), X: x}))
	if len(n.st.Audit) > 300 {
		n.st.Audit = n.st.Audit[len(n.st.Audit)-300:]
	}
	n.dirty = true
	n.event("beheer", x)
}

// ---------- gebeurtenissen (Logboek-scherm) ----------

type LogEntry struct {
	T int64  `json:"t"` // ms
	K string `json:"k"`
	X string `json:"x"`
}

// event (onder slot)
func (n *Node) event(k, x string) {
	n.events = append(n.events, LogEntry{T: time.Now().UnixMilli(), K: k, X: x})
	if len(n.events) > 200 {
		n.events = n.events[len(n.events)-200:]
	}
	log.Printf("[%s] %s", k, x)
}

// ---------- toestellen ----------

type Session struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	How     string `json:"how"`
	Created int64  `json:"created"`
	Seen    int64  `json:"seen"`
}

func deviceName(ua string) (name, browser string) {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "ipad"):
		name = "iPad"
	case strings.Contains(u, "iphone"):
		name = "iPhone"
	case strings.Contains(u, "android"):
		if strings.Contains(u, "mobile") {
			name = "Android-telefoon"
		} else {
			name = "Android-tablet"
		}
	case strings.Contains(u, "macintosh"):
		name = "Mac"
	case strings.Contains(u, "windows"):
		name = "Windows-pc"
	case strings.Contains(u, "cros"):
		name = "Chromebook"
	case strings.Contains(u, "linux"):
		name = "Linux-computer"
	default:
		name = "Toestel"
	}
	switch {
	case strings.Contains(u, "edg/"):
		browser = "Edge"
	case strings.Contains(u, "firefox") || strings.Contains(u, "fxios"):
		browser = "Firefox"
	case strings.Contains(u, "chrome") || strings.Contains(u, "crios"):
		browser = "Chrome"
	case strings.Contains(u, "safari"):
		browser = "Safari"
	default:
		browser = "browser"
	}
	return
}

func reqIP(r *http.Request) net.IP {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

func isLocalReq(r *http.Request) bool {
	ip := reqIP(r)
	return ip != nil && ip.IsLoopback()
}

// newSession (onder slot) maakt een sessie voor een toestel dat met de pincode inlogt.
func (n *Node) newSession(r *http.Request) string {
	name, br := deviceName(r.UserAgent())
	how := br + " · "
	if ip := reqIP(r); ip != nil && isLocalNet(ip) {
		how += "zelfde wifi"
	} else if ip != nil {
		how += ip.String()
	}
	tok := randHex(16)
	n.st.Sessions[tok] = &Session{ID: randHex(4), Name: name, How: how, Created: now(), Seen: now()}
	n.audit(fmt.Sprintf("Nieuw toestel gekoppeld: %s (%s)", name, how))
	return tok
}

// authed (onder slot): localhost mag altijd; anders een geldige sessie.
func (n *Node) authed(r *http.Request) (bool, *Session) {
	if isLocalReq(r) {
		return true, nil
	}
	ck, err := r.Cookie("axblackout")
	if err != nil {
		return false, nil
	}
	s := n.st.Sessions[ck.Value]
	if s == nil {
		return false, nil
	}
	if now()-s.Seen > sessionIdle { // 30 dagen niet gebruikt: opnieuw de pincode
		delete(n.st.Sessions, ck.Value)
		n.dirty = true
		return false, nil
	}
	if now()-s.Seen > 60 {
		s.Seen = now()
		n.dirty = true
	}
	return true, s
}

// ---------- uitnodigingen ----------

type Invite struct {
	ID      string   `json:"id"` // 16 hex (8 bytes)
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Groups  []string `json:"groups"`
	Exp     int64    `json:"exp"`
	Used    bool     `json:"used"`
	UsedBy  string   `json:"used_by,omitempty"`
	Created int64    `json:"created"`
	Sig     string   `json:"sig"`
}

type inviteRef struct {
	ID  string // hex
	Exp int64
}

func inviteSignBytes(id string, exp int64) []byte {
	return []byte("aerocx-blackout-invite|" + id + "|" + strconv.FormatInt(exp, 10))
}

// inviteCode: "AXB2I:" + base64(kaart v2 | uitnodigings-ID[8] | vervaldatum[4] | handtekening[64])
func (n *Node) inviteCode(inv *Invite) string {
	b := cardCodeBytes(n.myCard())
	id, _ := hex.DecodeString(inv.ID)
	b = append(b, id...)
	b = binary.BigEndian.AppendUint32(b, uint32(inv.Exp))
	sig, _ := b64.DecodeString(inv.Sig)
	b = append(b, sig...)
	return inviteV2Prefix + b64.EncodeToString(b)
}

func (n *Node) findInvite(id string) *Invite {
	for _, i := range n.st.Invites {
		if i.ID == id {
			return i
		}
	}
	return nil
}

func (n *Node) makeInvite(name, role string, groups []string, days int) (*Invite, error) {
	if !validRoles[role] {
		role = "lid"
	}
	if days <= 0 {
		days = 7
	}
	if days > 365 {
		days = 365
	}
	name = strings.TrimSpace(name)
	name = truncBytes(name, 40)
	var gs []string
	for _, id := range groups {
		g := n.st.Groups[id]
		if g == nil || !g.visible() || !n.mine(g) {
			return nil, errors.New("Je kunt alleen uitnodigen voor groepen die je zelf beheert")
		}
		gs = append(gs, id)
	}
	inv := &Invite{ID: randHex(8), Name: name, Role: role, Groups: gs, Exp: now() + int64(days)*86400, Created: now()}
	inv.Sig = b64.EncodeToString(ed25519.Sign(n.edPriv, inviteSignBytes(inv.ID, inv.Exp)))
	n.st.Invites = append([]*Invite{inv}, n.st.Invites...)
	if len(n.st.Invites) > 100 {
		n.st.Invites = n.st.Invites[:100]
	}
	who := ""
	if name != "" {
		who = " voor " + name
	}
	n.audit(fmt.Sprintf("Uitnodiging gemaakt%s (%s)", who, role))
	return inv, nil
}

// tryInvite (onder slot): een hello met versleuteld uitnodigings-ID. True = toegelaten.
func (n *Node) tryInvite(card Card, sealed string) bool {
	raw, err := b64.DecodeString(sealed)
	if err != nil || len(raw) < 12+16 {
		return false
	}
	a, err := n.aeadX(card.X)
	if err != nil {
		return false
	}
	id, err := a.Open(nil, raw[:12], raw[12:], []byte("aerocx-blackout-invite"))
	if err != nil || len(id) != 8 {
		return false
	}
	inv := n.findInvite(hex.EncodeToString(id))
	if inv == nil || inv.Used || now() > inv.Exp {
		return false
	}
	inv.Used = true
	inv.UsedBy = card.E
	name := inv.Name
	c := n.addContact(card, name, inv.Role, "")
	if name == "" {
		name = c.Name
	}
	for _, gid := range inv.Groups {
		if g := n.st.Groups[gid]; g != nil && g.visible() && n.mine(g) && !g.has(c.ID) {
			g.Members = append(g.Members, c.ID)
			g.Kicked = removeStr(g.Kicked, c.ID)
			if inv.Role != "lid" {
				g.Roles[c.ID] = inv.Role
			}
			n.groupPublish(g)
		}
	}
	n.audit(fmt.Sprintf("%s toegelaten via uitnodiging (%s)", name, inv.Role))
	return true
}
