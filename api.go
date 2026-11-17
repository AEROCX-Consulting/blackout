package main

// Webscherm en HTTP-API (zie design/CONTRACT.md §4). Tijden in de API: milliseconden sinds epoch.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

var okJSON = map[string]bool{"ok": true}

func (n *Node) uiURLs() []string {
	var out []string
	if h, err := os.Hostname(); err == nil && h != "" {
		if !strings.HasSuffix(h, ".local") {
			h += ".local"
		}
		out = append(out, fmt.Sprintf("http://%s:%d", h, n.uiPort))
	}
	for _, ip := range localIPs(false) {
		if ip4 := ip.To4(); ip4 != nil && ip4.IsPrivate() {
			out = append(out, fmt.Sprintf("http://%s:%d", ip4, n.uiPort))
		}
	}
	return out
}

// allowedHost beschermt tegen DNS-rebinding: alleen IP-adressen, localhost, *.local en de eigen hostnaam.
func allowedHost(r *http.Request) bool {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".localhost") || net.ParseIP(h) != nil {
		return true
	}
	if hn, err := os.Hostname(); err == nil && strings.EqualFold(h, hn) {
		return true
	}
	return false
}

// sameOrigin: een POST van een andere website (CSRF) weigeren.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" && r.Method == http.MethodGet {
		return true
	}
	o = strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")
	return strings.EqualFold(o, r.Host)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && err != io.EOF {
		httpErr(w, 400, "Ongeldige invoer")
		return false
	}
	return true
}

func posOut(p *Pos) map[string]any {
	if p == nil {
		return nil
	}
	return map[string]any{"lat": p.Lat, "lon": p.Lon, "ts": ms(p.TS), "src": p.Src}
}

// route (onder slot): hoe bereik ik dit contact nu? k = star|lan|radio|bridge|relay|none
func (n *Node) route(c *Contact, radioReady bool) (string, string) {
	t := now()
	if c.Blocked {
		return "none", "geblokkeerd"
	}
	if t-c.LastSeen < onlineSecs {
		switch {
		case strings.HasPrefix(c.Via, "relay:"):
			return "relay", "doorgegeven door " + n.contactName(strings.TrimPrefix(c.Via, "relay:"))
		case c.Via == "lan":
			return "lan", "via wifi (zelfde netwerk)"
		default:
			return "star", "via Starlink"
		}
	}
	if radioReady && t-c.RadioSeen < 1200 {
		if c.RadioRSSI != 0 {
			return "radio", fmt.Sprintf("via radio · %d dBm", c.RadioRSSI)
		}
		return "radio", "via radio"
	}
	if b := n.pickBridge(c); b != nil {
		return "bridge", "via brug bij " + b.Name
	}
	if b := n.st.Contacts[c.BridgeVia]; b != nil && t-c.BridgeSeen < 1200 && n.ipOnline(b) {
		return "bridge", "via brug bij " + b.Name
	}
	if c.LastSeen == 0 && c.RadioSeen == 0 && c.BridgeSeen == 0 {
		return "none", "nog niet bereikt, wacht"
	}
	return "none", "nu niet bereikbaar, wacht"
}

func (n *Node) msgPreview(m *Message) map[string]any {
	if m == nil {
		return nil
	}
	body := m.Body
	if body == "" && m.Img != "" {
		body = "Foto"
	}
	name := n.contactName(m.From)
	if m.Sys {
		name = ""
	}
	return map[string]any{"body": body, "ts": ms(m.TS), "from": m.From, "fromName": name, "sys": m.Sys}
}

func (n *Node) routes() *http.ServeMux {
	mux := http.NewServeMux()
	page := func(path string, h http.HandlerFunc) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			securityHeaders(w)
			if !allowedHost(r) {
				http.Error(w, "Onbekende hostnaam", 403)
				return
			}
			if !allowedSource(r) {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					httpErr(w, 403, msgNotPrivate)
				} else {
					http.Error(w, msgNotPrivate, 403)
				}
				return
			}
			h(w, r)
		})
	}
	page("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := uiFS.ReadFile("ui.html")
		logo, _ := uiFS.ReadFile("assets/logo.svg")
		b = []byte(strings.ReplaceAll(string(b), "{{LOGO}}", string(logo)))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})
	assets := http.FileServer(http.FS(uiFS))
	page("/assets/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") { // geen mapoverzicht
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "max-age=86400")
		if strings.HasSuffix(r.URL.Path, ".webmanifest") {
			w.Header().Set("Content-Type", "application/manifest+json")
		}
		assets.ServeHTTP(w, r)
	})
	page("/manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) {
		b, err := uiFS.ReadFile("assets/manifest.webmanifest")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/manifest+json")
		w.Write(b)
	})
	page("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"app": appID, "version": version})
	})
	page("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpErr(w, 405, "Gebruik POST")
			return
		}
		if !sameOrigin(r) {
			httpErr(w, 403, "Verzoek van een andere website geweigerd")
			return
		}
		var in struct{ Pin string }
		if !readJSON(w, r, &in, 4096) {
			return
		}
		n.mu.Lock()
		code, msg := n.pinAttempt(in.Pin, r)
		tok := ""
		if code == 200 {
			tok = n.newSession(r)
		}
		n.mu.Unlock()
		if code != 200 {
			if code == 403 {
				time.Sleep(time.Second)
			}
			httpErr(w, code, msg)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "axblackout", Value: tok, Path: "/", MaxAge: 365 * 86400, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, okJSON)
	})
	api := func(path string, h func(w http.ResponseWriter, r *http.Request, s *Session)) {
		page(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
				httpErr(w, 403, "Verzoek van een andere website geweigerd")
				return
			}
			n.mu.Lock()
			ok, s := n.authed(r)
			n.mu.Unlock()
			if !ok {
				httpErr(w, 401, "Pincode nodig")
				return
			}
			h(w, r, s)
		})
	}
	post := func(path string, h func(w http.ResponseWriter, r *http.Request, s *Session)) {
		api(path, func(w http.ResponseWriter, r *http.Request, s *Session) {
			if r.Method != http.MethodPost {
				httpErr(w, 405, "Gebruik POST")
				return
			}
			h(w, r, s)
		})
	}

	post("/api/logout", func(w http.ResponseWriter, r *http.Request, s *Session) {
		if ck, err := r.Cookie("axblackout"); err == nil {
			n.mu.Lock()
			delete(n.st.Sessions, ck.Value)
			n.dirty = true
			n.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "axblackout", Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, okJSON)
	})

	api("/api/state", func(w http.ResponseWriter, r *http.Request, s *Session) {
		ou, oi := n.osint.Counts()
		writeJSON(w, n.stateJSON(r, s, ou, oi))
	})

	api("/api/convs", func(w http.ResponseWriter, r *http.Request, s *Session) {
		n.mu.Lock()
		defer n.mu.Unlock()
		writeJSON(w, n.convsJSON())
	})

	api("/api/messages", func(w http.ResponseWriter, r *http.Request, s *Session) {
		conv := r.URL.Query().Get("conv")
		n.mu.Lock()
		defer n.mu.Unlock()
		writeJSON(w, n.messagesJSON(conv))
	})

	post("/api/send", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct {
			Conv  string `json:"conv"`
			Body  string `json:"body"`
			Img   string `json:"img"`
			Osint bool   `json:"osint"`
		}
		if !readJSON(w, r, &in, 1<<20) {
			return
		}
		body := strings.TrimSpace(in.Body)
		if body == "" && in.Img == "" {
			httpErr(w, 400, "Leeg bericht")
			return
		}
		if utf8.RuneCountInString(body) > maxBody {
			httpErr(w, 400, fmt.Sprintf("Bericht te lang (max. %d tekens)", maxBody))
			return
		}
		o := sendOpts{Osint: in.Osint}
		if in.Img != "" {
			id, size, err := n.storeBlob(in.Img)
			if err != nil {
				httpErr(w, 400, err.Error())
				return
			}
			o.Img, o.ImgSize = id, size
		}
		n.mu.Lock()
		m, err := n.newOutMsg(in.Conv, body, o)
		if err == nil {
			what := "Bericht"
			if in.Osint {
				what = "OSINT gedeeld"
			} else if o.Img != "" {
				what = "Foto"
			}
			n.event("bericht", fmt.Sprintf("%s naar %s (%d)", what, n.convName(in.Conv), len(m.Recips)))
		}
		n.mu.Unlock()
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		n.kickOutbox()
		writeJSON(w, map[string]any{"ok": true, "id": m.ID})
	})

	api("/api/blob/", func(w http.ResponseWriter, r *http.Request, s *Session) {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/blob/"), ".jpg")
		if !validBlobID(id) {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(n.blobPath(id))
		if err != nil {
			httpErr(w, 404, "Foto niet (meer) beschikbaar")
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		w.Write(b)
	})

	post("/api/contact", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct{ Action, ID, Code, Name, Role string }
		if !readJSON(w, r, &in, 64<<10) {
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		in.Name = truncBytes(in.Name, 40)
		if in.Role != "" && !validRoles[in.Role] {
			httpErr(w, 400, "Onbekende rol")
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		c := n.st.Contacts[in.ID]
		needC := func() bool {
			if c == nil {
				httpErr(w, 404, "Contact niet gevonden")
				return false
			}
			return true
		}
		switch in.Action {
		case "add":
			card, ref, err := parseAnyCode(in.Code)
			if err != nil {
				httpErr(w, 400, err.Error())
				return
			}
			if card.E == n.myID {
				httpErr(w, 400, "Dat is je eigen code")
				return
			}
			if old := n.st.Contacts[card.E]; old != nil && old.Blocked {
				httpErr(w, 400, "Dit contact is geblokkeerd. Deblokkeer het eerst.")
				return
			}
			role := in.Role
			if ref != nil {
				if old := n.st.Contacts[card.E]; old == nil {
					nc := &Contact{ID: card.E, Card: card, Observed: map[string]int64{}, Name: card.N, Role: "lid", Invite: ref.ID, Added: now()}
					n.st.Contacts[card.E] = nc
				} else {
					old.Invite = ref.ID
				}
			}
			c := n.addContact(card, in.Name, role, "")
			if ref != nil {
				n.event("contact", fmt.Sprintf("Uitnodiging van %s gebruikt", c.Name))
			}
			writeJSON(w, map[string]any{"id": c.ID, "invite": ref != nil})
		case "accept":
			p := n.st.Pending[in.ID]
			if p == nil {
				httpErr(w, 404, "Verzoek niet gevonden")
				return
			}
			role := in.Role
			if role == "" {
				role = "lid"
			}
			c := n.addContact(p.Card, in.Name, role, "")
			n.audit(fmt.Sprintf("%s toegelaten als %s", c.Name, role))
			writeJSON(w, map[string]string{"id": c.ID})
		case "dismiss":
			if p := n.st.Pending[in.ID]; p != nil {
				n.audit(fmt.Sprintf("Verzoek van %s geweigerd", p.Card.N))
			}
			delete(n.st.Pending, in.ID)
			n.dirty = true
			writeJSON(w, okJSON)
		case "remove":
			if !needC() {
				return
			}
			delete(n.st.Contacts, c.ID)
			n.st.Removed[c.ID] = now()
			n.removeContactFromGroups(c.ID)
			n.clearIncomingSos(c.ID)
			n.radio.Drop("")
			n.audit(fmt.Sprintf("%s verwijderd", c.Name))
			n.dirty = true
			writeJSON(w, okJSON)
		case "rename":
			if !needC() {
				return
			}
			if in.Name == "" {
				httpErr(w, 400, "Geef een naam")
				return
			}
			c.Name = in.Name
			n.dirty = true
			writeJSON(w, okJSON)
		case "myname":
			if in.Name == "" {
				httpErr(w, 400, "Geef een naam")
				return
			}
			if in.Name != n.st.Name {
				n.st.Name = in.Name
				n.bumpCard()
				n.event("instelling", "Naam gewijzigd in "+in.Name)
			}
			writeJSON(w, okJSON)
		case "block", "unblock":
			if !needC() {
				return
			}
			c.Blocked = in.Action == "block"
			if c.Blocked {
				n.clearIncomingSos(c.ID)
				n.audit(fmt.Sprintf("%s geblokkeerd", c.Name))
			} else {
				n.audit(fmt.Sprintf("%s gedeblokkeerd", c.Name))
			}
			n.dirty = true
			writeJSON(w, okJSON)
		case "role":
			if !needC() {
				return
			}
			if in.Role == "" {
				httpErr(w, 400, "Onbekende rol")
				return
			}
			if c.Role != in.Role {
				c.Role = in.Role
				n.audit(fmt.Sprintf("%s is nu %s", c.Name, in.Role))
				n.dirty = true
			}
			writeJSON(w, okJSON)
		default:
			httpErr(w, 400, "Onbekende actie")
		}
	})

	post("/api/group", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in groupIn
		if !readJSON(w, r, &in, 64<<10) {
			return
		}
		n.mu.Lock()
		g, err := n.groupAction(in)
		n.mu.Unlock()
		if err != nil {
			code := 400
			if strings.HasPrefix(err.Error(), "Alleen de eigenaar") {
				code = 403
			}
			httpErr(w, code, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "id": g.ID})
	})

	post("/api/sos", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct{ Action, ID string }
		if !readJSON(w, r, &in, 4096) {
			return
		}
		n.mu.Lock()
		var err error
		var id string
		switch in.Action {
		case "start":
			var m *Message
			if m, err = n.sosStart(); err == nil {
				id = m.ID
			}
		case "stop":
			err = n.sosStop()
		case "seen":
			err = n.sosSeen(in.ID)
		default:
			err = fmt.Errorf("Onbekende actie")
		}
		n.mu.Unlock()
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		n.kickOutbox()
		writeJSON(w, map[string]any{"ok": true, "id": id})
	})

	post("/api/location", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct {
			Lat   *float64 `json:"lat"`
			Lon   *float64 `json:"lon"`
			Share *bool    `json:"share"`
			Clear bool     `json:"clear"`
		}
		if !readJSON(w, r, &in, 4096) {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if (in.Lat == nil) != (in.Lon == nil) {
			httpErr(w, 400, "Geef zowel breedte- als lengtegraad")
			return
		}
		if in.Lat != nil {
			p := &Pos{Lat: *in.Lat, Lon: *in.Lon, TS: now()}
			if !p.valid() {
				httpErr(w, 400, "Ongeldige locatie")
				return
			}
			n.st.Loc = p
			n.event("instelling", "Vaste locatie ingesteld")
		}
		if in.Clear {
			n.st.Loc = nil
			n.event("instelling", "Vaste locatie gewist")
		}
		if in.Share != nil && *in.Share != n.st.Share {
			n.st.Share = *in.Share
			if n.st.Share {
				n.event("instelling", "Locatie delen aan")
			} else {
				n.event("instelling", "Locatie delen uit")
			}
		}
		n.dirty = true
		writeJSON(w, map[string]any{"ok": true, "pos": posOut(n.myPos()), "share": n.st.Share})
	})

	post("/api/admin", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct {
			Action     string                     `json:"action"`
			Role       string                     `json:"role"`
			Perm       string                     `json:"perm"`
			On         *bool                      `json:"on"`
			Perms      map[string]map[string]bool `json:"perms"`
			AutoLan    *bool                      `json:"autoLan"`
			KeepDays   *int                       `json:"keepDays"`
			OpenGroups *bool                      `json:"openGroups"`
			Bridge     *bool                      `json:"bridge"`
			ID         string                     `json:"id"`
			Name       string                     `json:"name"`
			Groups     []string                   `json:"groups"`
			Days       int                        `json:"days"`
			Exp        int64                      `json:"exp"` // ms sinds epoch (alternatief voor days)
			Pin        string                     `json:"pin"`
		}
		if !readJSON(w, r, &in, 64<<10) {
			return
		}
		if (in.Action == "newpin" || in.Action == "revokeDevice") && !n.confirmPin(w, r, in.Pin) {
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		switch in.Action {
		case "perms":
			set := func(role, perm string, on bool) bool {
				if role == "beheerder" || n.st.Perms[role] == nil || !contains(permKeys, perm) {
					return false
				}
				if n.st.Perms[role][perm] != on {
					n.st.Perms[role][perm] = on
					st := "uitgezet"
					if on {
						st = "toegestaan"
					}
					n.audit(fmt.Sprintf("%s: “%s” %s", role, perm, st))
				}
				return true
			}
			if in.Perms != nil {
				for role, ps := range in.Perms {
					for p, on := range ps {
						set(role, p, on)
					}
				}
			} else if in.On == nil || !set(in.Role, in.Perm, *in.On) {
				httpErr(w, 400, "Onbekende rol of recht (beheerder mag altijd alles)")
				return
			}
			n.dirty = true
			writeJSON(w, map[string]any{"ok": true, "perms": n.st.Perms})
		case "policy", "bridge":
			if in.Action == "bridge" {
				in.Bridge = in.On
			}
			if in.AutoLan != nil && *in.AutoLan != n.st.Policy.AutoLan {
				n.st.Policy.AutoLan = *in.AutoLan
				if *in.AutoLan {
					n.audit("Automatisch toelaten op zelfde wifi aangezet")
				} else {
					n.audit("Automatisch toelaten op zelfde wifi uitgezet")
				}
			}
			if in.KeepDays != nil && *in.KeepDays != n.st.Policy.KeepDays {
				if *in.KeepDays < 0 || *in.KeepDays > 3650 {
					httpErr(w, 400, "Ongeldig aantal dagen")
					return
				}
				n.st.Policy.KeepDays = *in.KeepDays
				if *in.KeepDays == 0 {
					n.audit("Berichten bewaren: altijd")
				} else {
					n.audit(fmt.Sprintf("Berichten bewaren: %d dagen", *in.KeepDays))
				}
			}
			if in.OpenGroups != nil && *in.OpenGroups != n.st.Policy.OpenGroups {
				n.st.Policy.OpenGroups = *in.OpenGroups
				if *in.OpenGroups {
					n.audit("Leden mogen groepsleden toevoegen")
				} else {
					n.audit("Alleen beheerders voegen groepsleden toe")
				}
				for _, g := range n.st.Groups {
					if n.mine(g) && g.visible() {
						n.groupPublish(g)
					}
				}
			}
			if in.Bridge != nil && *in.Bridge != n.st.Bridge {
				n.st.Bridge = *in.Bridge
				if *in.Bridge {
					n.event("brug", "Dit apparaat werkt als brug")
				} else {
					n.event("brug", "Brugfunctie uit")
				}
			}
			n.dirty = true
			writeJSON(w, map[string]any{"ok": true, "policy": n.policyOut(), "bridge": n.st.Bridge})
		case "newpin":
			n.st.Pin = newPin()
			out := 0
			for tok, d := range n.st.Sessions { // alle andere toestellen moeten de nieuwe pincode typen
				if s == nil || d.ID != s.ID {
					delete(n.st.Sessions, tok)
					out++
				}
			}
			n.audit(fmt.Sprintf("Nieuwe pincode ingesteld, %d andere toestellen afgemeld", out))
			writeJSON(w, map[string]any{"ok": true, "pin": n.st.Pin})
		case "revokeDevice":
			for tok, d := range n.st.Sessions {
				if d.ID == in.ID {
					delete(n.st.Sessions, tok)
					n.audit(fmt.Sprintf("Toegang van %s ingetrokken", d.Name))
					writeJSON(w, okJSON)
					return
				}
			}
			httpErr(w, 404, "Toestel niet gevonden")
		case "invite":
			role := in.Role
			if role == "" {
				role = "lid"
			}
			if !validRoles[role] {
				httpErr(w, 400, "Onbekende rol")
				return
			}
			days := in.Days
			if days <= 0 && in.Exp > 0 {
				exp := in.Exp
				if exp > 1e11 { // milliseconden
					exp /= 1000
				}
				days = int((exp - now() + 86399) / 86400)
				if days < 1 {
					days = 1
				}
			}
			inv, err := n.makeInvite(in.Name, role, in.Groups, days)
			if err != nil {
				httpErr(w, 400, err.Error())
				return
			}
			writeJSON(w, map[string]any{"ok": true, "id": inv.ID, "code": n.inviteCode(inv), "exp": ms(inv.Exp)})
		case "revokeInvite":
			for i, inv := range n.st.Invites {
				if inv.ID == in.ID {
					n.st.Invites = append(n.st.Invites[:i], n.st.Invites[i+1:]...)
					who := ""
					if inv.Name != "" {
						who = " voor " + inv.Name
					}
					n.audit("Uitnodiging" + who + " ingetrokken")
					writeJSON(w, okJSON)
					return
				}
			}
			httpErr(w, 404, "Uitnodiging niet gevonden")
		case "rotateKeys":
			cnt := n.rotateGroupKeys()
			n.audit(fmt.Sprintf("Groepssleutels vernieuwd (%d groepen)", cnt))
			writeJSON(w, map[string]any{"ok": true, "groups": cnt})
		default:
			httpErr(w, 400, "Onbekende actie")
		}
	})

	api("/api/qr.png", func(w http.ResponseWriter, r *http.Request, s *Session) {
		q := r.URL.Query()
		n.mu.Lock()
		text := ""
		if id := q.Get("invite"); id != "" {
			if inv := n.findInvite(id); inv != nil && !inv.Used {
				text = n.inviteCode(inv)
			}
		} else if q.Get("me") != "" {
			text = cardCode(n.myCard())
		}
		n.mu.Unlock()
		if text == "" {
			httpErr(w, 404, "Niets om te tonen")
			return
		}
		scale, _ := strconv.Atoi(q.Get("scale"))
		if scale < 2 || scale > 16 {
			scale = 6
		}
		png, err := qrPNG(text, scale)
		if err != nil {
			httpErr(w, 500, "QR-code maken mislukt")
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(png)
	})

	post("/api/backup", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct{ Pass, Pin string }
		if !readJSON(w, r, &in, 4096) {
			return
		}
		if !n.confirmPin(w, r, in.Pin) {
			return
		}
		if err := checkPass(in.Pass); err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		n.mu.Lock()
		pt, err := n.backupPlain()
		n.mu.Unlock()
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		data, err := sealBackup(in.Pass, pt)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		n.mu.Lock()
		n.st.BackupLast = now()
		n.dirty = true
		n.event("back-up", "Versleutelde back-up gemaakt")
		n.mu.Unlock()
		name := "aerocx-blackout-backup-" + time.Now().Format("2006-01-02") + ".axb"
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	post("/api/restore", func(w http.ResponseWriter, r *http.Request, s *Session) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			httpErr(w, 400, "Kies een back-upbestand")
			return
		}
		if !n.confirmPin(w, r, r.FormValue("pin")) {
			return
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			httpErr(w, 400, "Kies een back-upbestand")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(f, 4<<20))
		f.Close()
		if err != nil {
			httpErr(w, 400, "Het bestand kon niet gelezen worden")
			return
		}
		d, err := openBackup(r.FormValue("pass"), raw)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			httpErr(w, 400, err.Error())
			return
		}
		n.mu.Lock()
		err = n.restoreBackup(d)
		n.mu.Unlock()
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		n.save()
		writeJSON(w, map[string]any{"ok": true, "contacts": len(d.Contacts), "groups": len(d.Groups)})
	})

	post("/api/autostart", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct {
			On  bool
			Pin string
		}
		if !readJSON(w, r, &in, 4096) {
			return
		}
		if !n.confirmPin(w, r, in.Pin) {
			return
		}
		err := autostartSet(in.On)
		on := autostartEnabled()
		n.mu.Lock()
		n.autostart = on
		if err == nil {
			if in.On {
				n.event("instelling", "Automatisch starten aan")
			} else {
				n.event("instelling", "Automatisch starten uit")
			}
		}
		n.mu.Unlock()
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "autostart": on})
	})

	post("/api/radio", func(w http.ResponseWriter, r *http.Request, s *Session) {
		var in struct {
			Mode    string
			Target  string
			Channel *int
		}
		if !readJSON(w, r, &in, 4096) {
			return
		}
		switch in.Mode {
		case "auto", "tcp", "off":
		default:
			httpErr(w, 400, "Onbekende keuze")
			return
		}
		in.Target = strings.TrimSpace(in.Target)
		if len(in.Target) > 200 {
			httpErr(w, 400, "Te lang")
			return
		}
		if in.Channel != nil && (*in.Channel < 0 || *in.Channel > 7) {
			httpErr(w, 400, "Kanaal moet 0 tot 7 zijn")
			return
		}
		n.mu.Lock()
		n.st.RadioMode, n.st.RadioTarget, n.st.RadioChannel = in.Mode, in.Target, in.Channel
		n.dirty = true
		n.applyRadioSettings()
		n.event("radio", "Radio-instellingen gewijzigd")
		n.mu.Unlock()
		writeJSON(w, okJSON)
	})

	api("/api/osint", func(w http.ResponseWriter, r *http.Request, s *Session) {
		n.osint.ServeHTTP(w, r)
	})

	var quitOnce sync.Once
	page("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		if !isLocalReq(r) {
			httpErr(w, 403, "Alleen op deze computer zelf")
			return
		}
		if r.Method != http.MethodPost || !sameOrigin(r) {
			httpErr(w, 405, "Gebruik POST")
			return
		}
		writeJSON(w, okJSON)
		quitOnce.Do(func() { close(n.quit) })
	})
	return mux
}

// ---------- JSON-opbouw ----------

func (n *Node) stateJSON(r *http.Request, s *Session, osUnread, osImportant int) map[string]any {
	radioInfo := n.radio.Snapshot()
	radioReady := n.radio.Ready()
	n.mu.Lock()
	defer n.mu.Unlock()
	t := now()
	local := isLocalReq(r)

	type uc struct {
		ID           string            `json:"id"`
		Short        string            `json:"short"`
		Name         string            `json:"name"`
		CardName     string            `json:"cardName"`
		Online       bool              `json:"online"`
		Via          string            `json:"via"`
		LastSeen     int64             `json:"lastSeen"`
		Unread       int               `json:"unread"`
		RadioSeen    int64             `json:"radioSeen"`
		RadioRSSI    int32             `json:"radioRssi"`
		RadioSNR     float32           `json:"radioSnr"`
		Pos          map[string]any    `json:"pos"`
		Role         string            `json:"role"`
		Blocked      bool              `json:"blocked"`
		IntroducedBy string            `json:"introducedBy"`
		Route        map[string]string `json:"route"`
		Addrs        []string          `json:"addrs"`
		Version      string            `json:"version"`
		HasRadio     bool              `json:"hasRadio"`
		Bridge       bool              `json:"bridge"`
		Groups       []string          `json:"groups"`
	}
	cs := []uc{}
	for _, c := range n.st.Contacts {
		k, txt := n.route(c, radioReady)
		via := k
		if k == "none" {
			via = ""
		}
		var gs []string
		for _, g := range n.st.Groups {
			if g.visible() && g.has(c.ID) {
				gs = append(gs, g.ID)
			}
		}
		if gs == nil {
			gs = []string{}
		}
		addrs := c.Card.A
		if addrs == nil {
			addrs = []string{}
		}
		cs = append(cs, uc{ID: c.ID, Short: short(c.ID), Name: c.Name, CardName: c.Card.N, Online: t-c.LastSeen < onlineSecs, Via: via,
			LastSeen: ms(c.LastSeen), Unread: c.Unread, RadioSeen: ms(c.RadioSeen), RadioRSSI: c.RadioRSSI, RadioSNR: c.RadioSNR,
			Pos: posOut(c.Pos), Role: roleOf(c), Blocked: c.Blocked, IntroducedBy: c.IntroducedBy,
			Route: map[string]string{"k": k, "t": txt}, Addrs: addrs, Version: c.PeerVer, HasRadio: c.PeerRadio, Bridge: c.PeerBridge, Groups: gs})
	}
	sort.Slice(cs, func(i, j int) bool { return strings.ToLower(cs[i].Name) < strings.ToLower(cs[j].Name) })

	groups := []map[string]any{}
	for _, g := range n.st.Groups {
		if !g.visible() {
			continue
		}
		mem := []string{}
		for _, id := range g.Members {
			if id != n.myID {
				mem = append(mem, id)
			}
		}
		roles := map[string]string{}
		for _, id := range g.Members {
			roles[id] = g.role(id)
		}
		groups = append(groups, map[string]any{"id": g.ID, "name": g.Name, "owner": g.Owner, "mine": n.mine(g), "members": mem,
			"roles": roles, "unread": g.Unread, "open": g.Open, "myRole": g.role(n.myID), "ownerName": n.contactName(g.Owner)})
	}
	sort.Slice(groups, func(i, j int) bool {
		return strings.ToLower(groups[i]["name"].(string)) < strings.ToLower(groups[j]["name"].(string))
	})

	pend := []map[string]any{}
	for id, p := range n.st.Pending {
		if t-p.Seen < 86400 {
			pend = append(pend, map[string]any{"id": id, "name": p.Card.N, "source": p.Source, "seen": ms(p.Seen), "note": p.Note})
		}
	}
	sort.Slice(pend, func(i, j int) bool { return pend[i]["seen"].(int64) > pend[j]["seen"].(int64) })

	var sos any
	if n.st.Sos != nil {
		acks := []string{}
		for id := range n.st.Sos.Acks {
			acks = append(acks, id)
		}
		sort.Strings(acks)
		sos = map[string]any{"active": true, "id": n.st.Sos.ID, "start": ms(n.st.Sos.Start), "acks": acks}
	}
	inSos := []map[string]any{}
	for _, x := range n.st.IncomingSos {
		inSos = append(inSos, map[string]any{"id": x.ID, "from": x.From, "fromName": n.contactName(x.From), "ts": ms(x.TS), "body": x.Body, "pos": posOut(x.Pos)})
	}

	devices := []map[string]any{}
	host, _ := os.Hostname()
	host = strings.TrimSuffix(host, ".local")
	if host == "" {
		host = "Deze computer"
	}
	devices = append(devices, map[string]any{"id": "node", "name": host, "how": "dit knooppunt", "seen": ms(t), "self": local})
	var sess []*Session
	for _, d := range n.st.Sessions {
		sess = append(sess, d)
	}
	sort.Slice(sess, func(i, j int) bool { return sess[i].Seen > sess[j].Seen })
	for _, d := range sess {
		devices = append(devices, map[string]any{"id": d.ID, "name": d.Name, "how": d.How, "seen": ms(d.Seen), "self": s != nil && s.ID == d.ID})
	}

	invites := []map[string]any{}
	for _, inv := range n.st.Invites {
		gs := inv.Groups
		if gs == nil {
			gs = []string{}
		}
		x := map[string]any{"id": inv.ID, "name": inv.Name, "role": inv.Role, "groups": gs, "exp": ms(inv.Exp), "used": inv.Used, "expired": t > inv.Exp}
		if !inv.Used && t <= inv.Exp {
			x["code"] = n.inviteCode(inv)
		}
		if inv.UsedBy != "" {
			x["usedBy"] = n.contactName(inv.UsedBy)
		}
		invites = append(invites, x)
	}

	audit := []map[string]any{}
	for i := len(n.st.Audit) - 1; i >= 0 && len(audit) < 150; i-- {
		audit = append(audit, map[string]any{"t": ms(n.st.Audit[i].T), "x": n.st.Audit[i].X})
	}
	logs := []LogEntry{}
	for i := len(n.events) - 1; i >= 0; i-- {
		logs = append(logs, n.events[i])
	}

	var bLast any
	if n.st.BackupLast > 0 {
		bLast = ms(n.st.BackupLast)
	}
	mp := n.myPos()
	card := n.myCard()
	addrs := n.myAddrs
	if addrs == nil {
		addrs = []string{}
	}
	urls := n.uiURLs()
	if urls == nil {
		urls = []string{}
	}
	out := map[string]any{
		"version": version, "now": time.Now().UnixMilli(),
		"me": map[string]any{"name": n.st.Name, "id": short(n.myID), "fullId": n.myID, "code": cardCode(card), "codeLong": cardText(card),
			"addrs": addrs, "pos": posOut(mp), "share": n.st.Share, "role": "beheerder", "hasFixedLoc": n.st.Loc != nil},
		"contacts": cs, "groups": groups, "pending": pend, "alleUnread": n.st.AlleUnread,
		"urls": urls, "local": local,
		"radio": radioInfo, "radioSettings": map[string]any{"mode": n.st.RadioMode, "target": n.st.RadioTarget, "channel": n.st.RadioChannel},
		"sos": sos, "incomingSos": inSos,
		"policy": n.policyOut(), "perms": n.st.Perms,
		"devices": devices, "invites": invites, "audit": audit, "log": logs,
		"osint":     map[string]int{"unread": osUnread, "important": osImportant},
		"autostart": n.autostart, "backup": map[string]any{"last": bLast}, "bridge": n.st.Bridge, "sdr": n.sdr,
	}
	if local {
		out["pin"] = n.st.Pin
	}
	return out
}

func (n *Node) policyOut() map[string]any {
	p := n.st.Policy
	return map[string]any{"autoLan": p.AutoLan, "keepDays": p.KeepDays, "openGroups": p.OpenGroups, "keyRot": ms(p.KeyRot)}
}

func (n *Node) convsJSON() []map[string]any {
	radioReady := n.radio.Ready()
	last := map[string]*Message{}
	for _, m := range n.st.Messages {
		last[m.Conv] = m
	}
	active := 0
	for _, c := range n.st.Contacts {
		if !c.Blocked {
			active++
		}
	}
	out := []map[string]any{{"id": "alle", "kind": "alle", "name": "Iedereen", "last": n.msgPreview(last["alle"]), "unread": n.st.AlleUnread, "route": nil, "members": active}}
	var rest []map[string]any
	for _, g := range n.st.Groups {
		if !g.visible() {
			continue
		}
		id := "g:" + g.ID
		rest = append(rest, map[string]any{"id": id, "kind": "groep", "name": g.Name, "last": n.msgPreview(last[id]), "unread": g.Unread, "route": nil, "members": len(g.Members) - 1, "mine": n.mine(g)})
	}
	for _, c := range n.st.Contacts {
		if c.Blocked {
			continue
		}
		k, t := n.route(c, radioReady)
		rest = append(rest, map[string]any{"id": c.ID, "kind": "direct", "name": c.Name, "last": n.msgPreview(last[c.ID]), "unread": c.Unread, "route": map[string]string{"k": k, "t": t}, "members": 1})
	}
	ts := func(x map[string]any) int64 {
		if l, ok := x["last"].(map[string]any); ok && l != nil {
			return l["ts"].(int64)
		}
		return 0
	}
	sort.SliceStable(rest, func(i, j int) bool {
		a, b := ts(rest[i]), ts(rest[j])
		if a != b {
			return a > b
		}
		return strings.ToLower(rest[i]["name"].(string)) < strings.ToLower(rest[j]["name"].(string))
	})
	return append(out, rest...)
}

func (n *Node) messagesJSON(conv string) []map[string]any {
	switch {
	case conv == "alle":
		if n.st.AlleUnread != 0 {
			n.st.AlleUnread = 0
			n.dirty = true
		}
	case strings.HasPrefix(conv, "g:"):
		if g := n.st.Groups[conv[2:]]; g != nil && g.Unread != 0 {
			g.Unread = 0
			n.dirty = true
		}
	default:
		if c := n.st.Contacts[conv]; c != nil && c.Unread != 0 {
			c.Unread = 0
			n.dirty = true
		}
	}
	out := []map[string]any{}
	for _, m := range n.st.Messages {
		if m.Conv != conv {
			continue
		}
		x := map[string]any{"id": m.ID, "mine": m.From == "me", "from": m.From, "body": m.Body, "ts": ms(m.TS), "acked": 0, "total": 0,
			"via": m.Via, "sos": m.Sos, "osint": m.Osint, "img": nil, "sys": m.Sys}
		if m.SosEnd {
			x["sosEnd"] = true
		}
		if m.Img != "" {
			st := m.ImgSt
			if st == "" {
				st = "ok"
			}
			x["img"] = map[string]string{"id": m.Img, "status": st}
		}
		switch {
		case m.Sys:
			x["fromName"] = ""
		case m.From == "me":
			x["fromName"] = "Ik"
			a, tot := 0, 0
			for _, ok := range m.Recips {
				tot++
				if ok {
					a++
				}
			}
			x["acked"], x["total"] = a, tot
		default:
			x["fromName"] = n.contactName(m.From)
		}
		out = append(out, x)
	}
	if len(out) > 400 {
		out = out[len(out)-400:]
	}
	return out
}

// ---------- OSINT-haken vanuit radio.go ----------

func (n *Node) osintMeshText(fromNode uint32, name, text string, rssi int32, snr float32, ch uint32) {
	n.osint.MeshText(fromNode, name, text, rssi, snr, ch)
}

func (n *Node) osintMeshNode(num uint32, name string) {
	n.osint.MeshNode(num, name)
}
