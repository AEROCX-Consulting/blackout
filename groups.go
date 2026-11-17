package main

// Groepen. De eigenaar beheert de groep en stuurt de groepskaart (t:"grp") naar elk lid, met de
// ondertekende kaarten van alle leden. Leden die elkaar nog niet kennen, worden zo contact
// ("voorgesteld via <groep>"). Groepsberichten gaan per lid versleuteld (ch "g:<id>"), ook over LoRa ('P').
// Elke wijziging = nieuwe versie; de eigenaar stuurt opnieuw tot elk lid bevestigt (grpack).

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

type Group struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Owner   string            `json:"owner"`
	Ver     int64             `json:"ver"`
	Members []string          `json:"members"` // volledige ID's, inclusief eigenaar en mezelf
	Roles   map[string]string `json:"roles,omitempty"`
	Open    bool              `json:"open,omitempty"`
	Unread  int               `json:"unread,omitempty"`
	Acked   map[string]int64  `json:"acked,omitempty"`  // eigenaar: lid -> bevestigde versie
	Kicked  []string          `json:"kicked,omitempty"` // eigenaar: verwijderde leden die het nog moeten horen
	Deleted bool              `json:"deleted,omitempty"`
	LeftAt  int64             `json:"left_at,omitempty"`
}

type grpWire struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Owner   string            `json:"owner"`
	Ver     int64             `json:"ver"`
	Members []string          `json:"members"`
	Roles   map[string]string `json:"roles,omitempty"`
	Open    bool              `json:"open,omitempty"`
	Del     bool              `json:"del,omitempty"`
}

var validRoles = map[string]bool{"beheerder": true, "lid": true, "lezer": true}

const (
	groupMaxMembers  = 50 // inclusief eigenaar
	groupMaxPerOwner = 50 // groepen die één contact bij mij kan aanmaken
)

// validGroupID: 16 hex-tekens (8 bytes), zoals randHex(8).
func validGroupID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (g *Group) has(id string) bool {
	for _, m := range g.Members {
		if m == id {
			return true
		}
	}
	return false
}

func (g *Group) role(id string) string {
	if id == g.Owner {
		return "beheerder"
	}
	if r := g.Roles[id]; r != "" {
		return r
	}
	return "lid"
}

func (g *Group) visible() bool { return !g.Deleted && g.LeftAt == 0 }

func (n *Node) mine(g *Group) bool { return g.Owner == n.myID }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (n *Node) groupTargets(g *Group) []string {
	var out []string
	for _, id := range g.Members {
		if id != n.myID {
			out = append(out, id)
		}
	}
	for _, id := range g.Kicked {
		if !contains(out, id) && id != n.myID {
			out = append(out, id)
		}
	}
	return out
}

// groupRecips: wie een groepsbericht krijgt.
func (n *Node) groupRecips(g *Group) map[string]bool {
	r := map[string]bool{}
	for _, id := range g.Members {
		if c := n.st.Contacts[id]; c != nil && !c.Blocked && id != n.myID {
			r[id] = false
		}
	}
	return r
}

func (n *Node) groupWire(g *Group) *grpWire {
	return &grpWire{ID: g.ID, Name: g.Name, Owner: g.Owner, Ver: g.Ver, Members: g.Members, Roles: g.Roles, Open: g.Open, Del: g.Deleted}
}

// groupParts verdeelt de kaarten van de leden over pakketten van ±900 bytes.
func (n *Node) groupParts(g *Group, exclude string) [][]Card {
	var parts [][]Card
	var cur []Card
	size := 0
	if !g.Deleted {
		for _, id := range g.Members {
			if id == exclude {
				continue
			}
			var card Card
			if id == n.myID {
				card = n.myCard()
			} else if c := n.st.Contacts[id]; c != nil {
				card = c.Card
			} else {
				continue
			}
			j, _ := json.Marshal(card)
			if size+len(j) > 900 && len(cur) > 0 {
				parts = append(parts, cur)
				cur, size = nil, 0
			}
			cur = append(cur, card)
			size += len(j)
		}
	}
	return append(parts, cur)
}

func (n *Node) groupSend(g *Group, c *Contact) {
	if c == nil || c.Blocked {
		return
	}
	parts := n.groupParts(g, c.ID)
	gw := n.groupWire(g)
	for i, cards := range parts {
		n.sendTo(c, n.sealJSON(c, wire{T: "grp", Grp: gw, Cards: cards, Part: i, Parts: len(parts), Ver: g.Ver}))
	}
}

// groupPublish: nieuwe versie en meteen uitsturen.
func (n *Node) groupPublish(g *Group) {
	v := now()
	if v <= g.Ver {
		v = g.Ver + 1
	}
	g.Ver = v
	g.Open = n.st.Policy.OpenGroups
	n.dirty = true
	for _, id := range n.groupTargets(g) {
		n.groupSend(g, n.st.Contacts[id])
	}
}

// groupTick (onder slot): eigen groepen opnieuw sturen naar wie nog niet bevestigde.
func (n *Node) groupTick() {
	for id, g := range n.st.Groups {
		if !n.mine(g) {
			continue
		}
		pending := 0
		for _, mid := range n.groupTargets(g) {
			c := n.st.Contacts[mid]
			if c == nil || c.Blocked || g.Acked[mid] >= g.Ver {
				continue
			}
			pending++
			n.groupSend(g, c)
		}
		if g.Deleted && pending == 0 {
			delete(n.st.Groups, id)
			n.dirty = true
		}
	}
}

func (n *Node) onGroupAck(c *Contact, m *wire) {
	g := n.st.Groups[m.ID]
	if g == nil || !n.mine(g) || m.Ver != g.Ver || m.Part < 0 || m.Part > 63 {
		return
	}
	key := fmt.Sprintf("%s|%s|%d", g.ID, c.ID, g.Ver)
	n.grpParts[key] |= 1 << uint(m.Part)
	if bits.OnesCount64(n.grpParts[key]) < m.Parts {
		return
	}
	delete(n.grpParts, key)
	if g.Acked == nil {
		g.Acked = map[string]int64{}
	}
	g.Acked[c.ID] = g.Ver
	if contains(g.Kicked, c.ID) {
		var k []string
		for _, x := range g.Kicked {
			if x != c.ID {
				k = append(k, x)
			}
		}
		g.Kicked = k
	}
	n.dirty = true
}

// onGroupCard: een lid ontvangt (een deel van) de groepskaart van de eigenaar.
func (n *Node) onGroupCard(c *Contact, m *wire, reply func(wire)) {
	gw := m.Grp
	if gw == nil || !validGroupID(gw.ID) || gw.Owner != c.ID {
		return
	}
	if n.st.Left[gw.ID] > 0 {
		reply(wire{T: "grpleave", ID: gw.ID})
		return
	}
	g := n.st.Groups[gw.ID]
	if g != nil && g.Owner != c.ID {
		return
	}
	if g != nil && g.LeftAt > 0 {
		reply(wire{T: "grpleave", ID: gw.ID})
		return
	}
	ack := func() { reply(wire{T: "grpack", ID: gw.ID, Ver: gw.Ver, Part: m.Part, Parts: m.Parts}) }
	// elke versie (en elk deel) van een groepskaart één keer verwerken; opnieuw afgespeeld = alleen bevestigen
	seenKey := fmt.Sprintf("grp|%s|%s|%d|%d", c.ID, gw.ID, gw.Ver, m.Part)
	if n.isSeen(seenKey) {
		ack()
		return
	}
	n.markSeenKey(seenKey)
	if g == nil && !n.can(c, "groups") {
		n.event("groep", fmt.Sprintf("Groepsuitnodiging van %s genegeerd (rol mag geen groepen maken)", c.Name))
		ack()
		return
	}
	if len(gw.Members) > groupMaxMembers || len(gw.Roles) > groupMaxMembers {
		if g == nil || gw.Ver > g.Ver {
			n.event("groep", fmt.Sprintf("Groepskaart van %s genegeerd (meer dan %d leden)", c.Name, groupMaxMembers))
		}
		ack()
		return
	}
	if g == nil {
		cnt := 0
		for _, og := range n.st.Groups {
			if og.Owner == c.ID {
				cnt++
			}
		}
		if cnt >= groupMaxPerOwner {
			n.event("groep", fmt.Sprintf("Groepsuitnodiging van %s genegeerd (al %d groepen)", c.Name, cnt))
			ack()
			return
		}
	}
	if g != nil && gw.Ver < g.Ver {
		ack()
		return
	}
	if gw.Del || !contains(gw.Members, n.myID) {
		if g != nil {
			delete(n.st.Groups, g.ID)
			n.dirty = true
			if gw.Del {
				n.event("groep", fmt.Sprintf("Groep “%s” is opgeheven door %s", g.Name, c.Name))
			} else {
				n.event("groep", fmt.Sprintf("Je bent uit de groep “%s” gehaald", g.Name))
			}
		}
		ack()
		return
	}
	name := strings.TrimSpace(gw.Name)
	name = truncBytes(name, 40)
	if name == "" {
		name = "Groep"
	}
	isNew := g == nil
	if isNew {
		g = &Group{ID: gw.ID, Owner: c.ID, Roles: map[string]string{}, Acked: map[string]int64{}}
		n.st.Groups[gw.ID] = g
		n.st.Messages = append(n.st.Messages, &Message{ID: randHex(8), Conv: "g:" + g.ID, Sys: true, Body: fmt.Sprintf("%s heeft je toegevoegd aan de groep", c.Name), TS: now()})
		n.event("groep", fmt.Sprintf("%s heeft je toegevoegd aan de groep “%s”", c.Name, name))
	}
	if isNew || gw.Ver > g.Ver {
		g.Name = name
		g.Members = append([]string{}, gw.Members...)
		g.Roles = map[string]string{}
		for id, r := range gw.Roles {
			if validRoles[r] && contains(gw.Members, id) {
				g.Roles[id] = r
			}
		}
		g.Open = gw.Open
		g.Ver = gw.Ver
	}
	n.dirty = true
	// Onbekende leden: alleen meteen contact als de eigenaar bij mij beheerder is;
	// anders komen ze als verzoek ("voorgesteld via <groep> door <naam>").
	trusted := roleOf(c) == "beheerder"
	if len(m.Cards) > groupMaxMembers {
		m.Cards = m.Cards[:groupMaxMembers]
	}
	for _, card := range m.Cards {
		if card.E == n.myID || !contains(gw.Members, card.E) || !card.Verify() {
			continue
		}
		if oc := n.st.Contacts[card.E]; oc != nil {
			n.updateCard(oc, card)
			continue
		}
		if n.st.Removed[card.E] > 0 {
			continue
		}
		if trusted {
			nc := n.addContact(card, "", "lid", g.Name)
			n.event("contact", fmt.Sprintf("%s voorgesteld via groep “%s”", nc.Name, g.Name))
			continue
		}
		p, isNew := n.addPending(card, "groep", "")
		wasGroup := p.Source == "groep"
		p.Source = "groep"
		p.Note = fmt.Sprintf("voorgesteld via %s door %s", g.Name, c.Name)
		if isNew || !wasGroup {
			n.event("contact", fmt.Sprintf("%s voorgesteld via groep “%s” door %s: wacht op jouw toelating", truncBytes(card.N, 40), g.Name, c.Name))
		}
	}
	ack()
}

func (n *Node) onGroupLeave(c *Contact, m *wire, reply func(wire)) {
	g := n.st.Groups[m.ID]
	if g == nil {
		reply(wire{T: "grpleft", ID: m.ID})
		return
	}
	if n.mine(g) {
		if g.has(c.ID) {
			n.removeMember(g, c.ID)
			n.st.Messages = append(n.st.Messages, &Message{ID: randHex(8), Conv: "g:" + g.ID, Sys: true, Body: c.Name + " heeft de groep verlaten", TS: now()})
			n.event("groep", fmt.Sprintf("%s heeft de groep “%s” verlaten", c.Name, g.Name))
			g.Kicked = removeStr(g.Kicked, c.ID)
			n.groupPublish(g)
		}
		reply(wire{T: "grpleft", ID: m.ID})
		return
	}
	if g.has(c.ID) && c.ID != g.Owner {
		g.Members = removeStr(g.Members, c.ID)
		n.dirty = true
	}
}

func (n *Node) onGroupLeft(c *Contact, m *wire) {
	g := n.st.Groups[m.ID]
	if g != nil && g.LeftAt > 0 && g.Owner == c.ID {
		delete(n.st.Groups, m.ID)
		n.st.Left[m.ID] = now()
		n.dirty = true
	}
}

// leaveTick (onder slot): verlaten groepen blijven het melden tot de eigenaar bevestigt.
func (n *Node) leaveTick() {
	t := now()
	for id, g := range n.st.Groups {
		if g.LeftAt == 0 {
			continue
		}
		o := n.st.Contacts[g.Owner]
		if o == nil || o.Blocked || t-g.LeftAt > 30*86400 {
			delete(n.st.Groups, id)
			n.st.Left[id] = t
			n.dirty = true
			continue
		}
		n.sendTo(o, n.sealJSON(o, wire{T: "grpleave", ID: id}))
	}
}

// onGroupRequest: een lid vraagt de eigenaar om mensen toe te voegen (policy openGroups).
func (n *Node) onGroupRequest(c *Contact, m *wire) {
	g := n.st.Groups[m.ID]
	if g == nil || !n.mine(g) || !g.visible() || !g.has(c.ID) {
		return
	}
	if !n.st.Policy.OpenGroups || g.role(c.ID) == "lezer" || !n.can(c, "invite") {
		n.event("groep", fmt.Sprintf("Verzoek van %s om leden toe te voegen aan “%s” geweigerd", c.Name, g.Name))
		return
	}
	added := 0
	for _, card := range m.Cards {
		if len(g.Members) >= groupMaxMembers {
			break
		}
		if card.E == n.myID || g.has(card.E) || !card.Verify() {
			continue
		}
		oc := n.st.Contacts[card.E]
		if oc != nil && oc.Blocked {
			continue
		}
		if oc == nil {
			oc = n.addContact(card, "", "lid", fmt.Sprintf("%s (groep %s)", c.Name, g.Name))
		}
		g.Members = append(g.Members, oc.ID)
		added++
	}
	if added > 0 {
		n.audit(fmt.Sprintf("%s heeft %d lid/leden toegevoegd aan “%s”", c.Name, added, g.Name))
		n.st.Messages = append(n.st.Messages, &Message{ID: randHex(8), Conv: "g:" + g.ID, Sys: true, Body: fmt.Sprintf("%s heeft %d lid/leden toegevoegd", c.Name, added), TS: now()})
		n.groupPublish(g)
	}
}

func removeStr(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func (n *Node) removeMember(g *Group, id string) {
	g.Members = removeStr(g.Members, id)
	delete(g.Roles, id)
	if !contains(g.Kicked, id) {
		g.Kicked = append(g.Kicked, id)
	}
	n.dirty = true
}

// ---------- acties vanuit de API (onder slot) ----------

type groupIn struct {
	Action  string            `json:"action"`
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Members *[]string         `json:"members"`
	Roles   map[string]string `json:"roles"`
}

func (n *Node) groupAction(in groupIn) (*Group, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Name = truncBytes(in.Name, 40)
	checkMembers := func() ([]string, error) {
		var out []string
		if in.Members == nil {
			return nil, nil
		}
		for _, id := range *in.Members {
			if id == n.myID || contains(out, id) {
				continue
			}
			c := n.st.Contacts[id]
			if c == nil {
				return nil, errors.New("Onbekend contact in de ledenlijst")
			}
			if c.Blocked {
				return nil, fmt.Errorf("%s is geblokkeerd en kan geen lid worden", c.Name)
			}
			out = append(out, id)
		}
		if len(out) > groupMaxMembers-1 {
			return nil, fmt.Errorf("Een groep heeft hooguit %d leden", groupMaxMembers)
		}
		return out, nil
	}
	setRoles := func(g *Group) {
		if in.Roles == nil {
			return
		}
		g.Roles = map[string]string{}
		for id, r := range in.Roles {
			if validRoles[r] && g.has(id) && id != g.Owner {
				g.Roles[id] = r
			}
		}
	}
	switch in.Action {
	case "create":
		if in.Name == "" {
			return nil, errors.New("Geef de groep een naam")
		}
		mem, err := checkMembers()
		if err != nil {
			return nil, err
		}
		if len(mem) == 0 {
			return nil, errors.New("Kies minstens één lid")
		}
		g := &Group{ID: randHex(8), Name: in.Name, Owner: n.myID, Members: append([]string{n.myID}, mem...), Roles: map[string]string{}, Acked: map[string]int64{}}
		setRoles(g)
		n.st.Groups[g.ID] = g
		n.st.Messages = append(n.st.Messages, &Message{ID: randHex(8), Conv: "g:" + g.ID, Sys: true, Body: fmt.Sprintf("Groep gemaakt, %d leden uitgenodigd", len(mem)), TS: now()})
		n.event("groep", fmt.Sprintf("Groep “%s” gemaakt", g.Name))
		n.groupPublish(g)
		return g, nil
	}
	g := n.st.Groups[in.ID]
	if g == nil || !g.visible() {
		return nil, errors.New("Groep niet gevonden")
	}
	switch in.Action {
	case "update":
		mem, err := checkMembers()
		if err != nil {
			return nil, err
		}
		if !n.mine(g) {
			if !g.Open {
				return nil, errors.New("Alleen de eigenaar kan deze groep aanpassen")
			}
			if g.role(n.myID) == "lezer" {
				return nil, errors.New("Je bent lezer in deze groep")
			}
			var cards []Card
			for _, id := range mem {
				if !g.has(id) {
					cards = append(cards, n.st.Contacts[id].Card)
				}
			}
			if len(cards) == 0 {
				return g, nil
			}
			if o := n.st.Contacts[g.Owner]; o != nil {
				n.sendTo(o, n.sealJSON(o, wire{T: "grpreq", ID: g.ID, Cards: cards}))
			}
			n.event("groep", fmt.Sprintf("Gevraagd aan de eigenaar om %d lid/leden toe te voegen aan “%s”", len(cards), g.Name))
			return g, nil
		}
		if in.Name != "" {
			g.Name = in.Name
		}
		if in.Members != nil {
			if len(mem) == 0 {
				return nil, errors.New("Kies minstens één lid")
			}
			for _, id := range g.Members {
				if id != n.myID && !contains(mem, id) {
					n.removeMember(g, id)
				}
			}
			for _, id := range mem {
				if !g.has(id) {
					g.Members = append(g.Members, id)
					g.Kicked = removeStr(g.Kicked, id)
				}
			}
		}
		setRoles(g)
		n.st.Messages = append(n.st.Messages, &Message{ID: randHex(8), Conv: "g:" + g.ID, Sys: true, Body: fmt.Sprintf("Groep bijgewerkt, %d leden", len(g.Members)-1), TS: now()})
		n.event("groep", fmt.Sprintf("Groep “%s” bijgewerkt", g.Name))
		n.groupPublish(g)
		return g, nil
	case "delete", "leave":
		if n.mine(g) {
			for _, id := range g.Members {
				if id != n.myID && !contains(g.Kicked, id) {
					g.Kicked = append(g.Kicked, id)
				}
			}
			g.Members = []string{n.myID}
			g.Deleted = true
			g.Unread = 0
			n.event("groep", fmt.Sprintf("Groep “%s” verwijderd", g.Name))
			n.groupPublish(g)
			return g, nil
		}
		g.LeftAt = now()
		g.Unread = 0
		n.dirty = true
		if o := n.st.Contacts[g.Owner]; o != nil {
			n.sendTo(o, n.sealJSON(o, wire{T: "grpleave", ID: g.ID}))
		}
		for _, id := range g.Members {
			if c := n.st.Contacts[id]; c != nil && id != g.Owner {
				n.sendTo(c, n.sealJSON(c, wire{T: "grpleave", ID: g.ID}))
			}
		}
		n.event("groep", fmt.Sprintf("Groep “%s” verlaten", g.Name))
		return g, nil
	}
	return nil, errors.New("Onbekende actie")
}

// removeContactFromGroups: na verwijderen of blokkeren van een contact.
func (n *Node) removeContactFromGroups(id string) {
	for _, g := range n.st.Groups {
		if n.mine(g) && g.visible() && g.has(id) {
			n.removeMember(g, id)
			n.groupPublish(g)
		}
	}
}

// rotateGroupKeys: nieuwe versie van alle eigen groepen en opnieuw uitsturen.
func (n *Node) rotateGroupKeys() int {
	cnt := 0
	for _, g := range n.st.Groups {
		if n.mine(g) && g.visible() {
			n.groupPublish(g)
			cnt++
		}
	}
	n.st.Policy.KeyRot = now()
	n.dirty = true
	return cnt
}
