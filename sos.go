package main

// Versturen van berichten, SOS en locatie.

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

type SosState struct {
	ID    string           `json:"id"`
	Start int64            `json:"start"`
	Acks  map[string]int64 `json:"acks"`
}

type IncomingSos struct {
	ID   string `json:"id"`
	From string `json:"from"`
	TS   int64  `json:"ts"`
	Body string `json:"body"`
	Pos  *Pos   `json:"pos,omitempty"`
}

type sendOpts struct {
	Sos, SosEnd, Osint bool
	SA                 string
	Img                string
	ImgSize            int
}

// newOutMsg (onder slot) maakt een eigen bericht en zet het in de uitgaande wachtrij.
func (n *Node) newOutMsg(conv, body string, o sendOpts) (*Message, error) {
	recips := map[string]bool{}
	switch {
	case conv == "alle":
		for id, c := range n.st.Contacts {
			if !c.Blocked {
				recips[id] = false
			}
		}
	case strings.HasPrefix(conv, "g:"):
		g := n.st.Groups[conv[2:]]
		if g == nil || !g.visible() {
			return nil, errors.New("Groep niet gevonden")
		}
		if !n.mine(g) && g.role(n.myID) == "lezer" {
			return nil, errors.New("Je bent lezer in deze groep en kunt hier niet schrijven")
		}
		recips = n.groupRecips(g)
	default:
		c := n.st.Contacts[conv]
		if c == nil {
			return nil, errors.New("Onbekend contact")
		}
		if c.Blocked {
			return nil, errors.New("Dit contact is geblokkeerd")
		}
		recips[conv] = false
	}
	m := &Message{ID: randHex(8), Conv: conv, From: "me", Body: body, TS: now(), Recips: recips,
		Sos: o.Sos, SosEnd: o.SosEnd, SA: o.SA, Osint: o.Osint, Img: o.Img, ImgSize: o.ImgSize}
	if o.Img != "" {
		m.ImgSt = "ok"
	}
	n.st.Messages = append(n.st.Messages, m)
	n.dirty = true
	return m, nil
}

func (n *Node) convName(conv string) string {
	switch {
	case conv == "alle":
		return "Iedereen"
	case strings.HasPrefix(conv, "g:"):
		if g := n.st.Groups[conv[2:]]; g != nil {
			return g.Name
		}
		return "groep"
	}
	return n.contactName(conv)
}

func (n *Node) contactName(id string) string {
	if id == n.myID || id == "me" {
		return "Ik"
	}
	if c := n.st.Contacts[id]; c != nil {
		return c.Name
	}
	return "?"
}

// ---------- SOS ----------

func (n *Node) sosStart() (*Message, error) {
	if n.st.Sos != nil {
		return nil, errors.New("Er is al een SOS actief")
	}
	pos := "Locatie niet gedeeld."
	if p := n.myPos(); p != nil && n.st.Share {
		pos = fmt.Sprintf("Positie %.5f, %.5f.", p.Lat, p.Lon)
	}
	body := fmt.Sprintf("%s heeft hulp nodig. %s", n.st.Name, pos)
	m, err := n.newOutMsg("alle", body, sendOpts{Sos: true})
	if err != nil {
		return nil, err
	}
	n.st.Sos = &SosState{ID: m.ID, Start: m.TS, Acks: map[string]int64{}}
	n.event("sos", fmt.Sprintf("SOS verstuurd naar %d contacten", len(m.Recips)))
	return m, nil
}

func (n *Node) sosStop() error {
	if n.st.Sos == nil {
		return errors.New("Er is geen SOS actief")
	}
	n.st.Sos = nil
	n.dirty = true
	_, err := n.newOutMsg("alle", sosEndText+": alles is weer onder controle.", sendOpts{SosEnd: true})
	n.event("sos", "SOS beëindigd")
	return err
}

// sosSeen: ik bevestig een binnengekomen SOS; de bevestiging gaat terug naar de zender.
func (n *Node) sosSeen(id string) error {
	for i, s := range n.st.IncomingSos {
		if s.ID != id {
			continue
		}
		n.st.IncomingSos = append(n.st.IncomingSos[:i], n.st.IncomingSos[i+1:]...)
		n.dirty = true
		if c := n.st.Contacts[s.From]; c != nil && !c.Blocked {
			if _, err := n.newOutMsg(c.ID, sosSeenText, sendOpts{SA: s.ID}); err != nil {
				return err
			}
			n.event("sos", "SOS van "+c.Name+" bevestigd")
		}
		return nil
	}
	return errors.New("Deze SOS is niet (meer) actief")
}

func (n *Node) addIncomingSos(c *Contact, m *Message) {
	for _, s := range n.st.IncomingSos {
		if s.ID == m.ID && s.From == c.ID {
			return
		}
	}
	n.clearIncomingSos(c.ID) // één actieve SOS per contact
	var p *Pos
	if c.Pos != nil {
		cp := *c.Pos
		p = &cp
	}
	n.st.IncomingSos = append(n.st.IncomingSos, &IncomingSos{ID: m.ID, From: c.ID, TS: m.TS, Body: m.Body, Pos: p})
	n.dirty = true
}

func (n *Node) clearIncomingSos(from string) {
	out := n.st.IncomingSos[:0]
	for _, s := range n.st.IncomingSos {
		if s.From != from {
			out = append(out, s)
		}
	}
	n.st.IncomingSos = out
	n.dirty = true
}

// ---------- locatie ----------

// myPos (onder slot): vaste locatie, anders GPS van de radio.
func (n *Node) myPos() *Pos {
	if n.st.Loc.valid() {
		return &Pos{Lat: n.st.Loc.Lat, Lon: n.st.Loc.Lon, TS: n.st.Loc.TS, Src: "vaste locatie"}
	}
	if lat, lon, ts, ok := n.radio.GPS(); ok {
		return &Pos{Lat: lat, Lon: lon, TS: ts, Src: "GPS radio"}
	}
	return nil
}

func samePos(a, b *Pos) bool {
	if a == nil || b == nil {
		return a == b
	}
	return math.Abs(a.Lat-b.Lat) < 1e-6 && math.Abs(a.Lon-b.Lon) < 1e-6
}
