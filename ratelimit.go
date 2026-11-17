package main

// Afremmen van hello's van vreemden (CPU voor handtekeningen) en begrenzen van verzoeken.

import (
	"encoding/hex"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	pendPerSrc   = 3  // openstaande verzoeken per bron-IP (IPv6: per /64)
	pendMax      = 50 // openstaande verzoeken in totaal (oudste eruit)
	helloRate    = 20 // hello's per seconde, globaal
	helloSrcRate = 4  // hello's per seconde per bron
)

// srcPrefix: IPv4-adres, of het /64 van een IPv6-adres.
func srcPrefix(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return hex.EncodeToString(ip.To16()[:8]) + "/64"
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(rate, burst float64, t time.Time) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens += t.Sub(b.last).Seconds() * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLim: token bucket per bron-prefix en globaal. Heeft een eigen slot (niet n.mu).
type rateLim struct {
	mu        sync.Mutex
	rate, src float64
	global    bucket
	per       map[string]*bucket
}

func newRateLim(global, perSrc float64) *rateLim {
	return &rateLim{rate: global, src: perSrc, per: map[string]*bucket{}}
}

func (l *rateLim) allow(prefix string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := time.Now()
	if len(l.per) > 4096 { // opruimen: emmers die al even vol zijn
		for k, b := range l.per {
			if t.Sub(b.last) > 10*time.Second {
				delete(l.per, k)
			}
		}
		if len(l.per) > 4096 {
			l.per = map[string]*bucket{}
		}
	}
	b := l.per[prefix]
	if b == nil {
		b = &bucket{}
		l.per[prefix] = b
	}
	// eerst per bron, dan globaal: één drukke bron kan zo de globale emmer niet leegmaken
	if !b.take(l.src, 2*l.src, t) {
		return false
	}
	return l.global.take(l.rate, 2*l.rate, t)
}

// addPending (onder slot): verzoek bewaren of bijwerken. Hooguit pendPerSrc per bron en
// pendMax in totaal; bij te veel valt het oudste weg (nieuwe worden niet geweigerd).
func (n *Node) addPending(card Card, source, prefix string) (*Pending, bool) {
	p := n.st.Pending[card.E]
	if p != nil {
		if card.TS >= p.Card.TS {
			p.Card = card
		}
		p.Seen = now()
		n.dirty = true
		return p, false
	}
	type kv struct {
		id   string
		seen int64
	}
	var all, same []kv
	for id, q := range n.st.Pending {
		all = append(all, kv{id, q.Seen})
		if prefix != "" && q.Prefix == prefix {
			same = append(same, kv{id, q.Seen})
		}
	}
	oldestFirst := func(l []kv) {
		sort.Slice(l, func(i, j int) bool { return l[i].seen < l[j].seen })
	}
	oldestFirst(same)
	for len(same) >= pendPerSrc {
		delete(n.st.Pending, same[0].id)
		same = same[1:]
	}
	if len(n.st.Pending) >= pendMax {
		all = all[:0]
		for id, q := range n.st.Pending {
			all = append(all, kv{id, q.Seen})
		}
		oldestFirst(all)
		for i := 0; len(n.st.Pending) >= pendMax && i < len(all); i++ {
			delete(n.st.Pending, all[i].id)
		}
	}
	p = &Pending{Card: card, Source: source, Prefix: prefix, Seen: now()}
	n.st.Pending[card.E] = p
	n.dirty = true
	return p, true
}
