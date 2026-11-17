package main

// Vers of opnieuw afgespeeld, ZONDER dat de klokken van twee stations moeten kloppen.
//
// Ontwerp (na review: een Raspberry Pi zonder RTC start na stroomuitval met een oude tijd, en zonder
// internet is er geen NTP):
//
//   - Elke opstart krijgt een willekeurige opstart-ID (boot, 8 hex). Die gaat mee in elke versleutelde
//     payload (veld "b"), samen met het verzendtijdstip "ts" (ms). Binnen één opstart is ts strikt
//     stijgend (ook als de klok terugspringt: max(klok, vorige+1)).
//   - Per contact en per opstart-ID onthoud ik het hoogwatermerk (hoogste ts). Een pakket is "vers" als
//     zijn ts hoger is dan het merk van zijn opstart-ID; een opnieuw afgespeeld pakket heeft altijd een
//     lager of gelijk ts. Een onbekende opstart-ID = nieuwe opstart = vers (een contact dat herstart met
//     een klok die een dag achterloopt, werkt dus meteen). De laatste 8 opstarts worden bewaard (in het
//     contact, dus ook over herstarts heen); een pakket van een oudere, gekende opstart met een lager ts
//     wordt nooit meer vers. Ik vergelijk nooit met mijn eigen klok.
//   - Alleen een vers pakket zet een contact online en leert een nieuw adres.
//   - Klokverschil per contact: (hun ts − mijn tijd) uit verse pings, mediaan van de laatste 5. Dat wordt
//     alleen gebruikt om (a) in het scherm te tonen en (b) berichten te weigeren die volgens de klok van
//     de afzender zelf ouder zijn dan 8 dagen (ts − verschil). Zonder bekend verschil: niets weigeren op
//     tijd, alleen de bewaarde gezien-lijst (bericht-ID, 9 dagen) gebruiken. Daarnaast: ouder dan 8 dagen
//     t.o.v. het hoogwatermerk van dezelfde opstart = weigeren (alleen de klok van de afzender).
//   - LoRa-frames dragen alleen ts (seconden): gezien-lijst op bericht-ID plus dezelfde leeftijdscontrole.
//     Bakens: hoogwatermerk per afzender en per opstart (16 bits opstart-ID + 16 bits teller).
//   - Leeftijd van berichten, SOS en groepskaarten (IP en radio), onafhankelijk van opstart of hoe lang
//     het contact al stil is (tooOld):
//       1. per contact het hoogste afzender-tijdstip ooit gezien (MaxTS, over alle opstarts en de radio
//          heen, bewaard): ts meer dan 8 dagen daaronder = weigeren;
//       2. volgens het klokverschil van die opstart, of anders het laatst bekende klokverschil (zonder
//          tijdslimiet): ouder dan 8 dagen = weigeren.
//     Pings worden nooit op leeftijd geweigerd (alleen vers of niet), zodat een contact altijd online kan komen.
//     Gevolg: een station dat herstart met een klok tot 8 dagen achter werkt gewoon (bv. een Pi zonder RTC
//     die 1 of 7 dagen uit stond). Loopt de klok MEER dan 8 dagen achter, dan worden berichten van dat
//     station geweigerd tot de klok klopt; het scherm toont dan bij dat contact "klok wijkt X af".
//     Omgekeerd: liep de klok van een station ooit meer dan 8 dagen VOOR (MaxTS te hoog) en wordt hij
//     daarna juist gezet, dan worden zijn berichten geweigerd tot zijn klok MaxTS − 8 dagen voorbij is.
//     De gezien-lijst bewaart berichten 60 dagen (begrensd aantal).

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync/atomic"
	"time"
)

const (
	maxBoots      = 8
	skewSamples   = 5
	skewShowMs    = 5 * 60 * 1000 // vanaf dit verschil toont het scherm "klok wijkt af"
	msgMaxAgeMs   = 8 * 86400 * 1000
	skewStateSecs = 3600 // in het scherm: alleen verschillen van het laatste uur
)

type bootMark struct {
	Hi     int64 `json:"hi"`            // hoogste ts (ms, klok van de afzender)
	Off    int64 `json:"off,omitempty"` // klokverschil (ms) tijdens deze opstart
	HasOff bool  `json:"has_off,omitempty"`
	At     int64 `json:"at"` // laatst bijgewerkt (s, mijn klok; alleen om de oudste te kiezen)
}

// sendSkew verschuift het verzendtijdstip (alleen voor tests: een klok die voor- of achterloopt).
var sendSkew atomic.Int64

func newBootID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// sendClockMs: verzendtijdstip in ms, strikt stijgend binnen deze opstart van dit station.
func (n *Node) sendClockMs() int64 {
	t := time.Now().UnixMilli() + sendSkew.Load()
	for {
		last := n.tsLast.Load()
		v := t
		if v <= last {
			v = last + 1
		}
		if n.tsLast.CompareAndSwap(last, v) {
			return v
		}
	}
}

// boot16: de eerste 16 bits van de opstart-ID (voor het radiobaken).
func (n *Node) boot16() uint16 {
	b, _ := hex.DecodeString(n.bootID)
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// tooOld (onder slot): is een bericht/SOS/groepskaart met afzendertijd ts (ms) ouder dan 8 dagen?
// boot = opstart-ID ("" voor radioframes). Zie de uitleg bovenaan.
func (n *Node) tooOld(c *Contact, ts int64, boot string) bool {
	if c.MaxTS > 0 && ts < c.MaxTS-msgMaxAgeMs {
		return true // 8 dagen ouder dan het nieuwste dat dit contact ooit stuurde
	}
	off, ok := int64(0), false
	if bm := c.Boots[boot]; boot != "" && bm != nil && bm.HasOff {
		off, ok = bm.Off, true
	} else {
		off, ok = lastSkew(c)
	}
	return ok && time.Now().UnixMilli()-(ts-off) > msgMaxAgeMs
}

// noteMaxTS (onder slot): hoogste afzendertijd van c bijhouden (geldig, ondertekend of versleuteld pakket).
func (n *Node) noteMaxTS(c *Contact, ts int64) {
	if ts > c.MaxTS {
		c.MaxTS = ts
		n.hwmDirty = true
	}
}

// peerTS (onder slot) beoordeelt ts (ms) + opstart-ID van een payload van c: fresh = hoger dan het
// hoogwatermerk van die opstart (of een nieuwe opstart). Geen leeftijdscontrole (zie tooOld).
func (n *Node) peerTS(c *Contact, ts int64, boot string) (fresh bool) {
	if c.Boots == nil {
		c.Boots = map[string]*bootMark{}
	}
	t := now()
	n.noteMaxTS(c, ts)
	bm := c.Boots[boot]
	if bm != nil {
		if ts <= bm.Hi {
			return false
		}
		bm.Hi = ts
		bm.At = t
		n.hwmDirty = true
		return true
	}
	c.Boots[boot] = &bootMark{Hi: ts, At: t}
	for len(c.Boots) > maxBoots {
		old, ot := "", int64(-1)
		for k, v := range c.Boots {
			if k != boot && (ot < 0 || v.At < ot) {
				old, ot = k, v.At
			}
		}
		delete(c.Boots, old)
	}
	n.dirty = true
	return true
}

// sampleSkew (onder slot): klokverschil uit een verse ping/pong.
func (n *Node) sampleSkew(c *Contact, ts int64, boot string) {
	off := ts - time.Now().UnixMilli()
	if c.Boot != boot {
		c.Boot = boot
		c.Skews = nil
	}
	c.Skews = append(c.Skews, off)
	if len(c.Skews) > skewSamples {
		c.Skews = c.Skews[len(c.Skews)-skewSamples:]
	}
	c.SkewAt = now()
	if bm := c.Boots[boot]; bm != nil {
		bm.Off, bm.HasOff = median(c.Skews), true
	}
}

func median(l []int64) int64 {
	if len(l) == 0 {
		return 0
	}
	s := append([]int64{}, l...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// recentSkew (onder slot): het laatst gemeten klokverschil (IP of radiobaken), als het jonger is dan maxAge s.
func recentSkew(c *Contact, maxAge int64) (int64, bool) {
	t := now()
	switch {
	case len(c.Skews) > 0 && t-c.SkewAt <= maxAge && (c.RadioOffAt == 0 || c.SkewAt >= c.RadioOffAt):
		return median(c.Skews), true
	case c.RadioOffAt > 0 && t-c.RadioOffAt <= maxAge:
		return c.RadioOff, true
	case len(c.Skews) > 0 && t-c.SkewAt <= maxAge:
		return median(c.Skews), true
	}
	return 0, false
}

// lastSkew (onder slot): het laatst gemeten klokverschil (IP of radiobaken), hoe oud ook.
func lastSkew(c *Contact) (int64, bool) {
	return recentSkew(c, 1<<62)
}

// myClockSkew (onder slot): hoe ver mijn klok afwijkt van de mediaan van mijn contacten (ms), als
// er recente metingen zijn. Positief = mijn klok loopt voor.
func (n *Node) myClockSkew() (int64, bool) {
	var l []int64
	for _, c := range n.st.Contacts {
		if off, ok := recentSkew(c, skewStateSecs); ok && !c.Blocked {
			l = append(l, off)
		}
	}
	if len(l) == 0 {
		return 0, false
	}
	return -median(l), true
}
