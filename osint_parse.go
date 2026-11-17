package main

// OSINT-parsers: Meteoalarm (Atom + CAP), GDACS (RSS), EMSC (FDSN GeoJSON), RSS/Atom,
// readsb/dump1090 aircraft.json. Plus kleine hulpfuncties (afstand, getallen in het Nederlands).

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---------- XML ----------

type osAtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr"`
}

type osAtomEntry struct {
	Title     string       `xml:"title"`
	ID        string       `xml:"id"`
	Published string       `xml:"published"`
	Updated   string       `xml:"updated"`
	Summary   string       `xml:"summary"`
	Content   string       `xml:"content"`
	Links     []osAtomLink `xml:"link"`
	// CAP-velden (Meteoalarm)
	AreaDesc   string `xml:"areaDesc"`
	Event      string `xml:"event"`
	Sent       string `xml:"sent"`
	Expires    string `xml:"expires"`
	Onset      string `xml:"onset"`
	Severity   string `xml:"severity"`
	MsgType    string `xml:"message_type"`
	Status     string `xml:"status"`
	Identifier string `xml:"identifier"`
}

type osRSSItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	Encoded     string `xml:"encoded"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"date"`
	GUID        string `xml:"guid"`
	// GDACS
	AlertLevel string `xml:"alertlevel"`
	EventType  string `xml:"eventtype"`
	Country    string `xml:"country"`
	IsCurrent  string `xml:"iscurrent"`
	Point      string `xml:"point"`
}

type osXMLFeed struct {
	XMLName xml.Name
	Title   string `xml:"title"`
	Channel struct {
		Title string      `xml:"title"`
		Items []osRSSItem `xml:"item"`
	} `xml:"channel"`
	Items   []osRSSItem   `xml:"item"` // RSS 1.0 (RDF)
	Entries []osAtomEntry `xml:"entry"`
}

var osCP1252 = map[byte]rune{0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…', 0x86: '†', 0x87: '‡',
	0x88: 'ˆ', 0x89: '‰', 0x8A: 'Š', 0x8B: '‹', 0x8C: 'Œ', 0x8E: 'Ž', 0x91: '‘', 0x92: '’', 0x93: '“',
	0x94: '”', 0x95: '•', 0x96: '–', 0x97: '—', 0x98: '˜', 0x99: '™', 0x9A: 'š', 0x9B: '›', 0x9C: 'œ',
	0x9E: 'ž', 0x9F: 'Ÿ'}

func osCharsetReader(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "utf-8", "utf8", "":
		return in, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "iso-8859-15", "windows-1252", "cp1252", "us-ascii", "ascii":
		b, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		var sb strings.Builder
		for _, c := range b {
			if r, ok := osCP1252[c]; ok {
				sb.WriteRune(r)
			} else {
				sb.WriteRune(rune(c))
			}
		}
		return strings.NewReader(sb.String()), nil
	}
	return nil, fmt.Errorf("tekenset %q niet ondersteund", label)
}

func osDecodeXML(b []byte, v any) error {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	b = bytes.TrimLeftFunc(b, unicode.IsSpace)
	d := xml.NewDecoder(bytes.NewReader(b))
	d.CharsetReader = osCharsetReader
	d.Strict = false
	d.Entity = xml.HTMLEntity
	return d.Decode(v)
}

// ---------- tijd ----------

var osTimeLayouts = []string{
	time.RFC3339Nano, time.RFC3339, time.RFC1123Z, time.RFC1123,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04 -0700",
	"Mon, 2 Jan 2006 15:04 MST", "2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 06 15:04:05 -0700", "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05",
	"2006-01-02T15:04:05.999999999", "2006-01-02",
}

// osParseTime geeft ms sinds epoch, of 0.
func osParseTime(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	for _, l := range osTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

// ---------- tekst ----------

var osTagRE = regexp.MustCompile(`(?s)<[^>]*>`)

func osStripHTML(s string) string {
	s = strings.ReplaceAll(s, "<br", "\n<br")
	s = strings.ReplaceAll(s, "</p>", "</p>\n")
	s = osTagRE.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// osClean haalt stuurtekens weg (behalve regeleinden) en maakt geldige UTF-8.
func osClean(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func osTrunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

func osCap(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

func osTitleCase(s string) string {
	words := strings.Fields(strings.ToLower(s))
	for i, w := range words {
		words[i] = osCap(w)
	}
	return strings.Join(words, " ")
}

// osNum: getal in Nederlandse notatie (1.200 / 2,1 / −101).
func osNum(f float64, dec int) string {
	neg := f < 0
	if neg {
		f = -f
	}
	s := strconv.FormatFloat(f, 'f', dec, 64)
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i+1:]
	}
	var b strings.Builder
	for i, c := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte('.')
		}
		b.WriteRune(c)
	}
	out := b.String()
	if frac != "" {
		out += "," + frac
	}
	if neg && strings.Trim(out, "0.,") != "" {
		out = "−" + out
	}
	return out
}

func osKm(d float64) string {
	if d < 10 {
		return osNum(d, 1) + " km"
	}
	return osNum(math.Round(d), 0) + " km"
}

// ---------- afstand ----------

func osDistKm(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * R * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func osBearing(lat1, lon1, lat2, lon2 float64) float64 {
	rad := math.Pi / 180
	y := math.Sin((lon2-lon1)*rad) * math.Cos(lat2*rad)
	x := math.Cos(lat1*rad)*math.Sin(lat2*rad) - math.Sin(lat1*rad)*math.Cos(lat2*rad)*math.Cos((lon2-lon1)*rad)
	return math.Mod(math.Atan2(y, x)/rad+360, 360)
}

func osCompass(b float64) string {
	dirs := []string{"N", "NO", "O", "ZO", "Z", "ZW", "W", "NW"}
	return dirs[int(math.Mod(b+22.5, 360)/45)%8]
}

// osWhere: "22 km O" (van mij naar het punt).
func osWhere(myLat, myLon, lat, lon float64) (string, float64) {
	d := osDistKm(myLat, myLon, lat, lon)
	if d < 0.5 {
		return "hier", d
	}
	return osKm(d) + " " + osCompass(osBearing(myLat, myLon, lat, lon)), d
}

func osLocalTime(ms int64) string {
	return time.UnixMilli(ms).Local().Format("02/01 15:04")
}

// ---------- Meteoalarm ----------

var osMeteoHazard = map[string]string{
	"wind": "wind", "rain": "regen", "snow-ice": "sneeuw en ijzel", "snow/ice": "sneeuw en ijzel", "snow": "sneeuw",
	"ice": "ijzel", "thunderstorm": "onweer", "thunderstorms": "onweer", "fog": "mist",
	"high-temperature": "hitte", "high temperature": "hitte", "extreme high temperature": "hitte",
	"low-temperature": "koude", "low temperature": "koude", "extreme low temperature": "koude",
	"coastalevent": "stormtij aan de kust", "coastal event": "stormtij aan de kust",
	"forest-fire": "bosbrandgevaar", "forest fire": "bosbrandgevaar", "avalanches": "lawines", "avalanche": "lawines",
	"rain-flood": "overstromingen door regen", "rain flood": "overstromingen door regen", "flooding": "overstromingen",
	"flood": "overstromingen",
}

var osBEAreas = map[string]string{
	"west flanders": "West-Vlaanderen", "east flanders": "Oost-Vlaanderen", "antwerp": "Antwerpen",
	"limburg": "Limburg", "flemish brabant": "Vlaams-Brabant", "walloon brabant": "Waals-Brabant",
	"brabant": "Brabant", "brussels": "Brussel", "brussels capital region": "Brussel", "hainaut": "Henegouwen",
	"liège": "Luik", "liege": "Luik", "namur": "Namen", "luxembourg": "Luxemburg", "coastal zone": "Kustzone",
	"belgium": "België",
}

var osColorNL = map[string]string{"yellow": "geel", "orange": "oranje", "red": "rood", "green": "groen"}

func osMeteoColor(e osAtomEntry) string {
	for _, s := range []string{e.Event, e.Title} {
		l := strings.ToLower(strings.TrimSpace(s))
		for _, c := range []string{"green", "yellow", "orange", "red"} {
			if strings.HasPrefix(l, c+" ") {
				return c
			}
		}
	}
	switch strings.ToLower(e.Severity) {
	case "minor":
		return "green"
	case "moderate":
		return "yellow"
	case "severe":
		return "orange"
	case "extreme":
		return "red"
	}
	return ""
}

func osMeteoHazardNL(e osAtomEntry) string {
	l := strings.ToLower(e.Event)
	if i := strings.Index(l, " for "); i >= 0 {
		h := strings.TrimSpace(l[i+5:])
		if nl, ok := osMeteoHazard[h]; ok {
			return nl
		}
		if h != "" {
			return h
		}
	}
	t := strings.ToLower(e.Title) // "Yellow Wind Warning issued for …"
	for k, v := range osMeteoHazard {
		if strings.Contains(t, " "+k+" warning") {
			return v
		}
	}
	return "weer"
}

// osParseMeteo leest de Meteoalarm-Atomfeed. Groene en verlopen meldingen vallen weg;
// dezelfde waarschuwing voor meerdere provincies wordt één melding.
// active = aantal waarschuwingen die nu of later vandaag gelden.
func osParseMeteo(b []byte, now time.Time) (cands []osCand, active int, err error) {
	var f osXMLFeed
	if err := osDecodeXML(b, &f); err != nil {
		return nil, 0, err
	}
	if f.XMLName.Local != "feed" {
		return nil, 0, errors.New("geen Atom-feed")
	}
	type group struct {
		color, hazard  string
		onset, expires int64
		sent           int64
		areas          []string
		link           string
	}
	groups := map[string]*group{}
	var keys []string
	nowMs := now.UnixMilli()
	for _, e := range f.Entries {
		if s := strings.ToLower(e.Status); s != "" && s != "actual" {
			continue
		}
		if strings.EqualFold(e.MsgType, "cancel") {
			continue
		}
		color := osMeteoColor(e)
		if color == "" || color == "green" {
			continue
		}
		exp := osParseTime(e.Expires)
		if exp > 0 && exp < nowMs {
			continue
		}
		onset := osParseTime(e.Onset)
		sent := osParseTime(e.Sent)
		if sent == 0 {
			sent = osParseTime(e.Published)
		}
		if sent == 0 {
			sent = osParseTime(e.Updated)
		}
		hz := osMeteoHazardNL(e)
		area := strings.TrimSpace(e.AreaDesc)
		if nl, ok := osBEAreas[strings.ToLower(area)]; ok {
			area = nl
		}
		k := fmt.Sprintf("%s|%s|%d|%d", color, hz, onset, exp)
		g := groups[k]
		if g == nil {
			g = &group{color: color, hazard: hz, onset: onset, expires: exp, sent: sent}
			for _, l := range e.Links {
				if (l.Rel == "" || l.Rel == "alternate") && (l.Type == "" || l.Type == "text/html") && l.Href != "" {
					g.link = osSafeLink(l.Href)
					break
				}
			}
			groups[k] = g
			keys = append(keys, k)
		}
		if sent > g.sent {
			g.sent = sent
		}
		dup := false
		for _, a := range g.areas {
			if a == area {
				dup = true
			}
		}
		if area != "" && !dup {
			g.areas = append(g.areas, area)
		}
	}
	for _, k := range keys {
		g := groups[k]
		sort.Strings(g.areas)
		sev := map[string]int{"yellow": 1, "orange": 2, "red": 3}[g.color]
		areas := strings.Join(g.areas, ", ")
		title := "Code " + osColorNL[g.color] + ": " + g.hazard
		body := "Meteoalarm (KMI): code " + osColorNL[g.color] + " voor " + g.hazard
		if areas != "" {
			body += " in " + areas
		}
		body += "."
		switch {
		case g.onset > 0 && g.expires > 0:
			body += " Geldig van " + osLocalTime(g.onset) + " tot " + osLocalTime(g.expires) + "."
		case g.expires > 0:
			body += " Geldig tot " + osLocalTime(g.expires) + "."
		}
		switch g.color {
		case "orange":
			body += " Wees voorzichtig en volg de raad van de overheid."
		case "red":
			body += " Gevaarlijk weer: blijf zo veel mogelijk binnen en volg de instructies van de overheid."
		}
		if areas == "" {
			areas = "België"
		}
		cands = append(cands, osCand{Key: k + "|" + strings.Join(g.areas, ","), Sev: sev, Title: title,
			Body: body, Area: areas, Link: g.link, TS: g.sent})
		active++
	}
	return cands, active, nil
}

// ---------- GDACS ----------

var osGDACSType = map[string]string{"EQ": "aardbeving", "TC": "tropische storm", "FL": "overstroming",
	"VO": "vulkaanuitbarsting", "DR": "droogte", "WF": "bosbrand", "TS": "tsunami"}

func osShortCountries(s string) string {
	var parts []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 3 {
		return strings.Join(parts[:3], ", ") + fmt.Sprintf(" en %d andere landen", len(parts)-3)
	}
	return strings.Join(parts, ", ")
}

// osParseGDACS: oranje en rood altijd, groen enkel binnen 300 km van de eigen positie.
func osParseGDACS(b []byte, now time.Time, myLat, myLon float64, hasPos bool) ([]osCand, error) {
	var f osXMLFeed
	if err := osDecodeXML(b, &f); err != nil {
		return nil, err
	}
	if f.XMLName.Local != "rss" {
		return nil, errors.New("geen RSS")
	}
	var out []osCand
	for _, it := range f.Channel.Items {
		if strings.EqualFold(strings.TrimSpace(it.IsCurrent), "false") {
			continue
		}
		level := strings.ToLower(strings.TrimSpace(it.AlertLevel))
		sev := map[string]int{"green": 1, "orange": 2, "red": 3}[level]
		if sev == 0 {
			continue
		}
		var lat, lon float64
		hasPt := false
		if p := strings.Fields(it.Point); len(p) == 2 {
			la, e1 := strconv.ParseFloat(p[0], 64)
			lo, e2 := strconv.ParseFloat(p[1], 64)
			if e1 == nil && e2 == nil {
				lat, lon, hasPt = la, lo, true
			}
		}
		dist := -1.0
		where := ""
		if hasPos && hasPt {
			where, dist = osWhere(myLat, myLon, lat, lon)
		}
		if sev == 1 && (dist < 0 || dist > osQuakeKm) {
			continue
		}
		typ := osGDACSType[strings.ToUpper(strings.TrimSpace(it.EventType))]
		if typ == "" {
			typ = "ramp"
		}
		country := osShortCountries(html.UnescapeString(it.Country))
		kleur := map[int]string{1: "Groen", 2: "Oranje", 3: "Rood"}[sev]
		title := kleur + " alarm: " + typ
		if country != "" {
			title += " in " + country
		}
		body := osTrunc(osStripHTML(it.Description), 500)
		if t := osStripHTML(it.Title); t != "" && !strings.Contains(body, t) {
			if body != "" {
				body = t + "\n" + body
			} else {
				body = t
			}
		}
		body += "\nBron: GDACS (Europese Commissie, VN)."
		area := country
		if where != "" {
			if area != "" {
				area += " · "
			}
			area += where
		}
		key := strings.TrimSpace(it.GUID)
		if key == "" {
			key = strings.TrimSpace(it.Link)
		}
		out = append(out, osCand{Key: key + "|" + level, Sev: sev, Title: title, Body: body, Area: area,
			Link: osSafeLink(it.Link), TS: osParseTime(it.PubDate)})
	}
	return out, nil
}

// ---------- EMSC ----------

type osEMSCFeed struct {
	Type     string `json:"type"`
	Features []struct {
		ID         string `json:"id"`
		Properties struct {
			Time    string  `json:"time"`
			Lat     float64 `json:"lat"`
			Lon     float64 `json:"lon"`
			Depth   float64 `json:"depth"`
			Mag     float64 `json:"mag"`
			MagType string  `json:"magtype"`
			Region  string  `json:"flynn_region"`
			Unid    string  `json:"unid"`
		} `json:"properties"`
	} `json:"features"`
}

// osParseEMSC: binnen 300 km (positie bekend) of Europa vanaf M4 (positie onbekend).
// Leeg antwoord (HTTP 204) = geen bevingen.
func osParseEMSC(b []byte, myLat, myLon float64, hasPos bool) ([]osCand, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var f osEMSCFeed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Type != "FeatureCollection" && f.Features == nil {
		return nil, errors.New("geen FDSN-GeoJSON")
	}
	var out []osCand
	for _, ft := range f.Features {
		p := ft.Properties
		where := ""
		if hasPos {
			var d float64
			where, d = osWhere(myLat, myLon, p.Lat, p.Lon)
			if d > osQuakeKm {
				continue
			}
		} else if p.Mag < 4 || p.Lat < 34 || p.Lat > 72 || p.Lon < -25 || p.Lon > 45 {
			continue
		}
		sev := 1
		if p.Mag >= 5 {
			sev = 3
		} else if p.Mag >= 4 {
			sev = 2
		}
		region := osTitleCase(p.Region)
		ts := osParseTime(p.Time)
		title := "Aardbeving M" + osNum(p.Mag, 1)
		if region != "" {
			title += " – " + region
		}
		body := fmt.Sprintf("Magnitude %s", osNum(p.Mag, 1))
		if p.MagType != "" {
			body += " (" + p.MagType + ")"
		}
		body += ", diepte " + osNum(math.Abs(p.Depth), 0) + " km"
		if ts > 0 {
			body += ", om " + osLocalTime(ts)
		}
		body += "."
		if p.Mag < 3 {
			body += " Meestal niet of nauwelijks voelbaar."
		} else if p.Mag < 4 {
			body += " Kan licht voelbaar zijn in de buurt; schade is onwaarschijnlijk."
		} else if p.Mag < 5 {
			body += " Duidelijk voelbaar in de buurt; lichte schade mogelijk."
		} else {
			body += " Zware beving: schade mogelijk. Volg de officiële kanalen."
		}
		body += " Bron: EMSC."
		area := region
		if where != "" {
			area = where
		}
		id := p.Unid
		if id == "" {
			id = ft.ID
		}
		link := ""
		if id != "" {
			link = "https://www.seismicportal.eu/eventdetails.html?unid=" + id
		}
		out = append(out, osCand{Key: id, Sev: sev, Title: title, Body: body, Area: area, Link: link, TS: ts})
	}
	return out, nil
}

// ---------- RSS / Atom ----------

// osParseFeed leest RSS 2.0, RSS 1.0 (RDF) of Atom. Geeft de feedtitel en max n nieuwste items.
func osParseFeed(b []byte, n int) (string, []osCand, error) {
	var f osXMLFeed
	if err := osDecodeXML(b, &f); err != nil {
		return "", nil, err
	}
	var out []osCand
	title := ""
	switch strings.ToLower(f.XMLName.Local) {
	case "rss", "rdf":
		title = f.Channel.Title
		items := f.Channel.Items
		if len(items) == 0 {
			items = f.Items
		}
		for _, it := range items {
			ts := osParseTime(it.PubDate)
			if ts == 0 {
				ts = osParseTime(it.Date)
			}
			body := it.Description
			if body == "" {
				body = it.Encoded
			}
			key := strings.TrimSpace(it.GUID)
			if key == "" {
				key = strings.TrimSpace(it.Link)
			}
			if key == "" {
				key = osHash(it.Title)
			}
			out = append(out, osCand{Key: key, Sev: 1, Title: osTrunc(osStripHTML(it.Title), 200),
				Body: osTrunc(osStripHTML(body), 600), Link: osSafeLink(it.Link), TS: ts})
		}
	case "feed":
		title = f.Title
		for _, e := range f.Entries {
			ts := osParseTime(e.Published)
			if u := osParseTime(e.Updated); u > ts {
				ts = u
			}
			link := ""
			for _, l := range e.Links {
				if (l.Rel == "" || l.Rel == "alternate") && osSafeLink(l.Href) != "" {
					link = osSafeLink(l.Href)
					break
				}
			}
			body := e.Summary
			if strings.TrimSpace(body) == "" {
				body = e.Content
			}
			key := strings.TrimSpace(e.ID)
			if key == "" {
				key = link
			}
			if key == "" {
				key = osHash(e.Title)
			}
			out = append(out, osCand{Key: key, Sev: 1, Title: osTrunc(osStripHTML(e.Title), 200),
				Body: osTrunc(osStripHTML(body), 600), Link: link, TS: ts})
		}
	default:
		return "", nil, errors.New("geen RSS of Atom")
	}
	title = strings.TrimSpace(osStripHTML(title))
	for i := range out {
		if out[i].Body == "" {
			out[i].Body = title
		}
		if out[i].Title == "" {
			out[i].Title = osTrunc(out[i].Body, 120)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].TS > out[b].TS })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return title, out, nil
}

// ---------- ADS-B (readsb / dump1090 / tar1090) ----------

type osAircraft struct {
	Hex       string          `json:"hex"`
	Flight    string          `json:"flight"`
	AltBaro   json.RawMessage `json:"alt_baro"`
	AltGeom   json.RawMessage `json:"alt_geom"`
	Altitude  json.RawMessage `json:"altitude"` // oudere dump1090
	GS        *float64        `json:"gs"`
	Speed     *float64        `json:"speed"`
	Track     *float64        `json:"track"`
	Lat       *float64        `json:"lat"`
	Lon       *float64        `json:"lon"`
	SeenPos   *float64        `json:"seen_pos"`
	Category  string          `json:"category"`
	Squawk    string          `json:"squawk"`
	Emergency string          `json:"emergency"`
}

type osAircraftFile struct {
	Now      float64       `json:"now"`
	Aircraft *[]osAircraft `json:"aircraft"`
}

func osParseAircraft(b []byte) ([]osAircraft, error) {
	var f osAircraftFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Aircraft == nil {
		return nil, errors.New("geen aircraft.json")
	}
	return *f.Aircraft, nil
}

// osAlt: hoogte in voet; ground=true als het toestel aan de grond staat.
func osAlt(a osAircraft) (ft float64, ground, ok bool) {
	for _, raw := range []json.RawMessage{a.AltBaro, a.Altitude, a.AltGeom} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if strings.EqualFold(s, "ground") {
				return 0, true, true
			}
			continue
		}
		var f float64
		if json.Unmarshal(raw, &f) == nil {
			return f, false, true
		}
	}
	return 0, false, false
}

var osSquawkNL = map[string]string{"7500": "kaping", "7600": "radio-uitval", "7700": "algemene nood"}

// osADSBCands: toestellen binnen 25 km die lager dan 3000 ft vliegen, of een noodcode uitzenden.
// seen = aantal toestellen met een positie.
func osADSBCands(list []osAircraft, myLat, myLon float64) (out []osCand, seen int) {
	for _, a := range list {
		if a.Lat == nil || a.Lon == nil || a.Hex == "" {
			continue
		}
		if a.SeenPos != nil && *a.SeenPos > 60 {
			continue
		}
		seen++
		where, d := osWhere(myLat, myLon, *a.Lat, *a.Lon)
		if d > osADSBKm {
			continue
		}
		alt, ground, altOK := osAlt(a)
		sq := strings.TrimSpace(a.Squawk)
		emerg := osSquawkNL[sq] != "" || (a.Emergency != "" && a.Emergency != "none")
		low := altOK && !ground && alt < osADSBMaxFt
		if !low && !emerg {
			continue
		}
		kind := "Vliegtuig"
		switch strings.ToUpper(a.Category) {
		case "A7":
			kind = "Helikopter"
		case "A1", "B1", "B4":
			kind = "Klein toestel"
		case "B6":
			kind = "Drone"
		case "":
			kind = "Toestel"
		}
		hex := strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(a.Hex), "~"))
		call := strings.TrimSpace(a.Flight)
		var parts []string
		switch {
		case ground:
			parts = append(parts, "aan de grond")
		case altOK:
			parts = append(parts, "hoogte "+osNum(alt, 0)+" ft")
		}
		if a.Track != nil {
			parts = append(parts, fmt.Sprintf("koers %03.0f°", math.Mod(*a.Track, 360)))
		}
		spd := a.GS
		if spd == nil {
			spd = a.Speed
		}
		if spd != nil {
			parts = append(parts, "snelheid "+osNum(*spd, 0)+" kn")
		}
		body := osCap(strings.Join(parts, ", "))
		if body != "" {
			body += ". "
		}
		body += "ICAO " + hex
		if call != "" {
			body += ", vlucht " + call
		} else {
			body += ", geen vluchtnummer"
		}
		if sq != "" {
			body += ", squawk " + sq
		}
		body += "."
		c := osCand{Key: hex, DedupFor: time.Hour, Sev: 1, Area: where, Body: body}
		if emerg {
			why := osSquawkNL[sq]
			if why == "" {
				why = a.Emergency
			}
			c.Sev = 3
			c.Key = hex + "|nood"
			c.Title = kind + " in de buurt meldt een noodsituatie (" + why + ")"
		} else {
			c.Title = kind + " laag in de buurt"
			if call != "" {
				c.Title += " (" + call + ")"
			}
		}
		out = append(out, c)
	}
	return out, seen
}

// osSafeLink: alleen http(s)-links bewaren (geen javascript:, data: en dergelijke).
func osSafeLink(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return s
	}
	return ""
}
