package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var osTestNow = time.Date(2026, 11, 17, 13, 0, 0, 0, time.UTC)

const testLat, testLon = 50.8798, 4.7005 // Leuven

type osClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *osClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *osClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestOSINT(t *testing.T, dir string) (*OSINT, *osClock) {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	o := newOSINT(dir)
	c := &osClock{t: osTestNow}
	o.now = c.now
	t.Cleanup(o.close)
	return o, c
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "osint", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serveFixture: httptest-server die een fixture teruggeeft en de User-Agent controleert.
func serveFixture(t *testing.T, name, ctype string) *httptest.Server {
	t.Helper()
	b := fixture(t, name)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != osUserAgent {
			http.Error(w, "geen user agent", 400)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

type osState struct {
	Items   []osItemOut   `json:"items"`
	Sources []osSourceOut `json:"sources"`
	Words   []string      `json:"words"`
	OK      bool          `json:"ok"`
	Error   string        `json:"error"`
}

func getState(t *testing.T, o *OSINT) osState {
	t.Helper()
	rec := httptest.NewRecorder()
	o.ServeHTTP(rec, httptest.NewRequest("GET", "/api/osint", nil))
	if rec.Code != 200 {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	var st osState
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func post(t *testing.T, o *OSINT, body string) (int, osState) {
	t.Helper()
	rec := httptest.NewRecorder()
	o.ServeHTTP(rec, httptest.NewRequest("POST", "/api/osint", strings.NewReader(body)))
	var st osState
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("POST %s: geen JSON: %s", body, rec.Body)
	}
	return rec.Code, st
}

func srcOf(st osState, id string) osSourceOut {
	for _, s := range st.Sources {
		if s.ID == id {
			return s
		}
	}
	return osSourceOut{}
}

func itemsOf(st osState, src string) []osItemOut {
	var out []osItemOut
	for _, it := range st.Items {
		if it.Src == src {
			out = append(out, it)
		}
	}
	return out
}

// ---------- parsers ----------

func TestOSINTParseMeteoalarm(t *testing.T) {
	cands, active, err := osParseMeteo(fixture(t, "meteoalarm-belgium.atom.xml"), osTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 || active != len(cands) {
		t.Fatalf("verwacht waarschuwingen, kreeg %d (actief %d)", len(cands), active)
	}
	var rain *osCand
	for i, c := range cands {
		if strings.Contains(strings.ToLower(c.Title), "groen") {
			t.Errorf("groene melding niet weggefilterd: %s", c.Title)
		}
		if c.Sev < 1 || c.Sev > 3 || c.TS == 0 || c.Link == "" {
			t.Errorf("onvolledige kandidaat: %+v", c)
		}
		if c.Title == "Code geel: regen" {
			rain = &cands[i]
		}
	}
	if rain == nil {
		t.Fatalf("geen 'Code geel: regen' in %v", cands)
	}
	if rain.Sev != 1 || !strings.Contains(rain.Area, "Limburg") || !strings.Contains(rain.Area, "Luik") {
		t.Errorf("regen-groep fout: %+v", rain)
	}
	// later dan alle vervaldata: niets meer
	cands, _, _ = osParseMeteo(fixture(t, "meteoalarm-belgium.atom.xml"), osTestNow.Add(48*time.Hour))
	if len(cands) != 0 {
		t.Errorf("verlopen waarschuwingen niet weggefilterd: %d", len(cands))
	}
	// kleuren -> ernst
	x := `<feed xmlns="http://www.w3.org/2005/Atom" xmlns:cap="urn:oasis:names:tc:emergency:cap:1.2">
<entry><cap:areaDesc>Limburg</cap:areaDesc><cap:event>Orange warning for thunderstorm</cap:event><cap:expires>2026-11-18T05:00:00+00:00</cap:expires><cap:severity>Severe</cap:severity><cap:status>Actual</cap:status><cap:message_type>Alert</cap:message_type><title>x</title><id>a</id></entry>
<entry><cap:areaDesc>Antwerp</cap:areaDesc><cap:event>Red warning for wind</cap:event><cap:expires>2026-11-18T05:00:00+00:00</cap:expires><cap:severity>Extreme</cap:severity><cap:status>Actual</cap:status><title>y</title><id>b</id></entry>
</feed>`
	cands, _, err = osParseMeteo([]byte(x), osTestNow)
	if err != nil || len(cands) != 2 {
		t.Fatalf("%v %v", err, cands)
	}
	if cands[0].Sev != 2 || cands[0].Title != "Code oranje: onweer" || cands[1].Sev != 3 || cands[1].Area != "Antwerpen" {
		t.Errorf("kleur/ernst fout: %+v", cands)
	}
}

func TestOSINTParseGDACS(t *testing.T) {
	b := fixture(t, "gdacs.rss.xml")
	cands, err := osParseGDACS(b, osTestNow, testLat, testLon, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 {
		t.Fatal("geen oranje meldingen gevonden")
	}
	for _, c := range cands {
		if c.Sev < 2 {
			t.Errorf("groene melding ver weg niet weggefilterd: %s", c.Title)
		}
		if !strings.HasPrefix(c.Title, "Oranje alarm: ") || c.Link == "" || c.TS == 0 || !strings.Contains(c.Area, "km") {
			t.Errorf("onvolledig: %+v", c)
		}
	}
	// groen dichtbij komt wel door
	near := `<?xml version="1.0"?><rss version="2.0" xmlns:gdacs="http://www.gdacs.org" xmlns:georss="http://www.georss.org/georss"><channel><item>
<title>Green flood alert in Belgium</title><description>Flooding along the Meuse.</description><link>https://www.gdacs.org/x</link>
<pubDate>Tue, 17 Nov 2026 10:00:00 GMT</pubDate><guid>FL1</guid><gdacs:alertlevel>Green</gdacs:alertlevel><gdacs:eventtype>FL</gdacs:eventtype>
<gdacs:country>Belgium</gdacs:country><gdacs:iscurrent>true</gdacs:iscurrent><georss:point>50.9 5.7</georss:point></item></channel></rss>`
	cands, err = osParseGDACS([]byte(near), osTestNow, testLat, testLon, true)
	if err != nil || len(cands) != 1 || cands[0].Sev != 1 || cands[0].Title != "Groen alarm: overstroming in Belgium" {
		t.Fatalf("groen dichtbij: %v %+v", err, cands)
	}
	if cands, _ := osParseGDACS([]byte(near), osTestNow, 0, 0, false); len(cands) != 0 {
		t.Error("groen zonder positie moet weg")
	}
}

func TestOSINTParseEMSC(t *testing.T) {
	cands, err := osParseEMSC(fixture(t, "emsc-near.json"), testLat, testLon, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 {
		t.Fatal("geen bevingen binnen 300 km")
	}
	for _, c := range cands {
		if !strings.HasPrefix(c.Title, "Aardbeving M") || !strings.Contains(c.Area, " km") || c.TS == 0 ||
			!strings.HasPrefix(c.Link, "https://www.seismicportal.eu/eventdetails.html?unid=") {
			t.Errorf("onvolledig: %+v", c)
		}
	}
	// wereldfeed zonder positie: enkel Europa M>=4
	cands, err = osParseEMSC(fixture(t, "emsc-world.json"), 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	var f osEMSCFeed
	json.Unmarshal(fixture(t, "emsc-world.json"), &f)
	want := 0
	for _, ft := range f.Features {
		p := ft.Properties
		if p.Mag >= 4 && p.Lat >= 34 && p.Lat <= 72 && p.Lon >= -25 && p.Lon <= 45 {
			want++
		}
	}
	if len(cands) != want {
		t.Errorf("Europa M4+: %d, verwacht %d", len(cands), want)
	}
	// ernst
	j := `{"type":"FeatureCollection","features":[
{"id":"a","properties":{"time":"2026-11-17T10:00:00Z","lat":51.2,"lon":5.9,"depth":10,"mag":5.3,"magtype":"mw","flynn_region":"BELGIUM","unid":"a"}},
{"id":"b","properties":{"time":"2026-11-17T10:00:00Z","lat":51.2,"lon":5.9,"depth":10,"mag":4.1,"magtype":"ml","flynn_region":"BELGIUM","unid":"b"}},
{"id":"c","properties":{"time":"2026-11-17T10:00:00Z","lat":40.0,"lon":20.0,"depth":10,"mag":6.0,"magtype":"mw","flynn_region":"GREECE","unid":"c"}}]}`
	cands, _ = osParseEMSC([]byte(j), testLat, testLon, true)
	if len(cands) != 2 || cands[0].Sev != 3 || cands[1].Sev != 2 || cands[0].Title != "Aardbeving M5,3 – Belgium" {
		t.Errorf("ernst/filter fout: %+v", cands)
	}
	if c, err := osParseEMSC(nil, 0, 0, false); err != nil || len(c) != 0 {
		t.Error("leeg antwoord (204) moet nul bevingen geven")
	}
	u := osEMSCURL(osURLEMSC, testLat, testLon, true, osTestNow)
	for _, p := range []string{"lat=50.8798", "lon=4.7005", "maxradius=2.7", "minmag=2.5", "format=json", "starttime=2026-11-10T13"} {
		if !strings.Contains(u, p) {
			t.Errorf("EMSC-URL mist %s: %s", p, u)
		}
	}
	u = osEMSCURL(osURLEMSC, 0, 0, false, osTestNow)
	if !strings.Contains(u, "minmag=4") || !strings.Contains(u, "minlat=34") || strings.Contains(u, "maxradius") {
		t.Errorf("EMSC-URL zonder positie: %s", u)
	}
}

func TestOSINTParseFeeds(t *testing.T) {
	title, cands, err := osParseFeed(fixture(t, "vrtnws.atom.xml"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if title != "VRT NWS: nieuws" || len(cands) == 0 || len(cands) > 30 {
		t.Fatalf("VRT: %q %d", title, len(cands))
	}
	for i, c := range cands {
		if c.Title == "" || c.Body == "" || !strings.HasPrefix(c.Link, "https://") || c.TS == 0 || c.Key == "" {
			t.Errorf("VRT-item onvolledig: %+v", c)
		}
		if i > 0 && c.TS > cands[i-1].TS {
			t.Error("niet nieuwste eerst")
		}
	}
	title, cands, err = osParseFeed(fixture(t, "custom-latin1.rss.xml"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if title != "Gemeente Voorbeeld – Nieuws" || len(cands) != 3 {
		t.Fatalf("latin1: %q %d", title, len(cands))
	}
	c := cands[0]
	if c.Title != "Stroomonderbreking in de Kerkstraat op dinsdag" || !strings.Contains(c.Body, "Café en winkels zijn bereikbaar.") ||
		strings.Contains(c.Body, "<p>") || c.Key != "vb-123" {
		t.Errorf("latin1-item fout: %+v", c)
	}
	if cands[1].TS == 0 || !strings.Contains(cands[1].Body, "& duurt") {
		t.Errorf("dc:date of entiteit fout: %+v", cands[1])
	}
	if _, _, err := osParseFeed([]byte("<html><body>geen feed</body></html>"), 10); err == nil {
		t.Error("html moet een fout geven")
	}
}

func TestOSINTHelpers(t *testing.T) {
	cases := map[string]string{osNum(1200, 0): "1.200", osNum(2.14, 1): "2,1", osNum(-101, 0): "−101",
		osNum(1234567, 0): "1.234.567", osKm(1.83): "1,8 km", osKm(214.4): "214 km", osCompass(95): "O",
		osCompass(350): "N", osCompass(225): "ZW", osTitleCase("NIAS REGION, INDONESIA"): "Nias Region, Indonesia"}
	for got, want := range cases {
		if got != want {
			t.Errorf("kreeg %q, verwacht %q", got, want)
		}
	}
	if d := osDistKm(50.8798, 4.7005, 50.8503, 4.3517); d < 23 || d > 27 { // Leuven–Brussel ±25 km
		t.Errorf("haversine: %.1f", d)
	}
	for _, u := range []string{"", "ftp://x.be/feed", "https://", "javascript:alert(1)", "https://a b.be/"} {
		if osValidFeedURL(u) == nil {
			t.Errorf("ongeldige url aanvaard: %q", u)
		}
	}
	if osValidFeedURL("https://www.voorbeeld.be/rss.xml") != nil {
		t.Error("geldige url geweigerd")
	}
}

// ---------- bronnen via httptest ----------

func TestOSINTFetchSources(t *testing.T) {
	o, _ := newTestOSINT(t, "")
	o.SetLocation(testLat, testLon, true)
	o.urlMeteo = serveFixture(t, "meteoalarm-belgium.atom.xml", "application/atom+xml").URL
	o.urlGDACS = serveFixture(t, "gdacs.rss.xml", "application/xml").URL
	var emscQuery string
	emscFix := fixture(t, "emsc-near.json")
	emsc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		emscQuery = r.URL.RawQuery
		w.Write(emscFix)
	}))
	defer emsc.Close()
	o.urlEMSC = emsc.URL + "/fdsnws/event/1/query?format=json&limit=50&minmag=2.5"
	news := serveFixture(t, "vrtnws.atom.xml", "application/atom+xml")
	o.mu.Lock()
	o.srcs["news"].URL = news.URL
	o.mu.Unlock()

	for _, id := range []string{"meteoalarm", "gdacs", "emsc", "news"} {
		if err := o.refresh(id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if !strings.Contains(emscQuery, "maxradius") {
		t.Errorf("EMSC zonder afstandsfilter gevraagd: %s", emscQuery)
	}
	st := getState(t, o)
	for _, id := range []string{"meteoalarm", "gdacs", "emsc", "news"} {
		s := srcOf(st, id)
		if !s.Active || !s.On || s.LastOk != osTestNow.UnixMilli() || s.LastErr != "" || !strings.HasPrefix(s.Status, "actief") {
			t.Errorf("bron %s: %+v", id, s)
		}
	}
	if n := len(itemsOf(st, "meteoalarm")); n == 0 {
		t.Error("geen weeritems")
	}
	if n := len(itemsOf(st, "emsc")); n == 0 {
		t.Error("geen aardbevingen")
	}
	// GDACS: droogtes van maanden geleden vallen weg (7 dagen)
	for _, it := range itemsOf(st, "gdacs") {
		if osTestNow.UnixMilli()-it.TS > osMaxAge.Milliseconds() {
			t.Errorf("te oud item: %s", it.Title)
		}
	}
	nws := itemsOf(st, "news")
	if len(nws) == 0 {
		t.Fatal("geen nieuws")
	}
	// eerste import van een nieuwsfeed telt niet als ongelezen (tenzij trefwoord)
	for _, it := range nws {
		if !it.Read && len(it.Hit) == 0 {
			t.Errorf("eerste import ongelezen: %s", it.Title)
		}
	}
	for i := 1; i < len(st.Items); i++ {
		if st.Items[i].TS > st.Items[i-1].TS {
			t.Fatal("items niet nieuwste eerst")
		}
	}
	// tweede ophaling: niets dubbel
	before := len(st.Items)
	for _, id := range []string{"meteoalarm", "gdacs", "emsc", "news"} {
		o.refresh(id)
	}
	if after := len(getState(t, o).Items); after != before {
		t.Errorf("dubbele items: %d -> %d", before, after)
	}
}

func TestOSINTNoInternet(t *testing.T) {
	o, _ := newTestOSINT(t, "")
	o.client = osNewClient(false, 2*time.Second)
	o.urlMeteo = "http://feeds.meteoalarm.invalid/feed"
	// gesloten poort
	l := httptest.NewServer(http.NotFoundHandler())
	closed := l.URL
	l.Close()
	o.urlGDACS = closed + "/rss.xml"
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "kapot", 503) }))
	defer srv500.Close()
	o.urlEMSC = srv500.URL
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hallo</html>")) }))
	defer garbage.Close()
	o.mu.Lock()
	o.srcs["news"].URL = garbage.URL
	o.mu.Unlock()

	for _, id := range []string{"meteoalarm", "gdacs", "emsc", "news"} {
		if err := o.refresh(id); err == nil {
			t.Errorf("%s: verwacht fout", id)
		}
	}
	st := getState(t, o)
	exp := map[string]string{"meteoalarm": "geen internet", "gdacs": "server niet bereikbaar", "emsc": "fout van de server (503)", "news": "geen geldige feed"}
	for id, want := range exp {
		s := srcOf(st, id)
		if s.Active || s.Status != want || s.LastErr == "" {
			t.Errorf("%s: status %q (verwacht %q), lastErr %q", id, s.Status, want, s.LastErr)
		}
	}
	o.mu.Lock()
	next := o.srcs["meteoalarm"].nextAt
	o.mu.Unlock()
	if d := next.Sub(osTestNow); d != 2*time.Minute {
		t.Errorf("opnieuw proberen na %v, verwacht 2m", d)
	}
}

func TestOSINTADSB(t *testing.T) {
	o, clock := newTestOSINT(t, "")
	ac := serveFixture(t, "aircraft.json", "application/json")
	l := httptest.NewServer(http.NotFoundHandler())
	dead := l.URL
	l.Close()
	o.adsbURLs = []string{dead + "/data/aircraft.json", ac.URL + "/data/aircraft.json"}

	// zonder positie: ontvanger gevonden, geen items
	if err := o.refresh("adsb"); err != nil {
		t.Fatal(err)
	}
	s := srcOf(getState(t, o), "adsb")
	if !s.Active || !strings.Contains(s.Status, "eigen positie onbekend") {
		t.Errorf("zonder positie: %+v", s)
	}
	if o.adsbURLs[0] != ac.URL+"/data/aircraft.json" {
		t.Error("werkende poort niet vooraan gezet")
	}

	o.SetLocation(testLat, testLon, true)
	o.refresh("adsb")
	st := getState(t, o)
	items := itemsOf(st, "adsb")
	if len(items) != 3 {
		for _, it := range items {
			t.Log(it.Title, "|", it.Body, "|", it.Area)
		}
		t.Fatalf("verwacht 3 toestellen (heli, oud formaat, noodcode), kreeg %d", len(items))
	}
	var heli, nood, oud bool
	for _, it := range items {
		switch {
		case strings.HasPrefix(it.Title, "Helikopter laag in de buurt"):
			heli = it.Sev == 1 && strings.Contains(it.Body, "Hoogte 1.200 ft, koers 095°, snelheid 110 kn. ICAO 44A1B2, geen vluchtnummer") && strings.HasSuffix(it.Area, " km O")
		case strings.Contains(it.Title, "noodsituatie (algemene nood)"):
			nood = it.Sev == 3 && strings.Contains(it.Body, "DLH9XY")
		case it.Title == "Toestel laag in de buurt (BAF62)":
			oud = strings.Contains(it.Body, "Hoogte 2.500 ft") && strings.Contains(it.Body, "snelheid 180 kn")
		}
	}
	if !heli || !nood || !oud {
		t.Errorf("heli=%v nood=%v oud=%v: %+v", heli, nood, oud, items)
	}
	if s := srcOf(st, "adsb"); !s.Active || s.Status != "actief · 6 toestellen ontvangen" {
		t.Errorf("status: %+v", s)
	}
	// binnen het uur: geen dubbele; na een uur opnieuw
	clock.add(30 * time.Minute)
	o.refresh("adsb")
	if n := len(itemsOf(getState(t, o), "adsb")); n != 3 {
		t.Errorf("ontdubbelen per uur: %d", n)
	}
	clock.add(31 * time.Minute)
	o.refresh("adsb")
	if n := len(itemsOf(getState(t, o), "adsb")); n != 6 {
		t.Errorf("na een uur opnieuw melden: %d", n)
	}
	// geen ontvanger
	o.adsbURLs = []string{dead + "/data/aircraft.json"}
	o.refresh("adsb")
	s = srcOf(getState(t, o), "adsb")
	if s.Active || s.Status != "niet gevonden" || !strings.Contains(s.LastErr, "8080") {
		t.Errorf("geen ontvanger: %+v", s)
	}
}

// ---------- mesh, trefwoorden, API, opslag ----------

func TestOSINTMesh(t *testing.T) {
	o, clock := newTestOSINT(t, "")
	o.MeshText(0x3c9e1234, "Dorp-Kerk", "Waterpost aan de kerk open tot 20u", -101, 6.5, 0)
	o.MeshText(0x3c9e1234, "Dorp-Kerk", "Waterpost aan de kerk open tot 20u", -99, 6, 0) // herhaling
	o.MeshText(0x3c9e1234, "Dorp-Kerk", "   ", 0, 0, 0)
	o.MeshNode(0xabcdef01, "Hamont-Basis")
	o.MeshNode(0xabcdef01, "Hamont-Basis")
	st := getState(t, o)
	items := itemsOf(st, "mesh")
	if len(items) != 2 {
		t.Fatalf("mesh: %d items", len(items))
	}
	var txt, node osItemOut
	for _, it := range items {
		if strings.HasPrefix(it.Title, "Nieuwe node") {
			node = it
		} else {
			txt = it
		}
	}
	if txt.Title != "“Waterpost aan de kerk open tot 20u”" || !strings.Contains(txt.Body, "Dorp-Kerk (!3c9e1234)") ||
		!strings.Contains(txt.Body, "Signaal −101 dBm, SNR 6,5 dB") || txt.Area != "Dorp-Kerk" {
		t.Errorf("mesh-tekst: %+v", txt)
	}
	if node.Title != "Nieuwe node gehoord: Hamont-Basis" || !strings.Contains(node.Body, "!abcdef01") {
		t.Errorf("mesh-node: %+v", node)
	}
	if s := srcOf(st, "mesh"); !s.Active || !s.Offline || s.LastOk == 0 {
		t.Errorf("mesh-bron: %+v", s)
	}
	clock.add(31 * time.Minute)
	o.MeshText(0x3c9e1234, "Dorp-Kerk", "Waterpost aan de kerk open tot 20u", -101, 6.5, 0)
	if n := len(itemsOf(getState(t, o), "mesh")); n != 3 {
		t.Errorf("na 30 min mag dezelfde tekst terugkomen: %d", n)
	}
	// stil na een uur
	clock.add(2 * time.Hour)
	o.mu.Lock()
	o.meshQuietLocked(o.srcs["mesh"], clock.now())
	o.mu.Unlock()
	if s := srcOf(getState(t, o), "mesh"); s.Active || !strings.HasPrefix(s.Status, "stil sinds") {
		t.Errorf("mesh stil: %+v", s)
	}
	// bron uit: niets meer bewaren en items verborgen
	post(t, o, `{"action":"source","id":"mesh","on":false}`)
	o.MeshText(1, "x", "nog een bericht", 0, 0, 0)
	if n := len(itemsOf(getState(t, o), "mesh")); n != 0 {
		t.Errorf("bron uit: %d items zichtbaar", n)
	}
	post(t, o, `{"action":"source","id":"mesh","on":true}`)
	if n := len(itemsOf(getState(t, o), "mesh")); n != 3 {
		t.Errorf("bron weer aan: %d", n)
	}
}

func TestOSINTKeywordsAndAPI(t *testing.T) {
	o, _ := newTestOSINT(t, "")
	st := getState(t, o)
	if strings.Join(st.Words, ",") != "stroom,noodplan,evacuatie,BE-Alert,storing" {
		t.Errorf("standaardwoorden: %v", st.Words)
	}
	if len(st.Items) != 0 || len(st.Sources) != 6 {
		t.Errorf("leeg begin: %d items, %d bronnen", len(st.Items), len(st.Sources))
	}
	o.MeshText(1, "Buur", "Stroom is weer terug in de Kerkstraat", 0, 0, 0)
	o.MeshText(2, "Buur2", "Waterpost aan de sporthal", 0, 0, 0)
	st = getState(t, o)
	var stroom, water osItemOut
	for _, it := range st.Items {
		if strings.Contains(it.Title, "Stroom") {
			stroom = it
		} else {
			water = it
		}
	}
	if stroom.Sev != 2 || len(stroom.Hit) != 1 || stroom.Hit[0] != "stroom" {
		t.Errorf("trefwoord: %+v", stroom)
	}
	if water.Sev != 1 || water.Hit == nil || len(water.Hit) != 0 {
		t.Errorf("geen trefwoord: %+v", water)
	}
	if u, imp := o.Counts(); u != 2 || imp != 0 {
		t.Errorf("Counts: %d %d", u, imp)
	}
	// word-add
	code, st := post(t, o, `{"action":"word-add","word":"  Water  "}`)
	if code != 200 || !st.OK || st.Words[len(st.Words)-1] != "Water" {
		t.Fatalf("word-add: %d %+v", code, st)
	}
	for _, it := range st.Items {
		if it.ID == water.ID && (it.Sev != 2 || len(it.Hit) != 1) {
			t.Errorf("hit na word-add: %+v", it)
		}
	}
	if code, st := post(t, o, `{"action":"word-add","word":"water"}`); code != 400 || st.Error == "" {
		t.Errorf("dubbel woord: %d %+v", code, st)
	}
	if code, _ := post(t, o, `{"action":"word-add","word":"`+strings.Repeat("x", 31)+`"}`); code != 400 {
		t.Error("te lang woord aanvaard")
	}
	code, st = post(t, o, `{"action":"word-del","word":"STROOM"}`)
	if code != 200 {
		t.Fatal(code)
	}
	for _, it := range st.Items {
		if it.ID == stroom.ID && (it.Sev != 1 || len(it.Hit) != 0) {
			t.Errorf("na word-del: %+v", it)
		}
	}
	// read / hide / readall
	if code, _ := post(t, o, `{"action":"read","id":"`+stroom.ID+`"}`); code != 200 {
		t.Error("read")
	}
	if u, _ := o.Counts(); u != 1 {
		t.Errorf("na read: %d", u)
	}
	code, st = post(t, o, `{"action":"hide","id":"`+water.ID+`"}`)
	if code != 200 || len(st.Items) != 1 {
		t.Errorf("hide: %d %d", code, len(st.Items))
	}
	o.MeshText(3, "Buur3", "Derde bericht", 0, 0, 0)
	post(t, o, `{"action":"readall"}`)
	if u, _ := o.Counts(); u != 0 {
		t.Errorf("readall: %d", u)
	}
	// Item()
	title, body, ok := o.Item(stroom.ID)
	if !ok || title != "Mesh: “Stroom is weer terug in de Kerkstraat”" || !strings.HasSuffix(body, "\nBuur") {
		t.Errorf("Item: %q %q %v", title, body, ok)
	}
	if _, _, ok := o.Item("bestaat-niet"); ok {
		t.Error("Item van onbestaand id")
	}
	// fouten
	for _, b := range []string{`{"action":"read","id":"nope"}`, `{"action":"zever"}`, `{}`, `nope`,
		`{"action":"source","id":"news"}`, `{"action":"source","id":"x","on":true}`, `{"action":"feed-add","url":"ftp://x"}`,
		`{"action":"feed-del","id":"news"}`, `{"action":"feed-del","id":"rss-onbekend"}`, `{"action":"word-del","word":"nope"}`} {
		code, st := post(t, o, b)
		if code != 400 || st.Error == "" {
			t.Errorf("%s: %d %+v", b, code, st)
		}
	}
	rec := httptest.NewRecorder()
	o.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/osint", nil))
	if rec.Code != 405 || !strings.Contains(rec.Body.String(), "error") {
		t.Errorf("DELETE: %d", rec.Code)
	}
}

func TestOSINTCustomFeeds(t *testing.T) {
	o, _ := newTestOSINT(t, "")
	feed := serveFixture(t, "custom-latin1.rss.xml", "application/rss+xml")
	code, st := post(t, o, `{"action":"feed-add","url":"`+feed.URL+`/rss"}`)
	if code != 200 {
		t.Fatalf("feed-add: %d %+v", code, st)
	}
	var id string
	for _, s := range st.Sources {
		if s.Custom {
			id = s.ID
			if s.URL != feed.URL+"/rss" || s.Tag != "RSS" || !s.On || s.Name != "127.0.0.1" {
				t.Errorf("nieuwe feed: %+v", s)
			}
		}
	}
	if !strings.HasPrefix(id, "rss-") {
		t.Fatal("geen eigen feed")
	}
	if code, _ := post(t, o, `{"action":"feed-add","url":"`+feed.URL+`/rss"}`); code != 400 {
		t.Error("dubbele feed aanvaard")
	}
	if err := o.refresh(id); err != nil {
		t.Fatal(err)
	}
	st = getState(t, o)
	s := srcOf(st, id)
	if s.Name != "Gemeente Voorbeeld – Nieuws" || !s.Active {
		t.Errorf("na ophalen: %+v", s)
	}
	items := itemsOf(st, id)
	if len(items) != 2 { // het bericht van 2025 is te oud
		t.Fatalf("eigen feed: %d items", len(items))
	}
	for _, it := range items {
		if strings.Contains(it.Title, "Stroomonderbreking") {
			if it.Read || it.Sev != 2 || it.Hit[0] != "stroom" {
				t.Errorf("trefwoord in eerste import moet ongelezen blijven: %+v", it)
			}
		} else if !it.Read {
			t.Errorf("eerste import zonder trefwoord moet gelezen zijn: %+v", it)
		}
	}
	code, st = post(t, o, `{"action":"feed-del","id":"`+id+`"}`)
	if code != 200 || srcOf(st, id).ID != "" || len(itemsOf(st, id)) != 0 {
		t.Errorf("feed-del: %d %+v", code, st)
	}
}

func TestOSINTPersistAndPrune(t *testing.T) {
	dir := t.TempDir()
	o, clock := newTestOSINT(t, dir)
	o.MeshText(1, "A", "eerste", 0, 0, 0)
	post(t, o, `{"action":"word-add","word":"Leuven"}`)
	post(t, o, `{"action":"source","id":"gdacs","on":false}`)
	post(t, o, `{"action":"feed-add","url":"https://www.voorbeeld.be/rss.xml"}`)
	id := getState(t, o).Items[0].ID
	post(t, o, `{"action":"read","id":"`+id+`"}`)

	b, err := os.ReadFile(filepath.Join(dir, "osint.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatal("osint.json ongeldig")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".osint-*")); len(m) != 0 {
		t.Errorf("tijdelijke bestanden blijven staan: %v", m)
	}

	o2, _ := newTestOSINT(t, dir)
	st := getState(t, o2)
	if len(st.Items) != 1 || !st.Items[0].Read || st.Items[0].ID != id {
		t.Errorf("items niet hersteld: %+v", st.Items)
	}
	if st.Words[len(st.Words)-1] != "Leuven" || srcOf(st, "gdacs").On {
		t.Errorf("woorden/bronnen niet hersteld: %v %+v", st.Words, srcOf(st, "gdacs"))
	}
	found := false
	for _, s := range st.Sources {
		found = found || (s.Custom && s.URL == "https://www.voorbeeld.be/rss.xml")
	}
	if !found {
		t.Error("eigen feed niet hersteld")
	}
	// ontdubbelen overleeft herstart
	o2.MeshNode(5, "N")
	o3, _ := newTestOSINT(t, dir)
	o3.MeshNode(5, "N")
	if n := len(itemsOf(getState(t, o3), "mesh")); n != 2 {
		t.Errorf("node na herstart opnieuw gemeld: %d", n)
	}

	// snoeien: max 300 en 7 dagen
	for i := 0; i < 320; i++ {
		clock.add(time.Second)
		o.MeshText(uint32(100+i), "n", fmt.Sprintf("bericht %d", i), 0, 0, 0)
	}
	o.MeshText(9999, "n", "stroom valt uit", 0, 0, 0)
	o.mu.Lock()
	n := len(o.items)
	o.mu.Unlock()
	if n != osMaxItems {
		t.Errorf("max items: %d", n)
	}
	st = getState(t, o)
	if len(itemsOf(st, "mesh")) != osMaxItems || st.Items[0].Title != "“stroom valt uit”" {
		t.Errorf("nieuwste/trefwoord moet blijven")
	}
	clock.add(8 * 24 * time.Hour)
	o.MeshText(1, "A", "nieuw na een week", 0, 0, 0)
	if n := len(getState(t, o).Items); n != 1 {
		t.Errorf("7 dagen: %d items over", n)
	}
	// kapot bestand: opnieuw beginnen, kopie bewaren
	os.WriteFile(filepath.Join(dir, "osint.json"), []byte("{kapot"), 0o600)
	o4, _ := newTestOSINT(t, dir)
	if len(getState(t, o4).Items) != 0 {
		t.Error("kapot bestand")
	}
	if _, err := os.Stat(filepath.Join(dir, "osint.json.kapot")); err != nil {
		t.Error("geen kopie van kapot bestand")
	}
}

func TestOSINTSchedulerAndConcurrency(t *testing.T) {
	o, _ := newTestOSINT(t, "")
	o.now = time.Now
	var mu sync.Mutex
	hits := map[string]int{}
	mk := func(name, fix string) string {
		b := fixture(t, fix)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[name]++
			mu.Unlock()
			w.Write(b)
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	o.urlMeteo = mk("meteo", "meteoalarm-belgium.atom.xml")
	o.urlGDACS = mk("gdacs", "gdacs.rss.xml")
	o.urlEMSC = mk("emsc", "emsc-near.json")
	o.adsbURLs = []string{mk("adsb", "aircraft.json")}
	o.mu.Lock()
	o.srcs["news"].URL = mk("news", "vrtnws.atom.xml")
	o.mu.Unlock()
	o.SetLocation(testLat, testLon, true)
	o.Start()
	o.Start()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				o.MeshText(uint32(g), "n", fmt.Sprintf("tekst %d %d", g, i), -90, 5, 0)
				o.Counts()
				o.SetLocation(testLat, testLon, true)
				rec := httptest.NewRecorder()
				o.ServeHTTP(rec, httptest.NewRequest("GET", "/api/osint", nil))
				o.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/osint", bytes.NewBufferString(`{"action":"readall"}`)))
			}
		}(g)
	}
	wg.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st := getState(t, o)
		all := true
		for _, id := range []string{"adsb", "meteoalarm", "gdacs", "emsc", "news"} {
			if !srcOf(st, id).Active {
				all = false
			}
		}
		if all {
			mu.Lock()
			defer mu.Unlock()
			for _, k := range []string{"meteo", "gdacs", "emsc", "adsb", "news"} {
				if hits[k] == 0 {
					t.Errorf("%s nooit opgehaald", k)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("niet alle bronnen actief: %+v", getState(t, o).Sources)
}

// Live test tegen de echte feeds: OSINT_LIVE=1 go test -run TestOSINTLive -v
func TestOSINTLive(t *testing.T) {
	if os.Getenv("OSINT_LIVE") == "" {
		t.Skip("zet OSINT_LIVE=1 om de echte feeds op te halen")
	}
	o := newOSINT(t.TempDir())
	defer o.close()
	o.SetLocation(testLat, testLon, true)
	for _, id := range []string{"meteoalarm", "gdacs", "emsc", "news", "adsb"} {
		err := o.refresh(id)
		st := getState(t, o)
		s := srcOf(st, id)
		t.Logf("%-10s err=%v active=%v status=%q lastErr=%q items=%d", id, err, s.Active, s.Status, s.LastErr, len(itemsOf(st, id)))
		for i, it := range itemsOf(st, id) {
			if i >= 3 {
				break
			}
			t.Logf("    [%d] %s | %s | %s", it.Sev, it.Title, it.Area, osTrunc(strings.ReplaceAll(it.Body, "\n", " "), 120))
		}
		if id != "adsb" && err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}
