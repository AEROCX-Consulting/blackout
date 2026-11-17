package main

// OSINT-bronnen: definities, planner (één lus voor alle bronnen), ophalen over HTTP,
// foutmeldingen in gewone taal. Alles hier hoort bij de agent "osint".

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const (
	osURLMeteo = "https://feeds.meteoalarm.org/feeds/meteoalarm-legacy-atom-belgium"
	osURLGDACS = "https://www.gdacs.org/xml/rss.xml"
	osURLEMSC  = "https://www.seismicportal.eu/fdsnws/event/1/query?format=json&limit=50&minmag=2.5"
	osURLNews  = "https://www.vrt.be/vrtnws/nl.rss.articles.xml"

	osMaxBody      = 8 << 20
	osNewsPerPoll  = 30
	osQuakeKm      = 300
	osADSBKm       = 25
	osADSBMaxFt    = 3000
	osMeshQuietFor = time.Hour
)

var osADSBURLs = []string{
	"http://127.0.0.1:8080/data/aircraft.json",
	"http://127.0.0.1:8504/data/aircraft.json",
	"http://127.0.0.1:30152/data/aircraft.json",
}

func osBuiltinSources() []*osSource {
	return []*osSource{
		{ID: "mesh", Kind: "mesh", Name: "Mesh-netwerk", Tag: "Mesh", Icon: "radio", Offline: true, On: true,
			Desc: "Openbare Meshtastic-berichten en nieuwe nodes via je radio"},
		{ID: "adsb", Kind: "adsb", Name: "Luchtverkeer", Tag: "ADS-B", Icon: "plane", Offline: true, On: true,
			Desc:  "Laagvliegende vliegtuigen en helikopters binnen 25 km via een SDR-ontvanger (readsb of dump1090)",
			every: 15 * time.Second, retry: 15 * time.Second},
		{ID: "meteoalarm", Kind: "meteoalarm", Name: "Weerwaarschuwingen", Tag: "Weer", Icon: "weer", On: true,
			Desc: "Meteoalarm België (KMI): code geel, oranje en rood", URL: osURLMeteo,
			every: 5 * time.Minute, retry: 2 * time.Minute},
		{ID: "gdacs", Kind: "gdacs", Name: "Rampen wereldwijd", Tag: "Ramp", Icon: "ramp", On: true,
			Desc: "GDACS: grote aardbevingen, overstromingen en stormen (oranje en rood)", URL: osURLGDACS,
			every: 10 * time.Minute, retry: 2 * time.Minute},
		{ID: "emsc", Kind: "emsc", Name: "Aardbevingen", Tag: "Aardbeving", Icon: "ramp", On: true,
			Desc: "EMSC: aardbevingen binnen 300 km (zonder eigen positie: Europa vanaf magnitude 4)", URL: osURLEMSC,
			every: 5 * time.Minute, retry: 2 * time.Minute},
		{ID: "news", Kind: "rss", Name: "Nieuws", Tag: "Nieuws", Icon: "nieuws", On: true,
			Desc: "VRT NWS (RSS)", URL: osURLNews,
			every: 10 * time.Minute, retry: 2 * time.Minute},
	}
}

func osCustomSource(u, name string) *osSource {
	host := u
	if pu, err := url.Parse(u); err == nil && pu.Host != "" {
		host = strings.TrimPrefix(pu.Hostname(), "www.")
	}
	if name == "" {
		name = host
	}
	return &osSource{ID: "rss-" + osHash(strings.ToLower(u))[:8], Kind: "rss", Name: name, Tag: "RSS",
		Icon: "nieuws", Desc: u, URL: u, Custom: true, On: true,
		every: 10 * time.Minute, retry: 2 * time.Minute}
}

func osValidFeedURL(u string) error {
	bad := errors.New("Geef het volledige webadres van een RSS- of Atom-feed, beginnend met http:// of https://.")
	if u == "" || len(u) > 500 || strings.ContainsAny(u, " \t\r\n") {
		return bad
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Hostname() == "" {
		return bad
	}
	return nil
}

func osNewClient(useProxy bool, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !useProxy {
		tr.Proxy = nil
	}
	tr.MaxIdleConnsPerHost = 2
	tr.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: tr, Timeout: timeout}
}

// ---------- planner ----------

func (o *OSINT) loop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastPrune time.Time
	for {
		o.dispatch()
		if time.Since(lastPrune) > 10*time.Minute {
			lastPrune = time.Now()
			o.mu.Lock()
			n := len(o.items)
			o.pruneLocked()
			o.pruneSeenLocked()
			var data []byte
			var gen uint64
			if len(o.items) != n {
				data, gen = o.snapshotLocked()
			}
			o.mu.Unlock()
			o.persist(data, gen)
		}
		select {
		case <-o.stop:
			return
		case <-tick.C:
		case <-o.wake:
		}
	}
}

func (o *OSINT) dispatch() {
	o.mu.Lock()
	now := o.now()
	var due []string
	for _, id := range o.order {
		s := o.srcs[id]
		if s.Kind == "mesh" {
			o.meshQuietLocked(s, now)
			continue
		}
		if !s.On || s.running || now.Before(s.nextAt) {
			continue
		}
		s.running = true
		due = append(due, id)
	}
	o.mu.Unlock()
	for _, id := range due {
		o.inflight.Add(1)
		go func(id string) {
			defer o.inflight.Done()
			o.fetchAndStore(id)
		}(id)
	}
}

// meshQuietLocked: na een uur zonder mesh-verkeer is de bron niet meer "actief".
func (o *OSINT) meshQuietLocked(s *osSource, now time.Time) {
	if s.On && s.Active && now.UnixMilli()-s.LastOk > osMeshQuietFor.Milliseconds() {
		s.Active = false
		s.Status = "stil sinds " + time.UnixMilli(s.LastOk).Local().Format("15:04")
	}
}

// refresh haalt één bron nu meteen op (synchroon). Voor tests en handmatig vernieuwen.
func (o *OSINT) refresh(id string) error {
	o.mu.Lock()
	s := o.srcs[id]
	if s == nil || s.Kind == "mesh" || s.running {
		o.mu.Unlock()
		return nil
	}
	s.running = true
	o.mu.Unlock()
	return o.fetchAndStore(id)
}

type osResult struct {
	cands  []osCand
	status string
	title  string
}

func (o *OSINT) fetchAndStore(id string) (err error) {
	o.mu.Lock()
	s := o.srcs[id]
	if s == nil {
		o.mu.Unlock()
		return nil
	}
	kind, u := s.Kind, s.URL
	o.mu.Unlock()

	var res osResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("interne fout: %v", r)
			}
		}()
		switch kind {
		case "adsb":
			res, err = o.fetchADSB()
		case "meteoalarm":
			res, err = o.fetchMeteo(u)
		case "gdacs":
			res, err = o.fetchGDACS(u)
		case "emsc":
			res, err = o.fetchEMSC(u)
		case "rss":
			res, err = o.fetchFeed(u)
		default:
			err = errors.New("onbekend soort bron")
		}
	}()
	o.finish(id, res, err)
	return err
}

func (o *OSINT) finish(id string, res osResult, ferr error) {
	o.mu.Lock()
	s := o.srcs[id]
	if s == nil {
		o.mu.Unlock()
		return
	}
	s.running = false
	if !s.On {
		o.mu.Unlock()
		return
	}
	now := o.now()
	prevErr, first := s.LastErr, !s.everOk
	changed := false
	if ferr != nil {
		st, msg := osClassify(ferr, s.URL)
		s.Active, s.Status, s.LastErr = false, st, msg
		s.nextAt = now.Add(s.retry)
	} else {
		s.LastOk, s.everOk, s.Active, s.LastErr = now.UnixMilli(), true, true, ""
		s.okRun = now // tijdstip in deze run (monotoon), voor InternetSeen
		s.Status = res.status
		if s.Status == "" {
			s.Status = "actief"
		}
		s.nextAt = now.Add(s.every)
		if s.Custom && res.title != "" {
			if host := osCustomSource(s.URL, "").Name; s.Name == host {
				s.Name = osTrunc(osStripHTML(res.title), 40)
				changed = true
			}
		}
		markRead := first && s.Kind == "rss"
		for _, c := range res.cands {
			if o.ingestLocked(s, c, markRead) {
				changed = true
			}
		}
	}
	if first && ferr == nil || prevErr != s.LastErr {
		changed = true
	}
	var data []byte
	var gen uint64
	if changed {
		data, gen = o.snapshotLocked()
	}
	o.mu.Unlock()
	o.persist(data, gen)
}

// ---------- HTTP en fouten ----------

type osErr struct{ status, msg string }

func (e *osErr) Error() string { return e.msg }

func (o *OSINT) get(client *http.Client, u string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, &osErr{"ongeldig adres", "Het webadres van deze bron is ongeldig."}
	}
	req.Header.Set("User-Agent", osUserAgent)
	req.Header.Set("Accept", "application/atom+xml, application/rss+xml, application/xml, application/json, text/xml;q=0.9, */*;q=0.5")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, resp.StatusCode, &osErr{fmt.Sprintf("fout van de server (%d)", resp.StatusCode),
			fmt.Sprintf("De server van %s antwoordde met foutcode %d.", osHost(u), resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, osMaxBody+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(b) > osMaxBody {
		return nil, resp.StatusCode, &osErr{"antwoord te groot", "Het antwoord van " + osHost(u) + " is groter dan 8 MB."}
	}
	return b, resp.StatusCode, nil
}

func osHost(u string) string {
	if pu, err := url.Parse(u); err == nil && pu.Host != "" {
		return pu.Hostname()
	}
	return "de bron"
}

func osParseErr(u string) error {
	return &osErr{"antwoord niet leesbaar", "Het antwoord van " + osHost(u) + " kon niet gelezen worden (onverwacht formaat)."}
}

// osClassify vertaalt een fout naar een korte status en een zin voor "laatste fout".
func osClassify(err error, u string) (status, msg string) {
	host := osHost(u)
	var oe *osErr
	if errors.As(err, &oe) {
		return oe.status, oe.msg
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var uaErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "time-out", "Geen antwoord van " + host + " binnen 10 seconden. Later opnieuw."
	case errors.As(err, &dnsErr):
		return "geen internet", "Geen internet: " + host + " kan niet opgezocht worden. Later opnieuw."
	case errors.Is(err, syscall.ECONNREFUSED):
		return "server niet bereikbaar", host + " weigert de verbinding. Later opnieuw."
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN):
		return "geen internet", "Geen internet: geen verbinding met " + host + ". Later opnieuw."
	case errors.As(err, &certErr), errors.As(err, &uaErr), errors.As(err, &hostErr):
		return "beveiligde verbinding mislukt", "De beveiligde verbinding met " + host + " kon niet gecontroleerd worden."
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return "geen internet", "Geen internet: geen verbinding met " + host + ". Later opnieuw."
	}
	m := err.Error()
	if len(m) > 160 {
		m = m[:160] + "…"
	}
	return "fout bij ophalen", "Ophalen bij " + host + " mislukt: " + m
}

// ---------- fetchers ----------

func (o *OSINT) fetchMeteo(u string) (osResult, error) {
	if o.urlMeteo != "" && u == osURLMeteo {
		u = o.urlMeteo
	}
	b, _, err := o.get(o.client, u)
	if err != nil {
		return osResult{}, err
	}
	cands, nowActive, err := osParseMeteo(b, o.now())
	if err != nil {
		return osResult{}, osParseErr(u)
	}
	st := "actief · geen waarschuwingen"
	if nowActive == 1 {
		st = "actief · 1 waarschuwing"
	} else if nowActive > 1 {
		st = fmt.Sprintf("actief · %d waarschuwingen", nowActive)
	}
	return osResult{cands: cands, status: st}, nil
}

func (o *OSINT) fetchGDACS(u string) (osResult, error) {
	if o.urlGDACS != "" && u == osURLGDACS {
		u = o.urlGDACS
	}
	b, _, err := o.get(o.client, u)
	if err != nil {
		return osResult{}, err
	}
	lat, lon, ok := o.position()
	cands, err := osParseGDACS(b, o.now(), lat, lon, ok)
	if err != nil {
		return osResult{}, osParseErr(u)
	}
	st := "actief · geen oranje of rode meldingen"
	if n := len(cands); n == 1 {
		st = "actief · 1 melding"
	} else if n > 1 {
		st = fmt.Sprintf("actief · %d meldingen", n)
	}
	return osResult{cands: cands, status: st}, nil
}

func (o *OSINT) fetchEMSC(u string) (osResult, error) {
	if o.urlEMSC != "" && u == osURLEMSC {
		u = o.urlEMSC
	}
	lat, lon, ok := o.position()
	q := osEMSCURL(u, lat, lon, ok, o.now())
	b, _, err := o.get(o.client, q)
	if err != nil {
		return osResult{}, err
	}
	cands, err := osParseEMSC(b, lat, lon, ok)
	if err != nil {
		return osResult{}, osParseErr(u)
	}
	st := ""
	if ok {
		w := "bevingen"
		if len(cands) == 1 {
			w = "beving"
		}
		st = fmt.Sprintf("actief · %d %s binnen %d km (7 dagen)", len(cands), w, osQuakeKm)
	} else {
		st = fmt.Sprintf("actief · eigen positie onbekend, Europa vanaf M4 (%d)", len(cands))
	}
	return osResult{cands: cands, status: st}, nil
}

func osEMSCURL(base string, lat, lon float64, ok bool, now time.Time) string {
	pu, err := url.Parse(base)
	if err != nil {
		return base
	}
	v := pu.Query()
	v.Set("format", "json")
	if v.Get("limit") == "" {
		v.Set("limit", "50")
	}
	v.Set("starttime", now.UTC().Add(-osMaxAge).Format("2006-01-02T15:04:05"))
	if ok {
		v.Set("lat", fmt.Sprintf("%.4f", lat))
		v.Set("lon", fmt.Sprintf("%.4f", lon))
		v.Set("maxradius", fmt.Sprintf("%.2f", float64(osQuakeKm)/111.19+0.05))
		if v.Get("minmag") == "" {
			v.Set("minmag", "2.5")
		}
	} else {
		v.Set("minlat", "34")
		v.Set("maxlat", "72")
		v.Set("minlon", "-25")
		v.Set("maxlon", "45")
		v.Set("minmag", "4")
	}
	pu.RawQuery = v.Encode()
	return pu.String()
}

func (o *OSINT) fetchFeed(u string) (osResult, error) {
	b, _, err := o.get(o.client, u)
	if err != nil {
		return osResult{}, err
	}
	title, cands, err := osParseFeed(b, osNewsPerPoll)
	if err != nil {
		return osResult{}, &osErr{"geen geldige feed", "Op " + osHost(u) + " staat geen leesbare RSS- of Atom-feed."}
	}
	st := "actief · geen berichten"
	if n := len(cands); n == 1 {
		st = "actief · 1 bericht"
	} else if n > 1 {
		st = fmt.Sprintf("actief · %d berichten", n)
	}
	return osResult{cands: cands, status: st, title: title}, nil
}

func (o *OSINT) fetchADSB() (osResult, error) {
	o.mu.Lock()
	urls := append([]string(nil), o.adsbURLs...)
	o.mu.Unlock()
	for i, u := range urls {
		b, _, err := o.get(o.localClient, u)
		if err != nil || b == nil {
			continue
		}
		list, err := osParseAircraft(b)
		if err != nil {
			continue
		}
		if i > 0 { // de werkende poort eerst proberen bij de volgende ronde
			o.mu.Lock()
			if len(o.adsbURLs) == len(urls) {
				o.adsbURLs = append([]string{u}, append(urls[:i:i], urls[i+1:]...)...)
			}
			o.mu.Unlock()
		}
		lat, lon, ok := o.position()
		port := ""
		if pu, err := url.Parse(u); err == nil {
			port = pu.Port()
		}
		if !ok {
			return osResult{status: "ontvanger gevonden (poort " + port + ") · eigen positie onbekend"}, nil
		}
		cands, seen := osADSBCands(list, lat, lon)
		st := fmt.Sprintf("actief · %d toestellen ontvangen", seen)
		if seen == 1 {
			st = "actief · 1 toestel ontvangen"
		}
		return osResult{cands: cands, status: st}, nil
	}
	return osResult{}, &osErr{"niet gevonden", "Geen SDR-ontvanger gevonden: readsb of dump1090 antwoordt niet op poort 8080, 8504 of 30152 van deze computer."}
}
