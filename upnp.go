package main

// UPnP IGD: router zoeken met SSDP, beschrijving ophalen, poort openzetten met SOAP.
// Alleen routers op een privé-adres in het eigen subnet; geen proxy, geen doorverwijzingen,
// alles begrensd (grootte, tijd, aantal).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ssdpAddr     = "239.255.255.250:1900"
	upnpMaxBody  = 256 << 10
	upnpMaxLocs  = 4
	upnpDescName = "AEROCX Blackout"
)

var upnpSearchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
}

// upnpHTTP: zonder proxy (de router staat in huis), zonder doorverwijzingen, korte time-outs.
var upnpHTTP = &http.Client{
	Timeout: 4 * time.Second,
	Transport: &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  3 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// pmTestLoopback: alleen in tests mogen nep-routers op 127.0.0.1 staan.
var pmTestLoopback = false

// inOwnSubnet: ip is privé en valt in het subnet van een van mijn (niet link-local) IPv4-adressen.
func inOwnSubnet(addrs []ifAddr, ip net.IP) bool {
	ip = ip.To4()
	if pmTestLoopback && ip != nil && ip.IsLoopback() {
		return true
	}
	if ip == nil || !ip.IsPrivate() {
		return false
	}
	for _, a := range addrs {
		if a.v4() && !a.LL && !a.Loop && a.Net != nil && a.Net.Contains(ip) {
			return true
		}
	}
	return false
}

// parseSSDPReply leest een SSDP-antwoord en geeft de LOCATION terug als die naar een
// privé-adres in het eigen subnet wijst (en over http gaat).
func parseSSDPReply(pkt []byte, addrs []ifAddr) (*url.URL, error) {
	if len(pkt) > 2048 {
		return nil, errors.New("ssdp: te groot")
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(pkt)), nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("ssdp: geen 200")
	}
	return checkLocation(resp.Header.Get("Location"), addrs)
}

func checkLocation(loc string, addrs []ifAddr) (*url.URL, error) {
	if loc == "" || len(loc) > 512 {
		return nil, errors.New("ssdp: geen bruikbare LOCATION")
	}
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return nil, errors.New("ssdp: LOCATION moet http:// zijn")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !inOwnSubnet(addrs, ip) {
		return nil, errors.New("ssdp: LOCATION niet in het eigen netwerk")
	}
	return u, nil
}

// ssdpSearch zoekt routers vanaf elk eigen privé-IPv4-adres. Antwoorden van buiten het eigen
// subnet worden genegeerd.
func ssdpSearch(ctx context.Context, env pmEnv, addrs []ifAddr) []*url.URL {
	dst, err := net.ResolveUDPAddr("udp4", env.ssdpAddr)
	if err != nil {
		return nil
	}
	var conns []*net.UDPConn
	for _, a := range addrs {
		if !a.v4() || a.LL || (a.Loop && !dst.IP.IsLoopback()) || (!a.Loop && !a.IP.IsPrivate()) {
			continue
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: a.IP})
		if err != nil {
			continue
		}
		rawSock(c, func(fd uintptr) error { return sockMcastIf4(fd, a.IP) })
		conns = append(conns, c)
		if len(conns) >= 4 {
			break
		}
	}
	if len(conns) == 0 {
		return nil
	}
	timeout := env.timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	end := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(end) {
		end = d
	}
	type hit struct {
		u    *url.URL
		from net.IP
	}
	ch := make(chan hit, 32)
	done := make(chan struct{})
	for _, c := range conns {
		for _, st := range upnpSearchTargets {
			msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
			c.WriteToUDP([]byte(msg), dst)
		}
		go func(c *net.UDPConn) {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 2048)
			for i := 0; i < 64; i++ {
				c.SetReadDeadline(end)
				nr, from, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				if !inOwnSubnet(addrs, from.IP) {
					continue
				}
				if u, err := parseSSDPReply(buf[:nr], addrs); err == nil {
					select {
					case ch <- hit{u, from.IP}:
					default:
					}
				}
			}
		}(c)
	}
	for range conns {
		<-done
	}
	for _, c := range conns {
		c.Close()
	}
	close(ch)
	var out []*url.URL
	seen := map[string]bool{}
	for h := range ch {
		if !seen[h.u.String()] && len(out) < upnpMaxLocs {
			seen[h.u.String()] = true
			out = append(out, h.u)
		}
	}
	return out
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpRoot struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

func findWANService(d *upnpDevice, depth int) *upnpService {
	if depth > 6 {
		return nil
	}
	for i := range d.Services {
		st := d.Services[i].ServiceType
		if strings.HasPrefix(st, "urn:schemas-upnp-org:service:WANIPConnection:") || strings.HasPrefix(st, "urn:schemas-upnp-org:service:WANPPPConnection:") {
			return &d.Services[i]
		}
	}
	for i := range d.Devices {
		if s := findWANService(&d.Devices[i], depth+1); s != nil {
			return s
		}
	}
	return nil
}

func safeServiceType(s string) bool {
	if s == "" || len(s) > 120 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ':' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// parseIGDDescription geeft de control-URL (absoluut, zelfde host als de beschrijving) en het servicetype.
func parseIGDDescription(body []byte, loc *url.URL) (ctrl, svc string, err error) {
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", "", fmt.Errorf("upnp: beschrijving onleesbaar: %v", err)
	}
	s := findWANService(&root.Device, 0)
	if s == nil {
		return "", "", errors.New("upnp: geen internetgateway")
	}
	svc = strings.TrimSpace(s.ServiceType)
	if !safeServiceType(svc) {
		return "", "", errors.New("upnp: vreemd servicetype")
	}
	base := loc
	if b := strings.TrimSpace(root.URLBase); b != "" {
		if bu, err := url.Parse(b); err == nil {
			base = bu
		}
	}
	ref, err := url.Parse(strings.TrimSpace(s.ControlURL))
	if err != nil {
		return "", "", errors.New("upnp: control-URL onleesbaar")
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" || u.Hostname() != loc.Hostname() || u.User != nil {
		return "", "", errors.New("upnp: control-URL wijst naar een ander toestel")
	}
	return u.String(), svc, nil
}

func upnpGet(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := upnpHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upnp: http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, upnpMaxBody))
}

type upnpError struct {
	Code int
	Desc string
}

func (e *upnpError) Error() string { return fmt.Sprintf("upnp-fout %d %s", e.Code, e.Desc) }

func xmlEsc(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// soapCall voert een UPnP-actie uit en geeft de uitvoerargumenten (bladeren van de Body).
func soapCall(ctx context.Context, ctrl, svc, action string, args [][2]string) (map[string]string, error) {
	if !safeServiceType(svc) {
		return nil, errors.New("upnp: vreemd servicetype")
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\r\n" + `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	b.WriteString(`<u:` + action + ` xmlns:u="` + svc + `">`)
	for _, a := range args {
		b.WriteString("<" + a[0] + ">" + xmlEsc(a[1]) + "</" + a[0] + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	req, err := http.NewRequestWithContext(ctx, "POST", ctrl, strings.NewReader(b.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+svc+"#"+action+`"`)
	resp, err := upnpHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	out := parseSOAPLeaves(body)
	if resp.StatusCode != 200 {
		code, _ := strconv.Atoi(out["errorCode"])
		if code == 0 {
			return nil, fmt.Errorf("upnp: http %d", resp.StatusCode)
		}
		return nil, &upnpError{Code: code, Desc: out["errorDescription"]}
	}
	return out, nil
}

// parseSOAPLeaves: alle bladelementen (naam -> tekst), hooguit 64, korte waarden.
func parseSOAPLeaves(body []byte) map[string]string {
	out := map[string]string{}
	d := xml.NewDecoder(bytes.NewReader(body))
	var name string
	var text strings.Builder
	for i := 0; i < 4096 && len(out) < 64; i++ {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name = t.Name.Local
			text.Reset()
		case xml.CharData:
			if name != "" && text.Len() < 512 {
				text.Write(t)
			}
		case xml.EndElement:
			if name == t.Name.Local && name != "" {
				if _, dup := out[name]; !dup {
					out[name] = strings.TrimSpace(text.String())
				}
			}
			name = ""
		}
	}
	return out
}

// upnpMap: router zoeken, extern adres opvragen, UDP-poort doorverwijzen (1 uur, vernieuwd).
func upnpMap(ctx context.Context, env pmEnv, addrs []ifAddr, port int) (*portMapping, error) {
	locs := ssdpSearch(ctx, env, addrs)
	if len(locs) == 0 {
		return nil, errors.New("geen UPnP-router gevonden")
	}
	var lastErr error
	for _, loc := range locs {
		body, err := upnpGet(ctx, loc.String())
		if err != nil {
			lastErr = err
			continue
		}
		ctrl, svc, err := parseIGDDescription(body, loc)
		if err != nil {
			lastErr = err
			continue
		}
		host := net.ParseIP(loc.Hostname())
		la := localFor(addrs, host)
		if la == nil {
			if host.IsLoopback() { // tests
				la = &ifAddr{IP: host}
			} else {
				continue
			}
		}
		res, err := soapCall(ctx, ctrl, svc, "GetExternalIPAddress", nil)
		if err != nil {
			lastErr = err
			continue
		}
		ext := net.ParseIP(res["NewExternalIPAddress"]).To4()
		if !publicIP(ext) {
			lastErr = errors.New("de router heeft zelf geen publiek adres")
			continue
		}
		// een vorige doorverwijzing van deze app (bv. na een crash bij een router met alleen vaste
		// doorverwijzingen) hergebruiken; dubbele opruimen
		own := upnpFindOwn(ctx, ctrl, svc, la.IP, port)
		prefer := port
		if len(own) > 0 {
			prefer = own[0]
			for _, p := range own[1:] {
				soapCall(ctx, ctrl, svc, "DeletePortMapping", [][2]string{{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(p)}, {"NewProtocol", "UDP"}})
			}
		}
		m, err := upnpAdd(ctx, ctrl, svc, la.IP, ext, port, prefer)
		if err != nil {
			lastErr = err
			continue
		}
		m.Gateway = host
		return m, nil
	}
	return nil, lastErr
}

// upnpFindOwn: externe poorten van bestaande UDP-doorverwijzingen van deze app naar local:port
// (hooguit 32 regels bekeken).
func upnpFindOwn(ctx context.Context, ctrl, svc string, local net.IP, port int) []int {
	var out []int
	for i := 0; i < 32 && ctx.Err() == nil; i++ {
		r, err := soapCall(ctx, ctrl, svc, "GetGenericPortMappingEntry", [][2]string{{"NewPortMappingIndex", strconv.Itoa(i)}})
		if err != nil {
			break // 713: geen regels meer (of de router kent deze actie niet)
		}
		if r["NewPortMappingDescription"] != upnpDescName || !strings.EqualFold(r["NewProtocol"], "UDP") ||
			r["NewInternalClient"] != local.String() || r["NewInternalPort"] != strconv.Itoa(port) {
			continue
		}
		if p, err := strconv.Atoi(r["NewExternalPort"]); err == nil && p > 0 && p < 65536 && len(out) < 8 {
			out = append(out, p)
		}
	}
	return out
}

func upnpAdd(ctx context.Context, ctrl, svc string, local, ext net.IP, port, prefer int) (*portMapping, error) {
	lease := pmLease
	extPort := prefer
	var lastErr error
	for try := 0; try < 4; try++ {
		_, err := soapCall(ctx, ctrl, svc, "AddPortMapping", [][2]string{
			{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(extPort)}, {"NewProtocol", "UDP"},
			{"NewInternalPort", strconv.Itoa(port)}, {"NewInternalClient", local.String()}, {"NewEnabled", "1"},
			{"NewPortMappingDescription", upnpDescName}, {"NewLeaseDuration", strconv.Itoa(lease)}})
		if err == nil {
			life := time.Duration(lease) * time.Second
			if lease == 0 {
				life = time.Hour // vast: toch elk uur vernieuwen en bij stoppen weghalen
			}
			return &portMapping{Method: "upnp", Ext: &net.UDPAddr{IP: ext, Port: extPort}, Local: local, Port: port,
				Lifetime: life, Got: time.Now(), ctrl: ctrl, svc: svc, Permanent: lease == 0}, nil
		}
		lastErr = err
		var ue *upnpError
		if !errors.As(err, &ue) {
			return nil, err
		}
		switch ue.Code {
		case 725: // OnlyPermanentLeasesSupported
			lease = 0
		case 718: // ConflictInMappingEntry: andere externe poort
			extPort = 20000 + int(time.Now().UnixNano()%40000)
		default:
			return nil, err
		}
	}
	return nil, lastErr
}
