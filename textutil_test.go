package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncUTF8(t *testing.T) {
	s := strings.Repeat("é", 700) // 2 bytes per teken
	if got := truncRunes(s, maxBody); utf8.RuneCountInString(got) != maxBody || !utf8.ValidString(got) {
		t.Errorf("truncRunes: %d tekens", utf8.RuneCountInString(got))
	}
	if got := truncBytes("aé", 2); got != "a" {
		t.Errorf("truncBytes breekt UTF-8: %q", got)
	}
	if got := truncBytes(strings.Repeat("😀", 20), 41); len(got) != 40 || !utf8.ValidString(got) {
		t.Errorf("truncBytes: %d bytes", len(got))
	}
	n := bareNode(t, "Anna")
	b := bareNode(t, "Bert")
	c := know(n, b, "Bert")
	n.deliverMsg(c, inMsg{ID: "0102030405060708", Ch: "dm", Body: s})
	m := n.st.Messages[len(n.st.Messages)-1]
	if utf8.RuneCountInString(m.Body) != maxBody || !utf8.ValidString(m.Body) {
		t.Errorf("ontvangen bericht: %d tekens, geldig %v", utf8.RuneCountInString(m.Body), utf8.ValidString(m.Body))
	}
	// over de radio: ingekort zonder UTF-8 te breken
	nb := know(b, n, "Anna")
	_ = nb
	msg := &Message{ID: "1112131415161718", Conv: b.myID, From: "me", Body: strings.Repeat("€", 400), TS: now()}
	var body []byte
	frames := n.loraFrames(know(n, b, "Bert"), msg)
	a, _ := b.aead(b.st.Contacts[n.myID])
	for _, f := range frames {
		hl := loraHeadLen(f)
		pt, err := a.Open(nil, f[hl:hl+12], f[hl+12:], f[:hl])
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, pt...)
	}
	if !utf8.Valid(body) {
		t.Error("radiobericht breekt UTF-8")
	}
}

func TestSendLengthInRunes(t *testing.T) {
	a := liveNode(t, "Anna", nil)
	b := bareNode(t, "Bert")
	a.lock(func() { know(a.Node, b, "Bert") })
	code, _ := a.call("POST", "/api/send", map[string]any{"conv": b.myID, "body": strings.Repeat("é", maxBody)})
	if code != 200 {
		t.Errorf("600 tekens met accenten geweigerd: %d", code)
	}
	code, _ = a.call("POST", "/api/send", map[string]any{"conv": b.myID, "body": strings.Repeat("é", maxBody+1)})
	if code != 400 {
		t.Errorf("601 tekens aanvaard: %d", code)
	}
}

func TestOsintSafeLink(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.org/x":    "https://example.org/x",
		" http://example.org ":     "http://example.org",
		"javascript:alert(1)":      "",
		"JaVaScRiPt:alert(1)":      "",
		"data:text/html,<b>x</b>":  "",
		"//example.org/x":          "",
		"vbscript:x":               "",
		"HTTPS://example.org/caps": "HTTPS://example.org/caps",
	} {
		if got := osSafeLink(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	_, items, err := osParseFeed([]byte(`<?xml version="1.0"?><rss><channel><title>T</title><item><title>a</title><link>javascript:alert(1)</link><guid>1</guid></item><item><title>b</title><link>https://example.org/b</link><guid>2</guid></item></channel></rss>`), 10)
	if err != nil || len(items) != 2 || items[0].Link != "" || items[1].Link != "https://example.org/b" {
		t.Errorf("RSS-links: %v %+v", err, items)
	}
}
