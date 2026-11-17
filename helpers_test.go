package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var portSeq int32 = 47900

func nextPort() int { return int(atomic.AddInt32(&portSeq, 1)) }

// bareNode: een knooppunt zonder netwerk (voor unit-tests).
func bareNode(t *testing.T, name string) *Node {
	t.Helper()
	n, err := loadNode(t.TempDir(), 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	n.st.Name = name
	n.bumpCard()
	return n
}

// know: a kent b als contact (zonder netwerk).
func know(a, b *Node, name string) *Contact {
	c := &Contact{ID: b.myID, Name: name, Card: b.myCard(), Observed: map[string]int64{}, Role: "lid"}
	a.st.Contacts[b.myID] = c
	return c
}

type tnode struct {
	*Node
	t   *testing.T
	mux http.Handler
}

// liveNode: een echt knooppunt op loopback met snelle rondes.
func liveNode(t *testing.T, name string, setup func(n *Node)) *tnode {
	t.Helper()
	n, err := loadNode(t.TempDir(), nextPort(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	n.st.Name = name
	n.bumpCard()
	n.pingEvery = 300 * time.Millisecond
	n.outboxEvery = 200 * time.Millisecond
	n.retryGap = 1
	n.loraWait = 1
	if setup != nil {
		setup(n)
	}
	n.run()
	return &tnode{Node: n, t: t, mux: n.routes()}
}

func (tn *tnode) call(method, path string, body any) (int, []byte) {
	tn.t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Host = "localhost:8474"
	rec := httptest.NewRecorder()
	tn.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (tn *tnode) post(path string, body any) map[string]any {
	tn.t.Helper()
	code, b := tn.call("POST", path, body)
	if code != 200 {
		tn.t.Fatalf("%s %v: %d %s", path, body, code, b)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

func (tn *tnode) get(path string, v any) {
	tn.t.Helper()
	code, b := tn.call("GET", path, nil)
	if code != 200 {
		tn.t.Fatalf("GET %s: %d %s", path, code, b)
	}
	if err := json.Unmarshal(b, v); err != nil {
		tn.t.Fatalf("GET %s: %v", path, err)
	}
}

func (tn *tnode) state() map[string]any {
	var s map[string]any
	tn.get("/api/state", &s)
	return s
}

func (tn *tnode) code() string {
	return tn.state()["me"].(map[string]any)["code"].(string)
}

func (tn *tnode) messages(conv string) []map[string]any {
	var m []map[string]any
	tn.get("/api/messages?conv="+conv, &m)
	return m
}

// pair: beide kanten voegen elkaars code toe.
func pair(a, b *tnode) {
	a.post("/api/contact", map[string]any{"action": "add", "code": b.code(), "name": b.st.Name})
	b.post("/api/contact", map[string]any{"action": "add", "code": a.code(), "name": a.st.Name})
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("time-out: %s", what)
}

func (tn *tnode) online(id string) bool {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	c := tn.st.Contacts[id]
	return c != nil && tn.ipOnline(c)
}

func (tn *tnode) lock(f func()) {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	f()
}

func dump(v any) string {
	j, _ := json.Marshal(v)
	return fmt.Sprint(string(j))
}

func signWith(n *Node, b []byte) []byte { return ed25519.Sign(n.edPriv, b) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
