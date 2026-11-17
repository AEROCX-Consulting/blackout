package main

// Foto's (alleen over IP). JPEG ≤ 200 kB. ID = eerste 8 bytes van SHA-256 (16 hex).
// De ontvanger vraagt ontbrekende stukken op ("blobget" met lijst), de afzender antwoordt met
// versleutelde 'D'-pakketten: blobID[8] | index[2] | aantal[2] | data (≤ 1024 bytes).
// Zo zijn bevestiging en herhaling hetzelfde mechanisme: wat niet binnenkwam, wordt opnieuw gevraagd.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxBlob     = 200 * 1024
	blobChunk   = 1024
	blobPerReq  = 48
	blobTimeout = 600 // seconden
)

type blobRx struct {
	id      string
	from    string
	size    int
	parts   [][]byte
	got     int
	started int64
	lastReq int64
}

func validBlobID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (n *Node) blobDir() string { return filepath.Join(n.dir, "blobs") }

func (n *Node) blobPath(id string) string { return filepath.Join(n.blobDir(), id+".jpg") }

func blobID(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8])
}

// storeBlob controleert en bewaart een eigen foto. Geeft het ID.
func (n *Node) storeBlob(b64data string) (string, int, error) {
	if i := strings.Index(b64data, ","); i >= 0 && strings.HasPrefix(b64data, "data:") {
		b64data = b64data[i+1:]
	}
	b64data = strings.TrimSpace(b64data)
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64data, "="))
	}
	if err != nil {
		return "", 0, errors.New("De foto kon niet gelezen worden")
	}
	if len(data) > maxBlob {
		return "", 0, fmt.Errorf("De foto is te groot (%d kB, max. 200 kB)", len(data)/1024)
	}
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
		return "", 0, errors.New("Alleen JPEG-foto's kunnen verstuurd worden")
	}
	id := blobID(data)
	if err := os.MkdirAll(n.blobDir(), 0o700); err != nil {
		return "", 0, errors.New("De foto kon niet bewaard worden")
	}
	if err := os.WriteFile(n.blobPath(id), data, 0o600); err != nil {
		return "", 0, errors.New("De foto kon niet bewaard worden")
	}
	return id, len(data), nil
}

func (n *Node) haveBlob(id string) bool {
	fi, err := os.Stat(n.blobPath(id))
	return err == nil && fi.Size() > 0
}

// startBlobFetch (onder slot): begin met ophalen. Geeft de status.
func (n *Node) startBlobFetch(c *Contact, id string, size int) string {
	if n.haveBlob(id) {
		return "ok"
	}
	if n.blobIn[id] == nil {
		if len(n.blobIn) >= maxBlobIn {
			return "mislukt"
		}
		cnt := (size + blobChunk - 1) / blobChunk
		n.blobIn[id] = &blobRx{id: id, from: c.ID, size: size, parts: make([][]byte, cnt), started: now()}
	}
	n.blobRequest(n.blobIn[id])
	return "bezig"
}

func (n *Node) blobRequest(rx *blobRx) {
	c := n.st.Contacts[rx.from]
	if c == nil || c.Blocked {
		return
	}
	var miss []int
	for i, p := range rx.parts {
		if p == nil {
			miss = append(miss, i)
			if len(miss) >= blobPerReq {
				break
			}
		}
	}
	rx.lastReq = now()
	n.sendTo(c, n.sealJSON(c, wire{T: "blobget", ID: rx.id, Miss: miss}))
}

// blobTick (onder slot, elke 2 s): ontbrekende stukken opnieuw vragen of opgeven.
func (n *Node) blobTick() {
	t := now()
	for id, rx := range n.blobIn {
		if t-rx.started > blobTimeout {
			delete(n.blobIn, id)
			n.setBlobStatus(id, "mislukt")
			n.event("foto", "Foto ophalen mislukt (geen verbinding)")
			continue
		}
		if t-rx.lastReq >= 2 {
			n.blobRequest(rx)
		}
	}
	for k := range n.blobServe {
		delete(n.blobServe, k)
	}
}

func (n *Node) setBlobStatus(id, st string) {
	for _, m := range n.st.Messages {
		if m.Img == id && m.From != "me" {
			m.ImgSt = st
		}
	}
	n.dirty = true
}

// onBlobGet (onder slot): een contact vraagt stukken van een foto.
func (n *Node) onBlobGet(c *Contact, m *wire) {
	if !validBlobID(m.ID) {
		return
	}
	if n.blobServe[c.ID] > 4*blobPerReq { // per 2 s
		return
	}
	data, err := os.ReadFile(n.blobPath(m.ID))
	if err != nil || len(data) == 0 {
		return
	}
	cnt := (len(data) + blobChunk - 1) / blobChunk
	id, _ := hex.DecodeString(m.ID)
	sent := 0
	for _, i := range m.Miss {
		if i < 0 || i >= cnt || sent >= blobPerReq {
			continue
		}
		end := (i + 1) * blobChunk
		if end > len(data) {
			end = len(data)
		}
		pt := make([]byte, 0, 12+blobChunk)
		pt = append(pt, id...)
		pt = binary.BigEndian.AppendUint16(pt, uint16(i))
		pt = binary.BigEndian.AppendUint16(pt, uint16(cnt))
		pt = append(pt, data[i*blobChunk:end]...)
		n.sendTo(c, n.seal('D', c, pt))
		sent++
	}
	n.blobServe[c.ID] += sent
}

// onBlobChunk (onder slot): een stuk van een foto komt binnen.
func (n *Node) onBlobChunk(c *Contact, pt []byte) {
	if len(pt) < 12 {
		return
	}
	id := hex.EncodeToString(pt[:8])
	rx := n.blobIn[id]
	if rx == nil || rx.from != c.ID {
		return
	}
	idx, cnt := int(binary.BigEndian.Uint16(pt[8:10])), int(binary.BigEndian.Uint16(pt[10:12]))
	if cnt != len(rx.parts) || idx >= cnt || rx.parts[idx] != nil {
		return
	}
	// stukgrootte controleren: elk stuk precies blobChunk, het laatste de rest
	want := blobChunk
	if idx == cnt-1 {
		want = rx.size - (cnt-1)*blobChunk
	}
	if len(pt)-12 != want {
		return
	}
	rx.parts[idx] = append([]byte{}, pt[12:]...)
	rx.got++
	if rx.got < cnt {
		return
	}
	delete(n.blobIn, id)
	var data []byte
	for _, p := range rx.parts {
		data = append(data, p...)
	}
	if len(data) != rx.size || blobID(data) != id {
		n.setBlobStatus(id, "mislukt")
		n.event("foto", "Foto van "+c.Name+" kwam beschadigd binnen")
		return
	}
	os.MkdirAll(n.blobDir(), 0o700)
	if err := os.WriteFile(n.blobPath(id), data, 0o600); err != nil {
		n.setBlobStatus(id, "mislukt")
		return
	}
	n.setBlobStatus(id, "ok")
	n.event("foto", fmt.Sprintf("Foto van %s ontvangen (%d kB)", c.Name, len(data)/1024))
}

// cleanBlobs (onder slot): foto's die bij geen enkel bericht meer horen, weg.
func (n *Node) cleanBlobs() {
	ents, err := os.ReadDir(n.blobDir())
	if err != nil {
		return
	}
	used := map[string]bool{}
	for _, m := range n.st.Messages {
		if m.Img != "" {
			used[m.Img] = true
		}
	}
	for _, e := range ents {
		id := strings.TrimSuffix(e.Name(), ".jpg")
		fi, err := e.Info()
		if err != nil || e.IsDir() || time.Since(fi.ModTime()) < time.Hour {
			continue
		}
		if !used[id] {
			os.Remove(filepath.Join(n.blobDir(), e.Name()))
		}
	}
}
