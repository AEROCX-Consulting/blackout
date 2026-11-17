package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCleanMaps(t *testing.T) {
	n := bareNode(t, "Anna")
	tn := now()
	for i := 0; i < 100; i++ {
		n.relayCnt[fmt.Sprintf("x|%d", tn/60-int64(i))] = 1
		n.lastTry[fmt.Sprint("m", i)] = tn - 7200
		n.loraLast[fmt.Sprint("m", i)] = tn - 3*3600
		n.loraTries[fmt.Sprint("m", i)] = 3
		n.brTries[fmt.Sprint("b", i)] = 1
		n.grpParts[fmt.Sprintf("g%d|x|1", i)] = 1
	}
	n.lastTry["nieuw"] = tn
	n.cleanMaps(tn)
	if len(n.relayCnt) != 1 || len(n.lastTry) != 1 || len(n.loraLast) != 0 || len(n.loraTries) != 0 || len(n.brTries) != 0 || len(n.grpParts) != 0 {
		t.Fatalf("niet opgeruimd: relay %d, lastTry %d, loraLast %d, loraTries %d, brTries %d, grpParts %d",
			len(n.relayCnt), len(n.lastTry), len(n.loraLast), len(n.loraTries), len(n.brTries), len(n.grpParts))
	}
	// gezien-lijst begrensd
	for i := 0; i < seenMax+500; i++ {
		n.markSeenKey(fmt.Sprint("k", i))
	}
	if len(n.seenMsg) > seenMax {
		t.Fatalf("gezien-lijst %d", len(n.seenMsg))
	}
}

func TestRadioNodesBounded(t *testing.T) {
	r := newRadio()
	for i := 0; i < radioMaxNodes+50; i++ {
		r.mu.Lock()
		r.setNode(uint32(i+1), "")
		r.nodeSeen[uint32(i+1)] = int64(i) // oplopend: de eerste zijn de oudste
		r.mu.Unlock()
	}
	if len(r.nodes) != radioMaxNodes || len(r.nodeSeen) != radioMaxNodes {
		t.Fatalf("%d nodes", len(r.nodes))
	}
	if _, ok := r.nodes[1]; ok {
		t.Error("oudste node niet verwijderd")
	}
}

func TestBlobChunkSizeChecked(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	c := know(b, a, "Anna")
	id := "0011223344556677"
	b.blobIn[id] = &blobRx{id: id, from: c.ID, size: 1500, parts: make([][]byte, 2), started: now()}
	raw, _ := hex.DecodeString(id)
	chunk := func(idx, size int) []byte {
		pt := append([]byte{}, raw...)
		pt = binary.BigEndian.AppendUint16(pt, uint16(idx))
		pt = binary.BigEndian.AppendUint16(pt, 2)
		return append(pt, make([]byte, size)...)
	}
	b.onBlobChunk(c, chunk(0, 60000)) // veel te groot
	b.onBlobChunk(c, chunk(1, 10))    // te klein voor het laatste stuk (476)
	if rx := b.blobIn[id]; rx == nil || rx.got != 0 {
		t.Fatal("verkeerde stukgrootte aanvaard")
	}
	b.onBlobChunk(c, chunk(0, blobChunk))
	if b.blobIn[id].got != 1 {
		t.Fatal("goed stuk geweigerd")
	}
}
