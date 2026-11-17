package main

// Koppeling met een Meshtastic-radio (LoRa) via USB (serieel) of wifi (TCP 4403).
// Protocol: frames 0x94 0xC3 <lengte 2 bytes big-endian> <protobuf>, max 512 bytes.
// Veldnummers volgen meshtastic/protobufs (mesh.proto, channel.proto, config.proto).

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	mtStart1     = 0x94
	mtStart2     = 0xC3
	mtMaxFrame   = 512
	mtMaxPayload = 233 // Data.payload max_size
	mtPortApp    = 256 // PRIVATE_APP
	mtPortText   = 1   // TEXT_MESSAGE_APP
	mtPortPos    = 3   // POSITION_APP
	mtPortNode   = 4   // NODEINFO_APP
	mtBroadcast  = 0xFFFFFFFF
	mtTCPPort    = "4403"
)

var mtRegions = map[uint64]string{0: "UNSET", 1: "US", 2: "EU_433", 3: "EU_868", 29: "EU_866", 30: "EU_874", 31: "EU_917", 32: "EU_N_868"}
var mtPresets = map[uint64]string{0: "LONG_FAST", 1: "LONG_SLOW", 2: "VERY_LONG_SLOW", 3: "MEDIUM_SLOW", 4: "MEDIUM_FAST", 5: "SHORT_SLOW", 6: "SHORT_FAST", 7: "LONG_MODERATE", 8: "SHORT_TURBO", 9: "LONG_TURBO"}

type mtChannel struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Role  int    `json:"role"` // 0 uit, 1 primair, 2 secundair
}

type RadioInfo struct {
	Connected   bool        `json:"connected"`
	Transport   string      `json:"transport"`
	NodeID      string      `json:"nodeId"`
	LongName    string      `json:"longName"`
	Region      string      `json:"region"`
	Preset      string      `json:"preset"`
	CanSend     bool        `json:"canSend"`
	Channels    []mtChannel `json:"channels"`
	ChannelUsed int         `json:"channelUsed"`
	ChannelName string      `json:"channelName"`
	LastRx      int64       `json:"lastRx"`
	RxCount     int         `json:"rx"`
	TxCount     int         `json:"tx"`
	Queue       int         `json:"queue"`
	Error       string      `json:"error"`
	Ports       []string    `json:"ports"`
	GPS         *radioGPS   `json:"gps"`
	Nodes       int         `json:"nodes"`
}

type radioGPS struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
	TS  int64   `json:"ts"` // ms
}

type radioOut struct {
	key     string
	payload []byte
	prio    int // 0 bevestiging, 1 bericht, 2 baken
	added   time.Time
}

type Radio struct {
	mu        sync.Mutex
	conn      io.ReadWriteCloser
	info      RadioInfo
	nodeNum   uint32
	hopLimit  uint32
	region    uint64
	txEnabled bool
	queue     []radioOut
	txTimes   []time.Time
	lastTx    time.Time
	queueFree int
	gen       int
	minGap    time.Duration
	maxHour   int

	onPacket func(payload []byte, from uint32, rssi int32, snr float32)
	onText   func(fromNode uint32, name, text string, rssi int32, snr float32, ch uint32)
	onNode   func(num uint32, name string)
	testTx   func(payload []byte) // alleen voor testen: "uitzenden" zonder echte radio
	nodes    map[uint32]string
	nodeSeen map[uint32]int64 // laatst gehoord (voor het maximum van radioMaxNodes)
	gpsLat   float64
	gpsLon   float64
	gpsTS    int64
	cfgDone  bool
	mode     string // "auto" (USB), "tcp", "off"
	target   string
	chWant   int // -1 = automatisch (kanaal "Blackout", anders primair)
}

const radioMaxNodes = 500

// setNode (onder r.mu): node bewaren; boven het maximum valt de langst niet gehoorde weg.
func (r *Radio) setNode(num uint32, name string) {
	if _, ok := r.nodes[num]; !ok && len(r.nodes) >= radioMaxNodes {
		var oldest uint32
		var ot int64 = -1
		for k := range r.nodes {
			if ts := r.nodeSeen[k]; ot < 0 || ts < ot {
				oldest, ot = k, ts
			}
		}
		delete(r.nodes, oldest)
		delete(r.nodeSeen, oldest)
	}
	r.nodes[num] = name
	r.nodeSeen[num] = time.Now().Unix()
}

func newRadio() *Radio {
	return &Radio{minGap: 8 * time.Second, maxHour: 150, queueFree: -1, hopLimit: 3, mode: "auto", chWant: -1, nodes: map[uint32]string{}, nodeSeen: map[uint32]int64{}}
}

func (r *Radio) settings() (string, string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode, r.target, r.chWant
}

// SetSettings past de keuze aan; bij een andere verbinding wordt opnieuw verbonden.
func (r *Radio) SetSettings(mode, target string, ch int) {
	r.mu.Lock()
	reconnect := mode != r.mode || target != r.target
	r.mode, r.target, r.chWant = mode, target, ch
	if r.info.Connected {
		r.refreshCanSend()
	}
	r.mu.Unlock()
	if reconnect {
		r.Reconnect()
	}
}

// ---------- publieke kant ----------

func (r *Radio) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.testTx != nil || (r.info.Connected && r.info.CanSend)
}

// GPS geeft de positie van de eigen radio (als die er een heeft), niet ouder dan 6 uur.
func (r *Radio) GPS() (lat, lon float64, ts int64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gpsTS == 0 || time.Now().Unix()-r.gpsTS > 6*3600 || (r.gpsLat == 0 && r.gpsLon == 0) {
		return 0, 0, 0, false
	}
	return r.gpsLat, r.gpsLon, r.gpsTS, true
}

func (r *Radio) Snapshot() RadioInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	in := r.info
	in.Channels = append([]mtChannel{}, r.info.Channels...)
	in.Queue = len(r.queue)
	in.Nodes = len(r.nodes)
	if r.gpsTS != 0 && time.Now().Unix()-r.gpsTS <= 6*3600 {
		in.GPS = &radioGPS{Lat: r.gpsLat, Lon: r.gpsLon, TS: r.gpsTS * 1000}
	}
	return in
}

func (r *Radio) Reconnect() {
	r.mu.Lock()
	r.gen++
	if r.conn != nil {
		r.conn.Close()
	}
	r.mu.Unlock()
}

// Enqueue zet een LoRa-payload in de wachtrij; een gelijke sleutel wordt niet dubbel opgenomen.
func (r *Radio) Enqueue(key string, payload []byte, prio int) {
	if len(payload) > mtMaxPayload {
		log.Printf("radio: payload te groot (%d)", len(payload))
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.testTx != nil {
		r.info.TxCount++
		go r.testTx(append([]byte{}, payload...))
		return
	}
	for _, q := range r.queue {
		if q.key == key {
			return
		}
	}
	if len(r.queue) >= 60 { // vol: laagste prioriteit / oudste eruit
		worst := 0
		for i, q := range r.queue {
			if q.prio > r.queue[worst].prio || (q.prio == r.queue[worst].prio && q.added.Before(r.queue[worst].added)) {
				worst = i
			}
		}
		if r.queue[worst].prio < prio {
			return
		}
		r.queue = append(r.queue[:worst], r.queue[worst+1:]...)
	}
	r.queue = append(r.queue, radioOut{key: key, payload: payload, prio: prio, added: time.Now()})
}

// Drop haalt wachtende pakketten weg waarvan de sleutel met prefix begint (bv. na bevestiging).
func (r *Radio) Drop(prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.queue[:0]
	for _, q := range r.queue {
		if !strings.HasPrefix(q.key, prefix) {
			out = append(out, q)
		}
	}
	r.queue = out
}

// ---------- verbinding ----------

func (r *Radio) run() {
	for {
		mode, target, _ := r.settings()
		ports := serialPorts()
		r.mu.Lock()
		r.info.Ports = ports
		r.mu.Unlock()
		var cands []string
		switch {
		case mode == "off":
			r.setState(false, "", "")
			time.Sleep(3 * time.Second)
			continue
		case mode == "tcp":
			if target == "" {
				r.setState(false, "", "Geef het IP-adres van de radio in")
				time.Sleep(3 * time.Second)
				continue
			}
			cands = []string{"tcp:" + target}
		case target != "":
			cands = []string{"serial:" + target}
		default:
			for _, p := range ports {
				cands = append(cands, "serial:"+p)
			}
		}
		if len(cands) == 0 {
			r.setState(false, "", "Geen radio gevonden via USB")
			time.Sleep(5 * time.Second)
			continue
		}
		for _, c := range cands {
			if r.session(c) {
				break
			}
		}
		time.Sleep(4 * time.Second)
	}
}

func (r *Radio) setState(connected bool, transport, errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.info.Connected = connected
	if transport != "" || !connected {
		r.info.Transport = transport
	}
	r.info.Error = errMsg
	if !connected {
		r.info.CanSend = false
	}
}

func openTransport(c string) (io.ReadWriteCloser, string, error) {
	if strings.HasPrefix(c, "tcp:") {
		host := strings.TrimPrefix(c, "tcp:")
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), mtTCPPort)
		}
		conn, err := net.DialTimeout("tcp", host, 6*time.Second)
		return conn, "wifi " + host, err
	}
	p := strings.TrimPrefix(c, "serial:")
	f, err := openSerial(p)
	return f, "USB " + p, err
}

func writeFrame(w io.Writer, pb []byte) error {
	if len(pb) > mtMaxFrame {
		return errors.New("frame te groot")
	}
	h := []byte{mtStart1, mtStart2, byte(len(pb) >> 8), byte(len(pb))}
	_, err := w.Write(append(h, pb...))
	return err
}

func readFrames(rd io.Reader, out chan<- []byte) {
	defer close(out)
	br := bufio.NewReaderSize(rd, 4096)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		if b != mtStart1 {
			continue
		}
		b2, err := br.ReadByte()
		if err != nil {
			return
		}
		if b2 != mtStart2 {
			if b2 == mtStart1 {
				br.UnreadByte()
			}
			continue
		}
		var lb [2]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			return
		}
		n := int(lb[0])<<8 | int(lb[1])
		if n > mtMaxFrame {
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		out <- buf
	}
}

func rand32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// session houdt één verbinding open. Geeft true terug als er een radio antwoordde.
func (r *Radio) session(cand string) bool {
	conn, transport, err := openTransport(cand)
	if err != nil {
		r.setState(false, "", "Radio niet bereikbaar: "+err.Error())
		return false
	}
	r.mu.Lock()
	r.conn = conn
	gen := r.gen
	r.info.Channels = nil
	r.queueFree = -1
	r.cfgDone = false
	r.mu.Unlock()
	defer func() {
		conn.Close()
		r.mu.Lock()
		r.conn = nil
		r.mu.Unlock()
	}()

	frames := make(chan []byte, 64)
	go readFrames(conn, frames)

	// apparaat wekken en opnieuw laten synchroniseren (zoals de officiële Meshtastic-client)
	wake := make([]byte, 32)
	for i := range wake {
		wake[i] = mtStart2
	}
	conn.Write(wake)
	time.Sleep(100 * time.Millisecond)
	wantID := rand32()
	if err := writeFrame(conn, encWantConfig(wantID)); err != nil {
		r.setState(false, "", "Schrijven naar radio mislukt")
		return false
	}

	gotInfo := false
	configDone := false
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	lastHB := time.Now()

	for {
		select {
		case f, ok := <-frames:
			if !ok {
				if gotInfo {
					r.setState(false, "", "Verbinding met radio verbroken")
				} else {
					r.setState(false, "", "Geen Meshtastic-radio op "+transport)
				}
				return gotInfo
			}
			done, info := r.handleFromRadio(f, wantID)
			if info && !gotInfo {
				gotInfo = true
			}
			if done && !configDone {
				configDone = true
				r.mu.Lock()
				r.cfgDone = true
				r.info.Transport = transport
				r.info.Connected = true
				r.info.Error = ""
				r.refreshCanSend()
				r.mu.Unlock()
				log.Printf("radio verbonden: %s (%s)", transport, r.Snapshot().NodeID)
			}
		case <-deadline.C:
			if !configDone {
				r.setState(false, "", "Geen Meshtastic-antwoord op "+transport)
				return gotInfo
			}
		case <-tick.C:
			r.mu.Lock()
			changed := r.gen != gen
			r.mu.Unlock()
			if changed {
				r.setState(false, "", "")
				return true
			}
			if !configDone {
				continue
			}
			if time.Since(lastHB) > 5*time.Minute {
				lastHB = time.Now()
				writeFrame(conn, encHeartbeat())
			}
			if p := r.nextToSend(); p != nil {
				if err := writeFrame(conn, p); err != nil {
					r.setState(false, "", "Schrijven naar radio mislukt")
					return true
				}
			}
		}
	}
}

func (r *Radio) refreshCanSend() {
	r.info.ChannelUsed = r.pickChannel(r.chWant)
	r.info.ChannelName = "primair"
	for _, c := range r.info.Channels {
		if c.Index == r.info.ChannelUsed {
			if c.Name != "" {
				r.info.ChannelName = c.Name
			} else if c.Role == 1 {
				r.info.ChannelName = "primair (standaard)"
			}
		}
	}
	r.info.CanSend = r.region != 0 && r.txEnabled
	r.info.Error = ""
	if r.region == 0 {
		r.info.Error = "Regio van de radio is niet ingesteld. Stel EU_868 in via de Meshtastic-app."
	} else if !r.txEnabled {
		r.info.Error = "Zenden staat uit op de radio (LoRa → Transmit enabled)."
	}
}

func (r *Radio) pickChannel(want int) int {
	if want >= 0 {
		return want
	}
	for _, c := range r.info.Channels {
		if c.Role != 0 && strings.EqualFold(strings.TrimSpace(c.Name), "blackout") {
			return c.Index
		}
	}
	return 0
}

func (r *Radio) nextToSend() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.info.CanSend || len(r.queue) == 0 {
		return nil
	}
	now := time.Now()
	if now.Sub(r.lastTx) < r.minGap {
		return nil
	}
	if r.queueFree == 0 {
		return nil
	}
	keep := r.txTimes[:0]
	for _, t := range r.txTimes {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	r.txTimes = keep
	if len(r.txTimes) >= r.maxHour {
		return nil
	}
	sort.SliceStable(r.queue, func(i, j int) bool { return r.queue[i].prio < r.queue[j].prio })
	q := r.queue[0]
	r.queue = r.queue[1:]
	r.lastTx = now
	r.txTimes = append(r.txTimes, now)
	r.info.TxCount++
	return encSendPacket(uint32(r.info.ChannelUsed), rand32(), r.hopLimit, q.payload)
}

// ---------- protobuf: versturen (ToRadio) ----------

func encWantConfig(id uint32) []byte {
	b := protowire.AppendTag(nil, 3, protowire.VarintType) // ToRadio.want_config_id
	return protowire.AppendVarint(b, uint64(id))
}

func encHeartbeat() []byte {
	b := protowire.AppendTag(nil, 7, protowire.BytesType) // ToRadio.heartbeat
	return protowire.AppendBytes(b, nil)
}

func encSendPacket(channel, id, hop uint32, payload []byte) []byte {
	var data []byte // Data
	data = protowire.AppendTag(data, 1, protowire.VarintType)
	data = protowire.AppendVarint(data, mtPortApp)
	data = protowire.AppendTag(data, 2, protowire.BytesType)
	data = protowire.AppendBytes(data, payload)

	var mp []byte                                          // MeshPacket
	mp = protowire.AppendTag(mp, 2, protowire.Fixed32Type) // to
	mp = protowire.AppendFixed32(mp, mtBroadcast)
	if channel != 0 {
		mp = protowire.AppendTag(mp, 3, protowire.VarintType) // channel
		mp = protowire.AppendVarint(mp, uint64(channel))
	}
	mp = protowire.AppendTag(mp, 4, protowire.BytesType) // decoded
	mp = protowire.AppendBytes(mp, data)
	mp = protowire.AppendTag(mp, 6, protowire.Fixed32Type) // id
	mp = protowire.AppendFixed32(mp, id)
	mp = protowire.AppendTag(mp, 9, protowire.VarintType) // hop_limit
	mp = protowire.AppendVarint(mp, uint64(hop))

	b := protowire.AppendTag(nil, 1, protowire.BytesType) // ToRadio.packet
	return protowire.AppendBytes(b, mp)
}

// ---------- protobuf: ontvangen (FromRadio) ----------

type pbField struct {
	num  protowire.Number
	typ  protowire.Type
	v    uint64
	data []byte
}

func pbFields(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		b = b[n:]
		f := pbField{num: num, typ: typ}
		switch typ {
		case protowire.VarintType:
			f.v, n = protowire.ConsumeVarint(b)
		case protowire.Fixed32Type:
			var v uint32
			v, n = protowire.ConsumeFixed32(b)
			f.v = uint64(v)
		case protowire.Fixed64Type:
			f.v, n = protowire.ConsumeFixed64(b)
		case protowire.BytesType:
			f.data, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		b = b[n:]
		out = append(out, f)
	}
	return out, nil
}

// handleFromRadio verwerkt één FromRadio-bericht. done=true bij config_complete_id.
func (r *Radio) handleFromRadio(b []byte, wantID uint32) (done, info bool) {
	fs, err := pbFields(b)
	if err != nil {
		return
	}
	for _, f := range fs {
		switch f.num {
		case 2: // packet
			r.handleMeshPacket(f.data)
		case 3: // my_info
			sub, _ := pbFields(f.data)
			for _, s := range sub {
				if s.num == 1 {
					r.mu.Lock()
					r.nodeNum = uint32(s.v)
					r.info.NodeID = fmt.Sprintf("!%08x", uint32(s.v))
					r.mu.Unlock()
					info = true
				}
			}
		case 4: // node_info
			sub, _ := pbFields(f.data)
			var num uint32
			var long string
			var lat, lon float64
			var posTime int64
			for _, s := range sub {
				switch s.num {
				case 1:
					num = uint32(s.v)
				case 2:
					long = userLongName(s.data)
				case 3:
					lat, lon, posTime = parsePosition(s.data)
				}
			}
			r.mu.Lock()
			if num != 0 && num == r.nodeNum {
				if long != "" {
					r.info.LongName = long
				}
				if lat != 0 || lon != 0 {
					r.setGPS(lat, lon, posTime)
				}
			}
			isNew := false
			if num != 0 && num != r.nodeNum {
				_, known := r.nodes[num]
				if !known || (long != "" && r.nodes[num] == "") {
					r.setNode(num, long)
				}
				isNew = !known && r.cfgDone // nodes uit de lijst bij het verbinden zijn niet "nieuw"
			}
			cb := r.onNode
			r.mu.Unlock()
			if isNew && cb != nil {
				cb(num, long)
			}
		case 5: // config
			sub, _ := pbFields(f.data)
			for _, s := range sub {
				if s.num != 6 { // lora
					continue
				}
				lo, _ := pbFields(s.data)
				r.mu.Lock()
				r.txEnabled = false
				r.region = 0
				preset := uint64(0)
				for _, l := range lo {
					switch l.num {
					case 2:
						preset = l.v
					case 7:
						r.region = l.v
					case 8:
						if l.v > 0 && l.v <= 7 {
							r.hopLimit = uint32(l.v)
						}
					case 9:
						r.txEnabled = l.v != 0
					}
				}
				r.info.Region = mtRegions[r.region]
				if r.info.Region == "" {
					r.info.Region = fmt.Sprintf("code %d", r.region)
				}
				r.info.Preset = mtPresets[preset]
				r.mu.Unlock()
			}
		case 7: // config_complete_id
			if uint32(f.v) == wantID {
				done = true
			}
		case 8: // rebooted
			r.mu.Lock()
			if r.conn != nil {
				writeFrame(r.conn, encWantConfig(wantID))
			}
			r.mu.Unlock()
		case 10: // channel
			sub, _ := pbFields(f.data)
			ch := mtChannel{}
			for _, s := range sub {
				switch s.num {
				case 1:
					ch.Index = int(int32(s.v))
				case 2:
					cs, _ := pbFields(s.data)
					for _, c := range cs {
						if c.num == 3 {
							ch.Name = string(c.data)
						}
					}
				case 3:
					ch.Role = int(s.v)
				}
			}
			r.mu.Lock()
			repl := false
			for i := range r.info.Channels {
				if r.info.Channels[i].Index == ch.Index {
					r.info.Channels[i] = ch
					repl = true
				}
			}
			if !repl {
				r.info.Channels = append(r.info.Channels, ch)
			}
			if r.info.Connected {
				r.refreshCanSend()
			}
			r.mu.Unlock()
		case 11: // queueStatus
			sub, _ := pbFields(f.data)
			for _, s := range sub {
				if s.num == 2 {
					r.mu.Lock()
					r.queueFree = int(s.v)
					r.mu.Unlock()
				}
			}
		}
	}
	return
}

func (r *Radio) handleMeshPacket(b []byte) {
	fs, err := pbFields(b)
	if err != nil {
		return
	}
	var from uint32
	var rssi int32
	var snr float32
	var payload []byte
	var channel uint32
	port := uint64(0)
	for _, f := range fs {
		switch f.num {
		case 1:
			from = uint32(f.v)
		case 3:
			channel = uint32(f.v)
		case 4:
			ds, _ := pbFields(f.data)
			for _, d := range ds {
				if d.num == 1 {
					port = d.v
				}
				if d.num == 2 {
					payload = d.data
				}
			}
		case 8:
			snr = math.Float32frombits(uint32(f.v))
		case 12:
			rssi = int32(uint32(f.v))
		}
	}
	r.mu.Lock()
	mine := from == r.nodeNum
	if port == mtPortApp && !mine {
		r.info.RxCount++
		r.info.LastRx = time.Now().Unix()
	}
	if mine && port == mtPortPos {
		if lat, lon, ts := parsePosition(payload); lat != 0 || lon != 0 {
			r.setGPS(lat, lon, ts)
		}
	}
	newNode := false
	name := ""
	if !mine && from != 0 {
		if port == mtPortNode {
			name = userLongName(payload)
		}
		old, known := r.nodes[from]
		if !known || (name != "" && old != name) {
			r.setNode(from, name)
		} else {
			r.nodeSeen[from] = time.Now().Unix()
		}
		if name == "" {
			name = old
		}
		newNode = !known && r.cfgDone
	}
	cb, cbText, cbNode := r.onPacket, r.onText, r.onNode
	r.mu.Unlock()
	if newNode && cbNode != nil {
		cbNode(from, name)
	}
	if port == mtPortText && !mine && cbText != nil && len(payload) > 0 {
		cbText(from, name, string(payload), rssi, snr, channel)
	}
	if port == mtPortApp && !mine && cb != nil && len(payload) > 0 {
		cb(payload, from, rssi, snr)
	}
}

// setGPS (onder r.mu)
func (r *Radio) setGPS(lat, lon float64, ts int64) {
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return
	}
	if ts == 0 || ts > time.Now().Unix()+3600 {
		ts = time.Now().Unix()
	}
	r.gpsLat, r.gpsLon, r.gpsTS = lat, lon, ts
}

// parsePosition leest Position (latitude_i, longitude_i als sfixed32 in 1e-7 graden, time).
func parsePosition(b []byte) (lat, lon float64, ts int64) {
	fs, _ := pbFields(b)
	for _, f := range fs {
		switch f.num {
		case 1:
			if f.typ == protowire.Fixed32Type {
				lat = float64(int32(uint32(f.v))) / 1e7
			}
		case 2:
			if f.typ == protowire.Fixed32Type {
				lon = float64(int32(uint32(f.v))) / 1e7
			}
		case 4:
			ts = int64(uint32(f.v))
		}
	}
	return
}

// userLongName leest User.long_name.
func userLongName(b []byte) string {
	us, _ := pbFields(b)
	for _, u := range us {
		if u.num == 2 && u.typ == protowire.BytesType {
			return string(u.data)
		}
	}
	return ""
}
