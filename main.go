// AEROCX | Blackout – peer-to-peer berichten over wifi in huis, internet (Starlink of een gewone
// provider) en radio.
// Elke computer met AEROCX | Blackout is een volwaardig knooppunt: geen centrale server.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui.html assets
var uiFS embed.FS

var b64 = base64.RawURLEncoding

// version is overschrijfbaar met -ldflags "-X main.version=…".
var version = "1.2.1"

const (
	appID      = "aerocx-blackout"
	mcastGroup = "239.255.47.47:47475"
	maxBody    = 600 // tekens (runes) per bericht
	onlineSecs = 50
	cardPrefix = "AEROCX-BLACKOUT:"
	schemaV    = 2
)

// ---------- datamodel ----------

type Card struct {
	N  string   `json:"n"`  // naam
	E  string   `json:"e"`  // ed25519 publieke sleutel (identiteit)
	X  string   `json:"x"`  // x25519 publieke sleutel (versleuteling)
	A  []string `json:"a"`  // adressen "[ip]:poort"
	TS int64    `json:"ts"` // versie
	S  string   `json:"s,omitempty"`
}

func (c *Card) signBytes() []byte {
	return []byte("aerocx-blackout-card|" + c.N + "|" + c.E + "|" + c.X + "|" + strings.Join(c.A, ",") + "|" + strconv.FormatInt(c.TS, 10))
}

func (c *Card) Verify() bool {
	pub, err := b64.DecodeString(c.E)
	if err != nil || len(pub) != 32 {
		return false
	}
	x, err := b64.DecodeString(c.X)
	if err != nil || len(x) != 32 {
		return false
	}
	sig, err := b64.DecodeString(c.S)
	if err != nil || len(c.A) > 16 || len(c.N) > 64 {
		return false
	}
	return ed25519.Verify(pub, c.signBytes(), sig)
}

// cardText is de lange (v1) code. Blijft werken, maar de getoonde code is cardCode (AXB2:).
func cardText(c Card) string {
	j, _ := json.Marshal(c)
	return cardPrefix + b64.EncodeToString(j)
}

// parseCardText leest elke soort code (v1, AXB2:, AXB2I:) en geeft alleen de kaart terug.
func parseCardText(s string) (Card, error) {
	c, _, err := parseAnyCode(s)
	return c, err
}

// parseAnyCode leest een v1-code, een AXB2-code of een uitnodiging (AXB2I).
func parseAnyCode(s string) (Card, *inviteRef, error) {
	var c Card
	s = strings.Join(strings.Fields(s), "")
	if i := strings.Index(s, inviteV2Prefix); i >= 0 {
		return parseInviteCode(s[i+len(inviteV2Prefix):])
	}
	if i := strings.Index(s, codeV2Prefix); i >= 0 {
		c, err := parseCodeV2(s[i+len(codeV2Prefix):])
		return c, nil, err
	}
	i := strings.Index(s, cardPrefix)
	if i < 0 {
		return c, nil, errors.New("Dit is geen AEROCX Blackout-code")
	}
	raw, err := b64.DecodeString(s[i+len(cardPrefix):])
	if err != nil {
		return c, nil, errors.New("De code is beschadigd (niet volledig gekopieerd?)")
	}
	if err := json.Unmarshal(raw, &c); err != nil || !c.Verify() {
		return c, nil, errors.New("De code is ongeldig of beschadigd")
	}
	return c, nil, nil
}

// Pos is een positie. TS in seconden (intern); de API geeft milliseconden.
type Pos struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
	TS  int64   `json:"ts,omitempty"`
	Src string  `json:"src,omitempty"`
}

func (p *Pos) valid() bool {
	return p != nil && p.Lat >= -90 && p.Lat <= 90 && p.Lon >= -180 && p.Lon <= 180 && !(p.Lat == 0 && p.Lon == 0)
}

type Contact struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Card     Card             `json:"card"`
	Observed map[string]int64 `json:"observed"`
	LastSeen int64            `json:"last_seen"`
	Via      string           `json:"via"` // "lan", "star" (oud: "direct"), "relay:<id>"
	Unread   int              `json:"unread"`
	// radio (LoRa)
	RadioSeen int64   `json:"radio_seen,omitempty"`
	RadioRSSI int32   `json:"radio_rssi,omitempty"`
	RadioSNR  float32 `json:"radio_snr,omitempty"`
	// v1.2
	Role         string `json:"role,omitempty"` // beheerder | lid | lezer (leeg = lid)
	Blocked      bool   `json:"blocked,omitempty"`
	IntroducedBy string `json:"introduced_by,omitempty"`
	Pos          *Pos   `json:"pos,omitempty"`
	PeerVer      string `json:"peer_ver,omitempty"`
	PeerRadio    bool   `json:"peer_radio,omitempty"`
	PeerBridge   bool   `json:"peer_bridge,omitempty"`
	Invite       string `json:"invite,omitempty"` // uitnodigings-ID dat ik meestuur tot de ander antwoordt
	BridgeSeen   int64  `json:"bridge_seen,omitempty"`
	BridgeVia    string `json:"bridge_via,omitempty"`
	Added        int64  `json:"added,omitempty"`
	SendsTS      bool   `json:"sends_ts,omitempty"` // stuurt een verzendtijdstip mee (nieuwer dan v1.1)
	// vers of afgespeeld zonder klokvergelijking (clock.go)
	Boots      map[string]*bootMark `json:"boots,omitempty"`     // opstart-ID -> hoogwatermerk
	Boot       string               `json:"boot,omitempty"`      // opstart-ID van de laatste verse ping
	Skews      []int64              `json:"skews,omitempty"`     // klokverschil (ms), laatste metingen
	SkewAt     int64                `json:"skew_at,omitempty"`   // s
	RadioOff   int64                `json:"radio_off,omitempty"` // klokverschil uit het radiobaken (ms)
	RadioOffAt int64                `json:"radio_off_at,omitempty"`
	BeaconHi   map[string]int64     `json:"beacon_hi,omitempty"` // opstart (hex, 16 bits) -> hoogste teller; "" = v1.1 (tijd)
	MaxTS      int64                `json:"max_ts,omitempty"`    // hoogste afzendertijd ooit (ms), over opstarts en radio heen
}

type Pending struct {
	Card   Card   `json:"card"`
	Source string `json:"source"`
	Seen   int64  `json:"seen"`
	Note   string `json:"note,omitempty"`
	Prefix string `json:"prefix,omitempty"` // bron-IP (IPv6: /64), voor de limiet per bron
}

type Message struct {
	ID     string          `json:"id"`
	Conv   string          `json:"conv"` // "alle", contact-ID of "g:<groep>"
	From   string          `json:"from"` // "me", contact-ID of "" (systeembericht)
	Body   string          `json:"body"`
	TS     int64           `json:"ts"`
	Recips map[string]bool `json:"recips,omitempty"` // eigen berichten: ontvanger -> bevestigd
	Via    string          `json:"via,omitempty"`    // star | lan | radio | bridge | relay
	// v1.2
	Sos     bool   `json:"sos,omitempty"`
	SosEnd  bool   `json:"sos_end,omitempty"`
	SA      string `json:"sa,omitempty"` // bevestiging van SOS met dit ID
	Osint   bool   `json:"osint,omitempty"`
	Sys     bool   `json:"sys,omitempty"`
	Img     string `json:"img,omitempty"`
	ImgSt   string `json:"img_st,omitempty"` // ok | bezig | mislukt
	ImgSize int    `json:"img_size,omitempty"`
}

type Policy struct {
	AutoLan    bool  `json:"autoLan"`
	KeepDays   int   `json:"keepDays"`
	OpenGroups bool  `json:"openGroups"`
	KeyRot     int64 `json:"keyRot"`
	// v1.2.1: standaard aan (dus "uit" bewaren, zodat oude bestanden aan blijven)
	StunOff    bool `json:"stunOff,omitempty"`
	PortmapOff bool `json:"portmapOff,omitempty"`
}

type State struct {
	EdSeed     string              `json:"ed_seed"`
	XPriv      string              `json:"x_priv"`
	Name       string              `json:"name"`
	CardTS     int64               `json:"card_ts"`
	Pin        string              `json:"pin"`
	Token      string              `json:"token,omitempty"` // v1.1: één gedeelde sessie (wordt omgezet)
	AlleUnread int                 `json:"alle_unread"`
	Contacts   map[string]*Contact `json:"contacts"`
	Pending    map[string]*Pending `json:"pending"`
	Messages   []*Message          `json:"messages"`
	// radio
	RadioMode    string `json:"radio_mode,omitempty"` // "" of "auto" = USB automatisch, "tcp", "off"
	RadioTarget  string `json:"radio_target,omitempty"`
	RadioChannel *int   `json:"radio_channel,omitempty"`
	// v1.2
	Schema      int                        `json:"schema,omitempty"`
	Groups      map[string]*Group          `json:"groups,omitempty"`
	Left        map[string]int64           `json:"left,omitempty"`    // groepen die ik verliet
	Removed     map[string]int64           `json:"removed,omitempty"` // verwijderde contacten
	Perms       map[string]map[string]bool `json:"perms,omitempty"`
	Policy      Policy                     `json:"policy"`
	Sessions    map[string]*Session        `json:"sessions,omitempty"` // token -> toestel
	Invites     []*Invite                  `json:"invites,omitempty"`
	Audit       []AuditEntry               `json:"audit,omitempty"`
	Sos         *SosState                  `json:"sos,omitempty"`
	IncomingSos []*IncomingSos             `json:"incoming_sos,omitempty"`
	Loc         *Pos                       `json:"loc,omitempty"` // vaste locatie
	Share       bool                       `json:"share"`
	Bridge      bool                       `json:"bridge"`
	BackupLast  int64                      `json:"backup_last,omitempty"`
}

// ---------- knooppunt ----------

type Node struct {
	mu       sync.Mutex
	st       *State
	dir      string
	path     string
	udpPort  int
	uiPort   int
	loopback bool
	edPriv   ed25519.PrivateKey
	edPub    ed25519.PublicKey
	myID     string
	xPriv    *ecdh.PrivateKey
	keys     map[string]cipher.AEAD
	keyX     map[string]string
	socks    map[string]*net.UDPConn
	sockInfo map[string]ifAddr // socketsleutel -> adres en interface
	myAddrs  []string
	locAddrs []string                    // eigen adressen (zonder publieke adressen uit STUN/router)
	reach    map[string]map[string]int64 // doel -> tussenpersoon -> tijd
	lastTry  map[string]int64
	lastPing map[string]int64
	seenMsg  map[string]int64 // sleutel -> vervaltijd (s), zie seen.go
	relayCnt map[string]int
	dropFrom map[string]bool // alleen voor testen
	dirty    bool
	kick     chan struct{}
	quit     chan struct{}

	radio     *Radio
	frags     map[string]*fragBuf
	loraAcked map[string]int64
	loraLast  map[string]int64
	loraTries map[string]int
	loraWait  int64 // seconden voor radio als terugval (standaard 15)
	loraScale int64 // deler voor wachttijden (testen)

	// v1.2
	osint      *OSINT
	events     []LogEntry
	radioHeard map[string]map[string]int64 // doel -> brug -> tijd
	brLast     map[string]int64
	brTries    map[string]int
	brCount    map[string]int
	brSeen     map[string]int64
	grpParts   map[string]uint64 // eigenaar: groep|lid|versie -> ontvangen delen
	beaconSeq  uint16
	bootID     string // willekeurig per opstart (clock.go)
	hwmDirty   bool   // hoogwatermerken gewijzigd: binnen 5 s bewaren
	lastSave   time.Time
	pendMin    int64 // minuut van de teller nieuwe verzoeken
	pendNew    int
	tsLast     atomic.Int64 // laatst gebruikte verzendtijd (ms)
	mapClean   int64        // laatste opruimronde van de hulptabellen
	blobIn     map[string]*blobRx
	blobServe  map[string]int
	lastPos    *Pos
	sdr        bool
	autostart  bool

	seenDirty bool
	seenSaved time.Time

	// pincode raden (onder mu)
	pinFails     int
	pinLockUntil time.Time
	pinLockDur   time.Duration

	helloLim *rateLim

	// wifi en internet (netif.go, netstatus.go)
	mc        mcastState
	mcMu      sync.Mutex
	mcastPort int  // standaard 47475 (tests)
	noLAN     bool // (tests) geen multicast
	probeLast map[string]int64
	addrSig   string
	bindFail  map[string]bool
	nw        *netWatch
	quitOnce  sync.Once

	pingEvery   time.Duration
	outboxEvery time.Duration
	retryGap    int64
}

func now() int64 { return time.Now().Unix() }

func ms(t int64) int64 { return t * 1000 }

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func newPin() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%06d", (int(b[0])<<16|int(b[1])<<8|int(b[2]))%1000000)
}

func loadNode(dir string, udpPort, uiPort int, loopback bool) (*Node, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("kan de gegevensmap niet maken: %v", err)
	}
	n := &Node{
		dir: dir, path: filepath.Join(dir, "blackout.json"), udpPort: udpPort, uiPort: uiPort, loopback: loopback,
		keys: map[string]cipher.AEAD{}, keyX: map[string]string{}, socks: map[string]*net.UDPConn{}, sockInfo: map[string]ifAddr{},
		reach: map[string]map[string]int64{}, lastTry: map[string]int64{}, lastPing: map[string]int64{},
		seenMsg: map[string]int64{}, relayCnt: map[string]int{}, dropFrom: map[string]bool{},
		kick: make(chan struct{}, 1), quit: make(chan struct{}),
		radio: newRadio(), frags: map[string]*fragBuf{}, loraAcked: map[string]int64{},
		loraLast: map[string]int64{}, loraTries: map[string]int{}, loraWait: 15, loraScale: 1,
		radioHeard: map[string]map[string]int64{}, brLast: map[string]int64{}, brTries: map[string]int{},
		brCount: map[string]int{}, brSeen: map[string]int64{}, grpParts: map[string]uint64{}, bootID: newBootID(),
		blobIn: map[string]*blobRx{}, blobServe: map[string]int{},
		pingEvery: 15 * time.Second, outboxEvery: 3 * time.Second, retryGap: 8,
		helloLim: newRateLim(helloRate, helloSrcRate),
	}
	n.nw = newNetWatch()
	st := &State{}
	if raw, err := os.ReadFile(n.path); err == nil {
		if err := json.Unmarshal(raw, st); err != nil {
			return nil, fmt.Errorf("het gegevensbestand is beschadigd: %v", err)
		}
	}
	fresh := st.EdSeed == ""
	if fresh {
		seed := make([]byte, 32)
		rand.Read(seed)
		st.EdSeed = b64.EncodeToString(seed)
		xk, _ := ecdh.X25519().GenerateKey(rand.Reader)
		st.XPriv = b64.EncodeToString(xk.Bytes())
		host, _ := os.Hostname()
		host = strings.TrimSuffix(host, ".local")
		if host == "" {
			host = "Mijn computer"
		}
		host = truncBytes(host, 40)
		st.Name = host
		n.dirty = true
	}
	if st.Pin == "" {
		st.Pin = newPin()
		n.dirty = true
	}
	n.st = st
	n.migrate(fresh)
	if err := n.applyIdentity(); err != nil {
		return nil, err
	}
	n.loadSeen()
	for _, m := range st.Messages {
		if m.From != "me" && m.From != "" {
			n.seenMsg[m.From+"|"+m.ID] = now() + seenKeep
		}
	}
	n.pruneSeen()
	n.osint = newOSINT(dir)
	return n, nil
}

// migrate vult nieuwe velden in voor een bestand van v1.1 (of een nieuw bestand).
func (n *Node) migrate(fresh bool) {
	st := n.st
	if st.Contacts == nil {
		st.Contacts = map[string]*Contact{}
	}
	if st.Pending == nil {
		st.Pending = map[string]*Pending{}
	}
	if st.Groups == nil {
		st.Groups = map[string]*Group{}
	}
	if st.Left == nil {
		st.Left = map[string]int64{}
	}
	if st.Removed == nil {
		st.Removed = map[string]int64{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*Session{}
	}
	for _, c := range st.Contacts {
		if c.Observed == nil {
			c.Observed = map[string]int64{}
		}
		if c.Role == "" {
			c.Role = "lid"
		}
		if c.Via == "direct" {
			c.Via = "star"
		}
	}
	for _, g := range st.Groups {
		if g.Roles == nil {
			g.Roles = map[string]string{}
		}
		if g.Acked == nil {
			g.Acked = map[string]int64{}
		}
	}
	if st.Perms == nil {
		st.Perms = defaultPerms()
	}
	for r, def := range defaultPerms() {
		if st.Perms[r] == nil {
			st.Perms[r] = def
		}
	}
	if st.Schema < schemaV {
		// eerste start met v1.2: locatie delen staat uit tot de gebruiker het zelf aanzet
		st.Share = false
		st.Bridge = true
		if fresh {
			st.Policy.KeepDays = 30
		}
		if st.Policy.KeyRot == 0 {
			st.Policy.KeyRot = now()
		}
		if st.Token != "" { // v1.1: alle toestellen deelden één sleutel
			st.Sessions[st.Token] = &Session{ID: randHex(4), Name: "Eerder gekoppeld toestel", How: "pincode (v1.1)", Created: now(), Seen: now()}
			st.Token = ""
		}
		if fresh {
			st.Audit = append(st.Audit, n.signAudit(AuditEntry{T: now(), X: "Netwerk aangemaakt met jou als beheerder"}))
		} else {
			st.Audit = append(st.Audit, n.signAudit(AuditEntry{T: now(), X: "Bijgewerkt naar versie " + version}))
		}
		st.Schema = schemaV
		n.dirty = true
	}
}

// applyIdentity zet de sleutels uit de state klaar (bij laden en na herstel).
func (n *Node) applyIdentity() error {
	seed, err := b64.DecodeString(n.st.EdSeed)
	if err != nil || len(seed) != 32 {
		return errors.New("de sleutel in het gegevensbestand is beschadigd")
	}
	n.edPriv = ed25519.NewKeyFromSeed(seed)
	n.edPub = n.edPriv.Public().(ed25519.PublicKey)
	n.myID = b64.EncodeToString(n.edPub)
	xb, _ := b64.DecodeString(n.st.XPriv)
	n.xPriv, err = ecdh.X25519().NewPrivateKey(xb)
	if err != nil {
		return errors.New("de sleutel in het gegevensbestand is beschadigd")
	}
	n.keys = map[string]cipher.AEAD{}
	n.keyX = map[string]string{}
	return nil
}

func (n *Node) save() {
	n.saveSeen(false)
	n.mu.Lock()
	if n.hwmDirty && time.Since(n.lastSave) >= 5*time.Second {
		n.dirty = true // hoogwatermerken hooguit 5 s vertraagd bewaren
	}
	if !n.dirty {
		n.mu.Unlock()
		return
	}
	n.hwmDirty = false
	n.lastSave = time.Now()
	if len(n.st.Messages) > 5000 {
		n.st.Messages = n.st.Messages[len(n.st.Messages)-5000:]
	}
	raw, err := json.MarshalIndent(n.st, "", " ")
	n.dirty = false
	n.mu.Unlock()
	if err != nil {
		log.Printf("bewaren mislukt: %v", err)
		return
	}
	tmp := n.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("bewaren mislukt: %v", err)
		return
	}
	os.Rename(tmp, n.path)
}

func (n *Node) bumpCard() {
	t := now()
	if t <= n.st.CardTS {
		t = n.st.CardTS + 1
	}
	n.st.CardTS = t
	n.dirty = true
}

func (n *Node) myCard() Card {
	c := Card{N: n.st.Name, E: n.myID, X: b64.EncodeToString(n.xPriv.PublicKey().Bytes()), A: append([]string{}, n.myAddrs...), TS: n.st.CardTS}
	c.S = b64.EncodeToString(ed25519.Sign(n.edPriv, c.signBytes()))
	return c
}

// ---------- versleuteling ----------

func (n *Node) aeadX(x string) (cipher.AEAD, error) {
	raw, err := b64.DecodeString(x)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	sh, err := n.xPriv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	k := sha256.Sum256(append([]byte("aerocx-blackout-v1"), sh...))
	blk, _ := aes.NewCipher(k[:])
	return cipher.NewGCM(blk)
}

func (n *Node) aead(c *Contact) (cipher.AEAD, error) {
	if a, ok := n.keys[c.ID]; ok && n.keyX[c.ID] == c.Card.X {
		return a, nil
	}
	a, err := n.aeadX(c.Card.X)
	if err != nil {
		return nil, err
	}
	n.keys[c.ID] = a
	n.keyX[c.ID] = c.Card.X
	return a, nil
}

func (n *Node) header(t byte) []byte {
	h := make([]byte, 0, 1400)
	h = append(h, 'N', 'N', 1, t)
	return append(h, n.edPub...)
}

func (n *Node) seal(t byte, c *Contact, pt []byte) []byte {
	a, err := n.aead(c)
	if err != nil {
		return nil
	}
	h := n.header(t)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(h, nonce...)
	return a.Seal(out, nonce, pt, h[:36])
}

func (n *Node) open(c *Contact, pkt []byte) ([]byte, error) {
	if len(pkt) < 36+12+16 {
		return nil, errors.New("te kort")
	}
	a, err := n.aead(c)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, pkt[36:48], pkt[48:], pkt[:36])
}

// sealJSON versleutelt een payload voor c, met het verzendtijdstip (ms) erin.
func (n *Node) sealJSON(c *Contact, w wire) []byte {
	w.TS = n.sendClockMs()
	w.B = n.bootID
	j, _ := json.Marshal(w)
	return n.seal('E', c, j)
}

// ---------- netwerk ----------

func (n *Node) refreshAddrs() {
	list := listIfAddrs(n.loopback)
	want := map[string]ifAddr{}
	var order []string
	for _, a := range list {
		k := a.key()
		if _, ok := want[k]; !ok {
			want[k] = a
			order = append(order, k)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bindFail == nil {
		n.bindFail = map[string]bool{}
	}
	for k, conn := range n.socks {
		if a, ok := want[k]; !ok || a.Index != n.sockInfo[k].Index {
			conn.Close()
			delete(n.socks, k)
			delete(n.sockInfo, k)
		}
	}
	for _, k := range order {
		if _, ok := n.socks[k]; ok {
			n.sockInfo[k] = want[k]
			continue
		}
		a := want[k]
		network := "udp6"
		if a.v4() {
			network = "udp4"
		}
		conn, err := net.ListenUDP(network, a.udpAddr(n.udpPort))
		if err != nil {
			if !n.bindFail[k] {
				n.bindFail[k] = true
				log.Printf("kan niet luisteren op %s: %v", k, err)
			}
			continue
		}
		delete(n.bindFail, k)
		if a.v4() && !a.Loop {
			// multicast van deze socket via zijn eigen interface (werkt ook zonder standaardroute)
			rawSock(conn, func(fd uintptr) error { return sockMcastIf4(fd, a.IP) })
		}
		n.socks[k] = conn
		n.sockInfo[k] = a
		go n.readLoop(conn, false)
	}
	var addrs []string
	var sig []string
	for _, k := range order {
		if _, ok := n.socks[k]; !ok {
			continue
		}
		sig = append(sig, k+"/"+strconv.Itoa(want[k].Index))
		if !want[k].LL && len(addrs) < 8 {
			addrs = append(addrs, net.JoinHostPort(k, strconv.Itoa(n.udpPort)))
		}
	}
	n.locAddrs = addrs
	n.mcastRefresh(list)
	n.applyAddrs()
	if s := strings.Join(sig, ","); s != n.addrSig {
		first := n.addrSig == ""
		n.addrSig = s
		n.mcastHello() // meteen laten weten dat ik er (op een nieuw netwerk) ben
		if !first {
			n.event("netwerk", "Netwerk gewijzigd: verbindingen worden opnieuw gezocht")
			n.nw.kick() // publiek adres en router opnieuw bekijken
		}
	}
}

// applyAddrs (onder slot): de adressen in mijn kaart = eigen adressen + publieke adressen
// (STUN, poort op de router). Geeft true als de kaart wijzigde.
func (n *Node) applyAddrs() bool {
	addrs := append([]string{}, n.locAddrs...)
	for _, p := range n.nw.cardAddrs() {
		if len(addrs) >= 12 {
			break
		}
		if !contains(addrs, p) {
			addrs = append(addrs, p)
		}
	}
	if strings.Join(addrs, ",") != strings.Join(n.myAddrs, ",") {
		n.myAddrs = addrs
		n.bumpCard()
		log.Printf("mijn adressen: %v", addrs)
		return true
	}
	return false
}

// readLoop: mcast = de socket van de multicastgroep. Die socket ontvangt ook gewone unicast
// (poort 47475 op alle adressen), dus mcast is NOOIT een bewijs dat de afzender op het eigen
// netwerk zit; daarvoor telt alleen het bronadres (onLink).
func (n *Node) readLoop(conn *net.UDPConn, mcast bool) {
	buf := make([]byte, 65536)
	for {
		nr, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !mcast && isSTUN(buf[:nr]) {
			// antwoord van een STUN-server: nooit als pakket van een contact verwerken
			n.nw.onSTUN(buf[:nr], from, conn)
			continue
		}
		if mcast && n.mcastDup(buf[:nr]) {
			continue
		}
		pkt := make([]byte, nr)
		copy(pkt, buf[:nr])
		n.handle(pkt, from, mcast)
	}
}

func isLocalNet(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func (n *Node) destAddrs(c *Contact) []*net.UDPAddr {
	seen := map[string]bool{}
	var out []*net.UDPAddr
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		if a, err := net.ResolveUDPAddr("udp", s); err == nil && a.IP != nil {
			out = append(out, a)
		}
	}
	for _, a := range c.Card.A {
		add(a)
	}
	t := now()
	for a, ts := range c.Observed {
		if t-ts < 1800 {
			add(a)
		} else {
			delete(c.Observed, a)
		}
	}
	return out
}

// Verstuur vanaf ELK eigen adres naar ELK adres van de ander. Zo gaan de
// firewalls van beide routers voor elkaar open (UDP hole punching).
func (n *Node) writeAll(pkt []byte, dst *net.UDPAddr) {
	if pkt == nil {
		return
	}
	v4 := dst.IP.To4() != nil
	dstLL := dst.IP.IsLinkLocalUnicast()
	for _, conn := range n.socks {
		la := conn.LocalAddr().(*net.UDPAddr)
		if (la.IP.To4() != nil) != v4 {
			continue
		}
		if la.IP.IsLoopback() != dst.IP.IsLoopback() {
			continue
		}
		// link-local alleen vanaf link-local, en bij IPv6 vanaf dezelfde interface
		if la.IP.IsLinkLocalUnicast() != dstLL || (dstLL && !v4 && dst.Zone != "" && la.Zone != dst.Zone) {
			continue
		}
		conn.WriteToUDP(pkt, dst)
	}
}

func (n *Node) sendTo(c *Contact, pkt []byte) {
	if c == nil || c.Blocked || pkt == nil {
		return
	}
	for _, a := range n.destAddrs(c) {
		n.writeAll(pkt, a)
	}
}

func (n *Node) sendViaRelay(relay, target *Contact, inner []byte) {
	tp, err := b64.DecodeString(target.ID)
	if err != nil || inner == nil || relay.Blocked || target.Blocked {
		return
	}
	pt := append(append([]byte{}, tp...), inner...)
	n.sendTo(relay, n.seal('R', relay, pt))
}

// markSeen: c is rechtstreeks gehoord. Alleen een vers pakket (fresh) mag een nieuw adres toevoegen;
// een pakket zonder tijdstip (v1.1) ververst alleen adressen die al gekend zijn.
func (n *Node) markSeen(c *Contact, from *net.UDPAddr, fresh bool) {
	t := now()
	if t-c.LastSeen >= onlineSecs && c.LastSeen > 0 {
		n.event("contact", c.Name+" is weer online")
	}
	c.LastSeen = t
	a := from.String()
	if _, known := c.Observed[a]; fresh || known || contains(c.Card.A, a) {
		c.Observed[a] = t
	}
	if n.onLink(from.IP) {
		c.Via = "lan"
	} else {
		c.Via = "star"
	}
	if c.Invite != "" { // de uitnodiger antwoordt: uitnodiging is gebruikt
		c.Invite = ""
		n.dirty = true
	}
}

func (n *Node) updateCard(c *Contact, card Card) {
	if card.E != c.ID || card.TS <= c.Card.TS || !card.Verify() {
		return
	}
	c.Card = card
	n.dirty = true
}

// ipOnline: rechtstreeks (niet via een doorgever) bereikbaar over IP.
func (n *Node) ipOnline(c *Contact) bool {
	return c != nil && !c.Blocked && now()-c.LastSeen < onlineSecs && !strings.HasPrefix(c.Via, "relay")
}

func (n *Node) handle(pkt []byte, from *net.UDPAddr, mcast bool) {
	if len(pkt) < 36 || pkt[0] != 'N' || pkt[1] != 'N' || pkt[2] != 1 {
		return
	}
	t := pkt[3]
	fromID := b64.EncodeToString(pkt[4:36])
	if fromID == n.myID {
		return
	}
	if t == 'H' {
		n.handleHello(fromID, pkt[36:], from, mcast)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dropFrom[short(fromID)] && t != 'F' {
		return
	}
	if c := n.st.Contacts[fromID]; c != nil && c.Blocked {
		return // geblokkeerd: niets verwerken, niets doorgeven
	}
	switch t {
	case 'E':
		c := n.st.Contacts[fromID]
		if c == nil {
			return
		}
		pt, err := n.open(c, pkt)
		if err != nil {
			return
		}
		n.onPayload(c, pt, nil, func(fresh, legacy bool) string {
			if fresh || legacy {
				n.markSeen(c, from, fresh)
			}
			if n.onLink(from.IP) {
				return "lan"
			}
			return "star"
		})
	case 'D':
		c := n.st.Contacts[fromID]
		if c == nil {
			return
		}
		pt, err := n.open(c, pkt)
		if err != nil {
			return
		}
		n.onBlobChunk(c, pt) // geen tijdstip in fotostukken: geen adres bijwerken
	case 'L':
		c := n.st.Contacts[fromID]
		if c == nil {
			return
		}
		pt, err := n.open(c, pkt)
		if err != nil {
			return
		}
		n.onBridgeFrame(c, pt) // frames dragen hun eigen tijdstip; geen adres bijwerken
	case 'R':
		relayFor := n.st.Contacts[fromID]
		if relayFor == nil {
			return
		}
		pt, err := n.open(relayFor, pkt)
		if err != nil || len(pt) < 32+36 {
			return
		}
		target := n.st.Contacts[b64.EncodeToString(pt[:32])]
		if target == nil || target.Blocked {
			return
		}
		key := fromID + "|" + strconv.FormatInt(now()/60, 10)
		if n.relayCnt[key]++; n.relayCnt[key] > 120 {
			return
		}
		fwd := append(n.header('F'), pt[32:]...)
		n.sendTo(target, fwd)
	case 'F':
		relay := n.st.Contacts[fromID]
		inner := pkt[36:]
		if relay == nil || len(inner) < 36 || inner[0] != 'N' || inner[1] != 'N' || inner[3] != 'E' {
			return
		}
		origID := b64.EncodeToString(inner[4:36])
		orig := n.st.Contacts[origID]
		if orig == nil || origID == n.myID || orig.Blocked {
			return
		}
		pt, err := n.open(orig, inner)
		if err != nil {
			return
		}
		n.onPayload(orig, pt, relay, func(fresh, legacy bool) string {
			if fresh || legacy {
				orig.LastSeen = now()
				orig.Via = "relay:" + relay.ID
			}
			return "relay"
		})
	}
}

type imgMeta struct {
	ID   string `json:"id"`
	Size int    `json:"n"`
}

type wire struct {
	T     string   `json:"t"`
	Card  *Card    `json:"card,omitempty"`
	Seen  []string `json:"seen,omitempty"`
	ID    string   `json:"id,omitempty"`
	Ch    string   `json:"ch,omitempty"`
	Body  string   `json:"body,omitempty"`
	TS    int64    `json:"ts,omitempty"`
	Cards []Card   `json:"cards,omitempty"`
	// v1.2
	V      string   `json:"v,omitempty"`
	Pos    *Pos     `json:"pos,omitempty"`
	Radio  bool     `json:"radio,omitempty"`
	Bridge bool     `json:"bridge,omitempty"`
	RH     []string `json:"rh,omitempty"`
	Sos    bool     `json:"sos,omitempty"`
	SosEnd bool     `json:"se,omitempty"`
	SA     string   `json:"sa,omitempty"`
	Osint  bool     `json:"osint,omitempty"`
	Img    *imgMeta `json:"img,omitempty"`
	Grp    *grpWire `json:"grp,omitempty"`
	Ver    int64    `json:"ver,omitempty"`
	Part   int      `json:"part,omitempty"`
	Parts  int      `json:"parts,omitempty"`
	Miss   []int    `json:"miss,omitempty"`
	B      string   `json:"b,omitempty"` // opstart-ID van de afzender (clock.go)
}

// onPayload verwerkt een ontsleutelde payload. seen wordt aangeroepen nadat het tijdstip
// beoordeeld is (fresh: hoger dan het hoogwatermerk van die opstart; legacy: zonder tijdstip, v1.1)
// en geeft de weg terug. Er wordt niet vergeleken met de eigen klok (zie clock.go).
func (n *Node) onPayload(c *Contact, pt []byte, relay *Contact, seen func(fresh, legacy bool) string) {
	var m wire
	if json.Unmarshal(pt, &m) != nil {
		return
	}
	legacy := m.TS == 0
	fresh := false
	if legacy {
		if c.SendsTS {
			return // dit contact stuurt altijd een tijdstip mee: dit is een oud, opnieuw afgespeeld pakket
		}
	} else {
		ts := m.TS
		if ts < 1e11 { // seconden (ouder formaat)
			ts *= 1000
		}
		switch m.T {
		case "msg", "grp", "grpleave", "grpreq":
			if n.tooOld(c, ts, m.B) {
				return // ouder dan 8 dagen (afzenderklok): opgenomen en opnieuw afgespeeld
			}
		}
		fresh = n.peerTS(c, ts, m.B)
		if fresh && (m.T == "ping" || m.T == "pong") && m.TS >= 1e11 {
			n.sampleSkew(c, ts, m.B)
		}
		if m.TS >= 1e11 && !c.SendsTS {
			c.SendsTS = true
			n.dirty = true
		}
	}
	via := seen(fresh, legacy)
	t := now()
	reply := func(w wire) {
		p := n.sealJSON(c, w)
		n.sendTo(c, p)
		if relay != nil {
			n.sendViaRelay(relay, c, p)
		}
	}
	switch m.T {
	case "ping", "pong":
		if !fresh && !legacy {
			return // oude ping (opnieuw afgespeeld of klok verschoven): geen status of positie overnemen
		}
		if m.Card != nil {
			n.updateCard(c, *m.Card)
		}
		n.onPeerInfo(c, &m)
		for _, s := range m.Seen {
			for id := range n.st.Contacts {
				if id != c.ID && strings.HasPrefix(id, s) {
					if n.reach[id] == nil {
						n.reach[id] = map[string]int64{}
					}
					n.reach[id][c.ID] = t
				}
			}
		}
		if m.T == "ping" && relay == nil && t-n.lastPing[c.ID] >= 3 {
			n.lastPing[c.ID] = t
			n.sendTo(c, n.sealJSON(c, n.pingWire("pong")))
		}
	case "msg":
		if m.Sos && m.Pos.valid() {
			p := *m.Pos
			p.TS = t
			c.Pos = &p
		}
		in := inMsg{ID: m.ID, Ch: m.Ch, Body: m.Body, Sos: m.Sos, SosEnd: m.SosEnd, SA: m.SA, Osint: m.Osint, Img: m.Img, Via: via}
		if n.deliverMsg(c, in) {
			reply(wire{T: "ack", ID: m.ID})
		}
	case "ack":
		n.markAcked(c, m.ID, via)
	case "cards":
		for _, card := range m.Cards {
			if oc := n.st.Contacts[card.E]; oc != nil {
				n.updateCard(oc, card)
			}
		}
	case "grp":
		n.onGroupCard(c, &m, reply)
	case "grpack":
		n.onGroupAck(c, &m)
	case "grpleave":
		n.onGroupLeave(c, &m, reply)
	case "grpleft":
		n.onGroupLeft(c, &m)
	case "grpreq":
		n.onGroupRequest(c, &m)
	case "blobget":
		n.onBlobGet(c, &m)
	}
}

// onPeerInfo verwerkt de v1.2-velden uit een ping/pong.
func (n *Node) onPeerInfo(c *Contact, m *wire) {
	t := now()
	if m.V != "" {
		c.PeerVer = m.V
	} else {
		c.PeerVer = "1.1"
	}
	c.PeerRadio = m.Radio
	c.PeerBridge = m.Bridge
	if m.Pos.valid() {
		p := *m.Pos
		p.TS = t
		if p.Src == "" {
			p.Src = "gedeeld"
		}
		c.Pos = &p
	} else if m.V != "" && c.Pos != nil && t-c.RadioSeen > 1800 {
		c.Pos = nil // deelt zijn locatie niet (meer)
	}
	for _, s := range m.RH {
		for id := range n.st.Contacts {
			if id != c.ID && strings.HasPrefix(id, s) {
				if n.radioHeard[id] == nil {
					n.radioHeard[id] = map[string]int64{}
				}
				n.radioHeard[id][c.ID] = t
			}
		}
	}
}

type inMsg struct {
	ID, Ch, Body string
	Sos, SosEnd  bool
	SA           string
	Osint        bool
	Img          *imgMeta
	Via          string
}

const (
	sosSeenText = "Ik heb je SOS gezien."
	sosEndText  = "SOS beëindigd"
)

// deliverMsg bewaart een ontvangen bericht (eenmalig). Geeft true als het bevestigd mag worden.
// false = (nog) niet bevestigen, bv. omdat de groepskaart nog niet binnen is.
func (n *Node) deliverMsg(c *Contact, in inMsg) bool {
	if in.ID == "" || c.Blocked {
		return false
	}
	key := c.ID + "|" + in.ID
	if n.isSeen(key) {
		return true
	}
	in.Body = truncRunes(in.Body, maxBody)
	// SOS en einde-SOS ook herkennen als ze als gewone tekst (radio, v1.1) binnenkomen
	if !in.Sos && !in.SosEnd && in.Ch == "alle" && strings.HasPrefix(in.Body, sosEndText) {
		in.SosEnd = true
	}
	if in.SA == "" && in.Ch != "alle" && in.Body == sosSeenText && n.st.Sos != nil {
		in.SA = n.st.Sos.ID
	}
	ignore := func(why string) bool {
		n.markSeenKey(key)
		n.event("bericht", fmt.Sprintf("Bericht van %s genegeerd (%s)", c.Name, why))
		return true
	}
	if in.Sos && !n.can(c, "sos") {
		in.Sos = false
	}
	if in.Osint && !n.can(c, "osint") {
		return ignore("mag geen OSINT delen")
	}
	conv := c.ID
	var g *Group
	switch {
	case in.Ch == "alle":
		if !in.Sos && !in.SosEnd && !n.can(c, "alle") {
			return ignore("mag niet naar Iedereen sturen")
		}
		conv = "alle"
	case strings.HasPrefix(in.Ch, "g:"):
		g = n.st.Groups[in.Ch[2:]]
		if g == nil || g.Deleted {
			if n.st.Left[in.Ch[2:]] > 0 {
				return ignore("groep verlaten")
			}
			return false // groepskaart nog niet binnen: later opnieuw
		}
		if !g.has(c.ID) {
			return ignore("geen lid van " + g.Name)
		}
		if g.role(c.ID) == "lezer" {
			return ignore("lezer in " + g.Name)
		}
		if !n.can(c, "send") {
			return ignore("mag geen berichten sturen")
		}
		conv = "g:" + g.ID
	default:
		if !n.can(c, "send") && in.SA == "" {
			return ignore("mag geen berichten sturen")
		}
	}
	n.markSeenKey(key)
	msg := &Message{ID: in.ID, Conv: conv, From: c.ID, Body: in.Body, TS: now(), Via: in.Via, Sos: in.Sos, SosEnd: in.SosEnd, SA: in.SA, Osint: in.Osint}
	if in.Img != nil && validBlobID(in.Img.ID) && in.Img.Size > 0 && in.Img.Size <= maxBlob {
		msg.Img, msg.ImgSize = in.Img.ID, in.Img.Size
		msg.ImgSt = n.startBlobFetch(c, in.Img.ID, in.Img.Size)
	}
	n.st.Messages = append(n.st.Messages, msg)
	switch {
	case conv == "alle":
		n.st.AlleUnread++
	case g != nil:
		g.Unread++
	default:
		c.Unread++
	}
	if in.Sos {
		n.addIncomingSos(c, msg)
	}
	if in.SosEnd {
		n.clearIncomingSos(c.ID)
	}
	if in.SA != "" && n.st.Sos != nil && n.st.Sos.ID == in.SA {
		if _, ok := n.st.Sos.Acks[c.ID]; !ok {
			n.st.Sos.Acks[c.ID] = now()
			n.event("sos", c.Name+" heeft je SOS gezien")
		}
	}
	n.dirty = true
	what := "Bericht"
	if in.Sos {
		what = "SOS"
	}
	n.event(eventKind(in.Via, in.Sos), fmt.Sprintf("%s van %s%s", what, c.Name, viaText(in.Via)))
	return true
}

func eventKind(via string, sos bool) string {
	if sos {
		return "sos"
	}
	switch via {
	case "radio":
		return "radio"
	case "bridge":
		return "brug"
	}
	return "bericht"
}

func viaText(via string) string {
	switch via {
	case "star":
		return " via internet"
	case "lan":
		return " via wifi"
	case "radio":
		return " via radio"
	case "bridge":
		return " via brug"
	case "relay":
		return " (doorgegeven)"
	}
	return ""
}

// markAcked: geeft true als dit een nieuwe bevestiging was.
func (n *Node) markAcked(c *Contact, id, via string) bool {
	for i := len(n.st.Messages) - 1; i >= 0 && i >= len(n.st.Messages)-3000; i-- {
		msg := n.st.Messages[i]
		if msg.From == "me" && msg.ID == id {
			if acked, ok := msg.Recips[c.ID]; ok && !acked {
				msg.Recips[c.ID] = true
				if via != "" {
					msg.Via = via
				}
				n.dirty = true
				n.radio.Drop(id + "|" + c.ID)
				return true
			}
			return false
		}
	}
	return false
}

func (n *Node) pingWire(t string) wire {
	card := n.myCard()
	w := wire{T: t, Card: &card, V: version}
	tn := now()
	for id, c := range n.st.Contacts {
		if tn-c.LastSeen < 60 && !strings.HasPrefix(c.Via, "relay") && !c.Blocked {
			w.Seen = append(w.Seen, short(id))
		}
		if tn-c.RadioSeen < 1200 && !c.Blocked {
			w.RH = append(w.RH, short(id))
		}
	}
	if n.st.Share {
		if p := n.myPos(); p != nil {
			w.Pos = &Pos{Lat: p.Lat, Lon: p.Lon, Src: p.Src}
		}
	}
	w.Radio = n.radio.Ready()
	w.Bridge = w.Radio && n.st.Bridge
	return w
}

type helloMsg struct {
	Card
	Inv string `json:"inv,omitempty"`
}

func (n *Node) helloPkt() []byte {
	j, _ := json.Marshal(n.myCard())
	return append(n.header('H'), j...)
}

// helloFor is de hello voor één contact; met een openstaande uitnodiging gaat het ID versleuteld mee.
func (n *Node) helloFor(c *Contact) []byte {
	if c.Invite == "" {
		return n.helloPkt()
	}
	h := helloMsg{Card: n.myCard()}
	if a, err := n.aead(c); err == nil {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		id, _ := hex.DecodeString(c.Invite)
		h.Inv = b64.EncodeToString(a.Seal(nonce, nonce, id, []byte("aerocx-blackout-invite")))
	}
	j, _ := json.Marshal(h)
	return append(n.header('H'), j...)
}

// handleHello: de handtekening van een hello wordt BUITEN het globale slot gecontroleerd en
// hello's worden afgeremd per bron-prefix en globaal (tegen CPU-verbruik door vreemden).
func (n *Node) handleHello(fromID string, raw []byte, from *net.UDPAddr, mcast bool) {
	if len(raw) > 8192 {
		return
	}
	n.mu.Lock()
	c := n.st.Contacts[fromID]
	skip := n.dropFrom[short(fromID)] || (c != nil && c.Blocked)
	var knownTS int64
	if c != nil {
		knownTS = c.Card.TS
		if mcast && !skip && n.onLink(from.IP) {
			n.lanProbe(c, from) // bekend contact op het eigen netwerk: adres rechtstreeks leren
		}
	}
	n.mu.Unlock()
	if skip {
		return
	}
	var h helloMsg
	if json.Unmarshal(raw, &h) != nil || h.Card.E != fromID {
		return
	}
	if c != nil && h.Card.TS <= knownTS {
		return // niets nieuws: geen handtekening controleren
	}
	if !n.helloLim.allow(srcPrefix(from.IP)) {
		return
	}
	if !h.Card.Verify() {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onHello(fromID, h, from)
}

// onHello (onder slot): een hello met een geldige (al gecontroleerde) kaart.
func (n *Node) onHello(fromID string, h helloMsg, from *net.UDPAddr) {
	card := h.Card
	if c := n.st.Contacts[fromID]; c != nil {
		if !c.Blocked && card.TS > c.Card.TS {
			c.Card = card
			n.dirty = true
		}
		return
	}
	if h.Inv != "" && n.tryInvite(card, h.Inv) {
		return
	}
	source := "internet"
	if n.onLink(from.IP) { // bronadres op een eigen netwerk; de socket zegt niets (zie readLoop)
		source = "lan"
	}
	if source == "lan" && n.st.Policy.AutoLan && n.st.Removed[fromID] == 0 {
		c := n.addContact(card, "", "lid", "")
		n.audit(fmt.Sprintf("%s vanzelf toegelaten (zelfde wifi-netwerk)", c.Name))
		return
	}
	p, isNew := n.addPending(card, source, srcPrefix(from.IP))
	if p == nil {
		return // te veel nieuwe verzoeken deze minuut
	}
	if isNew {
		n.event("contact", card.N+" wil contact maken")
	}
	if p.Source == "groep" && !isNew {
		return // voorgesteld via een groep: die uitleg blijft staan
	}
	p.Source = source
	p.Prefix = srcPrefix(from.IP)
	if source == "lan" {
		p.Note = "zelfde wifi-netwerk"
	} else {
		p.Note = "via internet"
	}
	if h.Inv != "" {
		p.Note = "uitnodiging ongeldig, verlopen of al gebruikt"
	}
	if n.st.Removed[fromID] > 0 {
		p.Note += " · eerder verwijderd"
	}
	n.dirty = true
}

// addContact voegt een kaart toe (of werkt hem bij) en begroet meteen.
func (n *Node) addContact(card Card, name, role, introducedBy string) *Contact {
	c := n.st.Contacts[card.E]
	if c == nil {
		c = &Contact{ID: card.E, Card: card, Observed: map[string]int64{}, Name: card.N, Role: "lid", Added: now()}
		if introducedBy != "" {
			c.IntroducedBy = introducedBy
		}
		n.st.Contacts[card.E] = c
		n.event("contact", c.Name+" toegevoegd")
	} else {
		n.updateCard(c, card)
	}
	if name != "" {
		c.Name = name
	}
	if c.Name == "" {
		c.Name = "Naamloos"
	}
	if role != "" {
		c.Role = role
	}
	delete(n.st.Pending, card.E)
	delete(n.st.Removed, card.E)
	n.dirty = true
	// meteen begroeten zodat de firewalls opengaan
	n.sendTo(c, n.helloFor(c))
	n.sendTo(c, n.sealJSON(c, n.pingWire("ping")))
	return c
}

// ---------- vaste rondes ----------

func (n *Node) pingTick(round int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := now()
	for _, c := range n.st.Contacts {
		if c.Blocked {
			continue
		}
		n.lastPing[c.ID] = t
		n.sendTo(c, n.sealJSON(c, n.pingWire("ping")))
		if t-c.LastSeen > 60 || c.Invite != "" {
			n.sendTo(c, n.helloFor(c))
		}
		if round%4 == 0 { // adreskaarten van anderen doorgeven
			for _, o := range n.st.Contacts {
				if o.ID != c.ID && !o.Blocked {
					n.sendTo(c, n.sealJSON(c, wire{T: "cards", Cards: []Card{o.Card}}))
				}
			}
		}
	}
	n.groupTick()
	n.leaveTick()
}

func (n *Node) outboxTick() {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := now()
	radioReady := n.radio.Ready()
	start := len(n.st.Messages) - 2000
	if start < 0 {
		start = 0
	}
	for _, m := range n.st.Messages[start:] {
		if m.From != "me" || t-m.TS > 7*86400 {
			continue
		}
		var inner []byte
		for rid, acked := range m.Recips {
			c := n.st.Contacts[rid]
			if acked || c == nil || c.Blocked {
				continue
			}
			key := m.ID + "|" + rid
			if t-n.lastTry[key] < n.retryGap {
				continue
			}
			n.lastTry[key] = t
			inner = n.sealJSON(c, n.msgWire(m))
			n.sendTo(c, inner)
			if t-m.TS >= 10 || t-c.LastSeen > onlineSecs {
				for peer, pt := range n.reach[rid] {
					pc := n.st.Contacts[peer]
					if pc == nil || t-pt > 150 || t-pc.LastSeen > onlineSecs {
						continue
					}
					n.sendViaRelay(pc, c, inner)
				}
			}
		}
		// radio (eigen radio of een brug) als terugval: alleen voor wie niet over IP online is
		for rid, acked := range m.Recips {
			c := n.st.Contacts[rid]
			if acked || c == nil || c.Blocked {
				continue
			}
			wait := n.loraWait
			if m.Sos {
				wait = 5 / n.loraScale
			}
			if n.ipOnline(c) && !(m.Sos && t-m.TS >= wait) {
				continue
			}
			if !m.Sos && t-m.TS < wait {
				continue
			}
			br := n.pickBridge(c)
			ownHeard := t-c.RadioSeen < 1800
			key := m.ID + "|" + rid
			switch {
			case radioReady && (ownHeard || br == nil):
				if t-n.loraLast[key] < loraBackoff(n.loraTries[key])/n.loraScale {
					continue
				}
				n.loraLast[key] = t
				n.loraTries[key]++
				n.loraSendMsg(c, m)
			case br != nil:
				if t-n.brLast[key] < loraBackoff(n.brTries[key])/n.loraScale {
					continue
				}
				n.brLast[key] = t
				n.brTries[key]++
				for _, f := range n.loraFrames(c, m) {
					n.sendL(br, f)
				}
				if n.brTries[key] == 1 {
					n.event("brug", fmt.Sprintf("Bericht voor %s via brug bij %s", c.Name, br.Name))
				}
			}
		}
	}
}

func (n *Node) msgWire(m *Message) wire {
	ch := "dm"
	if m.Conv == "alle" || strings.HasPrefix(m.Conv, "g:") {
		ch = m.Conv
	}
	w := wire{T: "msg", ID: m.ID, Ch: ch, Body: m.Body, Sos: m.Sos, SosEnd: m.SosEnd, SA: m.SA, Osint: m.Osint}
	if m.Img != "" {
		w.Img = &imgMeta{ID: m.Img, Size: m.ImgSize}
	}
	if m.Sos && n.st.Share {
		if p := n.myPos(); p != nil {
			w.Pos = &Pos{Lat: p.Lat, Lon: p.Lon, Src: p.Src}
		}
	}
	return w
}

// stop: netjes stoppen (scherm, Ctrl+C of afmelden).
func (n *Node) stop() { n.quitOnce.Do(func() { close(n.quit) }) }

func (n *Node) kickOutbox() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

// startLAN: elke 10 s een hello per interface naar de multicastgroep (zie netif.go).
func (n *Node) startLAN() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			n.mu.Lock()
			n.mcastHello()
			n.mu.Unlock()
		}
	}()
}

func (n *Node) applyRadioSettings() {
	mode := n.st.RadioMode
	if mode == "" {
		mode = "auto"
	}
	ch := -1
	if n.st.RadioChannel != nil {
		ch = *n.st.RadioChannel
	}
	n.radio.SetSettings(mode, n.st.RadioTarget, ch)
}

func (n *Node) run() {
	n.refreshAddrs()
	n.startLAN()
	n.radio.onPacket = n.onLoRa
	n.radio.onText = n.osintMeshText
	n.radio.onNode = n.osintMeshNode
	n.mu.Lock()
	n.applyRadioSettings()
	n.event("start", "Dit apparaat is gestart (versie "+version+")")
	n.mu.Unlock()
	go n.radio.run()
	go func() {
		wasReady := false
		var lastBeacon time.Time
		for range time.Tick(2 * time.Second) {
			ready := n.radio.Ready()
			n.mu.Lock()
			if ready != wasReady {
				if ready {
					in := n.radio.Snapshot()
					n.event("radio", fmt.Sprintf("Radio verbonden: %s (%s, kanaal %s)", in.Transport, in.Region, in.ChannelName))
				} else {
					n.event("radio", "Radio niet meer beschikbaar")
				}
			}
			if ready && (!wasReady || time.Since(lastBeacon) > time.Duration(600/n.loraScale)*time.Second) {
				if len(n.st.Contacts) > 0 {
					n.loraBeacon()
					lastBeacon = time.Now()
				}
			}
			n.loraCleanup()
			n.blobTick()
			p := n.myPos()
			changed := !samePos(p, n.lastPos)
			if changed {
				n.lastPos = p
			}
			n.mu.Unlock()
			if changed {
				if p != nil {
					n.osint.SetLocation(p.Lat, p.Lon, true)
				} else {
					n.osint.SetLocation(0, 0, false)
				}
			}
			wasReady = ready
		}
	}()
	go func() {
		for range time.Tick(10 * time.Second) {
			n.refreshAddrs()
		}
	}()
	if !n.nw.manual {
		go n.netLoop()
	}
	go func() {
		round := 0
		n.pingTick(round)
		for range time.Tick(n.pingEvery) {
			round++
			n.pingTick(round)
		}
	}()
	go func() {
		tk := time.NewTicker(n.outboxEvery)
		for {
			select {
			case <-tk.C:
			case <-n.kick:
			}
			n.outboxTick()
		}
	}()
	go func() {
		for range time.Tick(2 * time.Second) {
			n.save()
		}
	}()
	go func() {
		n.housekeeping()
		for range time.Tick(time.Hour) {
			n.housekeeping()
		}
	}()
	go func() {
		for {
			sdr := probeSDR()
			as := autostartEnabled()
			n.mu.Lock()
			n.sdr, n.autostart = sdr, as
			n.mu.Unlock()
			time.Sleep(60 * time.Second)
		}
	}()
}

// housekeeping ruimt oude berichten, foto's en verzoeken op.
func (n *Node) housekeeping() {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := now()
	n.expireSessions()
	if d := n.st.Policy.KeepDays; d > 0 {
		cut := t - int64(d)*86400
		keep := n.st.Messages[:0]
		removed := 0
		for _, m := range n.st.Messages {
			if m.TS >= cut {
				keep = append(keep, m)
			} else {
				removed++
			}
		}
		n.st.Messages = keep
		if removed > 0 {
			n.dirty = true
			n.event("opruimen", fmt.Sprintf("%d oude berichten opgeruimd", removed))
		}
	}
	for id, p := range n.st.Pending {
		if t-p.Seen > 7*86400 {
			delete(n.st.Pending, id)
			n.dirty = true
		}
	}
	for id, ts := range n.st.Left {
		if t-ts > 30*86400 {
			delete(n.st.Left, id)
		}
	}
	for id, g := range n.st.Groups {
		if g.Deleted && t-g.Ver > 14*86400 {
			delete(n.st.Groups, id)
			n.dirty = true
		}
	}
	n.cleanBlobs()
}
