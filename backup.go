package main

// Versleutelde back-up: sleutels, contacten, groepen en instellingen (geen berichten).
// Bestand: "AXBK1" | t[4] | m[4] | p[1] | zout[16] | nonce[12] | AES-256-GCM(JSON)
// Sleutel uit de wachtzin met Argon2id (t=3, m=64 MiB, p=4). De kop is meegetekend (AAD).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	backupMagic   = "AXBK1"
	backupMinPass = 12
	backupT       = 3
	backupM       = 64 * 1024 // KiB = 64 MiB
	backupP       = 4
)

type backupData struct {
	V            int                        `json:"v"`
	Created      int64                      `json:"created"`
	EdSeed       string                     `json:"ed_seed"`
	XPriv        string                     `json:"x_priv"`
	Name         string                     `json:"name"`
	CardTS       int64                      `json:"card_ts"`
	Contacts     map[string]*Contact        `json:"contacts"`
	Groups       map[string]*Group          `json:"groups"`
	Left         map[string]int64           `json:"left,omitempty"`
	Removed      map[string]int64           `json:"removed,omitempty"`
	Perms        map[string]map[string]bool `json:"perms"`
	Policy       Policy                     `json:"policy"`
	Invites      []*Invite                  `json:"invites,omitempty"`
	Audit        []AuditEntry               `json:"audit,omitempty"`
	Loc          *Pos                       `json:"loc,omitempty"`
	Share        bool                       `json:"share"`
	Bridge       bool                       `json:"bridge"`
	RadioMode    string                     `json:"radio_mode,omitempty"`
	RadioTarget  string                     `json:"radio_target,omitempty"`
	RadioChannel *int                       `json:"radio_channel,omitempty"`
}

func checkPass(pass string) error {
	if utf8.RuneCountInString(strings.TrimSpace(pass)) < backupMinPass {
		return fmt.Errorf("Kies een wachtzin van minstens %d tekens", backupMinPass)
	}
	return nil
}

func backupKey(pass string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(pass), salt, t, m, p, 32)
}

// backupPlain (onder slot) geeft de onversleutelde inhoud; versleutelen gebeurt buiten het slot.
func (n *Node) backupPlain() ([]byte, error) {
	st := n.st
	d := backupData{V: 1, Created: now(), EdSeed: st.EdSeed, XPriv: st.XPriv, Name: st.Name, CardTS: st.CardTS,
		Contacts: st.Contacts, Groups: st.Groups, Left: st.Left, Removed: st.Removed, Perms: st.Perms, Policy: st.Policy,
		Invites: st.Invites, Audit: st.Audit, Loc: st.Loc, Share: st.Share, Bridge: st.Bridge,
		RadioMode: st.RadioMode, RadioTarget: st.RadioTarget, RadioChannel: st.RadioChannel}
	pt, err := json.Marshal(d)
	if err != nil {
		return nil, errors.New("Back-up maken mislukt")
	}
	return pt, nil
}

func sealBackup(pass string, pt []byte) ([]byte, error) {
	const t, m, p = backupT, backupM, backupP
	hdr := []byte(backupMagic)
	hdr = binary.BigEndian.AppendUint32(hdr, t)
	hdr = binary.BigEndian.AppendUint32(hdr, m)
	hdr = append(hdr, p)
	salt := make([]byte, 16)
	rand.Read(salt)
	hdr = append(hdr, salt...)
	key := backupKey(pass, salt, t, m, p)
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(append([]byte{}, hdr...), nonce...)
	return gcm.Seal(out, nonce, pt, hdr), nil
}

var errBackupPass = errors.New("De wachtzin klopt niet of het bestand is beschadigd")

func openBackup(pass string, raw []byte) (*backupData, error) {
	hl := len(backupMagic) + 4 + 4 + 1 + 16
	if len(raw) < hl+12+16 || string(raw[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("Dit is geen AEROCX Blackout-back-up")
	}
	p := raw[len(backupMagic):]
	t := binary.BigEndian.Uint32(p[0:4])
	m := binary.BigEndian.Uint32(p[4:8])
	par := p[8]
	if t != backupT || m != backupM || par != backupP { // alleen de vaste parameters (geen dure of zwakke afleiding)
		return nil, errors.New("Dit is geen geldige back-up")
	}
	salt := p[9:25]
	key := backupKey(pass, salt, t, m, par)
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	pt, err := gcm.Open(nil, raw[hl:hl+12], raw[hl+12:], raw[:hl])
	if err != nil {
		return nil, errBackupPass
	}
	var d backupData
	if err := json.Unmarshal(pt, &d); err != nil || d.EdSeed == "" || d.XPriv == "" {
		return nil, errBackupPass
	}
	return &d, nil
}

// restoreBackup (onder slot) zet sleutels, contacten, groepen en instellingen terug.
// Berichten op dit toestel blijven staan.
func (n *Node) restoreBackup(d *backupData) error {
	old := *n.st
	st := n.st
	st.EdSeed, st.XPriv, st.Name = d.EdSeed, d.XPriv, d.Name
	if d.CardTS > st.CardTS {
		st.CardTS = d.CardTS
	}
	st.Contacts = d.Contacts
	st.Groups = d.Groups
	st.Left = d.Left
	st.Removed = d.Removed
	st.Perms = d.Perms
	st.Policy = d.Policy
	st.Invites = d.Invites
	if len(d.Audit) > 0 {
		st.Audit = d.Audit
	}
	st.Loc, st.Share, st.Bridge = d.Loc, d.Share, d.Bridge
	st.RadioMode, st.RadioTarget, st.RadioChannel = d.RadioMode, d.RadioTarget, d.RadioChannel
	st.Pending = map[string]*Pending{}
	st.Sos = nil
	st.IncomingSos = nil
	if err := n.applyIdentity(); err != nil {
		*n.st = old
		n.applyIdentity()
		return err
	}
	n.migrate(false)
	for _, m := range st.Messages { // de gezien-lijst blijft; berichten erbij
		if m.From != "me" && m.From != "" {
			n.markSeenKey(m.From + "|" + m.ID)
		}
	}
	n.reach = map[string]map[string]int64{}
	n.radioHeard = map[string]map[string]int64{}
	n.bumpCard()
	n.applyRadioSettings()
	n.audit(fmt.Sprintf("Back-up teruggezet (%d contacten, %d groepen)", len(st.Contacts), len(st.Groups)))
	for _, c := range st.Contacts {
		if !c.Blocked {
			n.sendTo(c, n.helloFor(c))
		}
	}
	return nil
}
