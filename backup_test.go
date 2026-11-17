package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupRestore(t *testing.T) {
	a, b := bareNode(t, "Anna"), bareNode(t, "Bert")
	know(a, b, "Bert").Role = "beheerder"
	g, _ := a.groupAction(groupIn{Action: "create", Name: "Familie", Members: &[]string{b.myID}})
	a.st.Policy.KeepDays = 7
	a.st.Loc = &Pos{Lat: 50.5, Lon: 4.25}

	if err := checkPass("kort"); err == nil {
		t.Fatal("korte wachtzin aanvaard")
	}
	pt, err := a.backupPlain()
	if err != nil {
		t.Fatal(err)
	}
	pass := "paard batterij nietje correct"
	data, err := sealBackup(pass, pt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), a.st.EdSeed) || strings.Contains(string(data), "Bert") {
		t.Fatal("back-up niet versleuteld")
	}
	if _, err := openBackup("verkeerde wachtzin!!", data); err == nil {
		t.Fatal("verkeerde wachtzin aanvaard")
	}
	data2 := append([]byte{}, data...)
	data2[len(data2)-5] ^= 1
	if _, err := openBackup(pass, data2); err == nil {
		t.Fatal("beschadigd bestand aanvaard")
	}
	if _, err := openBackup(pass, []byte("geen back-up")); err == nil {
		t.Fatal("onzin aanvaard")
	}
	d, err := openBackup(pass, data)
	if err != nil {
		t.Fatal(err)
	}

	// herstellen op een nieuw toestel
	x := bareNode(t, "Nieuw toestel")
	x.st.Messages = append(x.st.Messages, &Message{ID: "1", Conv: "alle", From: "me", Body: "blijft"})
	if err := x.restoreBackup(d); err != nil {
		t.Fatal(err)
	}
	if x.myID != a.myID || x.st.Name != "Anna" {
		t.Fatal("identiteit niet teruggezet")
	}
	if c := x.st.Contacts[b.myID]; c == nil || c.Role != "beheerder" {
		t.Fatal("contact/rol niet teruggezet")
	}
	if xg := x.st.Groups[g.ID]; xg == nil || !x.mine(xg) {
		t.Fatal("groep niet teruggezet")
	}
	if x.st.Policy.KeepDays != 7 || x.st.Loc == nil || len(x.st.Messages) != 1 {
		t.Fatal("instellingen/berichten fout")
	}
	// de sleutels werken: Bert kan nog steeds met "Anna" praten
	bc := know(b, x, "Anna")
	pkt := b.seal('E', bc, []byte(`{"t":"ping"}`))
	if _, err := x.open(x.st.Contacts[b.myID], pkt); err != nil {
		t.Fatal("versleuteling werkt niet na herstel")
	}
}

func TestMigrateV11(t *testing.T) {
	// een blackout.json zoals v1.1 hem schreef
	dir := t.TempDir()
	src := bareNode(t, "Oud")
	peer := bareNode(t, "Peer")
	old := map[string]any{
		"ed_seed": src.st.EdSeed, "x_priv": src.st.XPriv, "name": "Oud", "card_ts": 5, "pin": "123456", "token": "abcdef0123456789",
		"alle_unread": 2,
		"contacts":    map[string]any{peer.myID: map[string]any{"id": peer.myID, "name": "Peer", "card": peer.myCard(), "observed": map[string]int64{}, "last_seen": 1, "via": "direct", "unread": 1}},
		"pending":     map[string]any{},
		"messages":    []any{map[string]any{"id": "aa", "conv": peer.myID, "from": peer.myID, "body": "hoi", "ts": 1}},
		"radio_mode":  "tcp", "radio_target": "192.168.1.50",
	}
	raw, _ := json.Marshal(old)
	os.WriteFile(filepath.Join(dir, "blackout.json"), raw, 0o600)
	n, err := loadNode(dir, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if n.myID != src.myID || n.st.Pin != "123456" || n.st.AlleUnread != 2 {
		t.Fatal("oude gegevens niet geladen")
	}
	c := n.st.Contacts[peer.myID]
	if c == nil || c.Role != "lid" || c.Via != "star" {
		t.Fatalf("contact niet omgezet: %+v", c)
	}
	if n.st.Token != "" || len(n.st.Sessions) != 1 || n.st.Sessions["abcdef0123456789"] == nil {
		t.Fatal("oude sessie niet omgezet")
	}
	if n.st.Share || !n.st.Bridge || n.st.Perms["lezer"] == nil || n.st.Policy.KeepDays != 0 { // delen staat na de migratie uit
		t.Fatal("standaardinstellingen niet gezet")
	}
	if n.st.RadioMode != "tcp" || len(n.st.Messages) != 1 || !n.isSeen(peer.myID+"|aa") {
		t.Fatal("radio/berichten niet bewaard")
	}
	// opslaan en opnieuw laden blijft werken
	n.dirty = true
	n.save()
	n2, err := loadNode(dir, 0, 0, true)
	if err != nil || n2.myID != n.myID || len(n2.st.Audit) != 1 {
		t.Fatalf("herladen: %v", err)
	}
}

// Een back-up met andere Argon2-parameters (bv. zwak of extreem duur) wordt geweigerd,
// ook als hij verder correct versleuteld is.
func TestBackupRejectsOtherArgonParams(t *testing.T) {
	seal := func(pass string, pt []byte, tt, m uint32, p uint8) []byte {
		hdr := []byte(backupMagic)
		hdr = binary.BigEndian.AppendUint32(hdr, tt)
		hdr = binary.BigEndian.AppendUint32(hdr, m)
		hdr = append(hdr, p)
		salt := make([]byte, 16)
		hdr = append(hdr, salt...)
		blk, _ := aes.NewCipher(backupKey(pass, salt, tt, m, p))
		gcm, _ := cipher.NewGCM(blk)
		nonce := make([]byte, 12)
		return gcm.Seal(append(append([]byte{}, hdr...), nonce...), nonce, pt, hdr)
	}
	a := bareNode(t, "Anna")
	pt, _ := a.backupPlain()
	pass := "een lange wachtzin voor de test"
	if _, err := openBackup(pass, seal(pass, pt, backupT, backupM, backupP)); err != nil {
		t.Fatalf("juiste parameters geweigerd: %v", err)
	}
	for _, c := range []struct {
		t uint32
		m uint32
		p uint8
	}{{1, backupM, backupP}, {backupT, 8 * 1024, backupP}, {backupT, backupM, 1}, {20, backupM, backupP}, {backupT, 1024 * 1024, backupP}} {
		raw := seal(pass, pt, c.t, c.m, c.p)
		if c.m > backupM { // niet echt afleiden (te duur): alleen de kop aanpassen
			raw = seal(pass, pt, backupT, backupM, backupP)
			binary.BigEndian.PutUint32(raw[len(backupMagic)+4:], c.m)
		}
		if _, err := openBackup(pass, raw); err == nil || err == errBackupPass {
			t.Errorf("parameters t=%d m=%d p=%d aanvaard of verkeerde fout: %v", c.t, c.m, c.p, err)
		}
	}
}
