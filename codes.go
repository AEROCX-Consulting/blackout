package main

// Compacte koppelcode (v2), uitnodigingen en QR-codes.
// v2: "AXB2:" + base64url( 2 | E[32] | X[32] | TS[8] | S[64] | len(naam) | naam | aantal | (fam ip poort[2])... )
// De handtekening is dezelfde als bij v1: de kaart wordt teruggebouwd en zo nagekeken.
// Uitnodiging: "AXB2I:" + base64url( kaart-v2-bytes | uitnodigings-ID[8] | vervaldatum[4] | handtekening[64] )

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"
)

const (
	codeV2Prefix   = "AXB2:"
	inviteV2Prefix = "AXB2I:"
)

func cardCode(c Card) string {
	return codeV2Prefix + b64.EncodeToString(cardCodeBytes(c))
}

func cardCodeBytes(c Card) []byte {
	e, _ := b64.DecodeString(c.E)
	x, _ := b64.DecodeString(c.X)
	s, _ := b64.DecodeString(c.S)
	var b bytes.Buffer
	b.WriteByte(2)
	b.Write(e)
	b.Write(x)
	binary.Write(&b, binary.BigEndian, c.TS)
	b.Write(s)
	name := c.N
	if len(name) > 64 {
		name = name[:64]
	}
	b.WriteByte(byte(len(name)))
	b.WriteString(name)
	var addrs [][]byte
	for _, a := range c.A {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		p, err := strconv.Atoi(port)
		if ip == nil || err != nil {
			continue
		}
		var rec []byte
		if v4 := ip.To4(); v4 != nil && !strings.Contains(host, ":") {
			rec = append([]byte{4}, v4...)
		} else {
			rec = append([]byte{6}, ip.To16()...)
		}
		rec = binary.BigEndian.AppendUint16(rec, uint16(p))
		addrs = append(addrs, rec)
	}
	b.WriteByte(byte(len(addrs)))
	for _, r := range addrs {
		b.Write(r)
	}
	return b.Bytes()
}

var errCodeBroken = errors.New("De code is beschadigd (niet volledig gekopieerd?)")

func parseCodeV2(s string) (Card, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return Card{}, errCodeBroken
	}
	c, _, err := parseCardV2Bytes(raw)
	return c, err
}

// parseInviteCode leest een uitnodiging (zonder "AXB2I:") en controleert handtekening en vervaldatum.
func parseInviteCode(s string) (Card, *inviteRef, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return Card{}, nil, errCodeBroken
	}
	c, rest, err := parseCardV2Bytes(raw)
	if err != nil {
		return c, nil, err
	}
	if len(rest) < 8+4+64 {
		return c, nil, errCodeBroken
	}
	ref := &inviteRef{ID: hex.EncodeToString(rest[:8]), Exp: int64(binary.BigEndian.Uint32(rest[8:12]))}
	pub, _ := b64.DecodeString(c.E)
	if !ed25519.Verify(pub, inviteSignBytes(ref.ID, ref.Exp), rest[12:76]) {
		return c, nil, errors.New("De uitnodiging is ongeldig")
	}
	if time.Now().Unix() > ref.Exp {
		return c, nil, errors.New("Deze uitnodiging is verlopen. Vraag een nieuwe.")
	}
	return c, ref, nil
}

// parseCardV2Bytes leest de kaart en geeft de overblijvende bytes terug.
func parseCardV2Bytes(raw []byte) (Card, []byte, error) {
	var c Card
	if len(raw) < 1+32+32+8+64+1+1 || raw[0] != 2 {
		return c, nil, errCodeBroken
	}
	p := raw[1:]
	c.E = b64.EncodeToString(p[:32])
	c.X = b64.EncodeToString(p[32:64])
	c.TS = int64(binary.BigEndian.Uint64(p[64:72]))
	c.S = b64.EncodeToString(p[72:136])
	p = p[136:]
	nl := int(p[0])
	if len(p) < 1+nl+1 {
		return c, nil, errCodeBroken
	}
	c.N = string(p[1 : 1+nl])
	p = p[1+nl:]
	na := int(p[0])
	p = p[1:]
	for i := 0; i < na; i++ {
		if len(p) < 1 {
			return c, nil, errCodeBroken
		}
		l := 4
		if p[0] == 6 {
			l = 16
		} else if p[0] != 4 {
			return c, nil, errCodeBroken
		}
		if len(p) < 1+l+2 {
			return c, nil, errCodeBroken
		}
		ip := net.IP(append([]byte{}, p[1:1+l]...))
		port := binary.BigEndian.Uint16(p[1+l : 3+l])
		c.A = append(c.A, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		p = p[3+l:]
	}
	if !c.Verify() {
		return c, nil, errors.New("De code is ongeldig of beschadigd")
	}
	return c, p, nil
}

// qrPNG maakt een QR-afbeelding (zwart op wit) met een stille rand.
func qrPNG(text string, scale int) ([]byte, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	n := code.Size
	quiet := 4
	size := (n + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, size, size))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if code.Black(x, y) {
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{0})
					}
				}
			}
		}
	}
	var buf bytes.Buffer
	err = png.Encode(&buf, img)
	return buf.Bytes(), err
}
