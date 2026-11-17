package main

// STUN (RFC 5389), alleen het "binding request": vraag aan een publieke server welk adres en welke
// poort hij van mij ziet. Verstuurd vanaf de eigen socket op poort 47474, zodat het antwoord precies
// het publieke adres van DIE socket is (dat zetten we in de kaart; contacten proberen het dan ook).

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
)

const (
	stunMagic       = 0x2112A442
	stunHeader      = 20
	stunBindReq     = 0x0001
	stunBindOK      = 0x0101
	stunAttrMapped  = 0x0001
	stunAttrXor     = 0x0020
	stunAttrXorOld  = 0x8020 // oudere servers
	stunAttrFinger  = 0x8028
	stunFingerXor   = 0x5354554e
	stunMaxMsg      = 1280
	stunMaxAttrs    = 32
	stunDefaultPort = 3478
)

var defaultStunServers = []string{"stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.cloudflare.com:3478"}

type stunTxID [12]byte

func newStunTxID() (id stunTxID) {
	rand.Read(id[:])
	return
}

// stunRequest bouwt een binding request zonder attributen.
func stunRequest(id stunTxID) []byte {
	b := make([]byte, stunHeader)
	binary.BigEndian.PutUint16(b[0:], stunBindReq)
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], id[:])
	return b
}

// isSTUN: ziet eruit als een STUN-bericht (eerste twee bits 0, magic cookie, lengte klopt).
// Pakketten van contacten beginnen met 'N' (0x4E) en vallen dus nooit hieronder.
func isSTUN(b []byte) bool {
	if len(b) < stunHeader || len(b) > stunMaxMsg || b[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(b[4:]) != stunMagic {
		return false
	}
	l := int(binary.BigEndian.Uint16(b[2:]))
	return l%4 == 0 && stunHeader+l == len(b)
}

func stunTxOf(b []byte) (id stunTxID) {
	copy(id[:], b[8:20])
	return
}

var (
	errStunNotOK   = errors.New("stun: geen geslaagd antwoord")
	errStunTx      = errors.New("stun: onbekende transactie")
	errStunBroken  = errors.New("stun: beschadigd bericht")
	errStunNoAddr  = errors.New("stun: geen adres in het antwoord")
	errStunFingerp = errors.New("stun: FINGERPRINT klopt niet")
)

// parseSTUNResponse leest een binding-antwoord voor transactie id en geeft het gemapte adres.
// XOR-MAPPED-ADDRESS heeft voorrang op MAPPED-ADDRESS. Een FINGERPRINT, als die er is, moet kloppen.
func parseSTUNResponse(b []byte, id stunTxID) (*net.UDPAddr, error) {
	if !isSTUN(b) {
		return nil, errStunBroken
	}
	if binary.BigEndian.Uint16(b[0:]) != stunBindOK {
		return nil, errStunNotOK
	}
	if stunTxOf(b) != id {
		return nil, errStunTx
	}
	var xor, mapped *net.UDPAddr
	off := stunHeader
	for i := 0; off < len(b); i++ {
		if i >= stunMaxAttrs || off+4 > len(b) {
			return nil, errStunBroken
		}
		typ := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		vs := off + 4
		if vs+l > len(b) {
			return nil, errStunBroken
		}
		v := b[vs : vs+l]
		switch typ {
		case stunAttrXor, stunAttrXorOld:
			if xor == nil {
				xor = stunAddr(v, true, b[4:20])
			}
		case stunAttrMapped:
			if mapped == nil {
				mapped = stunAddr(v, false, nil)
			}
		case stunAttrFinger:
			if l != 4 || vs+4 != len(b) {
				return nil, errStunBroken // FINGERPRINT moet het laatste attribuut zijn
			}
			want := crc32.ChecksumIEEE(b[:off]) ^ stunFingerXor
			if binary.BigEndian.Uint32(v) != want {
				return nil, errStunFingerp
			}
		}
		off = vs + (l+3)&^3
	}
	if off != len(b) {
		return nil, errStunBroken
	}
	if xor != nil {
		return xor, nil
	}
	if mapped != nil {
		return mapped, nil
	}
	return nil, errStunNoAddr
}

// stunAddr leest een (XOR-)MAPPED-ADDRESS. key = magic cookie + transactie-ID (voor XOR).
func stunAddr(v []byte, isXor bool, key []byte) *net.UDPAddr {
	if len(v) < 4 {
		return nil
	}
	fam := v[1]
	port := binary.BigEndian.Uint16(v[2:])
	var ip net.IP
	switch {
	case fam == 1 && len(v) == 8:
		ip = make(net.IP, 4)
		copy(ip, v[4:8])
	case fam == 2 && len(v) == 20:
		ip = make(net.IP, 16)
		copy(ip, v[4:20])
	default:
		return nil
	}
	if isXor {
		port ^= uint16(stunMagic >> 16)
		for i := range ip {
			ip[i] ^= key[i] // eerste 4 bytes: cookie; IPv6: daarna de transactie-ID
		}
	}
	if port == 0 || ip.IsUnspecified() {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}
}

// stunResponse bouwt een antwoord (voor de nep-server in de tests).
func stunResponse(id stunTxID, addr *net.UDPAddr, finger bool) []byte {
	b := make([]byte, stunHeader, 64)
	binary.BigEndian.PutUint16(b[0:], stunBindOK)
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], id[:])
	ip := addr.IP.To4()
	fam := byte(1)
	if ip == nil {
		ip, fam = addr.IP.To16(), 2
	}
	v := []byte{0, fam, 0, 0}
	binary.BigEndian.PutUint16(v[2:], uint16(addr.Port)^uint16(stunMagic>>16))
	key := b[4:20]
	for i := range ip {
		v = append(v, ip[i]^key[i])
	}
	b = binary.BigEndian.AppendUint16(b, stunAttrXor)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	b = append(b, v...)
	if finger {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)-stunHeader+8))
		crc := crc32.ChecksumIEEE(b) ^ stunFingerXor
		b = binary.BigEndian.AppendUint16(b, stunAttrFinger)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = binary.BigEndian.AppendUint32(b, crc)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-stunHeader))
	return b
}
