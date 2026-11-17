//go:build unix

package main

// Socketopties voor multicast (per interface) zonder cgo, via golang.org/x/sys/unix.

import (
	"errors"
	"net"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func setReuse(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if runtime.GOOS != "linux" { // BSD/macOS: nodig om dezelfde multicastpoort te delen
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}
	return nil
}

func ip4Bytes(ip net.IP) (b [4]byte) {
	copy(b[:], ip.To4())
	return
}

func ip16Bytes(ip net.IP) (b [16]byte) {
	copy(b[:], ip.To16())
	return
}

// joinGroup4 / leaveGroup4: lid worden van een IPv4-groep op de interface met adres ifAddr.
func sockJoin4(fd uintptr, group, ifAddr net.IP, join bool) error {
	opt := unix.IP_ADD_MEMBERSHIP
	if !join {
		opt = unix.IP_DROP_MEMBERSHIP
	}
	return unix.SetsockoptIPMreq(int(fd), unix.IPPROTO_IP, opt, &unix.IPMreq{Multiaddr: ip4Bytes(group), Interface: ip4Bytes(ifAddr)})
}

func sockJoin6(fd uintptr, group net.IP, ifIndex int, join bool) error {
	opt := unix.IPV6_JOIN_GROUP
	if !join {
		opt = unix.IPV6_LEAVE_GROUP
	}
	return unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, opt, &unix.IPv6Mreq{Multiaddr: ip16Bytes(group), Interface: uint32(ifIndex)})
}

// sockMcastIf4: uitgaande IPv4-multicast van deze socket via de interface met dit adres.
func sockMcastIf4(fd uintptr, ifAddr net.IP) error {
	return unix.SetsockoptInet4Addr(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF, ip4Bytes(ifAddr))
}

func isAddrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

func hideWindow(cmd *exec.Cmd) {}
