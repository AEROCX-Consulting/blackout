//go:build windows

package main

import (
	"errors"
	"net"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func setReuse(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}

func ip4Bytes(ip net.IP) (b [4]byte) {
	copy(b[:], ip.To4())
	return
}

func ip16Bytes(ip net.IP) (b [16]byte) {
	copy(b[:], ip.To16())
	return
}

func sockJoin4(fd uintptr, group, ifAddr net.IP, join bool) error {
	opt := windows.IP_ADD_MEMBERSHIP
	if !join {
		opt = windows.IP_DROP_MEMBERSHIP
	}
	return windows.SetsockoptIPMreq(windows.Handle(fd), windows.IPPROTO_IP, opt, &windows.IPMreq{Multiaddr: ip4Bytes(group), Interface: ip4Bytes(ifAddr)})
}

func sockJoin6(fd uintptr, group net.IP, ifIndex int, join bool) error {
	opt := windows.IPV6_JOIN_GROUP
	if !join {
		opt = windows.IPV6_LEAVE_GROUP
	}
	return windows.SetsockoptIPv6Mreq(windows.Handle(fd), windows.IPPROTO_IPV6, opt, &windows.IPv6Mreq{Multiaddr: ip16Bytes(group), Interface: uint32(ifIndex)})
}

func sockMcastIf4(fd uintptr, ifAddr net.IP) error {
	return windows.SetsockoptInet4Addr(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MULTICAST_IF, ip4Bytes(ifAddr))
}

func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, syscall.EADDRINUSE)
}

// hideWindow: geen zwart venster laten flitsen bij route print (achtergrondmodus).
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
