package main

// De standaardgateway (thuisrouter) per besturingssysteem, zonder cgo.
// Linux: /proc/net/route. macOS/BSD: `route -n get default`. Windows: `route print -4 0.0.0.0`.
// Lukt dat niet: ".1" van het eigen privé-subnet (UPnP via SSDP werkt ook zonder gateway-adres).

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// parseProcNetRoute: de standaardroute met de laagste metriek uit /proc/net/route.
func parseProcNetRoute(data string) net.IP {
	var best net.IP
	bestMetric := -1
	sc := bufio.NewScanner(strings.NewReader(data))
	for i := 0; sc.Scan() && i < 4096; i++ {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x3 != 0x3 { // RTF_UP | RTF_GATEWAY
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, binary.BigEndian.Uint32(raw))
		metric, _ := strconv.Atoi(f[6])
		if ip.IsUnspecified() {
			continue
		}
		if best == nil || metric < bestMetric {
			best, bestMetric = ip, metric
		}
	}
	return best
}

// parseRouteGetDefault: uitvoer van `route -n get default` (macOS/BSD).
func parseRouteGetDefault(out string) net.IP {
	sc := bufio.NewScanner(strings.NewReader(out))
	for i := 0; sc.Scan() && i < 200; i++ {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok || strings.TrimSpace(k) != "gateway" {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}

// parseRoutePrint: uitvoer van `route print -4` (Windows), regel "0.0.0.0 0.0.0.0 <gateway> <interface> <metriek>".
func parseRoutePrint(out string) net.IP {
	var best net.IP
	bestMetric := -1
	sc := bufio.NewScanner(strings.NewReader(out))
	for i := 0; sc.Scan() && i < 4096; i++ {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
			continue
		}
		ip := net.ParseIP(f[2]).To4()
		if ip == nil || ip.IsUnspecified() { // "On-link" geeft nil
			continue
		}
		metric, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		if best == nil || metric < bestMetric {
			best, bestMetric = ip, metric
		}
	}
	return best
}

func runQuiet(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	if len(out) > 256<<10 {
		out = out[:256<<10]
	}
	return string(out)
}

// osGateway: de gateway volgens het besturingssysteem, of nil.
func osGateway() net.IP {
	switch runtime.GOOS {
	case "linux", "android":
		raw, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return nil
		}
		return parseProcNetRoute(string(raw))
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return parseRouteGetDefault(runQuiet("route", "-n", "get", "default"))
	case "windows":
		return parseRoutePrint(runQuiet("route", "print", "-4", "0.0.0.0"))
	}
	return nil
}

// guessGateways: ".1" (eerste adres) van elk eigen privé-IPv4-subnet.
func guessGateways(addrs []ifAddr) []net.IP {
	var out []net.IP
	for _, a := range addrs {
		ip := a.IP.To4()
		if ip == nil || a.LL || a.Loop || !ip.IsPrivate() || a.Net == nil {
			continue
		}
		ones, bits := a.Net.Mask.Size()
		if bits != 32 || ones < 8 || ones > 30 {
			continue
		}
		g := ip.Mask(a.Net.Mask).To4()
		g = net.IPv4(g[0], g[1], g[2], g[3]+1).To4()
		if !g.Equal(ip) {
			out = append(out, g)
		}
	}
	return out
}

// localFor: het eigen IPv4-adres in hetzelfde subnet als ip (nil als er geen is).
func localFor(addrs []ifAddr, ip net.IP) *ifAddr {
	for i := range addrs {
		a := &addrs[i]
		if a.v4() && (!a.Loop || pmTestLoopback) && a.Net != nil && a.Net.Contains(ip) {
			return a
		}
	}
	return nil
}
