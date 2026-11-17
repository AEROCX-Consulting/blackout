//go:build darwin || linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

func serialPorts() []string {
	var out []string
	for _, pat := range serialPatterns {
		m, _ := filepath.Glob(pat)
		out = append(out, m...)
	}
	sort.Strings(out)
	return out
}

// openSerial opent een seriële poort op 115200 baud, 8N1, ruwe modus.
func openSerial(path string) (io.ReadWriteCloser, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	makeRaw115200(t)
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, t); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// fd blijft non-blocking: Go gebruikt dan de netpoller, zodat Close() een lopende Read beëindigt.
	return os.NewFile(uintptr(fd), path), nil
}
