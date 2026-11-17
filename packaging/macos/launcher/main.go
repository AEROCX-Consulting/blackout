// Command launcher is het kleine startprogramma in "AEROCX Blackout.app".
//
// Finder kan een app geen opdrachtregelvlaggen meegeven. Dit programma staat
// daarom als CFBundleExecutable in de app en start de echte binary
// (Contents/MacOS/aerocx-blackout) met -open, los van zichzelf, en stopt dan.
// Draait de app al, dan opent de binary zelf alleen de browser (één exemplaar).
//
// Het is een aparte Go-module, zodat `go vet ./...` en `go test ./...` in de
// hoofdmap er niets mee te maken hebben.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	bin := filepath.Join(filepath.Dir(self), "aerocx-blackout")

	args := append([]string{"-open"}, os.Args[1:]...)
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	// Eigen sessie: de app blijft draaien als dit startprogramma stopt.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}
	_ = cmd.Process.Release()
}
