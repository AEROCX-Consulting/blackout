//go:build linux

package main

// Automatisch starten op Linux / Raspberry Pi: systemd user unit
// ~/.config/systemd/user/aerocx-blackout.service (+ systemctl --user enable --now).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func unitPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", "aerocx-blackout.service")
}

const pkgUnitPath = "/usr/lib/systemd/user/aerocx-blackout.service" // uit het .deb-pakket

// autostartEnabled: aan als de app zelf een unit schreef, of als systemd de unit
// (ook die van het pakket in /usr/lib/systemd/user) als ingeschakeld meldt.
func autostartEnabled() bool {
	if _, err := os.Stat(unitPath()); err == nil {
		return true
	}
	out, _ := exec.Command("systemctl", "--user", "is-enabled", "aerocx-blackout").Output()
	switch strings.TrimSpace(string(out)) {
	case "enabled", "enabled-runtime":
		return true
	}
	// zonder systemctl: de koppelingen die "enable" maakt
	if _, err := os.Stat(pkgUnitPath); err == nil {
		for _, w := range []string{filepath.Join(filepath.Dir(unitPath()), "default.target.wants", "aerocx-blackout.service"),
			"/etc/systemd/user/default.target.wants/aerocx-blackout.service"} {
			if _, err := os.Lstat(w); err == nil {
				return true
			}
		}
	}
	return false
}

// unitExecPath ontsnapt het pad voor ExecStart="…" (zelfde regels als install.sh):
// \ → \\, " → \", % → %%, $ → $$.
func unitExecPath(p string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(p)
}

func unitText(exe string) string {
	return `[Unit]
Description=AEROCX Blackout (noodcommunicatie)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart="` + unitExecPath(exe) + `" -background
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func autostartSet(on bool) error {
	p := unitPath()
	if !on {
		// niet stoppen: dat zou de lopende app afsluiten
		systemctl("disable", "aerocx-blackout.service")
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("automatisch starten uitzetten mislukt: %v", err)
		}
		systemctl("daemon-reload")
		return nil
	}
	exe, err := exePath()
	if err != nil {
		return fmt.Errorf("kan het programma niet vinden: %v", err)
	}
	unit := unitText(exe)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	if err := os.WriteFile(p, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemd niet bereikbaar (%v); het bestand staat klaar in %s", err, p)
	}
	if err := systemctl("enable", "--now", "aerocx-blackout.service"); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	return nil
}
