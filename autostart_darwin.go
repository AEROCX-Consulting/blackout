//go:build darwin

package main

// Automatisch starten op macOS: LaunchAgent ~/Library/LaunchAgents/be.aerocx.blackout.plist.

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
)

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", "be.aerocx.blackout.plist")
}

func autostartEnabled() bool {
	_, err := os.Stat(launchAgentPath())
	return err == nil
}

func autostartSet(on bool) error {
	p := launchAgentPath()
	if !on {
		// alleen het bestand weg; launchctl bootout zou de lopende app stoppen
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("automatisch starten uitzetten mislukt: %v", err)
		}
		return nil
	}
	exe, err := exePath()
	if err != nil {
		return fmt.Errorf("kan het programma niet vinden: %v", err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>be.aerocx.blackout</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + html.EscapeString(exe) + `</string>
		<string>-background</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	return nil
}
