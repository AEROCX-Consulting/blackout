//go:build windows

package main

// Automatisch starten op Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run, waarde "AEROCX Blackout".

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "AEROCX Blackout"

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

func autostartSet(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("kan het register niet openen: %v", err)
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("automatisch starten uitzetten mislukt: %v", err)
		}
		return nil
	}
	exe, err := exePath()
	if err != nil {
		return fmt.Errorf("kan het programma niet vinden: %v", err)
	}
	if err := k.SetStringValue(runValue, `"`+exe+`" -background`); err != nil {
		return fmt.Errorf("automatisch starten aanzetten mislukt: %v", err)
	}
	return nil
}
