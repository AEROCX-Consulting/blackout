//go:build !darwin && !linux && !windows

package main

import "errors"

func autostartEnabled() bool { return false }

func autostartSet(on bool) error {
	return errors.New("automatisch starten wordt op dit systeem niet ondersteund")
}
