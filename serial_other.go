//go:build !darwin && !linux

package main

import (
	"errors"
	"io"
)

func serialPorts() []string { return nil }

func openSerial(path string) (io.ReadWriteCloser, error) {
	return nil, errors.New("USB wordt op dit systeem niet ondersteund; verbind de radio via wifi")
}
