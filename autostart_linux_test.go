//go:build linux

package main

import "testing"

func TestUnitTextEscaping(t *testing.T) {
	got := unitText(`/opt/a b/x"y\z%n$HOME/aerocx-blackout`)
	want := `[Unit]
Description=AEROCX Blackout (noodcommunicatie)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart="/opt/a b/x\"y\\z%%n$$HOME/aerocx-blackout" -background
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`
	if got != want {
		t.Errorf("unit:\n%s\nverwacht:\n%s", got, want)
	}
}
