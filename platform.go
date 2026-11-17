package main

// Alles wat per besturingssysteem verschilt, behalve automatisch starten (autostart_*.go).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// defaultDataDir: macOS ~/Library/Application Support/AEROCX Blackout,
// Windows %APPDATA%\AEROCX Blackout, Linux $XDG_DATA_HOME/aerocx-blackout of ~/.local/share/aerocx-blackout.
func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "AEROCX Blackout")
	case "windows":
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "AEROCX Blackout")
		}
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "AEROCX Blackout")
		}
		return filepath.Join(home, "AppData", "Roaming", "AEROCX Blackout")
	default:
		if d := os.Getenv("XDG_DATA_HOME"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, "aerocx-blackout")
		}
		return filepath.Join(home, ".local", "share", "aerocx-blackout")
	}
}

// openBrowser opent de standaardbrowser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("kan de browser niet openen: %v", err)
	}
	go cmd.Wait()
	return nil
}

// alreadyRunning: draait er al een AEROCX Blackout op deze poort?
func alreadyRunning(uiPort int) bool {
	cl := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := cl.Get(fmt.Sprintf("http://127.0.0.1:%d/api/ping", uiPort))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var p struct {
		App string `json:"app"`
	}
	return json.NewDecoder(resp.Body).Decode(&p) == nil && p.App == appID
}

// probeSDR: draait er lokaal readsb/dump1090 (vliegtuigen via een SDR-ontvanger)?
func probeSDR() bool {
	cl := &http.Client{Timeout: time.Second}
	for _, u := range []string{"http://127.0.0.1:8080/data/aircraft.json", "http://127.0.0.1:8504/data/aircraft.json", "http://127.0.0.1:30152/data/aircraft.json"} {
		resp, err := cl.Get(u)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}
	return false
}

// rotLog schrijft naar <datamap>/blackout.log en roteert bij 5 MB.
type rotLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

const maxLog = 5 * 1024 * 1024

func newRotLog(path string) (*rotLog, error) {
	l := &rotLog{path: path}
	return l, l.openFile()
}

func (l *rotLog) openFile() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, _ := f.Stat()
	l.f = f
	l.size = 0
	if fi != nil {
		l.size = fi.Size()
	}
	return nil
}

func (l *rotLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return len(p), nil
	}
	if l.size+int64(len(p)) > maxLog {
		l.f.Close()
		os.Remove(l.path + ".1")
		os.Rename(l.path, l.path+".1")
		if err := l.openFile(); err != nil {
			l.f = nil
			return len(p), nil
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// exePath: het pad van dit programma (symlinks opgelost).
func exePath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p, nil
}
