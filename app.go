package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	dataDir := flag.String("data", defaultDataDir(), "map voor gegevens")
	udpPort := flag.Int("port", 47474, "UDP-poort voor berichten")
	uiPort := flag.Int("ui", 8474, "poort van het chatscherm")
	loopback := flag.Bool("loopback", false, "(test) ook 127.0.0.1/::1 gebruiken")
	drop := flag.String("drop", "", "(test) negeer rechtstreekse pakketten van deze korte ID's, komma-gescheiden")
	radioPort := flag.String("radio-port", "", "seriële poort van de Meshtastic-radio (standaard: automatisch zoeken)")
	radioTCP := flag.String("radio-tcp", "", "IP-adres van een Meshtastic-radio via wifi")
	loraFast := flag.Bool("lora-fast", false, "(test) korte wachttijden voor de radio")
	openFlag := flag.Bool("open", false, "na het starten de browser openen")
	background := flag.Bool("background", false, "op de achtergrond draaien (logboek naar blackout.log in de gegevensmap)")
	autostart := flag.String("autostart", "", "automatisch starten bij aanmelden: on of off (en dan stoppen)")
	showVersion := flag.Bool("version", false, "toon de versie en stop")
	flag.Parse()

	if *showVersion {
		fmt.Println("AEROCX Blackout", version)
		return
	}
	if *autostart != "" {
		var on bool
		switch strings.ToLower(*autostart) {
		case "on", "aan", "true", "1":
			on = true
		case "off", "uit", "false", "0":
		default:
			fmt.Fprintln(os.Stderr, "Gebruik -autostart=on of -autostart=off")
			os.Exit(2)
		}
		if err := autostartSet(on); err != nil {
			fmt.Fprintln(os.Stderr, "Mislukt:", err)
			os.Exit(1)
		}
		if on {
			fmt.Println("Automatisch starten staat aan.")
		} else {
			fmt.Println("Automatisch starten staat uit.")
		}
		return
	}

	os.MkdirAll(*dataDir, 0o700)
	if *background {
		if lw, err := newRotLog(filepath.Join(*dataDir, "blackout.log")); err == nil {
			log.SetOutput(lw)
		} else {
			log.SetOutput(io.Discard)
		}
	}
	url := fmt.Sprintf("http://localhost:%d", *uiPort)

	// Eén exemplaar: draait er al een, dan alleen de browser openen.
	if alreadyRunning(*uiPort) {
		log.Printf("AEROCX Blackout draait al; ik open alleen de browser")
		if !*background {
			if err := openBrowser(url); err != nil {
				log.Print(err)
			}
		}
		return
	}

	n, err := loadNode(*dataDir, *udpPort, *uiPort, *loopback)
	if err != nil {
		log.Fatalf("Starten mislukt: %v", err)
	}
	for _, d := range strings.Split(*drop, ",") {
		if d = strings.TrimSpace(d); d != "" {
			n.dropFrom[d] = true
		}
	}
	if *radioPort != "" {
		n.st.RadioMode, n.st.RadioTarget = "auto", *radioPort
	}
	if *radioTCP != "" {
		n.st.RadioMode, n.st.RadioTarget = "tcp", *radioTCP
	}
	if *loraFast {
		n.loraWait, n.loraScale = 3, 30
		n.radio.minGap = 300 * time.Millisecond
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *uiPort))
	if err != nil {
		log.Fatalf("Poort %d is bezet door een ander programma: %v", *uiPort, err)
	}
	n.osint.Start()
	n.run()

	if !*background {
		fmt.Printf("\nAEROCX Blackout %s draait als knooppunt \"%s\" (%s)\n", version, n.st.Name, short(n.myID))
		fmt.Printf("Chatscherm op deze computer: %s\n", url)
		for _, u := range n.uiURLs() {
			fmt.Printf("Op iPad/telefoon (zelfde wifi): %s  – pincode %s\n", u, n.st.Pin)
		}
		fmt.Println("Laat dit venster open. Sluiten = AEROCX Blackout stopt.")
	}
	log.Printf("AEROCX Blackout %s gestart, gegevens in %s", version, *dataDir)

	srv := &http.Server{Handler: n.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-n.quit
		log.Printf("AEROCX Blackout stopt (gevraagd via het scherm)")
		n.mu.Lock()
		n.dirty = true
		n.mu.Unlock()
		n.save()
		n.saveSeen(true)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	if *openFlag {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := openBrowser(url); err != nil {
				log.Print(err)
			}
		}()
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Webscherm gestopt: %v", err)
	}
	n.save()
	n.saveSeen(true)
}
