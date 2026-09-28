// badgy-bridge listens on the Badgy's USB serial port and types the TOTP code the badge sends
// (joystick up) into whichever window has focus. Built as a GUI-subsystem exe, so it runs
// windowless; -install registers it to start at logon.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// The badge frames codes this way so its boot log can never be mistaken for a code.
var codeLine = regexp.MustCompile(`^#BADGYTOTP:(\d{6,8})$`)

// Must match the badge's pollBridge(); it hides the send option after 5 s of silence.
const (
	heartbeat      = "#BRIDGE:HELLO\n"
	heartbeatEvery = 2 * time.Second
)

// CP2104 on the Badgy.
const (
	badgyVID = "10C4"
	badgyPID = "EA60"
)

type config struct {
	port  string
	enter bool
}

// parseCode returns the code carried by one serial line, or "" if the line is not a code line.
func parseCode(line string) string {
	m := codeLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return ""
	}
	return m[1]
}

// findPort returns the configured port, or the first CP210x USB serial port present.
func findPort(cfg config) (string, error) {
	if cfg.port != "" {
		return cfg.port, nil
	}
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return "", err
	}
	for _, p := range ports {
		if p.IsUSB && strings.EqualFold(p.VID, badgyVID) && strings.EqualFold(p.PID, badgyPID) {
			return p.Name, nil
		}
	}
	return "", errors.New("no CP210x port present")
}

// listen reads one port until it errors (typically the badge being switched off, which
// removes the port) and types every code line it sees.
func listen(name string, cfg config) error {
	// DTR and RTS stay deasserted: on the Badgy they drive reset and GPIO0, and toggling
	// them on open would reset the badge or drop it into the bootloader.
	p, err := serial.Open(name, &serial.Mode{
		BaudRate:          115200,
		InitialStatusBits: &serial.ModemOutputBits{DTR: false, RTS: false},
	})
	if err != nil {
		return err
	}
	defer p.Close()
	log.Printf("listening on %s", name)
	setStatus(status{connected: true, text: "Badge connected on " + name})

	// Heartbeat: the badge only offers "right: type" while it hears one of these.
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			if _, err := p.Write([]byte(heartbeat)); err != nil {
				return // the reader sees the same failure and ends listen
			}
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()

	sc := bufio.NewScanner(p)
	for sc.Scan() {
		code := parseCode(sc.Text())
		if code == "" {
			continue
		}
		if err := typeString(code, cfg.enter); err != nil {
			log.Printf("typing failed: %v", err)
			continue
		}
		log.Printf("typed a %d-digit code", len(code)) // never log the code itself
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("port closed")
}

func run(cfg config) {
	lastErr := ""
	for {
		name, err := findPort(cfg)
		if err == nil {
			err = listen(name, cfg)
		}
		setStatus(status{text: "Waiting for badge"})
		if msg := err.Error(); msg != lastErr { // one log line per state change, not per retry
			log.Printf("waiting for badge: %v", err)
			lastErr = msg
		}
		time.Sleep(time.Second)
	}
}

func openLog() {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "BadgyTOTP")
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "bridge.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		log.SetOutput(f)
	}
}

func main() {
	var cfg config
	install := flag.Bool("install", false, "start at logon (current user) with the other flags given, then exit")
	uninstall := flag.Bool("uninstall", false, "remove the start-at-logon entry, then exit")
	flag.StringVar(&cfg.port, "port", "", "serial port, e.g. COM5 (default: auto-detect the CP210x)")
	flag.BoolVar(&cfg.enter, "enter", false, "press Enter after typing the code")
	flag.Parse()

	openLog()
	switch {
	case *install:
		exit(installRun(cfg), "installed: starts at logon")
	case *uninstall:
		exit(uninstallRun(), "uninstalled")
	}

	if !singleInstance() {
		log.Printf("another badgy-bridge is already running, exiting")
		return
	}
	log.Printf("badgy-bridge started (port=%q enter=%v)", cfg.port, cfg.enter)
	runTray(cfg)
}

func exit(err error, ok string) {
	if err != nil {
		log.Print(err)
		messageBox("badgy-bridge", err.Error())
		os.Exit(1)
	}
	log.Print(ok)
	messageBox("badgy-bridge", fmt.Sprintf("badgy-bridge %s.", ok))
}
