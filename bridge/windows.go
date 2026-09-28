package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procSendInput   = user32.NewProc("SendInput")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

const (
	inputKeyboard  = 1
	keyeventfKeyUp = 0x0002
	keyeventfUni   = 0x0004
	vkReturn       = 0x0D
	runKey         = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue       = "BadgyTOTPBridge"
)

type keybdInput struct {
	vk        uint16
	scan      uint16
	flags     uint32
	time      uint32
	extraInfo uintptr
}

// Only used for its size: MOUSEINPUT is the largest arm of INPUT's union.
type mouseInput struct {
	dx, dy                 int32
	mouseData, flags, time uint32
	extraInfo              uintptr
}

// INPUT with the KEYBDINPUT arm of the union, padded to the MOUSEINPUT arm. SendInput checks
// cbSize, so this must be exactly sizeof(INPUT): 40 bytes on amd64, 28 on 386.
type keyInput struct {
	typ uint32
	ki  keybdInput
	_   [unsafe.Sizeof(mouseInput{}) - unsafe.Sizeof(keybdInput{})]byte
}

func key(vk, scan uint16, flags uint32) keyInput {
	return keyInput{typ: inputKeyboard, ki: keybdInput{vk: vk, scan: scan, flags: flags}}
}

// typeString types s as Unicode keystrokes (layout-independent), optionally followed by Enter.
func typeString(s string, enter bool) error {
	var in []keyInput
	for _, r := range s {
		in = append(in, key(0, uint16(r), keyeventfUni), key(0, uint16(r), keyeventfUni|keyeventfKeyUp))
	}
	if enter {
		in = append(in, key(vkReturn, 0, 0), key(vkReturn, 0, keyeventfKeyUp))
	}
	n, _, err := procSendInput.Call(uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])), unsafe.Sizeof(in[0]))
	if int(n) != len(in) {
		return fmt.Errorf("SendInput sent %d of %d events: %v", n, len(in), err)
	}
	return nil
}

// singleInstance holds a named mutex for the life of the process, so a second copy started
// at logon (or by hand) exits instead of fighting over the port.
func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\BadgyTOTPBridge`)
	_, err := windows.CreateMutex(nil, false, name)
	return err != windows.ERROR_ALREADY_EXISTS
}

func installRun(cfg config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := []string{`"` + exe + `"`}
	if cfg.port != "" {
		cmd = append(cmd, "-port", cfg.port)
	}
	if cfg.enter {
		cmd = append(cmd, "-enter")
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runValue, strings.Join(cmd, " "))
}

func isInstalled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

func uninstallRun() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0)
}
