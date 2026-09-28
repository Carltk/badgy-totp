package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"

	"fyne.io/systray"
)

// status is what the tray shows; run() reports every change through setStatus.
type status struct {
	connected bool
	text      string
}

var (
	statusCh  = make(chan status, 8)
	iconOn    = makeIcon(color.RGBA{0x3B, 0x82, 0xF6, 0xFF}) // badge connected
	iconOff   = makeIcon(color.RGBA{0x9C, 0xA3, 0xAF, 0xFF}) // waiting for badge
	lastState status
)

func setStatus(s status) {
	if s == lastState {
		return
	}
	lastState = s
	select {
	case statusCh <- s:
	default: // tray not keeping up; the next change will land
	}
}

func runTray(cfg config) {
	systray.Run(func() { onTrayReady(cfg) }, func() {})
}

func onTrayReady(cfg config) {
	systray.SetIcon(iconOff)
	systray.SetTitle("BadgyTOTP bridge")
	systray.SetTooltip("BadgyTOTP bridge: waiting for badge")

	mStatus := systray.AddMenuItem("Waiting for badge", "")
	mStatus.Disable()
	systray.AddSeparator()
	mLogon := systray.AddMenuItemCheckbox("Start at logon", "Run the bridge when you sign in", isInstalled())
	mQuit := systray.AddMenuItem("Quit", "Stop the bridge")

	go run(cfg)

	for {
		select {
		case s := <-statusCh:
			mStatus.SetTitle(s.text)
			systray.SetTooltip("BadgyTOTP bridge: " + s.text)
			if s.connected {
				systray.SetIcon(iconOn)
			} else {
				systray.SetIcon(iconOff)
			}
		case <-mLogon.ClickedCh:
			var err error
			if mLogon.Checked() {
				err = uninstallRun()
			} else {
				err = installRun(cfg)
			}
			if err != nil {
				messageBox("badgy-bridge", err.Error())
			}
			if isInstalled() {
				mLogon.Check()
			} else {
				mLogon.Uncheck()
			}
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// makeIcon draws a 32x32 badge: a rounded body in the given colour with a white "screen".
// Windows accepts a PNG wrapped in a one-entry ICO container.
func makeIcon(body color.RGBA) []byte {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	white := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if inRounded(x, y, 2, 6, 29, 25, 5) {
				img.Set(x, y, body)
			}
			if x >= 7 && x <= 24 && y >= 11 && y <= 20 {
				img.Set(x, y, white)
			}
		}
	}
	var p bytes.Buffer
	_ = png.Encode(&p, img)

	var ico bytes.Buffer
	w := func(v any) { _ = binary.Write(&ico, binary.LittleEndian, v) }
	w(uint16(0))          // reserved
	w(uint16(1))          // type: icon
	w(uint16(1))          // image count
	w([]byte{n, n, 0, 0}) // width, height, palette, reserved
	w(uint16(1))          // colour planes
	w(uint16(32))         // bits per pixel
	w(uint32(p.Len()))    // image size
	w(uint32(6 + 16))     // offset of image data
	ico.Write(p.Bytes())
	return ico.Bytes()
}

func inRounded(x, y, x0, y0, x1, y1, r int) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx, cy := x, y
	if x < x0+r {
		cx = x0 + r
	} else if x > x1-r {
		cx = x1 - r
	}
	if y < y0+r {
		cy = y0 + r
	} else if y > y1-r {
		cy = y1 - r
	}
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}
