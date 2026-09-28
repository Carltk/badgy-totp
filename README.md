# badgy-totp

Turns a [Badgy](https://github.com/sqfmi/badgy) e-paper badge into a TOTP authenticator for shared
accounts: the Google, Slack or other logins a team shares, where the second factor shouldn't live
on one person's phone.

Switch it on and it joins WiFi, syncs the time, turns WiFi off, and shows the current 6-digit code
in large digits with a countdown bar. The joystick picks the account. After two minutes idle it
sleeps. Secrets are added from a web page the badge serves in setup mode, and an optional Windows
tray app can type the code into the focused window for you.

## Features

- Standard TOTP (RFC 6238, SHA1, 6–8 digits, 10–120 s period): works with Google, Slack, Microsoft,
  GitHub and any service that gives you a QR code or a base32 key.
- Setup page for adding accounts from an `otpauth://` link or a pasted key, deleting them, backup
  and restore, and choosing the clock's timezone.
- Time from NTP, with a fallback to the HTTP `Date` header for networks that block NTP.
  No time, no codes: it never shows a code it can't trust.
- The next code appears in the last 7 seconds of each period.
- Battery-friendly: WiFi is only on for the time sync, and the badge deep-sleeps when idle.
- `badgy-bridge`: a Windows tray app that types the code when you press right on the joystick.

## Hardware

| | |
|---|---|
| Board | Badgy (ESP-12 / ESP8266, 4 MB flash, CP2104 USB-serial) |
| Rev 2B and older | GDEH029A1 panel, PlatformIO env `badgy` (tested) |
| Rev 2C | GDEW029T5 panel, env `badgy_rev2c` (builds, **untested on hardware**) |
| Power | USB, or a rechargeable LIR2450 / 1S LiPo (never a CR2450: see the Badgy README) |

Rev 2C is the one with a closed solder jumper marked `*` on the back and a green tab on the screen
protector film.

## Build and flash

Needs [PlatformIO](https://platformio.org/).

```
pio test -e native                 # TOTP core against the RFC 4226/6238 test vectors
pio run -e badgy -t upload         # or -e badgy_rev2c
```

PlatformIO finds the serial port itself; add `--upload-port COM5` (or `/dev/ttyUSB0`) if it picks
the wrong one.

Two Badgy quirks worth knowing before you start:

- **It doesn't reset after flashing.** Slide the power switch off and on to start the new firmware.
- **It won't flash while asleep.** Deep sleep ignores the USB reset line. Switch it on and flash
  within the first couple of minutes, while it's awake.

You may want to back up the stock firmware first:
`esptool.py --port COM5 read_flash 0 0x400000 badgy-original.bin`.

## First-time setup

1. Hold the **centre** button while sliding the power switch on. This enters setup mode, which is
   also where a badge with no saved WiFi goes on its own.
2. The screen shows a WiFi network `Badgy-TOTP` and a password. Join it from a phone or laptop,
   and pick your WiFi network in the page that opens. Only WPA2-PSK networks work, not Enterprise.
3. Once it's joined, the screen shows `http://<ip>`, `http://badgy-totp.local` and a 6-digit PIN.
   Browse to it, enter the PIN and choose an admin password.
4. Log in as `admin`. Add accounts from an `otpauth://` link, or type an issuer, account name and
   base32 secret. When a service shows you a QR code, its "can't scan?" link reveals the key.
5. Set the clock timezone if you want local time on the badge. Codes are always UTC, so this only
   affects the clock.
6. Press **Finish and sleep**. Setup mode also ends by itself after 10 minutes idle.

## Using it

Slide the power switch on. Around 5–10 seconds later the code is on screen.

| Joystick | Action |
|---|---|
| Up / Down | Previous / next account |
| Right | Type the code on the PC (only when `badgy-bridge` is running; see below) |
| Centre | Full refresh, which clears e-paper ghosting |
| Left | Unused: its pin is the serial receive line |

To wake it after it sleeps, slide the switch off and on. The ESP8266 can only wake from deep sleep
by a reset, so the buttons can't do it.

## Backup and restore

**Download backup** in setup mode saves a text file of `otpauth://` links, one per account. Any
authenticator app can import it, and **Restore** loads it back: merging by default and skipping
secrets already on the badge, or replacing everything if you tick the box. A restore with no valid
lines never wipes the badge.

The download needs the admin login *and* the PIN currently on the badge's screen, and the PIN
changes after each download. **The file is not encrypted**: whoever holds it can generate the codes.

Moving from Authy: Authy has no export. Re-enrol each account (turn its authenticator off and on
again) and scan the new QR into both Authy and the badge. One secret works in several apps at once.

## Windows bridge (`badgy-bridge`)

A tray app that listens on the badge's USB serial port and types the code into whichever window has
focus when you press right.

```
cd bridge
set GOARCH=amd64
go build -ldflags "-H windowsgui -s -w" -o badgy-bridge.exe .
```

Run `badgy-bridge.exe`. The tray icon is blue while the badge is connected and grey while it's
waiting. Right-click it for the status, a **Start at logon** toggle and **Quit**. It finds the badge
by its USB ID (CP210x `10C4:EA60`), and it copes with the port vanishing when you switch the badge
off.

| Flag | Effect |
|---|---|
| `-port COM5` | Use this port instead of auto-detecting |
| `-enter` | Press Enter after the code |
| `-install` / `-uninstall` | Add or remove the start-at-logon entry (the tray toggle does the same) |

It logs to `%LOCALAPPDATA%\BadgyTOTP\bridge.log`, and never logs a code. **Quit it before
flashing**, because it holds the COM port.

How it talks to the badge: the bridge sends `#BRIDGE:HELLO` every 2 seconds, and the badge only
offers "right: type" while it hears one, so the option disappears within 5 seconds of the bridge
stopping. A right press sends `#BADGYTOTP:<code>`, and the bridge types only lines that match that
exactly, so boot noise can never be typed.

## Security model

Worth reading before trusting it with anything important:

- **The secrets are stored unencrypted in flash.** The ESP8266 has no flash encryption, so anyone
  with the badge and a USB cable can read them out. Treat the badge like the shared password
  itself, and lock it away when it isn't in use.
- In normal use the badge serves nothing over the network. The web page only exists in setup mode,
  which needs someone physically holding the centre button at power-on.
- Setting or resetting the admin password needs the PIN shown on the badge, which proves you're
  standing next to it. Five wrong PINs replace it with a new one.
- The login uses HTTP digest auth, so the password doesn't cross the network in the clear. Page
  contents do (plain HTTP on the LAN), including a secret while you add it. Do setup on a network
  you trust.
- The account list and pages never show a stored secret. Only the PIN-gated backup does.
- Forms carry a per-session CSRF token.
- `badgy-bridge` types into whatever has focus. Check where your cursor is before pressing right.

## Project layout

```
lib/totp/        portable TOTP, HMAC-SHA1, base32 and otpauth:// code (no Arduino dependencies)
src/main.cpp     badge firmware: display, buttons, WiFi and time, setup web server
test/            native unit tests for lib/totp (RFC test vectors)
bridge/          Windows tray app (Go)
```

## License

MIT. See [LICENSE](LICENSE).
