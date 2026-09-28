package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
	"unsafe"
)

func TestParseCode(t *testing.T) {
	cases := map[string]string{
		"#BADGYTOTP:123456":         "123456",
		"#BADGYTOTP:12345678\r":     "12345678",
		"  #BADGYTOTP:012345  ":     "012345",
		"#BADGYTOTP:12345":          "", // too short
		"#BADGYTOTP:123456789":      "", // too long
		"#BADGYTOTP:12a456":         "",
		"[boot] time 1790555189":    "",
		"x#BADGYTOTP:123456":        "", // must be the whole line
		"#BADGYTOTP:123456 extra":   "",
		"\x00\xff#BADGYTOTP:123456": "", // boot-ROM garbage on the same line is rejected, not stripped
	}
	for in, want := range cases {
		if got := parseCode(in); got != want {
			t.Errorf("parseCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// SendInput rejects the whole batch if cbSize is wrong. sizeof(INPUT) from the Windows SDK:
// 40 on 64-bit, 28 on 32-bit; the union starts at 8 and 4 respectively.
func TestKeyInputLayout(t *testing.T) {
	wantSize, wantOff := uintptr(40), uintptr(8)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		wantSize, wantOff = 28, 4
	}
	var k keyInput
	if got := unsafe.Sizeof(k); got != wantSize {
		t.Errorf("sizeof(keyInput) = %d, want %d", got, wantSize)
	}
	if got := unsafe.Offsetof(k.ki); got != wantOff {
		t.Errorf("offsetof(ki) = %d, want %d", got, wantOff)
	}
}

// The tray icon is a hand-built ICO: header fields must agree with the embedded PNG.
func TestIcon(t *testing.T) {
	for _, ico := range [][]byte{iconOn, iconOff} {
		if binary.LittleEndian.Uint16(ico[2:]) != 1 || binary.LittleEndian.Uint16(ico[4:]) != 1 {
			t.Fatal("bad ICO header")
		}
		size, off := binary.LittleEndian.Uint32(ico[14:]), binary.LittleEndian.Uint32(ico[18:])
		if int(off+size) != len(ico) {
			t.Fatalf("offset %d + size %d != len %d", off, size, len(ico))
		}
		img, err := png.Decode(bytes.NewReader(ico[off:]))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("embedded PNG: %v", err)
		}
	}
}
