// Package winexe switches a Windows program between console and windowed.
//
// Blackbox is one program. Run from a command prompt or the scheduled task
// it is a console program; the setup file and the tray are the same
// program marked "windowed" (the Windows GUI subsystem), so Windows opens
// no console for them. The mark is two bytes in the program's header.
package winexe

import (
	"encoding/binary"
	"errors"
)

const (
	subsystemWindowed = 2 // IMAGE_SUBSYSTEM_WINDOWS_GUI
	subsystemConsole  = 3 // IMAGE_SUBSYSTEM_WINDOWS_CUI
)

// subsystemOffset finds the Subsystem field in a PE file's optional header.
func subsystemOffset(exe []byte) (int, error) {
	bad := errors.New("not a Windows program")
	if len(exe) < 0x40 || exe[0] != 'M' || exe[1] != 'Z' {
		return 0, bad
	}
	pe := int(binary.LittleEndian.Uint32(exe[0x3c:]))
	opt := pe + 24 // "PE\0\0" and the 20-byte file header
	if pe < 0 || opt+70 > len(exe) || string(exe[pe:pe+4]) != "PE\x00\x00" {
		return 0, bad
	}
	if m := binary.LittleEndian.Uint16(exe[opt:]); m != 0x10b && m != 0x20b {
		return 0, bad
	}
	return opt + 68, nil // the same place in PE32 and PE32+
}

// ConsoleResource is the ID of the RCDATA resource in which a release's
// setup file carries the console blackbox.exe, signed, so setup can
// install it unchanged (A10).
const ConsoleResource = 101

// SetSubsystem returns a copy of exe marked windowed or console. The mark
// is covered by an Authenticode signature, so a signed program whose mark
// changes loses its signature: it is then plainly unsigned, not signed
// with a signature that no longer matches.
func SetSubsystem(exe []byte, windowed bool) ([]byte, error) {
	off, err := subsystemOffset(exe)
	if err != nil {
		return nil, err
	}
	v := uint16(subsystemConsole)
	if windowed {
		v = subsystemWindowed
	}
	out := append([]byte(nil), exe...)
	if binary.LittleEndian.Uint16(out[off:]) == v {
		return out, nil
	}
	binary.LittleEndian.PutUint16(out[off:], v)
	return stripSignature(out, off), nil
}

// securityDir finds the certificate table's entry in the optional
// header's data directories (entry 4).
func securityDir(exe []byte, subsystemOff int) (int, bool) {
	opt := subsystemOff - 68
	dirs := opt + 96 // PE32
	if binary.LittleEndian.Uint16(exe[opt:]) == 0x20b {
		dirs = opt + 112 // PE32+
	}
	e := dirs + 4*8
	return e, e+8 <= len(exe)
}

// stripSignature removes the Authenticode certificate table.
func stripSignature(exe []byte, subsystemOff int) []byte {
	e, ok := securityDir(exe, subsystemOff)
	if !ok {
		return exe
	}
	at := int(binary.LittleEndian.Uint32(exe[e:]))
	size := int(binary.LittleEndian.Uint32(exe[e+4:]))
	if at == 0 || size == 0 {
		return exe
	}
	binary.LittleEndian.PutUint64(exe[e:], 0)
	if at+size == len(exe) && at <= len(exe) {
		exe = exe[:at] // the table is the last thing in the file
	}
	return exe
}

// Signed reports whether exe carries an Authenticode certificate table.
func Signed(exe []byte) bool {
	off, err := subsystemOffset(exe)
	if err != nil {
		return false
	}
	e, ok := securityDir(exe, off)
	return ok && binary.LittleEndian.Uint32(exe[e+4:]) != 0
}

// IsWindowed reports whether exe is marked windowed.
func IsWindowed(exe []byte) (bool, error) {
	off, err := subsystemOffset(exe)
	if err != nil {
		return false, err
	}
	return binary.LittleEndian.Uint16(exe[off:]) == subsystemWindowed, nil
}
