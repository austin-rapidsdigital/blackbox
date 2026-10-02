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

// SetSubsystem returns a copy of exe marked windowed or console.
func SetSubsystem(exe []byte, windowed bool) ([]byte, error) {
	off, err := subsystemOffset(exe)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), exe...)
	v := uint16(subsystemConsole)
	if windowed {
		v = subsystemWindowed
	}
	binary.LittleEndian.PutUint16(out[off:], v)
	return out, nil
}

// IsWindowed reports whether exe is marked windowed.
func IsWindowed(exe []byte) (bool, error) {
	off, err := subsystemOffset(exe)
	if err != nil {
		return false, err
	}
	return binary.LittleEndian.Uint16(exe[off:]) == subsystemWindowed, nil
}
