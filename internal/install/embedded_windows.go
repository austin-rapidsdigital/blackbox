//go:build windows

package install

import (
	"unsafe"

	"github.com/casea1/blackbox/internal/winexe"
)

var (
	procFindResourceW   = kernel32.NewProc("FindResourceW")
	procLoadResource    = kernel32.NewProc("LoadResource")
	procLockResource    = kernel32.NewProc("LockResource")
	procSizeofResource  = kernel32.NewProc("SizeofResource")
	procRtlMoveMemory   = kernel32.NewProc("RtlMoveMemory")
	rtRCData            = uintptr(10)
	consoleResourceName = uintptr(winexe.ConsoleResource)
)

// embeddedConsole returns the console blackbox.exe a release's setup file
// carries (signed, when the release is), or nil when this program has
// none: a development build, or the installed console program itself.
func embeddedConsole() []byte {
	res, _, _ := procFindResourceW.Call(0, consoleResourceName, rtRCData)
	if res == 0 {
		return nil
	}
	size, _, _ := procSizeofResource.Call(0, res)
	h, _, _ := procLoadResource.Call(0, res)
	if size == 0 || h == 0 {
		return nil
	}
	p, _, _ := procLockResource.Call(h)
	if p == 0 {
		return nil
	}
	b := make([]byte, size)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&b[0])), p, size)
	return b
}
