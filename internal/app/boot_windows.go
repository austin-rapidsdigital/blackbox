package app

import (
	"syscall"
	"time"
)

var getTickCount64 = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

// bootTime is now minus the time since Windows started.
func bootTime() time.Time {
	ms, _, _ := getTickCount64.Call()
	if ms == 0 {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Minute)
}
