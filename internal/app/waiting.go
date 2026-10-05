package app

import (
	"fmt"
	"time"

	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/store"
)

// SendStaleAfter is how long data may wait to be sent before status, the
// status icon and the exit code of "blackbox status" warn (L10).
const SendStaleAfter = 24 * time.Hour

// Low free space on the data folder's disk: under 1 GB, or under 5%.
const (
	lowSpaceBytes   = 1 << 30
	lowSpacePercent = 5
)

// waitingSince is when the oldest data still waiting to be sent was
// queued (zero when nothing waits, or this computer does not send).
func (a *App) waitingSince(st *store.Store) time.Time {
	if a.Cfg.SendTo == "" {
		return time.Time{}
	}
	t, _ := lan.OldestQueued(st)
	return t
}

// lowSpace describes the data folder's disk when it is nearly full, or "".
// Queued evidence is never deleted to make room (L10).
func lowSpace(dir string) string {
	free, total, err := diskSpace(dir)
	if err != nil || total == 0 {
		return ""
	}
	if free >= lowSpaceBytes && free*100/total >= lowSpacePercent {
		return ""
	}
	return fmt.Sprintf("only %s free of %s on the disk holding %s", sizeText(free), sizeText(total), dir)
}

func sizeText(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KB", b>>10)
}
