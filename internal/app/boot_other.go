//go:build !linux && !windows

package app

import "time"

func bootTime() time.Time { return time.Time{} }
