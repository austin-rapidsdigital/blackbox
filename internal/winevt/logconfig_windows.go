//go:build windows

package winevt

import (
	"fmt"
	"os/exec"
)

// GetLogSettings reads a log's configuration with wevtutil.
func GetLogSettings(channel string) (LogSettings, error) {
	out, err := exec.Command("wevtutil.exe", "gl", channel).Output()
	if err != nil {
		return LogSettings{}, fmt.Errorf("wevtutil gl %s: %w", channel, err)
	}
	return ParseLogSettings(string(out)), nil
}
