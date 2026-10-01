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

// GetLogHistory reads how full a log is and the times of its oldest and
// newest events.
func GetLogHistory(channel string) (LogHistory, error) {
	out, err := exec.Command("wevtutil.exe", "gli", channel).Output()
	if err != nil {
		return LogHistory{}, fmt.Errorf("wevtutil gli %s: %w", channel, err)
	}
	h := LogHistory{FileSize: ParseFileSize(string(out))}
	oldest, newest, err := Edges(channel)
	if err != nil {
		return h, err
	}
	if oldest != nil && newest != nil {
		h.Oldest, h.Newest = oldest.Time, newest.Time
	}
	return h, nil
}
