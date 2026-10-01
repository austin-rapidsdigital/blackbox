package winevt

import (
	"bufio"
	"strconv"
	"strings"
	"time"
)

// LogSettings is the configuration of one event log.
type LogSettings struct {
	Name       string
	Enabled    bool
	MaxSize    uint64 // bytes
	Retention  bool   // true = do not overwrite (stop logging when full)
	AutoBackup bool   // true = archive the log when full
}

// ParseLogSettings parses `wevtutil gl <log>` output.
func ParseLogSettings(text string) LogSettings {
	var s LogSettings
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "name":
			s.Name = v
		case "enabled":
			s.Enabled = v == "true"
		case "maxSize":
			s.MaxSize, _ = strconv.ParseUint(v, 10, 64)
		case "retention":
			s.Retention = v == "true"
		case "autoBackup":
			s.AutoBackup = v == "true"
		}
	}
	return s
}

// OverwriteMode describes what happens when the log is full.
func (s LogSettings) OverwriteMode() string {
	switch {
	case s.Retention && s.AutoBackup:
		return "archive the log when full"
	case s.Retention:
		return "stop logging when full"
	}
	return "overwrite oldest events when full"
}

// LogHistory is how far back a log reaches and how full it is.
type LogHistory struct {
	Oldest, Newest time.Time
	FileSize       uint64 // bytes in use
}

// ParseFileSize reads fileSize from `wevtutil gli <log>` output.
func ParseFileSize(text string) uint64 {
	for _, l := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && k == "fileSize" {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}
