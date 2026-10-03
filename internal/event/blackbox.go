package event

import (
	"regexp"
	"strings"
)

// Blackbox watching itself (AU-9): a command that changes what Blackbox
// reports or keeps, stops its schedule, or removes it.

var (
	bbProgram  = `(?:^|[\s/\\"'])blackboxw?(?:\.exe)?["']?`
	bbConfig   = regexp.MustCompile(`(?i)` + bbProgram + `\s+config\s+set\s+(\S+)`)
	bbUninst   = regexp.MustCompile(`(?i)` + bbProgram + `\s+uninstall\b|(?:^|[\s/])uninstall\.sh\b`)
	bbStop     = regexp.MustCompile(`(?i)\bsystemctl\s+(?:\S+\s+)*(stop|disable|mask|kill)\s+(?:\S+\s+)*blackbox(?:\.timer|\.service)?\b`)
	bbTaskOff  = regexp.MustCompile(`(?i)\bschtasks(?:\.exe)?\s+.*(?:/delete|/disable|/end)\b.*\bblackbox|\bschtasks(?:\.exe)?\s+.*\bblackbox\b.*(?:/delete|/disable|/end)\b|(?:disable|unregister|stop)-scheduledtask\b.*\bblackbox`)
	bbRemoveFS = regexp.MustCompile(`(?i)\b(?:rm|del|erase|remove-item|rmdir|rd)\b.*(?:/etc/blackbox|/var/lib/blackbox|programdata[\\/]blackbox|/usr/local/bin/blackbox)`)
)

// sensitiveSettings change what the report shows or how long evidence is
// kept.
var sensitiveSettings = map[string]bool{"exclude_users": true, "exclude_processes": true, "retention_days": true,
	"report_dir": true, "send_to": true, "inbox": true}

// BlackboxChange recognises a command that changes Blackbox itself. ok is
// false for any other command.
func BlackboxChange(cmd string) (action string, sev Severity, what string, ok bool) {
	switch {
	case bbUninst.MatchString(cmd):
		return "blackbox_uninstalled", SevHigh, "removed Blackbox", true
	case bbStop.MatchString(cmd), bbTaskOff.MatchString(cmd):
		return "blackbox_stopped", SevHigh, "stopped or disabled Blackbox's scheduled collection", true
	case bbRemoveFS.MatchString(cmd):
		return "blackbox_files_removed", SevHigh, "deleted Blackbox's files", true
	}
	if m := bbConfig.FindStringSubmatch(cmd); m != nil {
		key := strings.ToLower(strings.Trim(m[1], `"'`))
		if sensitiveSettings[key] {
			return "blackbox_config_changed", SevHigh, "changed Blackbox's " + key + " setting (what it reports or keeps)", true
		}
		return "blackbox_config_changed", SevMedium, "changed Blackbox's " + key + " setting", true
	}
	return "", "", "", false
}
