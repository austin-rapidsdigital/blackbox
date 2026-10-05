//go:build !windows && !linux

package check

import "fmt"

// Supported reports whether the live check works on this OS.
const Supported = false

// Run is not yet implemented off Windows (Linux auditd checks come with
// Linux collection).
func Run() []Result { return nil }

// MissingRulesLive is only available on Linux.
func MissingRulesLive() (string, bool, error) {
	return "", false, fmt.Errorf("audit rules are for Linux")
}

// RulesOnlyInAuditRules is only meaningful on Linux.
func RulesOnlyInAuditRules() []string { return nil }

// OldRulesFilesPresent is only meaningful on Linux.
func OldRulesFilesPresent() []string { return nil }
