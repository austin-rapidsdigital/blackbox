//go:build windows

package check

import (
	"errors"
	"os/exec"
	"time"

	"github.com/casea1/blackbox/internal/winevt"
)

// Supported reports whether the live check works on this OS.
const Supported = true

// Run checks the local Windows system against the STIG for its kind:
// Windows 11 for a workstation, Windows Server 2025 for a server.
func Run() []Result {
	kind := "Client"
	if b, err := exec.Command("reg.exe", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "InstallationType").Output(); err == nil {
		if v, ok := ParseRegSZ(string(b), "InstallationType"); ok {
			kind = v
		}
	}
	base := BaselineFor(kind)
	out := []Result{{Area: "Baseline", Item: "Compared with", Status: Info, Have: base.Name, Want: base.Name}}
	if b, err := exec.Command("auditpol.exe", "/get", "/category:*", "/r").Output(); err != nil {
		out = append(out, Result{Area: "Audit policy", Item: "auditpol", Status: Error,
			Have: "could not run auditpol: " + err.Error(), Want: "readable (run as Administrator)"})
	} else if have, err := ParseAuditpol(string(b)); err != nil {
		out = append(out, Result{Area: "Audit policy", Item: "auditpol", Status: Error, Have: err.Error()})
	} else {
		out = append(out, EvaluateAuditpol(base, have)...)
	}
	out = append(out, EvaluateRegistry(base, func(key, value string) (string, error) {
		b, err := exec.Command("reg.exe", "query", key, "/v", value).Output()
		return string(b), err
	})...)
	out = append(out, EvaluateLogs(base, winevt.GetLogSettings, winevt.GetLogHistory)...)
	ps, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", DefenderQuery).Output()
	out = append(out, EvaluateDefender(string(ps), err, time.Now())...)
	return out
}

// MissingRulesLive is only available on Linux.
func MissingRulesLive() (string, bool, error) {
	return "", false, errors.New("audit rules are for Linux")
}

// RulesOnlyInAuditRules is only meaningful on Linux.
func RulesOnlyInAuditRules() int { return 0 }
