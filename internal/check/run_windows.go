//go:build windows

package check

import (
	"os/exec"

	"github.com/casea1/blackbox/internal/winevt"
)

// Supported reports whether the live check works on this OS.
const Supported = true

// Run checks the local Windows system.
func Run() []Result {
	var out []Result
	if b, err := exec.Command("auditpol.exe", "/get", "/category:*", "/r").Output(); err != nil {
		out = append(out, Result{Area: "Audit policy", Item: "auditpol", Status: Error,
			Have: "could not run auditpol: " + err.Error(), Want: "readable (run as Administrator)"})
	} else if have, err := ParseAuditpol(string(b)); err != nil {
		out = append(out, Result{Area: "Audit policy", Item: "auditpol", Status: Error, Have: err.Error()})
	} else {
		out = append(out, EvaluateAuditpol(have)...)
	}
	out = append(out, EvaluateRegistry(func(key, value string) (string, error) {
		b, err := exec.Command("reg.exe", "query", key, "/v", value).Output()
		return string(b), err
	})...)
	out = append(out, EvaluateLogs(winevt.GetLogSettings)...)
	return out
}
