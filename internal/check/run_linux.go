//go:build linux

package check

import (
	"os"
	"os/exec"
	"strings"
)

// Supported reports whether the live check works on this OS.
const Supported = true

// Run checks the local Linux system.
func Run() []Result {
	var out []Result
	svc := Result{Area: "Audit service", Item: "auditd running", Want: "active",
		Affects: "Logons, sudo, account changes and audit integrity (without it, only auth.log is available)"}
	b, _ := exec.Command("systemctl", "is-active", "auditd").Output()
	svc.Have = strings.TrimSpace(string(b))
	if svc.Have == "active" {
		svc.Status = Pass
	} else {
		svc.Status = Fail
		svc.Fix = "install auditd (apt install auditd, or dnf install audit) and run systemctl enable --now auditd"
		if svc.Have == "" {
			svc.Have = "not installed"
		}
	}
	out = append(out, svc)
	if svc.Status == Pass {
		rules, rerr := exec.Command("auditctl", "-l").Output()
		status, _ := exec.Command("auditctl", "-s").Output()
		if rerr != nil {
			out = append(out, Result{Area: "Audit rules", Item: "auditctl -l", Status: Error,
				Have: "could not read the loaded rules (run as root)", Want: "readable"})
		} else {
			out = append(out, EvaluateAuditRules(string(rules), string(status))...)
		}
		if conf, err := os.ReadFile("/etc/audit/auditd.conf"); err == nil {
			out = append(out, EvaluateAuditdConf(ParseAuditdConf(string(conf)))...)
		}
	}
	if cl, err := os.ReadFile("/proc/cmdline"); err == nil {
		out = append(out, EvaluateCmdline(string(cl)))
	}
	sys := Result{Area: "System log", Item: "Kernel and udisks messages kept", Want: "syslog file or persistent journal",
		Affects: "USB & Removable Media (device details and who mounted them)"}
	switch {
	case exists("/var/log/syslog"):
		sys.Status, sys.Have = Pass, "/var/log/syslog"
	case exists("/var/log/messages"):
		sys.Status, sys.Have = Pass, "/var/log/messages"
	case exists("/var/log/journal"):
		sys.Status, sys.Have = Pass, "persistent systemd journal"
	default:
		sys.Status, sys.Have = Fail, "journal is not persistent (lost at reboot)"
		sys.Fix = "mkdir -p /var/log/journal && systemctl restart systemd-journald"
	}
	out = append(out, sys)
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
