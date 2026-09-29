// Package check compares a system's audit configuration with what the
// DISA STIGs require and explains what is missing and how it affects the
// report. It only reports; it never changes settings.
package check

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"github.com/casea1/blackbox/internal/winevt"
)

// Status of one check.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Warn  Status = "warn"
	Info  Status = "info"
	Error Status = "error"
)

// Result is one checked setting.
type Result struct {
	Area    string `json:"area"`
	Item    string `json:"item"`
	Status  Status `json:"status"`
	Have    string `json:"have"`
	Want    string `json:"want"`
	Affects string `json:"affects,omitempty"` // report section that is incomplete without it
	Fix     string `json:"fix,omitempty"`
}

// Summary counts results by status.
func Summary(rs []Result) (pass, fail, warn int) {
	for _, r := range rs {
		switch r.Status {
		case Pass:
			pass++
		case Fail, Error:
			fail++
		case Warn:
			warn++
		}
	}
	return
}

type auditReq struct {
	guid, name string
	succ, fail bool
	affects    string
}

// windowsAuditReqs is the Windows 11 / Server 2025 STIG advanced audit
// policy baseline.
var windowsAuditReqs = []auditReq{
	{"{0CCE923F-69AE-11D9-BED3-505054503030}", "Credential Validation", true, true, "Failed Logons"},
	{"{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management", true, false, "Account & Group Changes"},
	{"{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", true, true, "Account & Group Changes"},
	{"{0CCE9248-69AE-11D9-BED3-505054503030}", "Plug and Play Events", true, false, "USB & Removable Media"},
	{"{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", true, false, "Privileged Activity (elevated programs)"},
	{"{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", false, true, "Failed Logons"},
	{"{0CCE9249-69AE-11D9-BED3-505054503030}", "Group Membership", true, false, ""},
	{"{0CCE9216-69AE-11D9-BED3-505054503030}", "Logoff", true, false, "Logon Activity"},
	{"{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", true, true, "Logon Activity and Failed Logons"},
	{"{0CCE921B-69AE-11D9-BED3-505054503030}", "Special Logon", true, false, "Privileged Activity (administrator logons)"},
	{"{0CCE921C-69AE-11D9-BED3-505054503030}", "Other Logon/Logoff Events", true, true, "Logon Activity (Remote Desktop sessions)"},
	{"{0CCE9224-69AE-11D9-BED3-505054503030}", "File Share", true, true, ""},
	{"{0CCE9244-69AE-11D9-BED3-505054503030}", "Detailed File Share", false, true, ""},
	{"{0CCE9227-69AE-11D9-BED3-505054503030}", "Other Object Access Events", true, true, "Other Security Events (scheduled tasks)"},
	{"{0CCE9245-69AE-11D9-BED3-505054503030}", "Removable Storage", true, true, "USB & Removable Media (files read/written)"},
	{"{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", true, true, "Audit & System Integrity"},
	{"{0CCE9230-69AE-11D9-BED3-505054503030}", "Authentication Policy Change", true, false, ""},
	{"{0CCE9231-69AE-11D9-BED3-505054503030}", "Authorization Policy Change", true, false, ""},
	{"{0CCE9232-69AE-11D9-BED3-505054503030}", "MPSSVC Rule-Level Policy Change", true, true, ""},
	{"{0CCE9234-69AE-11D9-BED3-505054503030}", "Other Policy Change Events", true, true, ""},
	{"{0CCE9228-69AE-11D9-BED3-505054503030}", "Sensitive Privilege Use", true, true, ""},
	{"{0CCE9213-69AE-11D9-BED3-505054503030}", "IPsec Driver", false, true, ""},
	{"{0CCE9214-69AE-11D9-BED3-505054503030}", "Other System Events", true, true, ""},
	{"{0CCE9210-69AE-11D9-BED3-505054503030}", "Security State Change", true, false, "Audit & System Integrity (startup, time changes)"},
	{"{0CCE9211-69AE-11D9-BED3-505054503030}", "Security System Extension", true, false, "Other Security Events (services installed)"},
	{"{0CCE9212-69AE-11D9-BED3-505054503030}", "System Integrity", true, true, "Audit & System Integrity"},
}

func settingText(s, f bool) string {
	switch {
	case s && f:
		return "Success and Failure"
	case s:
		return "Success"
	case f:
		return "Failure"
	}
	return "No Auditing"
}

// ParseAuditpol reads `auditpol /get /category:* /r` CSV output into a
// map of subcategory GUID → (success, failure).
func ParseAuditpol(text string) (map[string][2]bool, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse auditpol output: %w", err)
	}
	guidCol, setCol := -1, -1
	out := map[string][2]bool{}
	for _, row := range rows {
		if guidCol < 0 {
			for i, h := range row {
				switch strings.TrimSpace(h) {
				case "Subcategory GUID":
					guidCol = i
				case "Inclusion Setting":
					setCol = i
				}
			}
			continue
		}
		if len(row) <= guidCol || len(row) <= setCol {
			continue
		}
		v := strings.ToLower(row[setCol])
		out[strings.ToUpper(strings.TrimSpace(row[guidCol]))] = [2]bool{
			strings.Contains(v, "success"), strings.Contains(v, "failure"),
		}
	}
	if guidCol < 0 || setCol < 0 {
		return nil, fmt.Errorf("auditpol output has no Subcategory GUID / Inclusion Setting columns")
	}
	return out, nil
}

// EvaluateAuditpol compares auditpol settings with the STIG baseline.
func EvaluateAuditpol(have map[string][2]bool) []Result {
	var out []Result
	for _, q := range windowsAuditReqs {
		h := have[q.guid]
		r := Result{Area: "Audit policy", Item: q.name, Have: settingText(h[0], h[1]),
			Want: settingText(q.succ, q.fail), Affects: q.affects, Status: Pass}
		if (q.succ && !h[0]) || (q.fail && !h[1]) {
			r.Status = Fail
			var flags []string
			if q.succ && !h[0] {
				flags = append(flags, "/success:enable")
			}
			if q.fail && !h[1] {
				flags = append(flags, "/failure:enable")
			}
			r.Fix = fmt.Sprintf(`auditpol /set /subcategory:"%s" %s  (or set it in Group Policy: Advanced Audit Policy Configuration)`, q.guid, strings.Join(flags, " "))
		}
		out = append(out, r)
	}
	return out
}

// ParseRegDWORD extracts a REG_DWORD value from `reg query` output.
func ParseRegDWORD(text, name string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) && f[1] == "REG_DWORD" {
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(f[2]), "0x"), 16, 64)
			return v, err == nil
		}
	}
	return 0, false
}

type regReq struct {
	key, value, item, affects, why string
}

var windowsRegReqs = []regReq{
	{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "ProcessCreationIncludeCmdLine_Enabled",
		"Include command line in process creation events", "Privileged Activity (full commands, not just program names)",
		"Group Policy: Administrative Templates > System > Audit Process Creation"},
	{`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "SCENoApplyLegacyAuditPolicy",
		"Force audit policy subcategory settings", "All sections (advanced audit policy may be ignored without it)",
		"Group Policy: Security Options > Audit: Force audit policy subcategory settings"},
}

// EvaluateRegistry checks the registry settings; query returns `reg query`
// output for a key/value.
func EvaluateRegistry(query func(key, value string) (string, error)) []Result {
	var out []Result
	for _, q := range windowsRegReqs {
		r := Result{Area: "Audit settings", Item: q.item, Want: "Enabled (1)", Affects: q.affects}
		text, err := query(q.key, q.value)
		v, ok := ParseRegDWORD(text, q.value)
		switch {
		case err == nil && ok && v == 1:
			r.Status, r.Have = Pass, "Enabled (1)"
		case ok:
			r.Status, r.Have = Fail, fmt.Sprintf("%d", v)
		default:
			r.Status, r.Have = Fail, "Not set"
		}
		if r.Status == Fail {
			r.Fix = fmt.Sprintf(`reg add "%s" /v %s /t REG_DWORD /d 1 /f  (or %s)`, q.key, q.value, q.why)
		}
		out = append(out, r)
	}
	return out
}

// Minimum log sizes from the Windows 11 STIG.
var minLogSize = map[string]uint64{
	"Security":    1024000 * 1024,
	"System":      32768 * 1024,
	"Application": 32768 * 1024,
}

// USB-related logs Blackbox reads, and whether they matter.
var usbLogs = []struct {
	name     string
	required bool
	note     string
}{
	{"Microsoft-Windows-Partition/Diagnostic", true, "USB storage make, model, serial number and size (on by default)"},
	{"Microsoft-Windows-Kernel-PnP/Configuration", true, "first-time USB device setup (on by default)"},
	{"Microsoft-Windows-DriverFrameworks-UserMode/Operational", false, "extra USB connect/disconnect detail (optional, off by default)"},
}

// EvaluateLogs checks log sizes and that USB-related logs are enabled.
func EvaluateLogs(get func(string) (winevt.LogSettings, error)) []Result {
	var out []Result
	for _, name := range []string{"Security", "System", "Application"} {
		r := Result{Area: "Event log size", Item: name + " log", Want: fmt.Sprintf("at least %s", mb(minLogSize[name]))}
		s, err := get(name)
		if err != nil {
			r.Status, r.Have = Error, err.Error()
			out = append(out, r)
			continue
		}
		r.Have = fmt.Sprintf("%s, %s", mb(s.MaxSize), s.OverwriteMode())
		if s.MaxSize >= minLogSize[name] {
			r.Status = Pass
		} else {
			r.Status = Fail
			r.Affects = "Events may be overwritten before collection on busy systems"
			r.Fix = fmt.Sprintf("wevtutil sl %s /ms:%d  (or Group Policy: Event Log Service > %s > Specify the maximum log file size)", name, minLogSize[name], name)
		}
		out = append(out, r)
	}
	for _, l := range usbLogs {
		r := Result{Area: "USB logging", Item: l.name, Want: "Enabled", Affects: "USB & Removable Media: " + l.note}
		s, err := get(l.name)
		switch {
		case err != nil:
			r.Status, r.Have = Error, err.Error()
		case s.Enabled:
			r.Status, r.Have = Pass, "Enabled"
		case l.required:
			r.Status, r.Have = Fail, "Disabled"
			r.Fix = fmt.Sprintf(`wevtutil sl "%s" /e:true`, l.name)
		default:
			r.Status, r.Have, r.Want = Info, "Disabled", "Optional"
			r.Fix = fmt.Sprintf(`wevtutil sl "%s" /e:true`, l.name)
		}
		out = append(out, r)
	}
	return out
}

func mb(b uint64) string {
	if b >= 1024*1024*1024 {
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	}
	return fmt.Sprintf("%d MB", b/(1024*1024))
}
