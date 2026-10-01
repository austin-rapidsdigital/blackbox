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
	STIG    string `json:"stig,omitempty"` // STIG rule IDs, e.g. WN11-AU-000505
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
	succ, fail string // STIG IDs requiring success / failure auditing ("" = not required)
	affects    string
	optional   bool // not a STIG requirement here, but this report needs it
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

// EvaluateAuditpol compares auditpol settings with a STIG baseline.
func EvaluateAuditpol(b Baseline, have map[string][2]bool) []Result {
	var out []Result
	for _, q := range b.Audit {
		h := have[q.guid]
		wantS, wantF := q.succ != "", q.fail != ""
		if q.optional {
			wantS, wantF = true, true
		}
		r := Result{Area: "Audit policy", Item: q.name, Have: settingText(h[0], h[1]),
			Want: settingText(wantS, wantF), Affects: q.affects, STIG: joinIDs(q.succ, q.fail), Status: Pass}
		if (wantS && !h[0]) || (wantF && !h[1]) {
			r.Status = Fail
			if q.optional {
				r.Status = Info
				r.Want += " (recommended for this report; not a STIG requirement for this system)"
			}
			var flags []string
			if wantS && !h[0] {
				flags = append(flags, "/success:enable")
			}
			if wantF && !h[1] {
				flags = append(flags, "/failure:enable")
			}
			r.Fix = fmt.Sprintf(`auditpol /set /subcategory:"%s" %s  (or set it in Group Policy: Advanced Audit Policy Configuration)`, q.guid, strings.Join(flags, " "))
		}
		out = append(out, r)
	}
	return out
}

func joinIDs(ids ...string) string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return strings.Join(out, ", ")
}

// ParseRegSZ extracts a REG_SZ value from `reg query` output.
func ParseRegSZ(text, name string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) && f[1] == "REG_SZ" {
			return strings.Join(f[2:], " "), true
		}
	}
	return "", false
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
	key, value, item, affects, why, stig string
}

// EvaluateRegistry checks the registry settings; query returns `reg query`
// output for a key/value.
func EvaluateRegistry(b Baseline, query func(key, value string) (string, error)) []Result {
	var out []Result
	for _, q := range b.Registry {
		r := Result{Area: "Audit settings", Item: q.item, Want: "Enabled (1)", Affects: q.affects, STIG: q.stig}
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
// history reports how far back a log reaches, for a baseline that wants
// the Security log to hold a week of events.
func EvaluateLogs(b Baseline, get func(string) (winevt.LogSettings, error), history func(string) (winevt.LogHistory, error)) []Result {
	var out []Result
	for _, q := range b.Logs {
		r := Result{Area: "Event log size", Item: q.name + " log", STIG: q.stig}
		s, err := get(q.name)
		if err != nil {
			r.Status, r.Have = Error, err.Error()
			out = append(out, r)
			continue
		}
		r.Have = fmt.Sprintf("%s, %s", mb(s.MaxSize), s.OverwriteMode())
		if q.week {
			out = append(out, holdsWeek(r, s, history))
			continue
		}
		r.Want = fmt.Sprintf("at least %s (%d KB)", mb(q.minKB*1024), q.minKB)
		if s.MaxSize >= q.minKB*1024 {
			r.Status = Pass
		} else {
			r.Status = Fail
			r.Affects = "Events may be overwritten before collection on busy systems"
			r.Fix = fmt.Sprintf("wevtutil sl %s /ms:%d  (or Group Policy: Event Log Service > %s > Specify the maximum log file size (KB): %d)", q.name, q.minKB*1024, q.name, q.minKB)
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
