package report

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// R1: a failed logon whose user name is a spreadsheet formula stays text
// in every CSV.
func TestCSVFormulaInjection(t *testing.T) {
	evil := `=HYPERLINK("http://x","y")`
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", evil, "10.1.1.99")...), Options{})
	var b bytes.Buffer
	if err := r.writeCSV(&b); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b.Bytes(), []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range recs[1:] {
		for _, f := range rec {
			if strings.HasPrefix(f, "=") || strings.HasPrefix(f, "+") || strings.HasPrefix(f, "@") {
				t.Errorf("events.csv field starts a formula: %q", f)
			}
			if f == "'"+evil {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the user name should be kept, as text: %v", recs)
	}
	if got := csvText([][]string{{"-cmd", "@x", "ok", "\tx"}}); strings.Contains(got, ",-") || strings.HasPrefix(got, "-") {
		t.Errorf("csvText not made safe: %q", got)
	}
}

// R5: summary.json counts PowerShell under its own key, as the report's
// pages do, not under other_security.
func TestSummaryCountsPowerShell(t *testing.T) {
	r := buildFrom([]*event.Event{
		{Time: fx0, Host: "DSK1", Source: "Microsoft-Windows-PowerShell/Operational", Category: event.CatOther, Severity: event.SevMedium, Action: "powershell_suspicious", Summary: "x"},
		{Time: fx0, Host: "DSK1", Category: event.CatOther, Severity: event.SevMedium, Action: "service_installed", Summary: "y"},
	}, Options{})
	got := r.summary().ByCategory
	if got["powershell"] != 1 || got["other_security"] != 1 {
		t.Errorf("by_category = %v, want powershell 1 and other_security 1", got)
	}
}

// R6: verify fails on a file added to the report folder, and on a
// manifest cut down to leave a file out.
func TestVerifyFindsAddedAndUnlistedFiles(t *testing.T) {
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", "jsmith", "10.1.1.99")...), Options{})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("a fresh report should verify: %v %v", p, err)
	}
	os.WriteFile(filepath.Join(dir, "extra.html"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "desktop.ini"), []byte("x"), 0o644) // Windows adds these itself
	p, _ := Verify(dir)
	if len(p) != 1 || !strings.Contains(p[0], "extra.html: not in the manifest") {
		t.Errorf("added file: %v", p)
	}
	os.Remove(filepath.Join(dir, "extra.html"))
	// Remove summary.json and its line from the manifest.
	m, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(string(m)), "\n") {
		if !strings.HasSuffix(l, "summary.json") {
			keep = append(keep, l)
		}
	}
	os.Chmod(filepath.Join(dir, "manifest.sha256"), 0o644)
	os.WriteFile(filepath.Join(dir, "manifest.sha256"), []byte(strings.Join(keep, "\n")+"\n"), 0o644)
	os.Remove(filepath.Join(dir, "summary.json"))
	if p, _ := Verify(dir); len(p) == 0 {
		t.Error("a manifest without summary.json verified")
	}
}

// R7: a one-minute interim report doesn't call an hourly sender silent;
// a week without a collection does.
func TestShortReportIsNotSilence(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	sys := []SystemInfo{{Name: "DSK1", OS: "windows", LastRun: end.Add(-time.Minute)}, {Name: "claude-code", OS: "linux", Via: "", LastRun: end.Add(-40 * time.Minute)}}
	runs := []*store.Run{{Time: end.Add(-time.Minute), Host: "DSK1", OS: "windows"}}
	ev := []*event.Event{{Time: end.Add(-30 * time.Second), Host: "DSK1", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}
	short := Build(ev, runs, Options{WindowStart: end.Add(-time.Minute), WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Systems: sys, Interim: true})
	if len(short.Silent) != 0 {
		t.Errorf("a 1-minute report called %v silent", short.Silent[0].Name)
	}
	sys[1].LastRun = end.AddDate(0, 0, -8)
	week := Build(ev, runs, Options{WindowStart: end.AddDate(0, 0, -7), WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Systems: sys})
	if len(week.Silent) != 1 {
		t.Errorf("a week without collection should be silent: %v", week.Silent)
	}
}

// C4: one SSH sign-in and sign-out is one row each, whether it comes from
// auth.log read through two logs, or from auditd's two login records.
func TestLinuxSessionCountedOnce(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	defer func() { time.Local = saved }()
	count := func(evs []*event.Event, action string) int {
		r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)})
		n := 0
		for _, e := range r.Events {
			if e.Action == action {
				n++
			}
		}
		return n
	}
	auth := "../../testdata/linux/ssh-session-auth.log"
	evs, _, err := collect.LinuxFiles(nil, []string{auth, auth}, "", "", time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if n := count(evs, "logon"); n != 1 {
		t.Errorf("auth.log: %d logon rows, want 1", n)
	}
	if n := count(evs, "logoff"); n != 1 {
		t.Errorf("auth.log: %d logoff rows, want 1", n)
	}
	evs, _, err = collect.LinuxFiles([]string{"../../testdata/linux/ssh-session-audit.log"}, nil, "claude-code", "", time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if n := count(evs, "logon"); n != 1 {
		t.Errorf("audit.log: %d logon rows, want 1", n)
	}
	if n := count(evs, "logoff"); n != 1 {
		t.Errorf("audit.log: %d logoff rows, want 1", n)
	}
}

// C5: Audit health says when each system's settings were checked.
func TestHealthShowsCheckTime(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	r := Build([]*event.Event{{Time: fx0, Host: "claude-code", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}, nil,
		Options{WindowEnd: end, Location: time.UTC, Systems: []SystemInfo{{Name: "claude-code", OS: "linux", LastRun: end}},
			CheckSets: []CheckSet{{Host: "claude-code", Time: fx0.Add(90 * time.Minute)}}})
	hp := r.healthPage()
	if hp == nil || len(hp.Groups) == 0 || hp.Groups[0].Rows[0].CheckedAt == "" {
		t.Fatalf("no check time: %+v", hp)
	}
}

// C6: auditd stopping in a planned restart is routine; stopped on its own
// it stays High.
func TestRebootIsNotAuditTampering(t *testing.T) {
	stop := func() *event.Event {
		return &event.Event{Time: fx0.Add(10 * time.Second), Host: "claude-code", OS: "linux", Category: event.CatIntegrity,
			Severity: event.SevHigh, Action: "audit_stopped", User: "root", Summary: "auditd stopped by root"}
	}
	reboot := &event.Event{Time: fx0, Host: "claude-code", OS: "linux", Category: event.CatPrivileged, Severity: event.SevLow,
		Action: "sudo_command", User: "austin", Command: "/usr/sbin/reboot", Summary: "austin ran reboot with sudo"}
	r := buildFrom([]*event.Event{reboot, stop()}, Options{})
	for _, e := range r.Events {
		if e.Action == "audit_stopped" && e.Severity != event.SevInfo {
			t.Errorf("auditd stop in a reboot is %s", e.Severity)
		}
	}
	if hasFinding(r, "Auditing was switched off") {
		t.Error("a reboot raised \"Auditing was switched off\"")
	}
	r = buildFrom([]*event.Event{stop()}, Options{})
	if !hasFinding(r, "Auditing was switched off") {
		t.Errorf("auditd stopped by root, no restart: want a finding, got %v", findingTitles(r))
	}
}

// V1, V2: verify requires every data file report.html loads, and
// events.zip; a needed file the manifest leaves out is one clear line.
func TestVerifyNeedsDataFilesAndEventsZip(t *testing.T) {
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", "jsmith", "10.1.1.99")...), Options{})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	cut := func(drop func(string) bool) {
		m, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
		var keep []string
		for _, l := range strings.Split(strings.TrimSpace(string(m)), "\n") {
			if !drop(l) {
				keep = append(keep, l)
			}
		}
		os.Chmod(filepath.Join(dir, "manifest.sha256"), 0o644)
		os.WriteFile(filepath.Join(dir, "manifest.sha256"), []byte(strings.Join(keep, "\n")+"\n"), 0o644)
	}
	data, _ := filepath.Glob(filepath.Join(dir, "data", "*.js"))
	if len(data) == 0 {
		t.Fatal("report has no data files")
	}
	one := "data/" + filepath.Base(data[0])
	cut(func(l string) bool { return strings.HasSuffix(l, "  "+one) || strings.HasSuffix(l, "  events.zip") })
	os.Remove(filepath.Join(dir, "events.zip"))
	p, _ := Verify(dir)
	joined := strings.Join(p, "\n")
	if len(p) != 2 || !strings.Contains(joined, one+": not in the manifest, though the report needs it") ||
		!strings.Contains(joined, "events.zip: missing, and not in the manifest") {
		t.Errorf("problems:\n%s", joined)
	}
	cut(func(l string) bool { return strings.HasSuffix(l, "  report.html") })
	p, _ = Verify(dir)
	n := 0
	for _, l := range p {
		if strings.HasPrefix(l, "report.html:") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("report.html reported %d times: %v", n, p)
	}
}

// A9: reports removed under retention_days are listed in the next one.
func TestRemovedReportsListed(t *testing.T) {
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", "jsmith", "10.1.1.99")...), Options{RetentionDays: 30})
	r.Removed = []string{"2026-08-01_DSK1", "2026-08-08_DSK1"}
	found := false
	for _, l := range r.checklist(r.SystemRows, nil) {
		if l.Title == "Older reports removed" && strings.Contains(l.What, "2 reports deleted under retention_days = 30, with their original logs: 2026-08-01_DSK1, 2026-08-08_DSK1") {
			found = true
		}
	}
	if !found {
		t.Error("removed reports not listed")
	}
	if s := r.summary(); len(s.Removed) != 2 {
		t.Errorf("summary: %v", s.Removed)
	}
}

// U1: a burst within one second is "at", not "between 18:17:02 and
// 18:17:02".
func TestSpanSameSecond(t *testing.T) {
	r := buildFrom(nil, Options{})
	if s := r.span(fx0, fx0.Add(300*time.Millisecond)); s != "at 10:00:00" {
		t.Errorf("same second: %q", s)
	}
	if s := r.span(fx0, fx0.Add(2*time.Minute)); s != "between 10:00:00 and 10:02:00" {
		t.Errorf("two minutes: %q", s)
	}
}

// U3: an administrator's logon (4624 and 4672, one logon ID) is one row,
// which still counts as using administrator rights.
func TestAdminLogonIsOneRow(t *testing.T) {
	xml := []string{
		winEvent(4624, 900, fx0, "TargetUserName", "jsmith", "TargetDomainName", "DSK1", "TargetUserSid", "S-1-5-21-1-2-3-1001",
			"LogonType", "2", "TargetLogonId", "0x5a1", "ElevatedToken", "%%1842"),
		winEvent(4672, 901, fx0.Add(10*time.Millisecond), "SubjectUserName", "jsmith", "SubjectDomainName", "DSK1",
			"SubjectUserSid", "S-1-5-21-1-2-3-1001", "SubjectLogonId", "0x5a1", "PrivilegeList", "SeDebugPrivilege"),
	}
	r := buildFrom(translateAll(t, xml...), Options{})
	if len(r.Events) != 1 || r.Events[0].Action != "logon" || detail(r.Events[0], "Privileges") == "" {
		for _, e := range r.Events {
			t.Logf("%s: %s", e.Action, e.Summary)
		}
		t.Fatalf("want one logon row with the privileges, got %d rows", len(r.Events))
	}
	if !adminActivity(r.rows[0]) {
		t.Error("the merged logon does not count as administrator activity")
	}
}

// E1: a CSV field with a bare carriage return is quoted, so a value can't
// split a row in a spreadsheet.
func TestCSVQuotesCarriageReturn(t *testing.T) {
	if !strings.Contains(appJS, `/[",\r\n]/.test(s)`) {
		t.Error("app.js CSV export doesn't quote fields with a carriage return")
	}
}
