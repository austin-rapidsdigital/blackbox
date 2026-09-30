package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

func sampleEvents(t *testing.T) []*event.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample-events.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := winevt.NewTranslator()
	var out []*event.Event
	if err := winevt.ParseStream(f, func(r *winevt.Raw) error {
		if e := tr.Translate(r); e != nil {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func build(t *testing.T, opt Options) *Report {
	opt.Location = time.UTC
	opt.WindowEnd = time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	return Build(sampleEvents(t), nil, opt)
}

func TestFindings(t *testing.T) {
	r := build(t, Options{})
	titles := map[string]bool{}
	for _, f := range r.Findings {
		titles[f.Title] = true
	}
	for _, want := range []string{"Possible password guessing", "One source tried several accounts", "Successful logon after failures"} {
		if !titles[want] {
			t.Errorf("missing finding %q (have %v)", want, titles)
		}
	}
}

func TestDedupeMergesSameDevice(t *testing.T) {
	r := build(t, Options{})
	n := 0
	for _, e := range r.Events {
		if e.Action == "usb_connected" && strings.Contains(e.Summary, "Cruzer") {
			n++
			if e.EventID != 1006 {
				t.Errorf("kept event %d; want the most detailed (Partition/Diagnostic 1006)", e.EventID)
			}
			if e.User != "jsmith" {
				t.Errorf("device attributed to %q, want jsmith (logged on at the keyboard)", e.User)
			}
		}
	}
	if n != 1 {
		t.Errorf("SanDisk connection appears %d times, want 1", n)
	}
	// 4625+4776 pairs collapse to one row per attempt.
	fails := 0
	for _, e := range r.Events {
		if e.Action == "logon_failed" && e.Target == "administrator" {
			fails++
		}
	}
	if fails != 6 {
		t.Errorf("administrator failures = %d, want 6", fails)
	}
}

func TestExclusions(t *testing.T) {
	r := build(t, Options{ExcludeUsers: []string{"JSMITH"}, ExcludeProcesses: []string{"excel.exe"}})
	for _, e := range r.Events {
		if strings.EqualFold(e.User, "jsmith") {
			t.Fatalf("excluded user still present: %s", e.Summary)
		}
	}
	if r.Excluded == 0 {
		t.Error("nothing counted as excluded")
	}
}

func TestNewDeviceFlag(t *testing.T) {
	known := map[string]time.Time{"WS-07|4c530001231109115405": time.Now()}
	r := build(t, Options{KnownDevices: known})
	if len(r.NewDevices) != 1 {
		t.Fatalf("new devices = %v, want only the Kingston stick", r.NewDevices)
	}
	for k := range r.NewDevices {
		if !strings.Contains(k, "e0d55ea573dcf450e97c0a7f") {
			t.Errorf("unexpected new device %q", k)
		}
	}
}

func TestHealthGapWarning(t *testing.T) {
	runs := []*store.Run{{Time: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), Host: "WS-07",
		Channels: []store.ChannelRun{{Channel: "Security", Read: 10, Gap: &store.Gap{Lost: 4200,
			From: time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)}}}}}
	r := Build(nil, runs, Options{Location: time.UTC, Source: "Live collection"})
	if len(r.Health.Gaps) != 1 || !strings.Contains(strings.Join(r.Health.Warnings, " "), "4,200 events in the Security log were overwritten") {
		t.Errorf("gap not reported: %+v", r.Health.Warnings)
	}
}

func TestWriteAndVerify(t *testing.T) {
	r := build(t, Options{Site: "Test Site", InReportsDir: true})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var htmlFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".html") {
			htmlFiles = append(htmlFiles, e.Name())
		}
	}
	if len(htmlFiles) != 1 || htmlFiles[0] != "report.html" {
		t.Fatalf("want exactly one HTML file (report.html), got %v", htmlFiles)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{
		// every view is in the one file
		`data-view="overview"`, `data-view="privileged"`, `data-view="removable_media"`, `data-view="failed_logon"`,
		`data-view="account_changes"`, `data-view="audit_integrity"`, `data-view="other_security"`,
		`data-view="logon_activity"`, `data-view="health"`, `data-view="people"`,
		// content and in-file links
		"Possible password guessing", `href="#r`, "Mon 28 Sep 2026", "Test Site",
		"wevtutil  cl Application", "SanDisk Cruzer Blade", `data-user="admin_jd"`,
	} {
		if !bytes.Contains(html, []byte(want)) {
			t.Errorf("report.html missing %q", want)
		}
	}
	for _, bad := range []string{"SECRET", "UNCLASSIFIED", ".html#", "Signature", "sign-off"} {
		if bytes.Contains(html, []byte(bad)) {
			t.Errorf("report.html should not contain %q", bad)
		}
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("fresh report should verify: %v %v", p, err)
	}
	os.WriteFile(filepath.Join(dir, "report.html"), []byte("tampered"), 0o640)
	if p, _ := Verify(dir); len(p) != 1 || !strings.Contains(p[0], "CHANGED") {
		t.Errorf("tampering not detected: %v", p)
	}
	if err := WriteIndex(filepath.Dir(dir), "Test Site", time.UTC); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(filepath.Dir(dir), "index.html"))
	if !bytes.Contains(idx, []byte("rep/report.html")) {
		t.Error("list of reports does not link the report")
	}
}

func TestLinuxReport(t *testing.T) {
	// Syslog times are local; the sample was written in New York time.
	ny, _ := time.LoadLocation("America/New_York")
	saved := time.Local
	time.Local = ny
	defer func() { time.Local = saved }()
	evs, run, err := collect.LinuxFiles([]string{"../../testdata/linux/ubuntu-audit.log"}, []string{"../../testdata/linux/ubuntu-syslog"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := Build(evs, []*store.Run{run}, Options{Location: time.UTC, WindowEnd: time.Now()})
	if len(r.Hosts) != 1 || r.Hosts[0] != "ubu-ws12" {
		t.Errorf("hosts = %v", r.Hosts)
	}
	titles := map[string]bool{}
	for _, f := range r.Findings {
		titles[f.Title] = true
	}
	for _, want := range []string{"Possible password guessing", "Auditing was switched off", "Successful logon after failures"} {
		if !titles[want] {
			t.Errorf("missing finding %q", want)
		}
	}
	if len(r.Health.AuditOff) != 1 || !strings.Contains(r.Health.AuditOff[0], "12 minutes") {
		t.Errorf("audit-off period = %v", r.Health.AuditOff)
	}
	// Duplicates merged: each SSH attempt once, lockout once, sudo+root command once.
	count := func(action, target string) int {
		n := 0
		for _, e := range r.Events {
			if e.Action == action && (target == "" || e.Target == target) {
				n++
			}
		}
		return n
	}
	if n := count("logon_failed", "root"); n != 7 { // 6 SSH attempts + the failed su
		t.Errorf("failed logons for root = %d, want 7", n)
	}
	if n := count("account_locked", ""); n != 1 {
		t.Errorf("lockouts = %d, want 1", n)
	}
	if n := count("root_command", ""); n != 0 {
		t.Errorf("root commands left after merging with sudo = %d, want 0", n)
	}
	if n := count("group_member_added", ""); n != 1 {
		t.Errorf("group additions = %d, want 1 (shadow group merged)", n)
	}
	// USB attributed to the person who mounted it (udisks), not merely the
	// latest console logon (mjones) and never the SSH user.
	want := map[string]string{"SanDisk Cruzer Blade": "jsmith", "Kingston DataTraveler 3.0": "jsmith"}
	for _, e := range r.Events {
		if e.Action == "usb_connected" && e.User != want[e.Target] {
			t.Errorf("%s attributed to %q, want %q", e.Target, e.User, want[e.Target])
		}
	}
	var buf bytes.Buffer
	if err := r.WriteHTML(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("auditd USER_CMD record, serial")) {
		t.Error("Linux 'recorded as' text missing")
	}
}
