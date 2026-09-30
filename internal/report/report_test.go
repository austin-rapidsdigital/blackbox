package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	r := build(t, Options{Site: "Test Site", SignatureBlock: true, ReviewRoles: []string{"ISSO / Auditor", "ISSM"}, InReportsDir: true})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return b
	}
	// One page per category plus overview, health, people, review and the
	// full printable file.
	for _, name := range []string{"index.html", "health.html", "people.html", "review.html", "full-report.html",
		"privileged.html", "removable_media.html", "failed_logon.html", "account_changes.html",
		"audit_integrity.html", "other_security.html", "logon_activity.html"} {
		read(name)
	}
	checks := map[string][]string{
		"index.html":           {"Possible password guessing", `href="failed_logon.html#r`, "Mon 28 Sep 2026", "Test Site"},
		"privileged.html":      {`class="on"><span>Privileged Activity`, "wevtutil  cl Application"},
		"people.html":          {`href="privileged.html#user=admin_jd"`},
		"review.html":          {"ISSO / Auditor", "ISSM"},
		"full-report.html":     {`href="#privileged"`, "Possible password guessing", "ISSM", "wevtutil  cl Application"},
		"failed_logon.html":    {"Failed logon for administrator"},
		"removable_media.html": {"SanDisk Cruzer Blade"},
	}
	for name, wants := range checks {
		b := read(name)
		for _, w := range wants {
			if !bytes.Contains(b, []byte(w)) {
				t.Errorf("%s missing %q", name, w)
			}
		}
	}
	for _, name := range []string{"index.html", "full-report.html"} {
		if bytes.Contains(read(name), []byte("SECRET")) || bytes.Contains(read(name), []byte("UNCLASSIFIED")) {
			t.Errorf("%s still contains a classification banner", name)
		}
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("fresh report should verify: %v %v", p, err)
	}
	os.WriteFile(filepath.Join(dir, "privileged.html"), []byte("tampered"), 0o640)
	if p, _ := Verify(dir); len(p) != 1 || !strings.Contains(p[0], "CHANGED") {
		t.Errorf("tampering not detected: %v", p)
	}
	if err := WriteIndex(filepath.Dir(dir), "Test Site", time.UTC); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(filepath.Dir(dir), "index.html"))
	if !bytes.Contains(idx, []byte("rep/index.html")) {
		t.Error("list of reports does not link the report")
	}
}
