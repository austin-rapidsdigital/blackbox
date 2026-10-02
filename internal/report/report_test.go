package report

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
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
		// every page is in the one file
		`data-view="overview"`, `data-view="detections"`, `data-view="search"`, `data-view="people"`, `data-view="systems"`,
		`data-view="privileged"`, `data-view="usb"`, `data-view="failed"`, `data-view="accounts"`, `data-view="integrity"`,
		`data-view="powershell"`, `data-view="other"`, `data-view="logons"`,
		`data-view="health"`, `data-view="trends"`, `data-view="logs"`, "Test Site",
	} {
		if !bytes.Contains(html, []byte(want)) {
			t.Errorf("report.html missing %q", want)
		}
	}
	// The events are in the data folder, one file per page and day.
	var data strings.Builder
	files, _ := filepath.Glob(filepath.Join(dir, "data", "*.js"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		data.WriteString(unpackData(t, b))
	}
	for _, want := range []string{"wevtutil  cl Application", "SanDisk Cruzer Blade", "admin_jd"} {
		if !strings.Contains(data.String(), want) {
			t.Errorf("event data missing %q", want)
		}
	}
	if bytes.Contains(html, []byte("wevtutil  cl Application")) {
		t.Error("events belong in the data files, not report.html")
	}
	if !strings.Contains(fmt.Sprint(r.summary().Detections), "Possible password guessing") {
		t.Error("detection missing from summary.json")
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
	os.WriteFile(files[0], []byte("tampered"), 0o640)
	if p, _ := Verify(dir); len(p) != 2 || !strings.Contains(p[0], "CHANGED") || !strings.Contains(p[1], "CHANGED") {
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
	if !strings.Contains(dataText(t, r), "auditd USER_CMD record, serial") {
		t.Error("Linux 'recorded as' text missing")
	}
}

// dataText is the decompressed text of every event data file of r.
func dataText(t *testing.T, r *Report) string {
	t.Helper()
	_, files, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, f := range files {
		all.WriteString(unpackData(t, f.Body))
	}
	return all.String()
}

// unpackData decodes one data file (BB.put("key","base64 gzip")).
func unpackData(t *testing.T, body []byte) string {
	t.Helper()
	s := string(body)
	i := strings.Index(s, `,"`)
	j := strings.LastIndex(s, `");`)
	if i < 0 || j < i {
		t.Fatalf("bad data file: %.80s", s)
	}
	raw, err := base64.StdEncoding.DecodeString(s[i+2 : j])
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSystemsPage(t *testing.T) {
	end := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -7)
	runs := []*store.Run{
		{Time: end.Add(-2 * time.Hour), Host: "WS-01", OS: "windows"},
		{Time: end.Add(-26 * time.Hour), Host: "WS-01", OS: "windows"}, // a 24-hour pause
		{Time: end.Add(-3 * time.Hour), Host: "ubuntu-vm", OS: "linux"},
	}
	events := []*event.Event{
		{Time: end.Add(-3 * time.Hour), Host: "ubuntu-vm", OS: "linux", Category: event.CatPrivileged, Severity: event.SevHigh, Action: "sudo", Summary: "sudo"},
		{Time: end.Add(-4 * time.Hour), Host: "WS-01", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"},
	}
	r := Build(events, runs, Options{
		WindowStart: start, WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Collector: true,
		Systems: []SystemInfo{
			{Name: "WS-01", OS: "windows", FirstSeen: start.AddDate(0, -1, 0)},
			{Name: "UBUNTU-VM", OS: "linux", Via: "WS-01", FirstSeen: start.AddDate(0, -1, 0)},
			{Name: "WS-03", OS: "windows", FirstSeen: start.AddDate(0, -1, 0), LastRun: start.Add(-72 * time.Hour)},
		},
		CheckSets: []CheckSet{
			NewCheckSet("WS-01", end, []check.Result{{Area: "a", Item: "b", Status: check.Fail}, {Area: "a", Item: "c", Status: check.Pass}}),
			NewCheckSet("ubuntu-vm", end, []check.Result{{Area: "a", Item: "c", Status: check.Pass}}),
		},
	})
	if !r.ShowSystems() || len(r.SystemRows) != 3 {
		t.Fatalf("systems: %+v", r.SystemRows)
	}
	first := r.SystemRows[0]
	if first.Name != "WS-03" || first.Status != "silent" || !strings.Contains(first.StatusMsg, "No collection received") {
		t.Errorf("silent system should be listed first: %+v", first)
	}
	if len(r.Silent) != 1 {
		t.Errorf("silent systems: %v", r.Silent)
	}
	var vm, ws SystemRow
	for _, s := range r.SystemRows {
		switch s.Name {
		case "ubuntu-vm", "UBUNTU-VM":
			vm = s
		case "WS-01":
			ws = s
		}
	}
	if vm.Events != 1 || vm.High != 1 || vm.Via != "WS-01" || vm.Status != "ok" {
		t.Errorf("VM row (names differ only in case, so they are one system): %+v", vm)
	}
	if ws.Status != "warn" || ws.Checks == nil || ws.Checks.Fail != 1 {
		t.Errorf("WS-01 has a failing audit setting: %+v", ws)
	}
	if len(r.Hosts) != 3 {
		t.Errorf("every system is listed in the report, even with no events: %v", r.Hosts)
	}
	warned := strings.Join(r.Health.Warnings, "\n")
	if !strings.Contains(warned, "WS-03") || !strings.Contains(warned, "WS-01: the longest time between collections") {
		t.Errorf("warnings:\n%s", warned)
	}

	var html bytes.Buffer
	if err := r.WriteHTML(&html, nil); err != nil {
		t.Fatal(err)
	}
	h := html.String()
	// Redesign: the Systems page's own checks return with step 3
	// (WS-03 listed, the VM "via WS-01", failing settings, the audit trail).
	for _, want := range []string{`data-view="systems"`} {
		if !strings.Contains(h, want) {
			t.Errorf("report HTML missing %q", want)
		}
	}
	sum := r.summary()
	if len(sum.Systems) != 3 || sum.Systems[0].Status != "silent" {
		t.Errorf("summary.json systems: %+v", sum.Systems)
	}
}

// Old events can carry a computer's former name (a renamed PC, or a VM
// cloned from an image). That is not a second computer gone silent.
func TestFormerNameIsNotASilentSystem(t *testing.T) {
	end := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	runs := []*store.Run{{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows"}}
	events := []*event.Event{
		{Time: end.Add(-2 * time.Hour), Host: "WS-07", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"},
		{Time: end.AddDate(0, -2, 0), Host: "IMAGE-BUILD-01", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "old logon"},
	}
	r := Build(events, runs, Options{WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection",
		Systems: []SystemInfo{{Name: "WS-07", OS: "windows", LastRun: end.Add(-time.Hour)}}})
	if r.ShowSystems() || len(r.Silent) != 0 || len(r.SystemRows) != 1 {
		t.Errorf("a former name became a system: %+v", r.SystemRows)
	}
	if len(r.Events) != 2 {
		t.Error("events under the former name must still be reported")
	}
	for _, w := range r.Health.Warnings {
		if strings.Contains(w, "IMAGE-BUILD-01") {
			t.Errorf("false warning: %s", w)
		}
	}
}

func TestSingleSystemHasNoSystemsPage(t *testing.T) {
	r := build(t, Options{CheckSets: []CheckSet{NewCheckSet("WS-07", time.Now(), []check.Result{{Area: "a", Item: "b", Status: check.Pass}})}})
	if r.ShowSystems() {
		t.Error("a standalone report should not have a Systems page")
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), `<span>System</span><b>`) {
		t.Error("a standalone report names its system in the sidebar")
	}
	// Redesign: the single check set shown directly returns with Audit
	// health in step 4.
}

// Above MaxListed, routine Info events are counted but not listed; flagged
// events and those a detection points to are always listed.
func TestSizeSafeguard(t *testing.T) {
	defer func(n int) { MaxListed = n }(MaxListed)
	MaxListed = 5
	end := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	var events []*event.Event
	for i := 0; i < 8; i++ {
		events = append(events, &event.Event{Time: end.Add(-time.Duration(10-i) * time.Hour), Host: "WS-01", OS: "windows",
			Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: fmt.Sprintf("logon %d", i)})
	}
	events = append(events, &event.Event{Time: end.Add(-time.Hour), Host: "WS-01", OS: "windows",
		Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", Summary: "Security log cleared"})
	r := Build(events, nil, Options{WindowEnd: end, Generated: end, Location: time.UTC})
	pages, files, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	var logons, integrity *EventPage
	for _, p := range pages {
		switch p.ID {
		case "logons":
			logons = p
		case "integrity":
			integrity = p
		}
	}
	if logons.Total != 8 || logons.Omitted != 4 || integrity.Omitted != 0 {
		t.Errorf("logons %d listed, %d omitted; integrity omitted %d", logons.Total, logons.Omitted, integrity.Omitted)
	}
	var data strings.Builder
	for _, f := range files {
		data.WriteString(unpackData(t, f.Body))
	}
	if !strings.Contains(data.String(), "Security log cleared") || !strings.Contains(data.String(), "logon 0") || strings.Contains(data.String(), "logon 7") {
		t.Error("the safeguard should keep flagged and the earliest routine events")
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html, pages); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "4 routine Info events are counted in this report but not listed") {
		t.Error("the page must say events were not listed")
	}
}
