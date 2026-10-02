package app

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// TestLANEndToEnd is the single-PC scenario: a Windows collector (WS-07,
// the Windows sample) and the Linux VM it hosts (ubu-ws12, the Ubuntu
// sample) sending through a shared folder, plus a retired-looking
// workstation that stopped sending. Set BLACKBOX_SAMPLE_OUT to keep the
// report (scripts/screenshots.sh uses it).
func TestLANEndToEnd(t *testing.T) {
	winEvents, winRun := windowsSample(t)
	vmEvents, vmRun := linuxSample(t)
	last := latest(append(append([]*event.Event{}, winEvents...), vmEvents...))
	end := last.Add(time.Hour).Truncate(time.Hour)

	base := t.TempDir()
	inbox := filepath.Join(base, "inbox")
	if err := lan.PrepareInbox(inbox, "WS-07"); err != nil {
		t.Fatal(err)
	}

	// The collector's own collection.
	col, _ := store.Open(filepath.Join(base, "collector"))
	stamp(winEvents, end.Add(-time.Hour))
	col.AppendEvents(end.Add(-time.Hour), winEvents)
	winRun.Time = end.Add(-time.Hour)
	col.AppendRun(winRun)
	col.AppendChecks(&store.CheckRecord{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Results: []check.Result{
		{Area: "Audit policy", Item: "Logon", Status: check.Pass, Have: "Success and Failure", Want: "Success and Failure"},
		{Area: "Event log size", Item: "Security log", Status: check.Fail, Have: "20 MB", Want: "at least 1000 MB"},
	}})
	col.NoteSystem("WS-07", "windows", "test", "", winRun.Time, time.Time{}, end)
	// A workstation that sent last month and then went quiet.
	col.NoteSystem("WS-09", "windows", "test", "", end.AddDate(0, 0, -12), end.AddDate(0, 0, -12), end.AddDate(0, -1, 0))
	col.State.ArchivedUntil = end // the test places the original logs itself
	col.Save()

	// The VM collects, but the report is produced before its batch arrives.
	vm, _ := store.Open(filepath.Join(base, "vm"))
	stamp(vmEvents, end.Add(-2*time.Hour))
	vm.AppendEvents(end.Add(-2*time.Hour), vmEvents)
	vmRun.Time = end.Add(-2 * time.Hour)
	vm.AppendRun(vmRun)
	vm.AppendChecks(&store.CheckRecord{Time: end.Add(-2 * time.Hour), Host: "ubu-ws12", OS: "linux", Results: []check.Result{
		{Area: "auditd", Item: "Audit rules", Status: check.Pass, Have: "loaded", Want: "loaded"},
	}})

	a := &App{Cfg: &config.Config{DataDir: col.Dir, ReportDir: filepath.Join(base, "reports"), Inbox: inbox, ReportEvery: "daily", SiteName: "Lab 3"},
		Version: "test", Loc: time.UTC}
	a.Now = func() time.Time { return end.Add(5 * time.Minute) }
	pendingLogs(t, a, "WS-07", end)
	first, err := a.report(col, end, true)
	if err != nil {
		t.Fatal(err)
	}
	if html := readFile(t, first, "report.html"); strings.Contains(html, "ubu-ws12") {
		t.Error("the VM's events had not arrived yet")
	}

	// The VM's batch arrives after the report; the next report has it.
	if _, err := lan.Export(vm, "ubu-ws12", "test", end.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := lan.Deliver(vm, inbox, "ubu-ws12"); err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return end.Add(time.Hour) }
	a.receive(col)
	next := end.AddDate(0, 0, 1)
	// The collector keeps collecting hourly.
	col.AppendRun(&store.Run{Time: next.Add(-time.Hour), Host: "WS-07", OS: "windows", Version: "test",
		Channels: []store.ChannelRun{{Channel: "Security", Read: 1200, Kept: 3}}})
	a.Now = func() time.Time { return next.Add(5 * time.Minute) }
	pendingLogs(t, a, "ubu-ws12", end.Add(-2*time.Hour)) // delivered with the VM's batch
	col.State.ArchivedUntil = next
	dir, err := a.report(col, next, true)
	if err != nil {
		t.Fatal(err)
	}
	html := readFile(t, dir, "report.html")
	for _, want := range []string{
		`data-view="systems"`, // Systems page
		"3 systems",           // every system, including the silent WS-09
		`data-pick="WS-09"`, `data-pick="ubu-ws12"`, `data-pick="WS-07"`,
		"No collection received in this period", // WS-09 is silent
		"Audit settings that need attention",    // failing settings shown
	} {
		if !strings.Contains(html, want) {
			t.Errorf("combined report missing %q", want)
		}
	}
	data := reportData(t, dir)
	for _, want := range []string{"ubu-ws12", `"Late"`} { // late arrivals are marked
		if !strings.Contains(data, want) {
			t.Errorf("combined report's event data missing %q", want)
		}
	}
	var sum report.Summary
	if err := json.Unmarshal([]byte(readFile(t, dir, "summary.json")), &sum); err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, s := range sum.Systems {
		status[s.Name] = s.Status
	}
	if status["WS-09"] != "silent" || status["WS-07"] != "warn" || status["ubu-ws12"] != "ok" {
		t.Errorf("summary.json systems: %+v", sum.Systems)
	}

	// A report run by hand mid-period is interim: marked as such, and the
	// schedule (the end of the last scheduled report) is unchanged.
	a.Now = func() time.Time { return next.Add(9 * time.Hour) }
	interim, err := a.report(col, a.now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(interim, "_interim") || !strings.Contains(readFile(t, interim, "report.html"), "Interim report.") {
		t.Errorf("interim report not marked: %s", interim)
	}
	if !col.State.LastWindowEnd.Equal(next) {
		t.Errorf("an interim report moved the schedule to %v", col.State.LastWindowEnd)
	}
	var isum report.Summary
	if err := json.Unmarshal([]byte(readFile(t, interim, "summary.json")), &isum); err != nil || !isum.Interim {
		t.Errorf("summary.json interim flag: %+v %v", isum.Interim, err)
	}
	if idx := readFile(t, filepath.Dir(interim), "index.html"); !strings.Contains(idx, `class="st int">Interim`) {
		t.Error("the list of reports does not mark the interim report")
	}
	if out := os.Getenv("BLACKBOX_SAMPLE_OUT"); out != "" {
		os.RemoveAll(out)
		if err := os.Rename(dir, out); err != nil {
			t.Fatal(err)
		}
	}
}

func windowsSample(t *testing.T) ([]*event.Event, *store.Run) {
	t.Helper()
	f, err := os.Open("../../testdata/sample-events.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, run, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error { return winevt.ParseStream(f, fn) }, "Security", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	run.Host, run.OS = "WS-07", "windows"
	return events, run
}

func linuxSample(t *testing.T) ([]*event.Event, *store.Run) {
	t.Helper()
	events, run, err := collect.LinuxFiles([]string{"../../testdata/linux/ubuntu-audit.log"}, []string{"../../testdata/linux/ubuntu-syslog"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	run.OS = "linux"
	return events, run
}

func stamp(events []*event.Event, collected time.Time) {
	for _, e := range events {
		e.Collected = collected
	}
}

func latest(events []*event.Event) time.Time {
	var t time.Time
	for _, e := range events {
		if e.Time.After(t) {
			t = e.Time
		}
	}
	return t
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// reportData is the decompressed text of a report's event data files.
func reportData(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "data", "*.js"))
	if len(files) == 0 {
		t.Fatal("report has no event data files")
	}
	var all strings.Builder
	for _, f := range files {
		s := readFile(t, filepath.Dir(f), filepath.Base(f))
		i, j := strings.Index(s, `,"`), strings.LastIndex(s, `");`)
		raw, err := base64.StdEncoding.DecodeString(s[i+2 : j])
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(zr)
		all.Write(b)
	}
	return all.String()
}

func TestReportFolderHoldsTheOriginalLogs(t *testing.T) {
	winEvents, winRun := windowsSample(t)
	end := latest(winEvents).Add(time.Hour).Truncate(time.Hour)
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	stamp(winEvents, end.Add(-time.Hour))
	st.AppendEvents(end.Add(-time.Hour), winEvents)
	winRun.Time = end.Add(-time.Hour)
	st.AppendRun(winRun)
	st.State.ArchivedUntil = end // this computer's logs are already saved up to the end
	st.Save()

	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily"},
		Version: "test", Loc: time.UTC}
	a.Now = func() time.Time { return end.Add(5 * time.Minute) }

	// Two days of this computer's logs, one received from a VM, and one
	// that ends after the period (it belongs to the next report).
	day := func(host string, to time.Time) string { return pendingLogs(t, a, host, to) }
	day("WS-07", end.Add(-24*time.Hour))
	day("WS-07", end)
	day("ubu-vm", end.Add(-2*time.Hour))
	later := day("ubu-vm", end.Add(3*time.Hour))

	dir, err := a.report(st, end, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"logs-WS-07.zip", "logs-ubu-vm.zip"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not in the report folder", f)
		}
	}
	if problems, err := report.Verify(dir); err != nil || len(problems) != 0 {
		t.Errorf("verify: %v %v", problems, err)
	}
	if !strings.Contains(readFile(t, dir, "manifest.sha256"), "logs-WS-07.zip") {
		t.Error("the logs are not in the manifest")
	}
	left, _ := archive.List(a.pendingLogsDir())
	if len(left) != 1 || left[0].Path != later {
		t.Errorf("pending after the report: %+v (want only the one for the next report)", left)
	}
}

// pendingLogs places a day of a computer's original logs, ending at to, in
// the folder where they wait for the next report.
func pendingLogs(t *testing.T, a *App, host string, to time.Time) string {
	t.Helper()
	logFile := filepath.Join(t.TempDir(), "Security.evtx")
	os.WriteFile(logFile, []byte("pretend evtx"), 0o644)
	dir := filepath.Join(a.pendingLogsDir(), host)
	os.MkdirAll(dir, 0o750)
	p := filepath.Join(dir, archive.FileName(host, to.Add(-24*time.Hour), to))
	if _, err := archive.Write(p, archive.Info{Host: host, From: to.Add(-24 * time.Hour), To: to, Created: to},
		[]archive.Source{{Name: "Security.evtx", Source: "Security", Path: logFile}}); err != nil {
		t.Fatal(err)
	}
	return p
}
