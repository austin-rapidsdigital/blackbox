package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	dir, err := a.report(col, next, true)
	if err != nil {
		t.Fatal(err)
	}
	html := readFile(t, dir, "report.html")
	for _, want := range []string{
		`data-view="systems"`,        // Systems page
		"ubu-ws12", "WS-07", "WS-09", // every system
		"No collection received in this period", // WS-09 is silent
		`<option>ubu-ws12</option>`,             // system filter
		`id="checks-WS-07" open`,                // failing settings shown open
		">Late<",                                // late arrivals are marked
	} {
		if !strings.Contains(html, want) {
			t.Errorf("combined report missing %q", want)
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
