package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// A report for a chosen period takes the events Blackbox kept, and for the
// time before its copy starts, this computer's own logs. It does not move
// the schedule.
func TestReportRange(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	host := collect.LocalHost()
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	ev := func(at time.Time, summary string) *event.Event {
		return &event.Event{Time: at, Host: host, OS: "windows", Category: event.CatAccount, Severity: event.SevMedium,
			Action: "account_created", User: "admin_jd", Target: "x", Summary: summary, Collected: at}
	}
	// Blackbox's copy starts on 20 Sep (installed then); a report already ran yesterday.
	st.AppendEvents(now, []*event.Event{ev(time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC), "kept event"),
		ev(time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), "today's event")})
	st.AppendRun(&store.Run{Time: now.Add(-time.Hour), Host: host, OS: "windows"})
	last := now.Add(-24 * time.Hour)
	st.State.LastWindowEnd, st.State.LastGenerated = last, last
	st.Save()

	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "weekly"},
		Version: "test", Loc: time.UTC, Now: func() time.Time { return now }}
	var asked [2]time.Time
	a.LiveLogs = func(h string, from, to time.Time) ([]*event.Event, []string, error) {
		asked = [2]time.Time{from, to}
		return []*event.Event{ev(time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC), "from the event log"),
			ev(time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC), "before the period")}, nil, nil
	}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dir, err := a.reportRange(st, from, now)
	if err != nil {
		t.Fatal(err)
	}
	if !asked[0].Equal(from) || !asked[1].Equal(time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("the logs were read for %v, want from the period start to where Blackbox's copy starts", asked)
	}
	if !strings.HasSuffix(dir, "_range") {
		t.Errorf("folder %s", dir)
	}
	var sum report.Summary
	if err := json.Unmarshal([]byte(readFile(t, dir, "summary.json")), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Events != 3 || !sum.Interim || !sum.WindowStart.Equal(from) {
		t.Errorf("summary: %d events, interim %v, start %v (want 3, true, %v)", sum.Events, sum.Interim, sum.WindowStart, from)
	}
	if !strings.Contains(readFile(t, dir, "report.html"), "Report for a chosen period") {
		t.Error("the report does not say it covers a chosen period")
	}
	if !st.State.LastWindowEnd.Equal(last) {
		t.Errorf("a chosen-period report moved the schedule to %v", st.State.LastWindowEnd)
	}
}
