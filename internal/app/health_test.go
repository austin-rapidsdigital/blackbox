package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/store"
)

// C1: events lost to log rollover since the last report are in "blackbox
// status" and in the status icon's view of things, named by log.
func TestLostEventsAreReported(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.State.LastWindowEnd = now.Add(-24 * time.Hour)
	st.State.LastCollect = now.Add(-10 * time.Minute)
	st.Save()
	for i, lost := range []uint64{17925, 1200} {
		st.AppendRun(&store.Run{Time: now.Add(time.Duration(i-2) * time.Hour), Host: collect.LocalHost(), OS: "windows",
			Channels: []store.ChannelRun{{Channel: "Security", Gap: &store.Gap{Lost: lost}}}})
	}
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: time.Hour},
		Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	if err := a.Status(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Security log on "+collect.LocalHost()+": 19,125 events overwritten") || !strings.Contains(b.String(), "every 15 minutes") {
		t.Errorf("status:\n%s", b.String())
	}
	h, err := a.Health()
	if err != nil || len(h.Lost) != 1 || h.Lost[0].Count != 19125 {
		t.Errorf("health lost: %+v %v", h.Lost, err)
	}
}

// C3: a sender with no batch for more than two collection intervals is
// pointed out in status, well before it counts as silent.
func TestNoBatchSince(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.NoteSystem("claude-code", "linux", "0.9.2", "claude-code", now.Add(-3*time.Hour), now.Add(-3*time.Hour), now.Add(-3*time.Hour))
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, Inbox: t.TempDir(), ReportEvery: "weekly"}, Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	a.Status(&b)
	if !strings.Contains(b.String(), "no batch since 2026-10-02 12:00") {
		t.Errorf("status:\n%s", b.String())
	}
}

// C5: audit settings are checked again after a restart (auditd and the
// kernel's audit=1 take effect then), as well as daily.
func TestCheckDue(t *testing.T) {
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	last := now.Add(-4 * time.Hour)
	if checkDue(last, now.AddDate(0, 0, -3), now) {
		t.Error("checked again without a restart, 4 hours after the last")
	}
	if !checkDue(last, now.Add(-time.Hour), now) {
		t.Error("not checked again after a restart")
	}
	if !checkDue(now.Add(-21*time.Hour), time.Time{}, now) {
		t.Error("not checked daily")
	}
}

// Finding 11: a computer switched from collector to standalone shows only
// itself in the status icon, not a former sender.
func TestStandaloneShowsOnlyItself(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.State.LastWindowEnd = now.AddDate(0, 0, -3)
	st.NoteSystem("claude-code", "linux", "0.9.2", "claude-code", now.AddDate(0, 0, -4), now.AddDate(0, 0, -4), now.AddDate(0, 0, -4))
	st.Save()
	st.AppendChecks(&store.CheckRecord{Time: now.Add(-time.Hour), Host: "claude-code", OS: "linux",
		Results: []check.Result{{Area: "Audit service", Item: "auditd", Status: check.Fail}}})
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly"}, Now: func() time.Time { return now }, Loc: time.UTC}
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	if len(h.AuditGaps) != 0 || len(h.Quiet) != 0 {
		t.Errorf("a former sender is still shown: gaps %v, quiet %v", h.AuditGaps, h.Quiet)
	}
	a.Cfg.Inbox = t.TempDir()
	if h, _ := a.Health(); h.AuditGaps["claude-code"] != 1 || len(h.Quiet) != 1 {
		t.Errorf("a collector should show its sender: gaps %v, quiet %v", h.AuditGaps, h.Quiet)
	}
}
