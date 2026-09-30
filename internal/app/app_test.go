package app

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

func TestDueWindowEnd(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 9, 30, 1, 5, 0, 0, loc) // Wednesday 01:05
	if end, due := DueWindowEnd("daily", time.Time{}, now, loc); !due || !end.Equal(now) {
		t.Errorf("first report should be due immediately, got %v %v", end, due)
	}
	lastDaily := time.Date(2026, 9, 29, 0, 0, 0, 0, loc)
	if end, due := DueWindowEnd("daily", lastDaily, now, loc); !due || !end.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, loc)) {
		t.Errorf("daily: got %v %v", end, due)
	}
	if _, due := DueWindowEnd("daily", time.Date(2026, 9, 30, 0, 0, 0, 0, loc), now, loc); due {
		t.Error("daily: should not be due twice in one day")
	}
	lastWeekly := time.Date(2026, 9, 21, 0, 0, 0, 0, loc) // previous Monday
	if end, due := DueWindowEnd("weekly", lastWeekly, now, loc); !due || !end.Equal(time.Date(2026, 9, 28, 0, 0, 0, 0, loc)) {
		t.Errorf("weekly: got %v %v", end, due)
	}
	if end, due := DueWindowEnd("monthly", time.Date(2026, 9, 1, 0, 0, 0, 0, loc), now, loc); due {
		t.Errorf("monthly: not due until October, got %v", end)
	}
}

// Every event must appear in exactly one report, including events that
// happened before a report's period but were collected after it.
func TestSelectWindowReportsEachEventOnce(t *testing.T) {
	h := func(hh int) time.Time { return time.Date(2026, 9, 29, hh, 0, 0, 0, time.UTC) }
	mk := func(at, collected time.Time) *event.Event { return &event.Event{Time: at, Collected: collected} }
	events := []*event.Event{
		mk(h(1), h(2)),   // A: normal, first report
		mk(h(11), h(11)), // B: after first window end (10), collected before it was generated (12) → second report
		mk(h(9), h(13)),  // C: before first window end but collected late → second report, Late
		mk(h(15), h(16)), // D: after second window end (14) → third report
	}
	first := SelectWindow(events, time.Time{}, time.Time{}, h(10), h(12))
	second := SelectWindow(events, h(10), h(12), h(14), h(17))
	third := SelectWindow(events, h(14), h(17), h(20), h(21))
	seen := map[*event.Event]int{}
	for _, l := range [][]*event.Event{first, second, third} {
		for _, e := range l {
			seen[e]++
		}
	}
	for i, e := range events {
		if seen[e] != 1 {
			t.Errorf("event %d reported %d times", i, seen[e])
		}
	}
	if len(first) != 1 || len(second) != 2 || len(third) != 1 {
		t.Errorf("windows got %d/%d/%d events, want 1/2/1", len(first), len(second), len(third))
	}
	if !events[2].Late || events[1].Late {
		t.Error("late-collected event should be marked Late, others not")
	}
}

func TestContextEventsAreTheDayBefore(t *testing.T) {
	start := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	at := func(h int) *event.Event { return &event.Event{Time: start.Add(time.Duration(h) * time.Hour)} }
	old, dayBefore, inReport, lateArrival := at(-30), at(-3), at(2), at(-5)
	got := contextEvents([]*event.Event{old, dayBefore, inReport, lateArrival}, []*event.Event{inReport, lateArrival}, start)
	if len(got) != 1 || got[0] != dayBefore {
		t.Errorf("context = %v", got)
	}
	if contextEvents([]*event.Event{dayBefore}, nil, time.Time{}) != nil {
		t.Error("the first report has no previous period")
	}
}
