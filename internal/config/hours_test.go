package config

import (
	"testing"
	"time"
)

func TestWorkingHours(t *testing.T) {
	at := func(day, hh, mm int) time.Time { return time.Date(2026, 9, 27+day, hh, mm, 0, 0, time.UTC) } // 27 Sep 2026 is a Sunday
	w, err := ParseWorkingHours("Mon-Fri 06:00-18:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		t    time.Time
		want bool
	}{{at(1, 9, 0), true}, {at(1, 5, 59), false}, {at(1, 18, 0), false}, {at(0, 12, 0), false}, {at(6, 12, 0), false}, {at(5, 17, 59), true}} {
		if got := w.Contains(c.t); got != c.want {
			t.Errorf("%s: %v, want %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	night, err := ParseWorkingHours("Mon-Fri 22:00-06:00")
	if err != nil {
		t.Fatal(err)
	}
	if !night.Contains(at(6, 3, 0)) || night.Contains(at(1, 3, 0)) || !night.Contains(at(5, 23, 0)) {
		t.Error("overnight shift belongs to the day it starts")
	}
	if !(WorkingHours{}).Contains(at(0, 3, 0)) {
		t.Error("unset working hours contain everything")
	}
	for _, bad := range []string{"Mon-Fri", "Funday 06:00-18:00", "Mon-Fri 6-18", "Mon-Fri 09:00-09:00", "Mon-Fri 25:00-26:00"} {
		if _, err := ParseWorkingHours(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if w, err := ParseWorkingHours("Daily 07:00-19:00"); err != nil || !w.Contains(at(0, 8, 0)) {
		t.Errorf("Daily: %v", err)
	}
	if w, err := ParseWorkingHours("Mon,Wed,Friday 07:00-15:30"); err != nil || !w.Contains(at(3, 8, 0)) || w.Contains(at(2, 8, 0)) {
		t.Errorf("list: %v", err)
	}
}
