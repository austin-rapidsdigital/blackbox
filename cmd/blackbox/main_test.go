package main

import (
	"strings"
	"testing"
	"time"
)

func TestReportRange(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC)
	f, to, err := reportRange("2026-09-01", "2026-09-15", 0, now, time.UTC)
	if err != nil || !f.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !to.Equal(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("dates: %v %v %v", f, to, err)
	}
	if f, to, err := reportRange("", "", 30, now, time.UTC); err != nil || !f.Equal(now.AddDate(0, 0, -30)) || !to.Equal(now) {
		t.Errorf("--days: %v %v %v", f, to, err)
	}
	if f, _, _ := reportRange("", "", 0, now, time.UTC); !f.IsZero() {
		t.Error("no range chosen should mean since the last report")
	}
	for _, bad := range [][2]string{{"2026-09-15", "2026-09-01"}, {"yesterday", ""}, {"", "2026-09-01"}} {
		if _, _, err := reportRange(bad[0], bad[1], 0, now, time.UTC); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
	if f, to, err := parseRangeAnswer("7", now, time.UTC); err != nil || !f.Equal(now.AddDate(0, 0, -7)) || !to.Equal(now) {
		t.Errorf("answer 7: %v %v %v", f, to, err)
	}
	if f, _, err := parseRangeAnswer("", now, time.UTC); err != nil || !f.IsZero() {
		t.Errorf("Enter: %v %v", f, err)
	}
	if f, to, err := parseRangeAnswer("2026-09-01 2026-09-30", now, time.UTC); err != nil || f.Day() != 1 || to.Day() != 1 || to.Month() != 10 {
		t.Errorf("two dates: %v %v %v", f, to, err)
	}
}

// R4: a saved setting is used by the next run of any kind, not only the
// next scheduled one.
func TestSavedText(t *testing.T) {
	got := savedText("site_name", "Lab 3")
	if strings.Contains(got, "next scheduled run") || !strings.Contains(got, "blackbox report") {
		t.Errorf("savedText = %q", got)
	}
}
