package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseReportAt(t *testing.T) {
	for in, want := range map[string]ReportAt{
		"Wednesday 00:00": {time.Wednesday, 0},
		"thu 06:30":       {time.Thursday, 390},
		"18:00":           {time.Wednesday, 1080},
	} {
		got, err := ParseReportAt(in)
		if err != nil || got != want {
			t.Errorf("%q: got %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "noon", "Funday 00:00", "Wednesday 24:00", "Wed 00:00 extra"} {
		if _, err := ParseReportAt(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
	if s := DefaultReportAt.Describe("weekly"); s != "weekly, ready Wednesday 00:00 (each covers the week to Tuesday night)" {
		t.Errorf("describe: %q", s)
	}
}

func TestLastBoundary(t *testing.T) {
	loc := time.UTC
	at := ReportAt{Day: time.Wednesday}
	// Wednesday 00:00 itself is a boundary.
	wed := time.Date(2026, 9, 30, 0, 0, 0, 0, loc)
	if b := at.LastBoundary("weekly", wed, loc); !b.Equal(wed) {
		t.Errorf("at the boundary: %v", b)
	}
	if b := at.NextBoundary("weekly", wed, loc); !b.Equal(wed.AddDate(0, 0, 7)) {
		t.Errorf("next: %v", b)
	}
	m := ReportAt{Minute: 6 * 60}
	jan := time.Date(2026, 1, 1, 5, 0, 0, 0, loc) // before 06:00 on the 1st
	if b := m.LastBoundary("monthly", jan, loc); !b.Equal(time.Date(2025, 12, 1, 6, 0, 0, 0, loc)) {
		t.Errorf("monthly across the year: %v", b)
	}
}

// An older config file gains report_at with its explanation.
func TestSetValueAddsReportAt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	if err := os.WriteFile(p, []byte("site_name = Lab\nreport_every = weekly\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetValue(p, "report_at", "Thursday 06:00"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# When each report period ends") || !strings.Contains(string(b), "report_at = Thursday 06:00") {
		t.Errorf("config:\n%s", b)
	}
	c, err := Load(p)
	if err != nil || c.ReportAt != (ReportAt{time.Thursday, 360}) {
		t.Errorf("load: %+v %v", c.ReportAt, err)
	}
	if err := SetValue(p, "report_at", "noon"); err == nil {
		t.Error("a bad value must not be saved")
	}
}
