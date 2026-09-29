package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	text := Render("Lab 3", "SECRET//NOFORN", "daily") + "exclude_users = svc_backup, svc_scan  # noisy\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SiteName != "Lab 3" || c.ReportEvery != "daily" || len(c.ExcludeUsers) != 2 || c.ExcludeUsers[1] != "svc_scan" {
		t.Errorf("loaded wrong values: %+v", c)
	}
	text, bg, fg := c.Banner()
	if text != "SECRET//NOFORN" || bg != "#c8102e" || fg != "#ffffff" {
		t.Errorf("banner = %q %s %s", text, bg, fg)
	}
}

func TestBannerColors(t *testing.T) {
	cases := map[string]string{"UNCLASSIFIED": "#007a33", "CUI": "#502b85", "SECRET": "#c8102e",
		"TOP SECRET": "#ff8c00", "TOP SECRET//SCI": "#fce83a", "CONFIDENTIAL": "#0033a0"}
	for m, want := range cases {
		if bg, _ := BannerColors(m); bg != want {
			t.Errorf("%s: %s, want %s", m, bg, want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{"report_every = hourly\n", "nonsense\n", "unknown_key = 1\n", "classification_color = red\n"} {
		p := filepath.Join(t.TempDir(), "c.conf")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if c, err := Load(filepath.Join(t.TempDir(), "missing.conf")); err != nil || c.Classification != "UNCLASSIFIED" {
		t.Errorf("missing file should give defaults: %v %v", c, err)
	}
}
