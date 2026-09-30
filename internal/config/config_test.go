package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	text := Render("Lab 3", "daily") + "exclude_users = svc_backup, svc_scan  # noisy\n"
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
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{"report_every = hourly\n", "nonsense\n", "unknown_key = 1\n", "classification = SECRET\n"} {
		p := filepath.Join(t.TempDir(), "c.conf")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if c, err := Load(filepath.Join(t.TempDir(), "missing.conf")); err != nil || c.ReportEvery != "weekly" {
		t.Errorf("missing file should give defaults: %v %v", c, err)
	}
}
