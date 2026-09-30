package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadTemplateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	text := Render("Lab 3", "daily", "", time.Hour) + "exclude_users = svc_backup, svc_scan  # noisy\n"
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

func absDir() string {
	if runtime.GOOS == "windows" {
		return `D:\AuditReports`
	}
	return "/srv/audit-reports"
}

func TestReportDir(t *testing.T) {
	c := Default()
	if c.ReportsDir() != filepath.Join(c.DataDir, "reports") {
		t.Errorf("default reports dir = %s", c.ReportsDir())
	}
	c.ReportDir = absDir()
	if c.ReportsDir() != absDir() {
		t.Errorf("custom reports dir = %s", c.ReportsDir())
	}
	p := filepath.Join(t.TempDir(), "c.conf")
	os.WriteFile(p, []byte("report_dir = reports\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "full path") {
		t.Errorf("relative report_dir accepted: %v", err)
	}
}

func TestSetValuesKeepsCommentsAndLineEndings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	orig := strings.ReplaceAll(Render("Lab 3", "weekly", "", time.Hour), "\n", "\r\n")
	os.WriteFile(p, []byte(orig), 0o600)

	if err := SetValue(p, "report_dir", absDir()); err != nil {
		t.Fatal(err)
	}
	if err := SetValues(p, [][2]string{{"collect_every", "30m"}, {"site_name", "Lab 4"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	text := string(b)
	if strings.Count(text, "\n") != strings.Count(text, "\r\n") {
		t.Error("Windows line endings were not kept")
	}
	if !strings.Contains(text, "# How often a report is produced") {
		t.Error("comments were lost")
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReportDir != absDir() || c.CollectEvery != 30*time.Minute || c.SiteName != "Lab 4" || c.ReportEvery != "weekly" {
		t.Errorf("settings after SetValues: %+v", c)
	}
	if strings.Count(text, "report_dir =") != 1 {
		t.Error("report_dir written more than once")
	}

	// Invalid values are refused and the file is left as it was.
	if err := SetValue(p, "report_every", "hourly"); err == nil {
		t.Error("invalid report_every accepted")
	}
	if err := SetValue(p, "data_dir", "/tmp"); err == nil {
		t.Error("data_dir should not be settable")
	}
	if b2, _ := os.ReadFile(p); string(b2) != text {
		t.Error("file changed by a refused SetValue")
	}
}

func TestSetValueCreatesMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "blackbox.conf")
	if err := SetValue(p, "site_name", "New Site"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.SiteName != "New Site" {
		t.Errorf("got %+v, %v", c, err)
	}
}

func TestLANSettings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blackbox.conf")
	// A config written by an older version, without the LAN settings.
	old := "site_name = Lab\nreport_every = weekly\n"
	os.WriteFile(p, []byte(old), 0o640)
	share := "//COLLECTOR/BlackboxInbox"
	if runtime.GOOS == "windows" {
		share = `\\COLLECTOR\BlackboxInbox`
	}
	if err := SetValues(p, [][2]string{{"send_to", share}, {"share_user", "bbsend"}}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SendTo != share || c.ShareUser != "bbsend" || c.Role() != "sender" || c.MakesReports() {
		t.Errorf("got %+v, role %s", c, c.Role())
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# LAN:") || strings.Count(string(b), "# LAN:") != 1 {
		t.Errorf("LAN explanation should be added once:\n%s", b)
	}
	if err := SetValue(p, "send_to", "relative/folder"); err == nil {
		t.Error("a relative send_to was accepted")
	}
	inbox := "/srv/inbox"
	if runtime.GOOS == "windows" {
		inbox = `C:\BlackboxInbox`
	}
	// A computer sends to a collector or is one, never both.
	if err := SetValue(p, "inbox", inbox); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("setting inbox on a sender: got %v, want a clear refusal", err)
	}
	if err := SetValues(p, [][2]string{{"send_to", ""}, {"share_user", ""}, {"inbox", inbox}}); err != nil {
		t.Fatal(err)
	}
	c, _ = Load(p)
	if c.Role() != "collector" || !c.MakesReports() {
		t.Errorf("role %s, want collector", c.Role())
	}
	for _, s := range []string{`\\server\share`, "//server/share", `\\server\share\sub`} {
		if !IsShare(s) {
			t.Errorf("IsShare(%q) = false", s)
		}
	}
	for _, s := range []string{`\\server`, "//", "/srv/x"} {
		if IsShare(s) {
			t.Errorf("IsShare(%q) = true", s)
		}
	}
}
