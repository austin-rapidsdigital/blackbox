package report

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// R1: a failed logon whose user name is a spreadsheet formula stays text
// in every CSV.
func TestCSVFormulaInjection(t *testing.T) {
	evil := `=HYPERLINK("http://x","y")`
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", evil, "10.1.1.99")...), Options{})
	var b bytes.Buffer
	if err := r.writeCSV(&b); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b.Bytes(), []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range recs[1:] {
		for _, f := range rec {
			if strings.HasPrefix(f, "=") || strings.HasPrefix(f, "+") || strings.HasPrefix(f, "@") {
				t.Errorf("events.csv field starts a formula: %q", f)
			}
			if f == "'"+evil {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the user name should be kept, as text: %v", recs)
	}
	if got := csvText([][]string{{"-cmd", "@x", "ok", "\tx"}}); strings.Contains(got, ",-") || strings.HasPrefix(got, "-") {
		t.Errorf("csvText not made safe: %q", got)
	}
}

// R5: summary.json counts PowerShell under its own key, as the report's
// pages do, not under other_security.
func TestSummaryCountsPowerShell(t *testing.T) {
	r := buildFrom([]*event.Event{
		{Time: fx0, Host: "DSK1", Source: "Microsoft-Windows-PowerShell/Operational", Category: event.CatOther, Severity: event.SevMedium, Action: "powershell_suspicious", Summary: "x"},
		{Time: fx0, Host: "DSK1", Category: event.CatOther, Severity: event.SevMedium, Action: "service_installed", Summary: "y"},
	}, Options{})
	got := r.summary().ByCategory
	if got["powershell"] != 1 || got["other_security"] != 1 {
		t.Errorf("by_category = %v, want powershell 1 and other_security 1", got)
	}
}

// R6: verify fails on a file added to the report folder, and on a
// manifest cut down to leave a file out.
func TestVerifyFindsAddedAndUnlistedFiles(t *testing.T) {
	r := buildFrom(translateAll(t, failedLogon(10, fx0, "", "jsmith", "10.1.1.99")...), Options{})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("a fresh report should verify: %v %v", p, err)
	}
	os.WriteFile(filepath.Join(dir, "extra.html"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "desktop.ini"), []byte("x"), 0o644) // Windows adds these itself
	p, _ := Verify(dir)
	if len(p) != 1 || !strings.Contains(p[0], "extra.html: not in the manifest") {
		t.Errorf("added file: %v", p)
	}
	os.Remove(filepath.Join(dir, "extra.html"))
	// Remove summary.json and its line from the manifest.
	m, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(string(m)), "\n") {
		if !strings.HasSuffix(l, "summary.json") {
			keep = append(keep, l)
		}
	}
	os.Chmod(filepath.Join(dir, "manifest.sha256"), 0o644)
	os.WriteFile(filepath.Join(dir, "manifest.sha256"), []byte(strings.Join(keep, "\n")+"\n"), 0o644)
	os.Remove(filepath.Join(dir, "summary.json"))
	if p, _ := Verify(dir); len(p) == 0 {
		t.Error("a manifest without summary.json verified")
	}
}

// R7: a one-minute interim report doesn't call an hourly sender silent;
// a week without a collection does.
func TestShortReportIsNotSilence(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	sys := []SystemInfo{{Name: "DSK1", OS: "windows", LastRun: end.Add(-time.Minute)}, {Name: "claude-code", OS: "linux", Via: "", LastRun: end.Add(-40 * time.Minute)}}
	runs := []*store.Run{{Time: end.Add(-time.Minute), Host: "DSK1", OS: "windows"}}
	ev := []*event.Event{{Time: end.Add(-30 * time.Second), Host: "DSK1", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}
	short := Build(ev, runs, Options{WindowStart: end.Add(-time.Minute), WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Systems: sys, Interim: true})
	if len(short.Silent) != 0 {
		t.Errorf("a 1-minute report called %v silent", short.Silent[0].Name)
	}
	sys[1].LastRun = end.AddDate(0, 0, -8)
	week := Build(ev, runs, Options{WindowStart: end.AddDate(0, 0, -7), WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Systems: sys})
	if len(week.Silent) != 1 {
		t.Errorf("a week without collection should be silent: %v", week.Silent)
	}
}
