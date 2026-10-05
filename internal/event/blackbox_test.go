package event

import "testing"

// A15: what Blackbox writes to the system log reads back the same.
func TestSelfChangeRoundTrip(t *testing.T) {
	for _, c := range []SelfChange{
		{Kind: "setting", Setting: "retention_days", Old: "365", New: "30", Who: "claude", Program: "blackbox config set"},
		{Kind: "setting", Setting: "exclude_users", Old: "", New: `svc_a, "odd" (x) to y`, Who: `SERVER\claude`, Program: "setup"},
		{Kind: "installed", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "upgraded", Old: "0.10.4", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "upgraded", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "removed", Who: "claude", Program: "blackbox uninstall"},
	} {
		got, ok := ParseSelfChange(c.Message())
		if !ok || got != c {
			t.Errorf("%q read back as %+v (ok %v)", c.Message(), got, ok)
		}
	}
	e := SelfChange{Kind: "setting", Setting: "exclude_users", Old: "", New: "bob", Who: "claude", Program: "blackbox config set"}.Event()
	if e.Severity != SevHigh || e.Summary != "claude changed Blackbox's exclude_users setting from (empty) to bob (blackbox config set)." {
		t.Errorf("event: %s %s", e.Severity, e.Summary)
	}
	if e := (SelfChange{Kind: "setting", Setting: "site_name", New: "Lab", Program: "setup"}).Event(); e.Severity != SevMedium {
		t.Errorf("site_name: %s", e.Severity)
	}
	if _, ok := ParseSelfChange("Blackbox did something else."); ok {
		t.Error("parsed an unknown line")
	}
}
