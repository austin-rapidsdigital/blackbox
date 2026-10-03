package report

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.txt from the current output")

// TestGolden builds a report from the sample logs in testdata (Windows and
// Linux) and compares its rows, detections and summary.json with the saved
// copy, so a change in what a report says shows up in review. After a
// change that is meant to alter the report, run
// go test ./internal/report -run TestGolden -update and check the diff.
func TestGolden(t *testing.T) {
	const dir = "../../testdata/linux/"
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	events := sampleEvents(t)
	audit, _, err := collect.LinuxFiles([]string{dir + "ubuntu-audit.log", dir + "ssh-session-audit.log"}, nil, "ubu-audit", "", now)
	if err != nil {
		t.Fatal(err)
	}
	syslog, _, err := collect.LinuxFiles(nil, []string{dir + "ssh-session-auth.log", dir + "ubuntu-syslog"}, "ubu-syslog", "", now)
	if err != nil {
		t.Fatal(err)
	}
	events = append(append(events, audit...), syslog...)
	r := Build(events, nil, Options{Location: time.UTC, WindowEnd: now, Generated: now, Version: "golden", Source: "testdata"})

	var b strings.Builder
	fmt.Fprintf(&b, "# Detections (%d)\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%v %v %s %s | %s | %s\n", f.Time.Format(time.RFC3339), f.Severity, f.Host, f.Category, f.Title, f.Detail)
	}
	fmt.Fprintf(&b, "\n# Rows (%d)\n", len(r.Events))
	for _, e := range r.Events {
		fmt.Fprintf(&b, "%s %v %s %s %s %s | %s\n", e.Time.Format(time.RFC3339), e.Severity, e.Host, e.Category, e.Action, e.Outcome, e.Summary)
	}
	sum, err := json.MarshalIndent(r.summary(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&b, "\n# summary.json\n%s\n", sum)

	const golden = "testdata/golden.txt"
	if *update {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	// A Windows checkout may have turned the saved copy's line endings into CRLF.
	wantS := strings.ReplaceAll(string(want), "\r\n", "\n")
	if got := b.String(); got != wantS {
		gl, wl := strings.Split(got, "\n"), strings.Split(wantS, "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("report differs from %s at line %d:\n got: %s\nwant: %s\n(run with -update if the change is intended)", golden, i+1, g, w)
			}
		}
	}
}
