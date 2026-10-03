package scap

import (
	"strings"
	"testing"
)

const td = "../../testdata/scap"

// SCC results (XCCDF 1.2 with the benchmark) and OpenSCAP ARF, found in
// their folders: newest and previous per computer and benchmark.
func TestFind(t *testing.T) {
	scans, notes := Find(td)
	if len(notes) != 0 {
		t.Errorf("notes: %v", notes)
	}
	if len(scans) != 2 {
		t.Fatalf("scans: %v", scans)
	}
	w := scans["WS-07|xccdf_mil.disa.stig_benchmark_MS_Windows_11_STIG"]
	if w == nil || w.Latest == nil || w.Previous == nil {
		t.Fatalf("WS-07: %+v", w)
	}
	l := w.Latest
	if l.Host != "WS-07" || l.Benchmark != "Microsoft Windows 11 Security Technical Implementation Guide" || l.Version != "V2R8" ||
		l.Profile != "I - Mission Critical Classified" || l.When().Format("2006-01-02") != "2026-09-29" || l.Score != 40 {
		t.Errorf("latest: %+v", l)
	}
	if l.Counts["pass"] != 2 || l.Counts["fail"] != 3 || len(l.Open) != 3 {
		t.Errorf("counts %v open %d", l.Counts, len(l.Open))
	}
	if c := l.OpenByCat(); c[1] != 1 || c[2] != 1 || c[3] != 1 {
		t.Errorf("by CAT: %v", c)
	}
	var cat1 Rule
	for _, o := range l.Open {
		if o.Cat() == 1 {
			cat1 = o
		}
	}
	if cat1.VulnID != "V-253254" || cat1.STIGID != "WN11-00-000005" || !strings.HasPrefix(cat1.Title, "Domain-joined systems") {
		t.Errorf("CAT I rule: %+v", cat1)
	}
	d, ok := w.Delta()
	if !ok || len(d.NewlyOpen) != 1 || d.NewlyOpen[0].STIGID != "WN11-CC-000005" || len(d.NewlyFixed) != 1 || d.NewlyFixed[0].STIGID != "WN11-00-000040" {
		t.Errorf("delta: %+v", d)
	}
	u := scans["UBU-01|xccdf_org.ssgproject.content_benchmark_UBUNTU2204"]
	if u == nil || u.Latest.Host != "ubu-01" || u.Latest.Benchmark != "Guide to the Secure Configuration of Ubuntu 22.04" ||
		!strings.Contains(u.Latest.Profile, "STIG") || len(u.Latest.Open) != 1 || u.Latest.Open[0].Cat() != 3 ||
		u.Latest.Open[0].Title != "Enable Auditing for Processes Which Start Prior to the Audit Daemon" || int(u.Latest.Score) != 66 {
		t.Errorf("ubuntu: %+v %+v", u.Latest, u.Latest.Open)
	}
}

func TestParseRejectsOtherXML(t *testing.T) {
	if _, err := Parse(strings.NewReader(`<config><item/></config>`)); err == nil {
		t.Error("not SCAP, no error")
	}
}
