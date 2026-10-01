package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// SystemInfo is what the data folder knows about one computer (from
// store.System).
type SystemInfo struct {
	Name         string
	OS           string
	Version      string
	Via          string
	FirstSeen    time.Time
	LastRun      time.Time
	LastReceived time.Time
}

// CheckSet is the latest audit settings check of one computer.
type CheckSet struct {
	Host             string
	Time             time.Time
	Results          []check.Result
	Pass, Fail, Warn int
	Baseline         string // the STIG compared with, e.g. "Windows 11 STIG V2R8"
}

// SystemRow is one computer on the Systems page.
type SystemRow struct {
	SystemInfo
	Runs      int // collection runs in this period
	Events    int
	High      int
	Checks    *CheckSet
	Problems  int    // lost events, cleared logs and read errors
	Status    string // ok | warn | silent
	StatusMsg string
}

// OSName is a readable operating system name.
func (s SystemRow) OSName() string {
	switch s.OS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return s.OS
}

// silentAfter is how long a computer can go without a collection before
// the Systems page points it out, even within a period it did report in.
const silentAfter = 36 * time.Hour

// buildSystems fills in the Systems page: every known computer, what it
// contributed, and whether anything is wrong with its collection.
func (r *Report) buildSystems(runs []*store.Run, events []*event.Event) {
	idx := map[string]*SystemRow{}
	key := store.SystemKey
	get := func(name string) *SystemRow {
		k := key(name)
		if s := idx[k]; s != nil {
			return s
		}
		s := &SystemRow{SystemInfo: SystemInfo{Name: name}}
		idx[k] = s
		return s
	}
	for _, info := range r.Systems {
		if !info.FirstSeen.IsZero() && info.FirstSeen.After(r.WindowEnd) && info.LastRun.After(r.WindowEnd) {
			continue // first seen after this period
		}
		s := get(info.Name)
		s.SystemInfo = info
	}
	for _, run := range runs {
		s := get(run.Host)
		s.Runs++
		if s.OS == "" {
			s.OS = run.OS
		}
		if run.Time.After(s.LastRun) {
			s.LastRun = run.Time
		}
		for _, c := range run.Channels {
			if c.Gap != nil || c.Reset || c.Error != "" {
				s.Problems++
			}
		}
	}
	// Events and checks count towards a computer that collects. An event
	// recorded under another name (a former name of a renamed or cloned
	// computer) does not make a new system, so it cannot be reported as
	// silent; it still appears in every table under its own name.
	for _, e := range events {
		s := idx[key(e.Host)]
		if s == nil {
			continue
		}
		s.Events++
		if e.Severity == event.SevHigh {
			s.High++
		}
		if s.OS == "" {
			s.OS = e.OS
		}
	}
	for i := range r.CheckSets {
		cs := &r.CheckSets[i]
		if s := idx[key(cs.Host)]; s != nil {
			s.Checks = cs
		}
	}

	live := r.Source == "" || strings.HasPrefix(r.Source, "Live")
	for _, s := range idx {
		s.Status = "ok"
		switch {
		case !live:
		case s.Runs == 0:
			s.Status = "silent"
			if s.LastRun.IsZero() {
				s.StatusMsg = "No collection has been received from this computer yet."
			} else {
				s.StatusMsg = fmt.Sprintf("No collection received in this period. Last collection: %s (%s before the end of this report).",
					r.stamp(s.LastRun), roughDuration(r.WindowEnd.Sub(s.LastRun)))
			}
			s.StatusMsg += " It may have been switched off, or it cannot reach the collector."
		case r.WindowEnd.Sub(s.LastRun) > silentAfter:
			s.Status = "warn"
			s.StatusMsg = fmt.Sprintf("Last collection %s, %s before the end of this report.", r.stamp(s.LastRun), roughDuration(r.WindowEnd.Sub(s.LastRun)))
		case s.Problems > 0:
			s.Status = "warn"
			s.StatusMsg = "Collection problems in this period; see Audit health."
		case s.Checks != nil && s.Checks.Fail > 0:
			s.Status = "warn"
			s.StatusMsg = fmt.Sprintf("%d audit settings need attention.", s.Checks.Fail)
			if s.Checks.Fail == 1 {
				s.StatusMsg = "1 audit setting needs attention."
			}
		}
		r.SystemRows = append(r.SystemRows, *s)
	}
	rank := map[string]int{"silent": 0, "warn": 1, "ok": 2}
	sort.Slice(r.SystemRows, func(i, j int) bool {
		a, b := r.SystemRows[i], r.SystemRows[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})

	// Every computer is listed in the report, including one with no events.
	have := map[string]bool{}
	for _, h := range r.Hosts {
		have[key(h)] = true
	}
	for _, s := range r.SystemRows {
		if !have[key(s.Name)] {
			r.Hosts = append(r.Hosts, s.Name)
			have[key(s.Name)] = true
		}
		if s.Status == "silent" {
			r.Silent = append(r.Silent, s)
		}
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return strings.ToLower(r.Hosts[i]) < strings.ToLower(r.Hosts[j]) })
}

// ShowSystems reports whether the Systems page is useful: more than one
// computer, or this is a collector.
func (r *Report) ShowSystems() bool { return len(r.SystemRows) > 1 || r.Collector }

// SystemsNeedingAttention counts computers that are silent or have
// warnings.
func (r *Report) SystemsNeedingAttention() int {
	n := 0
	for _, s := range r.SystemRows {
		if s.Status != "ok" {
			n++
		}
	}
	return n
}

// NewCheckSet summarises one computer's audit settings check.
func NewCheckSet(host string, at time.Time, rs []check.Result) CheckSet {
	cs := CheckSet{Host: host, Time: at, Results: rs}
	cs.Pass, cs.Fail, cs.Warn = check.Summary(rs)
	for _, r := range rs {
		if r.Area == "Baseline" {
			cs.Baseline = r.Have
		}
	}
	// Settings that need attention first.
	sort.SliceStable(cs.Results, func(i, j int) bool {
		return (cs.Results[i].Status != check.Pass) && (cs.Results[j].Status == check.Pass)
	})
	return cs
}
