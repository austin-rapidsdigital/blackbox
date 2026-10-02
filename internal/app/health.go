package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// Health is what the status icon shows: whether collection is running on
// schedule, and anything that needs looking at. It reads the same state
// as "blackbox status".
type Health struct {
	Role        string
	ReportEvery string // daily, weekly or monthly
	Every       time.Duration
	LastCollect time.Time
	LastRun     LastRun
	NextReport  time.Time // zero when one is due at the next run
	PeriodStart time.Time // start of the current report period

	ReportsDir string
	Latest     *report.IndexEntry // newest report, if any

	AuditGaps map[string]int // host → audit settings that don't match the STIG
	AVOld     []string       // hosts whose Defender intelligence is out of date
	Quiet     map[string]time.Time
	Rejected  int // files set aside in the inbox
}

// LastRun is the outcome of the last scheduled run.
type LastRun struct {
	Time  time.Time `json:"time"`
	Error string    `json:"error,omitempty"`
}

func lastRunPath(dataDir string) string { return filepath.Join(dataDir, "last-run.json") }

// RecordRun notes the outcome of a scheduled run, for the status icon.
func (a *App) RecordRun(err error) {
	r := LastRun{Time: a.now()}
	if err != nil {
		r.Error = err.Error()
	}
	b, _ := json.Marshal(r)
	store.WriteFileAtomic(lastRunPath(a.Cfg.DataDir), b, 0o640)
}

// Health reads the current state.
func (a *App) Health() (Health, error) {
	h := Health{Role: a.Cfg.Role(), ReportEvery: a.Cfg.ReportEvery, Every: a.Cfg.CollectEvery, AuditGaps: map[string]int{}, Quiet: map[string]time.Time{}}
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return h, err
	}
	now := a.now()
	s := st.State
	h.LastCollect = s.LastCollect
	if b, err := os.ReadFile(lastRunPath(a.Cfg.DataDir)); err == nil {
		json.Unmarshal(b, &h.LastRun)
	}
	if !a.Cfg.MakesReports() {
		return h, nil
	}
	h.ReportsDir = a.Cfg.ReportsDir()
	h.NextReport, _ = nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, s.LastWindowEnd, now, a.loc())
	h.PeriodStart = s.LastWindowEnd
	if l, ok := report.Latest(h.ReportsDir); ok {
		h.Latest = &l
	}

	// Audit settings: the latest check of each system.
	if checks, err := st.LatestChecks(now.AddDate(0, 0, -8), now); err == nil {
		for _, c := range checks {
			for _, r := range c.Results {
				if r.Status != check.Fail {
					continue
				}
				if r.Area == "Antivirus" {
					h.AVOld = append(h.AVOld, c.Host)
				} else if r.Area != "Baseline" {
					h.AuditGaps[c.Host]++
				}
			}
		}
		sort.Strings(h.AVOld)
	}

	// A system is quiet once nothing has arrived from it in the current
	// report period for 36 hours, the same as the report's "silent": a
	// virtual machine that is off part of the week is not flagged.
	if !h.PeriodStart.IsZero() && now.Sub(h.PeriodStart) > silentAfter {
		for _, sys := range s.Systems {
			if sys.Removed.IsZero() && !sys.LastRun.IsZero() && sys.LastRun.Before(h.PeriodStart) {
				h.Quiet[sys.Name] = sys.LastRun
			}
		}
	}
	if a.Cfg.Inbox != "" {
		if rej, _ := filepath.Glob(filepath.Join(a.Cfg.Inbox, "rejected", "*")); len(rej) > 0 {
			h.Rejected = len(rej)
		}
	}
	return h, nil
}
