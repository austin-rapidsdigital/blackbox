// Package app ties collection, state and reporting together for the
// command-line tool.
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// App is a configured Blackbox instance.
type App struct {
	Cfg     *config.Config
	Version string
	Now     func() time.Time
	Loc     *time.Location
	Logf    func(format string, args ...any)
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) loc() *time.Location {
	if a.Loc != nil {
		return a.Loc
	}
	return time.Local
}

func (a *App) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

// ReportsDir is where reports are written.
func (a *App) ReportsDir() string { return filepath.Join(a.Cfg.DataDir, "reports") }

// Scheduled is what the scheduled task runs: collect, then produce a
// report if one is due. It returns the report folder ("" if none).
func (a *App) Scheduled() (string, error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return "", err
	}
	unlock, err := st.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf}); err != nil {
		return "", err
	}
	end, due := DueWindowEnd(a.Cfg.ReportEvery, st.State.LastWindowEnd, a.now(), a.loc())
	if !due {
		return "", nil
	}
	return a.report(st, end, true)
}

// ReportNow collects and produces a report up to now. With advance=false
// the report chain is left untouched (a preview).
func (a *App) ReportNow(advance bool) (string, error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return "", err
	}
	unlock, err := st.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf}); err != nil {
		return "", err
	}
	return a.report(st, a.now(), advance)
}

// Collect only collects.
func (a *App) Collect() (*store.Run, error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return nil, err
	}
	unlock, err := st.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf})
}

func (a *App) report(st *store.Store, end time.Time, advance bool) (string, error) {
	generated := a.now()
	prevEnd, prevGen := st.State.LastWindowEnd, st.State.LastGenerated
	since := prevEnd
	if !prevGen.IsZero() && prevGen.Before(since) {
		since = prevGen
	}
	all, err := st.ReadEvents(since)
	if err != nil {
		return "", err
	}
	events := SelectWindow(all, prevEnd, prevGen, end, generated)
	runs, err := st.ReadRuns(prevGen)
	if err != nil {
		return "", err
	}
	var checks []check.Result
	if check.Supported {
		checks = check.Run()
	}
	r := report.Build(events, runs, report.Options{
		Site:        a.Cfg.SiteName,
		WindowStart: prevEnd, WindowEnd: end, Generated: generated, Version: a.Version,
		Source: "Live collection", Location: a.loc(), InReportsDir: true,
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
		KnownDevices: st.State.KnownDevices, Checks: checks,
	})
	if len(r.Hosts) == 0 {
		if h, err := os.Hostname(); err == nil {
			r.Hosts = []string{strings.ToUpper(h)}
		}
	}
	name := report.DirName(end, r.Hosts, a.loc())
	if !advance {
		name += "_preview"
	}
	dir := report.UniqueDir(a.ReportsDir(), name)
	if err := r.Write(dir); err != nil {
		return "", err
	}
	if advance {
		st.State.LastWindowEnd = end
		st.State.LastGenerated = generated
		for k, t := range r.NewDevices {
			st.State.KnownDevices[k] = t
		}
		if err := st.Save(); err != nil {
			return dir, err
		}
		if err := st.Prune(a.Cfg.RetentionDays, generated); err != nil {
			a.logf("pruning old data: %v", err)
		}
		if err := pruneReports(a.ReportsDir(), a.Cfg.RetentionDays, generated); err != nil {
			a.logf("pruning old reports: %v", err)
		}
	}
	if err := report.WriteIndex(a.ReportsDir(), a.Cfg.SiteName, a.loc()); err != nil {
		a.logf("updating report index: %v", err)
	}
	return dir, nil
}

// SelectWindow picks the events that belong in the report ending at end,
// given the previous report's window end and generation time. Every event
// lands in exactly one report:
//   - events that happened before end, and
//   - were not already in the previous report (collected after it was
//     generated, or happened after its window ended).
//
// Events from before the previous window that were collected late are
// included and marked Late.
func SelectWindow(all []*event.Event, prevEnd, prevGen, end, generated time.Time) []*event.Event {
	var out []*event.Event
	for _, e := range all {
		if !e.Time.Before(end) || e.Collected.After(generated) {
			continue // belongs to a later report
		}
		if !prevGen.IsZero() {
			already := !e.Collected.After(prevGen) && e.Time.Before(prevEnd)
			if already {
				continue
			}
			if e.Time.Before(prevEnd) {
				e.Late = true
			}
		}
		out = append(out, e)
	}
	return out
}

// DueWindowEnd returns the end of the next scheduled report period and
// whether it is due. The first report is produced immediately; after
// that, periods end at local midnight (daily), Monday 00:00 (weekly) or
// the 1st of the month (monthly).
func DueWindowEnd(every string, lastEnd, now time.Time, loc *time.Location) (time.Time, bool) {
	if lastEnd.IsZero() {
		return now, true
	}
	n := now.In(loc)
	b := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	switch every {
	case "weekly":
		off := (int(b.Weekday()) + 6) % 7 // days since Monday
		b = b.AddDate(0, 0, -off)
	case "monthly":
		b = time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
	}
	if b.After(lastEnd) {
		return b, true
	}
	return time.Time{}, false
}

func pruneReports(dir string, days int, now time.Time) error {
	if days <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	cut := now.AddDate(0, 0, -days)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cut) {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.sha256")); err != nil {
			continue // only remove folders Blackbox created
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Inputs are exported log files for a one-off report.
type Inputs struct {
	XML    []string // Windows: wevtutil / Event Viewer XML (any OS)
	EVTX   []string // Windows: .evtx (Windows only)
	Audit  []string // Linux: auditd logs (audit.log, rotated copies, .gz)
	Syslog []string // Linux: syslog, messages, kern.log, auth.log, secure, journalctl output
	Host   string   // Linux: host name when the logs do not say
	Passwd string   // Linux: /etc/passwd copy for turning user IDs into names
}

// Empty reports whether no files were given.
func (in Inputs) Empty() bool {
	return len(in.XML)+len(in.EVTX)+len(in.Audit)+len(in.Syslog) == 0
}

// ReportFromFiles builds a one-off report from exported logs.
func (a *App) ReportFromFiles(in Inputs, outDir string) (string, error) {
	now := a.now()
	var events []*event.Event
	var runs []*store.Run
	var names []string
	for _, p := range in.XML {
		ev, run, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			return winevt.ParseStream(f, fn)
		}, p, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		names = append(names, filepath.Base(p))
	}
	for _, p := range in.EVTX {
		ev, run, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error { return winevt.ReadFile(p, fn) }, p, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		names = append(names, filepath.Base(p))
	}
	if len(in.Audit)+len(in.Syslog) > 0 {
		ev, run, err := collect.LinuxFiles(in.Audit, in.Syslog, in.Host, in.Passwd, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		for _, p := range append(append([]string{}, in.Audit...), in.Syslog...) {
			names = append(names, filepath.Base(p))
		}
	}
	end := now
	if len(events) > 0 {
		last := events[0].Time
		for _, e := range events {
			if e.Time.After(last) {
				last = e.Time
			}
		}
		end = last
	}
	r := report.Build(events, runs, report.Options{
		Site:      a.Cfg.SiteName,
		WindowEnd: end, Generated: now, Version: a.Version,
		Source: "Exported log file" + plural(len(names)) + ": " + strings.Join(names, ", "), Location: a.loc(),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
	})
	if outDir == "" {
		outDir = report.UniqueDir(".", "blackbox-report-"+now.In(a.loc()).Format("2006-01-02_1504"))
	}
	if err := r.Write(outDir); err != nil {
		return "", err
	}
	return outDir, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Describe formats a collection run for the console.
func Describe(run *store.Run) string {
	var b strings.Builder
	for _, c := range run.Channels {
		status := fmt.Sprintf("read %d, kept %d", c.Read, c.Kept)
		switch {
		case c.Unavailable != "":
			status = "not enabled"
		case c.Error != "":
			status = "ERROR: " + c.Error
		}
		if c.Gap != nil {
			status += fmt.Sprintf(" — %d events LOST to log rollover", c.Gap.Lost)
		}
		if c.Reset {
			status += " — log was cleared"
		}
		fmt.Fprintf(&b, "  %-58s %s\n", c.Channel, status)
	}
	return b.String()
}
