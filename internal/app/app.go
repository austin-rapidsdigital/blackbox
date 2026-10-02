// Package app ties collection, state and reporting together for the
// command-line tool.
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/share"
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
	// LiveLogs reads this computer's own logs for a period (tests replace
	// it); nil uses the event logs.
	LiveLogs func(host string, from, to time.Time) ([]*event.Event, []string, error)
	// BootTime is when this computer last started (tests replace it).
	BootTime func() time.Time
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
func (a *App) ReportsDir() string { return a.Cfg.ReportsDir() }

// pendingLogsDir holds each computer's daily archives of its original
// logs (this computer's own, and those received from senders) until a
// report takes them into its folder.
func (a *App) pendingLogsDir() string { return filepath.Join(a.Cfg.DataDir, "archives") }

// legacyLogsDir is where version 0.4 kept the daily archives; any left
// there go into the next report too.
func (a *App) legacyLogsDir() string { return filepath.Join(a.ReportsDir(), "archives") }

// archiveLogs exports the original logs (see package archive) from the end
// of the last archive until upTo: into the outbox on a sender, otherwise
// into the pending folder for the next report. Unless force is set it
// runs only once a day. If it fails, the same period is tried again.
func (a *App) archiveLogs(st *store.Store, upTo time.Time, force bool) {
	from, due := archive.Due(st.State.ArchivedUntil, upTo)
	if !(due || force) || !from.Before(upTo) {
		return
	}
	host := collect.LocalHost()
	dir := filepath.Join(a.pendingLogsDir(), archive.SafeName(host))
	if !a.Cfg.MakesReports() {
		dir = lan.OutboxDir(st)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		a.logf("archiving the logs: %v", err)
		return
	}
	info, err := archive.Create(filepath.Join(dir, archive.FileName(host, from, upTo)), host, runtime.GOOS, from, upTo, a.now())
	if err != nil {
		a.logf("archiving the logs: %v; will try again next run", err)
		return
	}
	for _, n := range info.Notes {
		a.logf("log archive: %s", n)
	}
	st.State.ArchivedUntil = upTo
	if err := st.Save(); err != nil {
		a.logf("saving state: %v", err)
	}
}

// bundleLogs combines, for each computer, the pending daily archives that
// end by end into one zip for the report folder. It returns them and the
// daily archives used, to remove once the report is written.
func (a *App) bundleLogs(end time.Time) (refs []report.ArchiveRef, used []string) {
	var list []archive.Stored
	for _, dir := range []string{a.pendingLogsDir(), a.legacyLogsDir()} {
		l, err := archive.List(dir)
		if err != nil {
			a.logf("listing log archives in %s: %v", dir, err)
		}
		list = append(list, l...)
	}
	byHost := map[string][]archive.Stored{}
	var hosts []string
	for _, s := range list {
		if s.To.After(end) {
			continue // for the next report
		}
		k := strings.ToLower(s.Host)
		if byHost[k] == nil {
			hosts = append(hosts, k)
		}
		byHost[k] = append(byHost[k], s)
	}
	sort.Strings(hosts)
	for _, k := range hosts {
		days := byHost[k]
		name := "logs-" + archive.SafeName(days[0].Host) + ".zip"
		tmp := filepath.Join(a.pendingLogsDir(), "."+name)
		from, to, sum, err := archive.Bundle(tmp, days)
		if err != nil {
			a.logf("original logs of %s: %v; they stay pending", days[0].Host, err)
			os.Remove(tmp)
			continue
		}
		fi, _ := os.Stat(tmp)
		var size uint64
		if fi != nil {
			size = uint64(fi.Size())
		}
		refs = append(refs, report.ArchiveRef{Host: days[0].Host, From: from, To: to, Name: name, Path: tmp, Bytes: size, SHA256: sum})
		for _, d := range days {
			used = append(used, d.Path)
		}
	}
	return refs, used
}

// open opens the data folder and takes the lock.
func (a *App) open() (*store.Store, func(), error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}
	unlock, err := st.Lock()
	if err != nil {
		return nil, nil, err
	}
	return st, unlock, nil
}

// gather does what every run does before reporting: collect this
// system's logs, check its audit settings (daily, or now if force), and
// receive what other systems sent, if this is a collector.
func (a *App) gather(st *store.Store, forceCheck bool) error {
	run, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf})
	if err != nil {
		return err
	}
	st.NoteSystem(run.Host, run.OS, a.Version, "", run.Time, time.Time{}, a.now())
	if err := a.recordChecks(st, run.Host, forceCheck); err != nil {
		a.logf("audit settings check: %v", err)
	}
	a.receive(st)
	return st.Save()
}

// checkEvery is how often a system that is not producing a report checks
// its audit settings (a report always includes a fresh check).
const checkEvery = 20 * time.Hour

// checkDue says whether the audit settings should be checked again: daily,
// and after every restart, since settings such as auditd or the kernel's
// audit=1 often only take effect after one.
func checkDue(last, boot, now time.Time) bool {
	return now.Sub(last) >= checkEvery || (!boot.IsZero() && boot.After(last))
}

func (a *App) bootTime() time.Time {
	if a.BootTime != nil {
		return a.BootTime()
	}
	return bootTime()
}

// recordChecks checks this system's audit settings and keeps the result,
// so it reaches reports here or on the collector.
func (a *App) recordChecks(st *store.Store, host string, force bool) error {
	if !check.Supported {
		return nil
	}
	now := a.now()
	if !force && !checkDue(st.State.LastCheck, a.bootTime(), now) {
		return nil
	}
	rec := &store.CheckRecord{Time: now, Host: host, OS: runtime.GOOS, Results: check.Run()}
	if err := st.AppendChecks(rec); err != nil {
		return err
	}
	st.State.LastCheck = now
	return nil
}

// receive imports batches other systems have delivered to this
// collector's inbox.
func (a *App) receive(st *store.Store) {
	if a.Cfg.Inbox == "" {
		return
	}
	if !lan.IsInbox(a.Cfg.Inbox) {
		if err := lan.PrepareInbox(a.Cfg.Inbox, collect.LocalHost()); err != nil {
			a.logf("inbox %s is not available: %v", a.Cfg.Inbox, err)
			return
		}
	}
	res, err := lan.Import(st, a.Cfg.Inbox, a.pendingLogsDir(), a.now(), a.Logf)
	if err != nil {
		a.logf("receiving from %s: %v", a.Cfg.Inbox, err)
	}
	if res.Batches > 0 {
		a.logf("received %d batch%s (%d records) from other systems", res.Batches, map[bool]string{true: "es"}[res.Batches != 1], res.Records)
	}
	if res.Archives > 0 {
		a.logf("received %d log archive(s) from other systems", res.Archives)
	}
}

// SendResult describes one attempt to send to the collector.
type SendResult struct {
	Made, Delivered, Waiting int
	ArchivesDelivered        int
	ArchivesWaiting          int
	Err                      error
}

// send batches new data and delivers what is waiting to the collector. A
// collector that cannot be reached is not an error for the run: the data
// waits in the outbox and goes next time.
func (a *App) send(st *store.Store) SendResult {
	var r SendResult
	host := collect.LocalHost()
	r.Made, r.Err = lan.Export(st, host, a.Version, a.now())
	if r.Err == nil {
		dest, err := share.Destination(a.Cfg)
		if err != nil {
			r.Err = err
		} else {
			r.Delivered, r.Err = lan.Deliver(st, dest, host)
			if r.Err == nil {
				r.ArchivesDelivered, r.Err = lan.DeliverArchives(st, dest)
			}
		}
	}
	r.Waiting = lan.Queued(st)
	r.ArchivesWaiting = lan.QueuedArchives(st)
	if s := st.State.Send; s != nil {
		s.LastAttempt = a.now()
		s.LastError = ""
		if r.Err != nil {
			s.LastError = r.Err.Error()
		} else if r.Waiting == 0 && r.ArchivesWaiting == 0 {
			s.LastDelivered = a.now()
		}
		st.Save()
	}
	switch {
	case r.Err != nil:
		a.logf("could not send to the collector: %v; %d batch(es) waiting, will retry next run", r.Err, r.Waiting)
	case r.Delivered > 0 || r.ArchivesDelivered > 0:
		a.logf("sent %d batch(es) and %d log archive(s) to the collector", r.Delivered, r.ArchivesDelivered)
	}
	return r
}

// Scheduled is what the scheduled task runs: collect (and receive, on a
// collector), then send to the collector or produce a report if one is
// due. It returns the report folder ("" if none).
func (a *App) Scheduled() (string, error) {
	st, unlock, err := a.open()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.gather(st, false); err != nil {
		return "", err
	}
	if !a.Cfg.MakesReports() {
		a.archiveLogs(st, a.now(), false)
		a.send(st)
		return "", nil
	}
	end, due := DueWindowEnd(a.Cfg.ReportEvery, a.Cfg.ReportAt, st.State.LastWindowEnd, a.now(), a.loc())
	if !due {
		a.archiveLogs(st, a.now(), false)
		return "", nil
	}
	return a.report(st, end, true)
}

// ReportNow collects and produces a report up to now. With advance=false
// it is an interim report: the schedule and report chain are untouched,
// and the next scheduled report covers the same time again.
func (a *App) ReportNow(advance bool) (string, error) {
	st, unlock, err := a.open()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.gather(st, true); err != nil {
		return "", err
	}
	return a.report(st, a.now(), advance)
}

// SendNow collects and sends to the collector straight away (for example
// from a script that starts a virtual machine only for a short time).
func (a *App) SendNow() (SendResult, error) {
	if a.Cfg.SendTo == "" {
		return SendResult{}, fmt.Errorf("this computer is not set to send to a collector (send_to is empty)")
	}
	st, unlock, err := a.open()
	if err != nil {
		return SendResult{}, err
	}
	defer unlock()
	if err := a.gather(st, false); err != nil {
		return SendResult{}, err
	}
	r := a.send(st)
	return r, r.Err
}

// Collect only collects.
func (a *App) Collect() (*store.Run, error) {
	st, unlock, err := a.open()
	if err != nil {
		return nil, err
	}
	defer unlock()
	run, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf})
	if err == nil {
		st.NoteSystem(run.Host, run.OS, a.Version, "", run.Time, time.Time{}, a.now())
		err = st.Save()
	}
	return run, err
}

func (a *App) report(st *store.Store, end time.Time, advance bool) (string, error) {
	generated := a.now()
	prevEnd, prevGen := st.State.LastWindowEnd, st.State.LastGenerated
	since := prevEnd
	if !prevGen.IsZero() && prevGen.Before(since) {
		since = prevGen
	}
	// A day before the period is read as well, for detections that span
	// two reports.
	readFrom := since
	if !readFrom.IsZero() {
		readFrom = readFrom.Add(-contextSpan)
	}
	all, err := st.ReadEvents(readFrom)
	if err != nil {
		return "", err
	}
	events := SelectWindow(all, prevEnd, prevGen, end, generated)
	// The report's folder holds the original logs for its period: this
	// computer's are saved up to the end of the period first.
	var logs []report.ArchiveRef
	var usedLogs []string
	if advance {
		a.archiveLogs(st, end, true)
		logs, usedLogs = a.bundleLogs(end)
		defer func() {
			for _, l := range logs {
				os.Remove(l.Path) // left only if the report was not written
			}
		}()
	}
	context := contextEvents(all, events, prevEnd)
	runs, err := st.ReadRuns(prevGen)
	if err != nil {
		return "", err
	}
	// The latest audit settings check of each computer: a week's look-back
	// finds one even for a computer that checks only once a day.
	checkSince := prevEnd
	if !checkSince.IsZero() {
		checkSince = checkSince.AddDate(0, 0, -7)
	}
	latest, err := st.LatestChecks(checkSince, generated)
	if err != nil {
		return "", err
	}
	var sets []report.CheckSet
	for _, c := range latest {
		sets = append(sets, report.NewCheckSet(c.Host, c.Time, c.Results))
	}
	sort.Slice(sets, func(i, j int) bool { return strings.ToLower(sets[i].Host) < strings.ToLower(sets[j].Host) })

	r := report.Build(events, runs, report.Options{
		Site:        a.Cfg.SiteName,
		WindowStart: prevEnd, WindowEnd: end, Generated: generated, Version: a.Version,
		Source: "Live collection", Location: a.loc(), InReportsDir: true, Interim: !advance, Period: a.Cfg.ReportEvery,
		History:      report.History(a.ReportsDir(), end, 11),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
		KnownDevices: st.State.KnownDevices, CheckSets: sets,
		Context: context, Baseline: st.State.Baseline, BaselineHosts: st.State.BaselineHosts,
		WorkingHours: a.Cfg.WorkingHours,
		Archives:     logs, ArchivesKept: advance,
		Systems: systemsFor(st, prevEnd), Collector: a.Cfg.Inbox != "",
		LANWarnings: lanWarnings(st, prevGen, generated, a.loc()),
	})
	if len(r.Hosts) == 0 {
		r.Hosts = []string{collect.LocalHost()}
	}
	name := report.DirName(end, r.Hosts, a.loc())
	if !advance {
		name += "_interim"
	}
	dir := report.UniqueDir(a.ReportsDir(), name)
	if err := r.Write(dir); err != nil {
		return "", err
	}
	if advance {
		for _, p := range usedLogs {
			if err := os.Remove(p); err != nil {
				a.logf("removing a daily log archive now in the report: %v", err)
			}
		}
		st.State.LastWindowEnd = end
		st.State.LastGenerated = generated
		for k, t := range r.NewDevices {
			st.State.KnownDevices[k] = t
		}
		report.UpdateBaseline(st.State.Baseline, st.State.BaselineHosts, r, generated)
		if err := st.Save(); err != nil {
			return dir, err
		}
		if err := st.Prune(a.Cfg.RetentionDays, generated); err != nil {
			a.logf("pruning old data: %v", err)
		}
		if err := pruneReports(a.ReportsDir(), a.Cfg.RetentionDays, generated); err != nil {
			a.logf("pruning old reports: %v", err)
		}
		for _, d := range []string{a.pendingLogsDir(), a.legacyLogsDir()} {
			if err := archive.Prune(d, a.Cfg.RetentionDays, generated); err != nil {
				a.logf("pruning old log archives: %v", err)
			}
		}
	}
	if err := report.WriteIndex(a.ReportsDir(), a.Cfg.SiteName, a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.loc()); err != nil {
		a.logf("updating report index: %v", err)
	}
	return dir, nil
}

// contextSpan is how far before a report's period detections look.
const contextSpan = 24 * time.Hour

// contextEvents returns the events from the day before the period start
// that are not in the report itself (they were in the previous one).
func contextEvents(all, inReport []*event.Event, start time.Time) []*event.Event {
	if start.IsZero() {
		return nil
	}
	in := make(map[*event.Event]bool, len(inReport))
	for _, e := range inReport {
		in[e] = true
	}
	var out []*event.Event
	for _, e := range all {
		if !in[e] && !e.Time.Before(start.Add(-contextSpan)) && e.Time.Before(start) {
			out = append(out, e)
		}
	}
	return out
}

// systemsFor lists the computers to show in a report whose period starts
// at start: all known, except those retired before it.
func systemsFor(st *store.Store, start time.Time) []report.SystemInfo {
	var out []report.SystemInfo
	for _, s := range st.State.Systems {
		if !s.Removed.IsZero() && !s.Removed.After(start) {
			continue
		}
		out = append(out, report.SystemInfo{Name: s.Name, OS: s.OS, Version: s.Version, Via: s.Via,
			FirstSeen: s.FirstSeen, LastRun: s.LastRun, LastReceived: s.LastReceived})
	}
	return out
}

// lanWarnings describes problems noticed receiving from other computers
// since the previous report.
func lanWarnings(st *store.Store, since, until time.Time, loc *time.Location) []string {
	var out []string
	ids := make([]string, 0, len(st.State.Senders))
	for id := range st.State.Senders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := st.State.Senders[id]
		for _, g := range s.Missing {
			if g.Noted.After(since) && !g.Noted.After(until) {
				what := fmt.Sprintf("batch %d", g.From)
				if g.To > g.From {
					what = fmt.Sprintf("batches %d to %d", g.From, g.To)
				}
				out = append(out, fmt.Sprintf("%s: %s sent by this computer never arrived (noticed %s). The events in them are missing from the reports; they may have been deleted from the inbox folder.",
					s.Host, what, g.Noted.In(loc).Format("2006-01-02 15:04")))
			}
		}
		if s.ClockNoted.After(since) && !s.ClockNoted.After(until) {
			out = append(out, fmt.Sprintf("%s: its clock was %s ahead of this collector's (noticed %s). Event times from it may be wrong; check its time settings.",
				s.Host, s.ClockAhead, s.ClockNoted.In(loc).Format("2006-01-02 15:04")))
		}
	}
	return out
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
// that, periods end at the configured time (see config.ReportAt): each
// day, each week on the configured day, or on the 1st of each month.
func DueWindowEnd(every string, at config.ReportAt, lastEnd, now time.Time, loc *time.Location) (time.Time, bool) {
	if lastEnd.IsZero() {
		return now, true
	}
	b := at.LastBoundary(every, now, loc)
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
