package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/store"
)

// Status writes a plain summary of what this computer does and whether it
// is working: for a quick check by an administrator, or a support call.
func (a *App) Status(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	now := a.now()
	s := st.State
	host := collect.LocalHost()
	p := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-17s %s\n", label, fmt.Sprintf(format, args...))
	}

	fmt.Fprintf(w, "%s %s on %s\n\n", brand.Name, a.Version, host)
	switch a.Cfg.Role() {
	case "standalone":
		p("Role:", "standalone (reports on this computer only)")
	case "collector":
		p("Role:", "collector (reports on this computer and the computers that send to it)")
	case "sender":
		p("Role:", "sends to a collector (reports are produced on the collector)")
	}
	if s.LastCollect.IsZero() {
		p("Last collection:", "never (the scheduled task has not run yet)")
	} else {
		p("Last collection:", "%s (%s)", stampLocal(s.LastCollect, a.loc()), ago(now.Sub(s.LastCollect)))
	}
	if !s.LastCheck.IsZero() {
		p("Settings checked:", "%s", stampLocal(s.LastCheck, a.loc()))
	}
	if s.ArchivedUntil.IsZero() {
		p("Log archive:", "none yet (the original logs are saved once a day)")
	} else {
		where := "they go into the next report's folder"
		if !a.Cfg.MakesReports() {
			where = "sent to the collector"
			if n := lan.QueuedArchives(st); n > 0 {
				where = fmt.Sprintf("%d waiting to be sent to the collector", n)
			}
		}
		p("Log archive:", "original logs saved up to %s (%s)", stampLocal(s.ArchivedUntil, a.loc()), where)
	}

	for _, l := range lostSince(st, s.LastWindowEnd, now) {
		p("Events lost:", "%s", LostText(l, a.loc()))
	}

	if a.Cfg.SendTo != "" {
		fmt.Fprintln(w)
		p("Sending to:", "%s", a.Cfg.SendTo)
		if a.Cfg.ShareUser != "" {
			p("Share account:", "%s", a.Cfg.ShareUser)
		}
		waiting := lan.Queued(st)
		switch snd := s.Send; {
		case snd == nil:
			p("Sent:", "nothing yet (sends after the next collection)")
		case snd.LastError != "":
			p("Last attempt:", "%s — FAILED: %s", stampLocal(snd.LastAttempt, a.loc()), snd.LastError)
			p("Waiting to send:", "%d batch%s (kept safely here; sent when the collector can be reached)", waiting, es(waiting))
		default:
			if !snd.LastDelivered.IsZero() {
				p("Last delivered:", "%s (%s)", stampLocal(snd.LastDelivered, a.loc()), ago(now.Sub(snd.LastDelivered)))
			}
			p("Waiting to send:", "%d batch%s", waiting, es(waiting))
		}
	}
	if a.Cfg.MakesReports() {
		fmt.Fprintln(w)
		p("Reports:", "%s, saved in %s", a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.Cfg.ReportsDir())
		if !s.LastWindowEnd.IsZero() {
			p("Last report:", "period ending %s", stampLocal(s.LastWindowEnd, a.loc()))
			if next, due := nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, s.LastWindowEnd, now, a.loc()); !due {
				p("Next report:", "after %s", stampLocal(next, a.loc()))
			} else {
				p("Next report:", "at the next scheduled run")
			}
		}
	}
	if a.Cfg.Inbox != "" {
		fmt.Fprintln(w)
		state := "OK"
		if !lan.IsInbox(a.Cfg.Inbox) {
			state = "NOT READY (created at the next scheduled run)"
		}
		waiting := 0
		if list, err := filepath.Glob(filepath.Join(a.Cfg.Inbox, "*.bbx")); err == nil {
			waiting = len(list)
		}
		p("Inbox:", "%s — %s; %d batch%s waiting to be imported", a.Cfg.Inbox, state, waiting, es(waiting))
		if rej, _ := filepath.Glob(filepath.Join(a.Cfg.Inbox, "rejected", "*")); len(rej) > 0 {
			p("", "%d file%s set aside in %s (see blackbox.log)", len(rej), map[bool]string{true: "s"}[len(rej) != 1], filepath.Join(a.Cfg.Inbox, "rejected"))
		}
	}
	if a.Cfg.Inbox != "" {
		fmt.Fprintln(w)
		a.writeSystems(w, st, now)
	}
	return nil
}

// Systems writes the table of known computers.
func (a *App) Systems(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	a.writeSystems(w, st, a.now())
	return nil
}

func (a *App) writeSystems(w io.Writer, st *store.Store, now time.Time) {
	var list []*store.System
	for _, s := range st.State.Systems {
		if s.Removed.IsZero() {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	fmt.Fprintf(w, "Systems (%d)\n", len(list))
	if len(list) == 0 {
		fmt.Fprintln(w, "  none yet")
		return
	}
	fmt.Fprintf(w, "  %-20s %-8s %-18s %-18s %s\n", "NAME", "OS", "LAST COLLECTION", "LAST RECEIVED", "NOTE")
	self := store.SystemKey(collect.LocalHost())
	for _, s := range list {
		recv := stampLocal(s.LastReceived, a.loc())
		note := ""
		if store.SystemKey(s.Name) == self {
			recv, note = "-", "this computer"
		}
		if s.Via != "" {
			note = "via " + s.Via
		}
		switch {
		case !s.LastRun.IsZero() && now.Sub(s.LastRun) > silentAfter:
			note = strings.TrimSpace(note + "  NO DATA SINCE " + strings.ToUpper(ago(now.Sub(s.LastRun))))
		case store.SystemKey(s.Name) != self && !s.LastReceived.IsZero() && now.Sub(s.LastReceived) > 2*expectedSend:
			// Earlier than the silence above: a sender whose deliveries
			// are refused (or that is switched off) shows here first.
			note = strings.TrimSpace(note + "  no batch since " + stampLocal(s.LastReceived, a.loc()))
		}
		fmt.Fprintf(w, "  %-20s %-8s %-18s %-18s %s\n", s.Name, s.OS, stampLocal(s.LastRun, a.loc()), recv, note)
	}
	for _, snd := range st.State.Senders {
		for _, g := range snd.Missing {
			fmt.Fprintf(w, "  Missing: batches %d-%d from %s never arrived (noticed %s)\n", g.From, g.To, snd.Host, stampLocal(g.Noted, a.loc()))
		}
	}
}

// expectedSend is how often a sender delivers: after each collection, by
// default every hour.
const expectedSend = time.Hour

// silentAfter matches the report's threshold for pointing out a computer
// that has stopped collecting.
const silentAfter = 36 * time.Hour

// RemoveSystem retires a computer: it is no longer listed, or reported as
// silent. Its past events stay in earlier reports. If it sends again, it
// is listed again.
func (a *App) RemoveSystem(name string) error {
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	defer unlock()
	s := st.State.Systems[store.SystemKey(name)]
	if s == nil {
		var names []string
		for _, x := range st.State.Systems {
			names = append(names, x.Name)
		}
		sort.Strings(names)
		return fmt.Errorf("no system named %q (known: %s)", name, strings.Join(names, ", "))
	}
	s.Removed = a.now()
	return st.Save()
}

// NextScheduled returns when the last scheduled report period ended (zero
// if no report has been produced yet) and when the next one is due (zero
// if it is due now: at the next scheduled run).
func (a *App) NextScheduled() (lastEnd, next time.Time, err error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	lastEnd = st.State.LastWindowEnd
	next, _ = nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, lastEnd, a.now(), a.loc())
	return lastEnd, next, nil
}

// NextText says when the next scheduled report is due, in words.
func NextText(next time.Time) string {
	if next.IsZero() {
		return "at the next scheduled run"
	}
	return next.In(time.Local).Format("Monday 2 Jan 2006 15:04")
}

func nextReport(every string, at config.ReportAt, lastEnd, now time.Time, loc *time.Location) (time.Time, bool) {
	if _, due := DueWindowEnd(every, at, lastEnd, now, loc); due {
		return time.Time{}, true
	}
	return at.NextBoundary(every, now, loc), false
}

// LostText describes events lost to rollover, with what to do about it.
func LostText(l LostLog, loc *time.Location) string {
	return fmt.Sprintf("%s log on %s: %s events overwritten before they could be collected, since %s. Collect more often (every 15 minutes), or make the log larger.",
		l.Channel, l.Host, commaNum(l.Count), stampLocal(l.Since, loc))
}

func commaNum(n uint64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func stampLocal(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func es(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// Exists reports whether a data folder has been used (for messages).
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "state.json"))
	return err == nil
}
