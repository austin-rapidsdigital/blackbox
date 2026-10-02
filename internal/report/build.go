// Package report turns translated events and collection records into a
// self-contained HTML report plus CSV/JSON exports and a SHA-256 manifest.
package report

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// maxRowsPerSection keeps the HTML file a manageable size; every event
// is always in events.zip (events.csv).
const maxRowsPerSection = 5000

// Options describe the report being built.
type Options struct {
	Site         string
	WindowStart  time.Time // zero = from the beginning of collected data
	WindowEnd    time.Time
	Generated    time.Time
	Version      string
	Source       string // e.g. "Live collection" or "Exported file sec.xml"
	Location     *time.Location
	InReportsDir bool // report sits in the reports folder next to the list of all reports

	// Interim marks a report run by hand between scheduled reports. It
	// covers the time since the last scheduled report and does not move
	// the schedule; the next scheduled report covers that time again.
	Interim bool

	// Period is how often reports are made ("weekly"), shown as "Weekly
	// report". Empty for a report from exported files.
	Period string

	ExcludeUsers     []string
	ExcludeProcesses []string

	// KnownDevices lists removable devices seen in earlier reports; new
	// ones are flagged. Nil disables the check.
	KnownDevices map[string]time.Time

	// Context is events from the day before the period, already reported,
	// so a detection that started then can be completed now.
	Context []*event.Event

	// Baseline is what has been seen before (first logons, administrator
	// use, logon addresses), and BaselineHosts the computers whose normal
	// activity has been learned. Nil Baseline turns first-time detection off.
	Baseline      map[string]time.Time
	BaselineHosts map[string]time.Time

	// WorkingHours: administrator activity outside them is detected.
	WorkingHours config.WorkingHours

	// Archives are the original logs for this period, one zip per
	// computer, stored in the report folder. ArchivesKept says logs are
	// archived, so a computer without them is pointed out.
	Archives     []ArchiveRef
	ArchivesKept bool

	// CheckSets are the latest audit settings check of each computer.
	CheckSets []CheckSet

	// LAN: the computers this data folder knows about, whether this is a
	// collector, and problems noticed receiving from other computers.
	Systems     []SystemInfo
	Collector   bool
	LANWarnings []string
}

// ArchiveRef is one computer's original logs for the period: a zip that
// Write moves from Path into the report folder as Name.
type ArchiveRef struct {
	Host     string
	From, To time.Time
	Name     string // file name in the report folder, e.g. logs-WS-07.zip
	Path     string // where the zip is before the report is written
	Bytes    uint64
	SHA256   string
}

// Row is one event in a section table.
type Row struct {
	*event.Event
	ID    string
	Flags []string
}

// Section is one category of the report.
type Section struct {
	Info      event.CategoryInfo
	Rows      []*Row
	Total     int
	Truncated int
	BySev     map[string]int // by severity
	Logons    []LogonSummary // Logon Activity only
}

// LogonSummary is one person's logons in the period.
type LogonSummary struct {
	User    string
	Host    string
	ByType  map[string]int
	Types   string
	Count   int
	Sources string
	First   time.Time
	Last    time.Time
}

// Finding is a pattern across several events.
type Finding struct {
	Severity event.Severity
	Category event.Category
	Host     string
	Time     time.Time
	Title    string
	Detail   string
	RowID    string   // first related row, for linking
	RowIDs   []string // every related row
}

// AttentionGroup summarises medium-severity events by kind.
type AttentionGroup struct {
	Category event.Category
	Label    string
	Count    int
	RowID    string
}

// UserRow is the per-person view.
type UserRow struct {
	User   string
	Counts map[event.Category]int
	High   int
	Total  int
}

// ChannelHealth summarises collection of one log on one host.
type ChannelHealth struct {
	Host        string
	Channel     string
	Runs        int
	Read        int
	Kept        int
	Lost        uint64
	Resets      int
	LastError   string
	Unavailable string
	History     time.Duration // how far back the log reached at the last run
	MaxSize     uint64
}

// VolumeRow is one busy event ID (Windows) or record type (Linux).
type VolumeRow struct {
	Channel string
	EventID int
	Type    string
	Name    string
	Count   int
	Percent float64
}

// GapItem is one period where events were lost.
type GapItem struct {
	Host, Channel string
	Lost          uint64
	From, To      time.Time
	Reset         bool
	Note          string // when the number lost is not known
}

// Health describes whether the report is complete.
type Health struct {
	Runs         int
	FirstRun     time.Time
	LastRun      time.Time
	LongestPause time.Duration
	Channels     []ChannelHealth
	Gaps         []GapItem
	Volume       []VolumeRow
	TotalRead    int
	TotalKept    int
	Warnings     []string
	ChecksPass   int
	ChecksFail   int
	ChecksWarn   int
	LogClears    int
	AuditOff     []string // periods auditing was switched off
}

// Report is everything the template needs.
type Report struct {
	Options
	Hosts      []string
	FirstEvent time.Time
	LastEvent  time.Time
	Sections   []*Section
	Findings   []Finding
	HighRows   []*Row
	Medium     []AttentionGroup
	Users      []UserRow
	Health     Health
	Events     []*event.Event // final list (after exclusions and de-duplication)
	Excluded   int
	Duplicates int
	Late       int
	NewDevices map[string]time.Time
	Learned    map[string]time.Time // baseline items seen in this period
	Learning   []string             // computers whose normal activity is being learned
	NoArchive  []string             // computers with no log archive for this period
	BySev      map[string]int       // by severity
	SystemRows []SystemRow          // Systems page
	Silent     []SystemRow          // computers with no collection in this period

	rows []*Row // one per event, in the order of Events
}

// Build assembles a report from events (already filtered to the period)
// and the collection runs in the period.
func Build(events []*event.Event, runs []*store.Run, opt Options) *Report {
	if opt.Location == nil {
		opt.Location = time.Local
	}
	r := &Report{Options: opt, NewDevices: map[string]time.Time{}, Learned: map[string]time.Time{}, BySev: map[string]int{}}

	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	events = r.exclude(events)
	events = r.dedupe(events)
	attributeDevices(events)

	rows := make([]*Row, len(events))
	hosts := map[string]bool{}
	for i, e := range events {
		rows[i] = &Row{Event: e, ID: "r" + strconv.Itoa(i+1)}
		hosts[e.Host] = true
		r.BySev[string(e.Severity)]++
		if e.Late {
			r.Late++
			rows[i].Flags = append(rows[i].Flags, "Late")
		}
	}
	r.Events = events
	r.rows = rows
	for h := range hosts {
		r.Hosts = append(r.Hosts, h)
	}
	sort.Strings(r.Hosts)
	if len(events) > 0 {
		r.FirstEvent, r.LastEvent = events[0].Time, events[len(events)-1].Time
	}

	r.flagNewDevices(rows)
	r.buildSections(rows)
	r.findPatterns(rows)
	r.detect(rows, r.withContext(rows))
	r.buildAttention(rows)
	r.buildUsers(events)
	r.buildHealth(runs, events)
	r.buildSystems(runs, events)
	r.checkArchives()
	for _, s := range r.Silent {
		r.Health.Warnings = append(r.Health.Warnings, s.Name+": "+s.StatusMsg)
	}
	return r
}

// checkArchives notes the computers in this report with no archive of
// their original logs for the period.
func (r *Report) checkArchives() {
	if !r.ArchivesKept {
		return
	}
	have := map[string]bool{}
	for _, a := range r.Archives {
		have[strings.ToLower(a.Host)] = true
	}
	for _, h := range r.Hosts {
		if !have[strings.ToLower(archiveName(h))] {
			r.NoArchive = append(r.NoArchive, h)
		}
	}
	if len(r.NoArchive) > 0 {
		r.Health.Warnings = append(r.Health.Warnings, "No archive of the original logs for this period from: "+strings.Join(r.NoArchive, ", ")+". See Audit health.")
	}
}

// archiveName is how a host appears in archive file names.
var archiveUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func archiveName(h string) string {
	h = strings.Trim(archiveUnsafe.ReplaceAllString(h, "-"), "-")
	if h == "" {
		return "unknown"
	}
	return h
}

// ---------------------------------------------------------------- filters

func (r *Report) exclude(in []*event.Event) []*event.Event {
	if len(r.ExcludeUsers) == 0 && len(r.ExcludeProcesses) == 0 {
		return in
	}
	users := map[string]bool{}
	for _, u := range r.ExcludeUsers {
		users[strings.ToLower(u)] = true
	}
	out := in[:0:0]
	for _, e := range in {
		u := strings.ToLower(e.User)
		short := u
		if i := strings.LastIndex(u, `\`); i >= 0 {
			short = u[i+1:]
		}
		skip := users[u] || users[short]
		if !skip && e.Process != "" {
			p := strings.ToLower(e.Process)
			base := strings.ToLower(filepath.Base(strings.ReplaceAll(e.Process, `\`, "/")))
			for _, x := range r.ExcludeProcesses {
				x = strings.ToLower(x)
				if p == x || base == x {
					skip = true
					break
				}
			}
		}
		if skip {
			r.Excluded++
			continue
		}
		out = append(out, e)
	}
	return out
}

// dedupeWindow is how close in time two events with the same key must be
// to count as one.
func dedupeWindow(key string) time.Duration {
	switch {
	case strings.HasPrefix(key, "authfail|"):
		return 2 * time.Second
	case strings.HasPrefix(key, "4672|"):
		return 24 * time.Hour
	case strings.HasPrefix(key, "rm|"):
		return time.Minute
	case strings.HasPrefix(key, "svc|"), strings.HasPrefix(key, "psblock|"):
		return 10 * time.Minute
	}
	return 5 * time.Minute
}

// dedupe merges events describing the same thing, keeping the most
// informative one (highest Priority). Input must be sorted by time.
func (r *Report) dedupe(in []*event.Event) []*event.Event {
	type slot struct {
		idx  int
		time time.Time
	}
	last := map[string]slot{}
	out := make([]*event.Event, 0, len(in))
	for _, e := range in {
		if e.DedupeKey == "" {
			out = append(out, e)
			continue
		}
		k := e.Host + "|" + e.DedupeKey
		if s, ok := last[k]; ok && e.Time.Sub(s.time) <= dedupeWindow(e.DedupeKey) {
			r.Duplicates++
			kept := out[s.idx]
			if e.Priority > kept.Priority {
				out[s.idx] = e
			}
			continue
		}
		last[k] = slot{len(out), e.Time}
		out = append(out, e)
	}
	return out
}

// attributeDevices names the person most likely using a removable device:
// device events do not record a user, so use whoever is logged on at the
// console of that host (not remotely: a remote user cannot plug in a
// device). When several people are, the most recent is named and the
// others are listed.
func attributeDevices(events []*event.Event) {
	// Best evidence: the person who mounted the device right after it was
	// connected (recorded by udisks on Linux).
	for i, e := range events {
		if e.Action != "usb_connected" || e.User != "" {
			continue
		}
		for _, m := range events[i+1:] {
			if m.Time.Sub(e.Time) > 2*time.Minute {
				break
			}
			if m.Host == e.Host && m.Action == "removable_mounted" && m.User != "" {
				e.User = m.User
				e.AddDetail("User", m.User+" (opened the device right after it was connected)")
				break
			}
		}
	}
	active := map[string][]string{} // host → console users, oldest first
	remove := func(host, user string) {
		l := active[host]
		for i := len(l) - 1; i >= 0; i-- {
			if l[i] == user {
				active[host] = append(l[:i:i], l[i+1:]...)
				return
			}
		}
	}
	for _, e := range events {
		switch {
		case e.Action == "logon" && consoleLogon(e):
			remove(e.Host, e.User)
			active[e.Host] = append(active[e.Host], e.User)
		case e.Action == "logoff":
			remove(e.Host, e.User)
		case e.Category == event.CatRemovable && e.User == "":
			l := active[e.Host]
			if len(l) == 0 {
				continue
			}
			e.User = l[len(l)-1]
			e.AddDetail("User", e.User+" (logged on at the console at the time; device events do not record a user)")
			if len(l) > 1 {
				e.AddDetail("Also logged on at the console", strings.Join(l[:len(l)-1], ", "))
			}
		}
	}
}

// consoleLogon reports a logon made at the machine itself.
func consoleLogon(e *event.Event) bool {
	switch e.Fields["LogonType"] {
	case "2", "7", "11", "13":
		return true
	}
	for _, d := range e.Details {
		if d.Label == "Logon type" && (d.Value == "Graphical console" || d.Value == "Text console") {
			return true
		}
	}
	return false
}

func (r *Report) flagNewDevices(rows []*Row) {
	if r.KnownDevices == nil {
		return
	}
	for _, row := range rows {
		if row.Action != "usb_connected" {
			continue
		}
		key := deviceKey(row.Event)
		if key == "" {
			continue
		}
		if _, seen := r.KnownDevices[key]; seen {
			continue
		}
		if _, seen := r.NewDevices[key]; !seen {
			r.NewDevices[key] = row.Time
			row.Flags = append(row.Flags, "New device")
			if row.Severity.Rank() < event.SevHigh.Rank() {
				row.Severity = event.SevHigh
			}
		}
	}
}

func deviceKey(e *event.Event) string {
	if strings.HasPrefix(e.DedupeKey, "usb|") {
		return e.Host + "|" + strings.TrimPrefix(e.DedupeKey, "usb|")
	}
	return ""
}

// ---------------------------------------------------------------- sections

func (r *Report) buildSections(rows []*Row) {
	by := map[event.Category]*Section{}
	for _, ci := range event.Categories {
		s := &Section{Info: ci, BySev: map[string]int{}}
		by[ci.ID] = s
		r.Sections = append(r.Sections, s)
	}
	for _, row := range rows {
		s := by[row.Category]
		if s == nil {
			continue
		}
		s.Total++
		s.BySev[string(row.Severity)]++
		if len(s.Rows) < maxRowsPerSection {
			s.Rows = append(s.Rows, row)
		} else {
			s.Truncated++
		}
	}
	by[event.CatLogon].Logons = summarizeLogons(rows)
}

func summarizeLogons(rows []*Row) []LogonSummary {
	idx := map[string]*LogonSummary{}
	sources := map[string]map[string]bool{}
	for _, row := range rows {
		if row.Action != "logon" {
			continue
		}
		k := row.Host + "|" + row.User
		s := idx[k]
		if s == nil {
			s = &LogonSummary{User: row.User, Host: row.Host, ByType: map[string]int{}, First: row.Time}
			idx[k] = s
			sources[k] = map[string]bool{}
		}
		s.Count++
		s.Last = row.Time
		for _, d := range row.Details {
			if d.Label == "Logon type" {
				s.ByType[d.Value]++
			}
		}
		if row.SourceIP != "" {
			sources[k][row.SourceIP] = true
		}
	}
	var out []LogonSummary
	for k, s := range idx {
		s.Types = joinCounts(s.ByType)
		var src []string
		for ip := range sources[k] {
			src = append(src, ip)
		}
		sort.Strings(src)
		s.Sources = strings.Join(src, ", ")
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].User < out[j].User
	})
	return out
}

func joinCounts(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for _, x := range l {
		parts = append(parts, fmt.Sprintf("%s ×%d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------- patterns

const (
	guessWindow    = 15 * time.Minute
	guessThreshold = 5
	sprayThreshold = 3
	successWindow  = 30 * time.Minute
)

func (r *Report) findPatterns(rows []*Row) {
	var fails []*Row
	for _, row := range rows {
		if row.Action == "logon_failed" {
			fails = append(fails, row)
		}
	}
	// Repeated failures for one account.
	byUser := map[string][]*Row{}
	for _, f := range fails {
		k := f.Host + "|" + strings.ToLower(f.Target)
		byUser[k] = append(byUser[k], f)
	}
	for _, list := range byUser {
		for _, c := range clusters(list, guessWindow) {
			if len(c) < guessThreshold {
				continue
			}
			first, last := c[0], c[len(c)-1]
			src := distinct(c, func(x *Row) string { return x.SourceIP })
			d := fmt.Sprintf("%d failed logons for %s on %s between %s and %s", len(c), first.Target, first.Host,
				r.clock(first.Time), r.clock(last.Time))
			if src != "" {
				d += " from " + src
			}
			r.Findings = append(r.Findings, Finding{Severity: event.SevHigh, Category: event.CatFailedLogon,
				Host: first.Host, Time: first.Time, RowID: first.ID, RowIDs: rowIDs(c),
				Title: "Possible password guessing", Detail: d + "."})
		}
	}
	// One source trying several accounts.
	bySrc := map[string][]*Row{}
	for _, f := range fails {
		src := f.SourceIP
		if src == "" {
			continue
		}
		bySrc[f.Host+"|"+src] = append(bySrc[f.Host+"|"+src], f)
	}
	for _, list := range bySrc {
		for _, c := range clusters(list, guessWindow) {
			users := distinctList(c, func(x *Row) string { return x.Target })
			if len(users) < sprayThreshold {
				continue
			}
			first := c[0]
			r.Findings = append(r.Findings, Finding{Severity: event.SevHigh, Category: event.CatFailedLogon,
				Host: first.Host, Time: first.Time, RowID: first.ID, RowIDs: rowIDs(c),
				Title: "One source tried several accounts",
				Detail: fmt.Sprintf("%s tried %d different accounts on %s (%s) with %d failed logons between %s and %s.",
					first.SourceIP, len(users), first.Host, strings.Join(users, ", "), len(c),
					r.clock(first.Time), r.clock(c[len(c)-1].Time))})
		}
	}
	// Several failures followed by a success (reported once per burst).
	reported := map[string]bool{}
	for _, row := range rows {
		if row.Action != "logon" {
			continue
		}
		var n int
		var firstFail *Row
		for _, f := range byUser[row.Host+"|"+strings.ToLower(row.User)] {
			if f.Time.Before(row.Time) && row.Time.Sub(f.Time) <= successWindow {
				if firstFail == nil {
					firstFail = f
				}
				n++
			}
		}
		if n >= 3 && !reported[firstFail.ID] {
			reported[firstFail.ID] = true
			r.Findings = append(r.Findings, Finding{Severity: event.SevMedium, Category: event.CatFailedLogon,
				Host: row.Host, Time: row.Time, RowID: firstFail.ID, RowIDs: rowIDs([]*Row{firstFail, row}),
				Title: "Successful logon after failures",
				Detail: fmt.Sprintf("%s logged on to %s at %s after %d failed attempts in the previous %d minutes.",
					row.User, row.Host, r.clock(row.Time), n, int(successWindow.Minutes()))})
		}
	}
	// Auditing switched off by a person, until it came back.
	for i, row := range rows {
		if row.Action != "audit_stopped" || row.Severity != event.SevHigh {
			continue
		}
		var until *Row
		for _, next := range rows[i+1:] {
			if next.Host == row.Host && next.Action == "audit_started" {
				until = next
				break
			}
		}
		f := Finding{Severity: event.SevHigh, Category: event.CatIntegrity, Host: row.Host, Time: row.Time, RowID: row.ID,
			RowIDs: []string{row.ID}, Title: "Auditing was switched off"}
		if until != nil {
			f.RowIDs = append(f.RowIDs, until.ID)
			f.Detail = fmt.Sprintf("The audit service on %s was off for %s (%s to %s). Nothing done in that time was recorded.",
				row.Host, roughDuration(until.Time.Sub(row.Time)), r.clock(row.Time), r.clock(until.Time))
			r.Health.AuditOff = append(r.Health.AuditOff, fmt.Sprintf("%s: auditing was off for %s (%s to %s).",
				row.Host, roughDuration(until.Time.Sub(row.Time)), r.stamp(row.Time), r.stamp(until.Time)))
		} else {
			f.Detail = fmt.Sprintf("The audit service on %s was stopped at %s and had not restarted by the end of this report.", row.Host, r.clock(row.Time))
			r.Health.AuditOff = append(r.Health.AuditOff, fmt.Sprintf("%s: auditing was stopped at %s and not restarted.", row.Host, r.stamp(row.Time)))
		}
		r.Findings = append(r.Findings, f)
	}
}

// withContext returns the rows of the period preceded by the context
// events (filtered and merged the same way, with no row ID).
func (r *Report) withContext(rows []*Row) []*Row {
	if len(r.Context) == 0 {
		return rows
	}
	ctx := append([]*event.Event(nil), r.Context...)
	sort.SliceStable(ctx, func(i, j int) bool { return ctx[i].Time.Before(ctx[j].Time) })
	excluded, dups := r.Excluded, r.Duplicates
	ctx = r.dedupe(r.exclude(ctx))
	r.Excluded, r.Duplicates = excluded, dups
	all := make([]*Row, 0, len(ctx)+len(rows))
	for _, e := range ctx {
		all = append(all, &Row{Event: e})
	}
	all = append(all, rows...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all
}

// clusters splits time-sorted rows into runs where each row is within
// window of the first row of its run.
func clusters(rows []*Row, window time.Duration) [][]*Row {
	var out [][]*Row
	var cur []*Row
	for _, x := range rows {
		if len(cur) > 0 && x.Time.Sub(cur[0].Time) > window {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, x)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// rowIDs lists the IDs of rows in this report's period (rows read only
// for context have none).
func rowIDs(rows []*Row) []string {
	var ids []string
	seen := map[string]bool{}
	for _, x := range rows {
		if x.ID != "" && !seen[x.ID] {
			seen[x.ID] = true
			ids = append(ids, x.ID)
		}
	}
	return ids
}

func distinctList(rows []*Row, f func(*Row) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range rows {
		v := f(x)
		if v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

func distinct(rows []*Row, f func(*Row) string) string {
	return strings.Join(distinctList(rows, f), ", ")
}

// ---------------------------------------------------------------- attention

// actionLabels are singular/plural descriptions for the "Also review" list.
var actionLabels = map[string][2]string{
	"usb_connected":           {"removable device connected", "removable devices connected"},
	"virtual_disk_mounted":    {"virtual disk (ISO/VHD) mounted", "virtual disks (ISO/VHD) mounted"},
	"removable_write":         {"file written to removable media", "files written to removable media"},
	"removable_delete":        {"file deleted from removable media", "files deleted from removable media"},
	"removable_execute":       {"program run from removable media", "programs run from removable media"},
	"removable_access_denied": {"blocked removable media access attempt", "blocked removable media access attempts"},
	"usb_blocked":             {"USB device blocked by USBGuard", "USB devices blocked by USBGuard"},
	"account_locked":          {"account lockout", "account lockouts"},
	"account_created":         {"user account created", "user accounts created"},
	"account_enabled":         {"user account enabled", "user accounts enabled"},
	"account_disabled":        {"user account disabled", "user accounts disabled"},
	"account_deleted":         {"user account deleted", "user accounts deleted"},
	"account_renamed":         {"user account renamed", "user accounts renamed"},
	"password_reset":          {"password reset by an administrator", "passwords reset by an administrator"},
	"group_member_added":      {"group membership added", "group memberships added"},
	"group_member_removed":    {"group membership removed", "group memberships removed"},
	"group_deleted":           {"group deleted", "groups deleted"},
	"explicit_credentials":    {"use of another account's credentials", "uses of another account's credentials"},
	"service_installed":       {"service installed", "services installed"},
	"scheduled_task_created":  {"scheduled task created", "scheduled tasks created"},
	"time_changed":            {"system time change", "system time changes"},
	"audit_policy_changed":    {"audit policy change", "audit policy changes"},
	"malware_action":          {"anti-malware action", "anti-malware actions"},
	"eventlog_error":          {"event log error", "event log errors"},
	"sudo_denied":             {"refused sudo command", "refused sudo commands"},
	"removable_mounted":       {"removable disk opened (mounted)", "removable disks opened (mounted)"},
	"module_loaded":           {"kernel module loaded", "kernel modules loaded"},
	"module_unloaded":         {"kernel module unloaded", "kernel modules unloaded"},
	"promiscuous_mode":        {"network capture (promiscuous mode) started", "network captures (promiscuous mode) started"},
	"audit_rule_added":        {"audit rule added", "audit rules added"},
	"audit_config_changed":    {"audit configuration change", "audit configuration changes"},
	"powershell_suspicious":   {"PowerShell script flagged as suspicious", "PowerShell scripts flagged as suspicious"},
	"powershell_tamper":       {"PowerShell script that can clear logs or weaken auditing", "PowerShell scripts that can clear logs or weaken auditing"},
	"powershell_av_tamper":    {"PowerShell script that weakens Microsoft Defender", "PowerShell scripts that weaken Microsoft Defender"},
	"powershell_download":     {"PowerShell script that downloads and runs code", "PowerShell scripts that download and run code"},
	"powershell_credential":   {"password-stealing tool run in PowerShell", "password-stealing tools run in PowerShell"},
	"powershell_amsi_bypass":  {"PowerShell attempt to switch off script scanning (AMSI)", "PowerShell attempts to switch off script scanning (AMSI)"},
}

func (r *Report) buildAttention(rows []*Row) {
	groups := map[string]*AttentionGroup{}
	var order []string
	for _, row := range rows {
		switch row.Severity {
		case event.SevHigh:
			r.HighRows = append(r.HighRows, row)
		case event.SevMedium:
			g := groups[row.Action]
			if g == nil {
				g = &AttentionGroup{Category: row.Category, RowID: row.ID}
				groups[row.Action] = g
				order = append(order, row.Action)
			}
			g.Count++
		}
	}
	for _, a := range order {
		g := groups[a]
		l, ok := actionLabels[a]
		if !ok {
			l = [2]string{strings.ReplaceAll(a, "_", " "), strings.ReplaceAll(a, "_", " ")}
		}
		g.Label = l[1]
		if g.Count == 1 {
			g.Label = l[0]
		}
		r.Medium = append(r.Medium, *g)
	}
	sort.SliceStable(r.Medium, func(i, j int) bool {
		return catIndex(r.Medium[i].Category) < catIndex(r.Medium[j].Category)
	})
}

func catIndex(c event.Category) int {
	for i, ci := range event.Categories {
		if ci.ID == c {
			return i
		}
	}
	return len(event.Categories)
}

// ---------------------------------------------------------------- users

func (r *Report) buildUsers(events []*event.Event) {
	idx := map[string]*UserRow{}
	for _, e := range events {
		if e.User == "" || e.Action == "logoff" {
			continue
		}
		u := idx[e.User]
		if u == nil {
			u = &UserRow{User: e.User, Counts: map[event.Category]int{}}
			idx[e.User] = u
		}
		u.Counts[e.Category]++
		u.Total++
		if e.Severity == event.SevHigh {
			u.High++
		}
	}
	for _, u := range idx {
		r.Users = append(r.Users, *u)
	}
	sort.Slice(r.Users, func(i, j int) bool {
		a, b := r.Users[i], r.Users[j]
		if a.High != b.High {
			return a.High > b.High
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		return a.User < b.User
	})
}

// ---------------------------------------------------------------- health

func (r *Report) buildHealth(runs []*store.Run, events []*event.Event) {
	h := &r.Health
	for _, cs := range r.CheckSets {
		h.ChecksPass += cs.Pass
		h.ChecksFail += cs.Fail
		h.ChecksWarn += cs.Warn
	}
	for _, e := range events {
		if e.Action == "log_cleared" {
			h.LogClears++
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Time.Before(runs[j].Time) })
	chIdx := map[string]*ChannelHealth{}
	var chOrder []string
	vol := map[string]*VolumeRow{}
	lastRun := map[string]time.Time{} // by host, for gaps between runs
	pause := map[string]time.Duration{}
	for _, run := range runs {
		h.Runs++
		if h.FirstRun.IsZero() {
			h.FirstRun = run.Time
		}
		h.LastRun = run.Time
		hk := store.SystemKey(run.Host)
		if prev, ok := lastRun[hk]; ok {
			if p := run.Time.Sub(prev); p > pause[hk] {
				pause[hk] = p
			}
			if p := run.Time.Sub(prev); p > h.LongestPause {
				h.LongestPause = p
			}
		}
		lastRun[hk] = run.Time
		for _, c := range run.Channels {
			k := run.Host + "|" + c.Channel
			ch := chIdx[k]
			if ch == nil {
				ch = &ChannelHealth{Host: run.Host, Channel: c.Channel}
				chIdx[k] = ch
				chOrder = append(chOrder, k)
			}
			ch.Runs++
			ch.Read += c.Read
			ch.Kept += c.Kept
			h.TotalRead += c.Read
			h.TotalKept += c.Kept
			ch.Unavailable = c.Unavailable
			if c.Error != "" {
				ch.LastError = c.Error
			}
			if !c.OldestTime.IsZero() {
				ch.History = run.Time.Sub(c.OldestTime)
			}
			if c.MaxSizeBytes > 0 {
				ch.MaxSize = c.MaxSizeBytes
			}
			if c.Gap != nil {
				ch.Lost += c.Gap.Lost
				h.Gaps = append(h.Gaps, GapItem{Host: run.Host, Channel: c.Channel, Lost: c.Gap.Lost, From: c.Gap.From, To: c.Gap.To, Note: c.Gap.Note})
			}
			if c.Reset {
				ch.Resets++
				h.Gaps = append(h.Gaps, GapItem{Host: run.Host, Channel: c.Channel, Reset: true, To: run.Time})
			}
			for id, n := range c.EventCounts {
				vk := c.Channel + "|" + strconv.Itoa(id)
				v := vol[vk]
				if v == nil {
					v = &VolumeRow{Channel: c.Channel, EventID: id}
					if c.Channel == "Security" || c.Channel == "System" {
						v.Name = winevt.EventNames[id]
					}
					vol[vk] = v
				}
				v.Count += n
			}
			for typ, n := range c.TypeCounts {
				vk := c.Channel + "|" + typ
				v := vol[vk]
				if v == nil {
					v = &VolumeRow{Channel: c.Channel, Type: typ, Name: linuxlog.RecordTypeNames[typ]}
					vol[vk] = v
				}
				v.Count += n
			}
		}
	}
	for _, k := range chOrder {
		h.Channels = append(h.Channels, *chIdx[k])
	}
	for _, v := range vol {
		if h.TotalRead > 0 {
			v.Percent = 100 * float64(v.Count) / float64(h.TotalRead)
		}
		h.Volume = append(h.Volume, *v)
	}
	sort.Slice(h.Volume, func(i, j int) bool {
		if h.Volume[i].Count != h.Volume[j].Count {
			return h.Volume[i].Count > h.Volume[j].Count
		}
		if h.Volume[i].EventID != h.Volume[j].EventID {
			return h.Volume[i].EventID < h.Volume[j].EventID
		}
		return h.Volume[i].Type < h.Volume[j].Type
	})
	if len(h.Volume) > 12 {
		h.Volume = h.Volume[:12]
	}

	// Plain-language warnings.
	for _, g := range h.Gaps {
		if g.Note != "" {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: %s: %s (since %s).", g.Host, g.Channel, g.Note, r.stamp(g.From)))
			continue
		}
		if g.Reset {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: the %s log was cleared or recreated before %s; events in it that had not yet been collected are gone.", g.Host, g.Channel, r.stamp(g.To)))
			continue
		}
		h.Warnings = append(h.Warnings, fmt.Sprintf("%s: %s events in the %s log were overwritten before Blackbox could collect them (between %s and %s). Collect more often or increase the log size.",
			g.Host, commas(g.Lost), g.Channel, r.stamp(g.From), r.stamp(g.To)))
	}
	for _, ch := range h.Channels {
		if ch.LastError != "" {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: could not read the %s log: %s", ch.Host, ch.Channel, ch.LastError))
		}
		if ch.Channel == "Security" && ch.History > 0 && ch.History < 24*time.Hour {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: the Security log only holds about %s of history. Hourly collection keeps up, but if collection stops for longer than that, events will be lost. Increasing the log size is recommended.",
				ch.Host, roughDuration(ch.History)))
		}
	}
	if r.Source == "" || strings.HasPrefix(r.Source, "Live") {
		if h.Runs == 0 && len(r.Systems) <= 1 {
			h.Warnings = append(h.Warnings, "No collection runs were recorded in this period.")
		}
		hosts := make([]string, 0, len(pause))
		for k := range pause {
			hosts = append(hosts, k)
		}
		sort.Strings(hosts)
		for _, k := range hosts {
			if p := pause[k]; p > 6*time.Hour {
				who := "The"
				if len(lastRun) > 1 {
					who = k + ": the"
				}
				h.Warnings = append(h.Warnings, fmt.Sprintf("%s longest time between collections was %s (the computer may have been off, or the scheduled task did not run).", who, roughDuration(p)))
			}
		}
	}
	h.Warnings = append(h.Warnings, r.LANWarnings...)
}

// ---------------------------------------------------------------- formatting

func (r *Report) clock(t time.Time) string { return t.In(r.Location).Format("15:04:05") }

func (r *Report) stamp(t time.Time) string {
	if t.IsZero() {
		return "an unknown time"
	}
	return t.In(r.Location).Format("2006-01-02 15:04")
}

func roughDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	case d >= time.Hour:
		return "1 hour"
	}
	return fmt.Sprintf("%.0f minutes", d.Minutes())
}

func commas[T ~int | ~uint64](n T) string {
	s := strconv.FormatUint(uint64(n), 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
